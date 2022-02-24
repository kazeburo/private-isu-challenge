package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"unsafe"

	//"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/profiler"
	"github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
	"github.com/mojura/enkodo"
	"github.com/valyala/bytebufferpool"
	"golang.org/x/sync/singleflight"
)

var (
	db                 *sqlx.DB
	templRegister      *template.Template
	templBanned        *template.Template
	postLock           sync.RWMutex
	postCache          map[int]Post
	recentCommentLock  sync.RWMutex
	recentCommentCache map[int][]Comment
	userLock           sync.RWMutex
	userCache          map[int]*User
	delFlgCache        map[int]interface{}
	accountCache       map[string]int
	sfGroup            singleflight.Group
	indexCache         []byte
	indexLock          sync.RWMutex
	emptyInterface     interface{}
)

const (
	postsPerPage     = 20
	relaxPostPerPage = 25
	ISO8601Format    = "2006-01-02T15:04:05-07:00"
	UploadLimit      = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID               int       `db:"id"`
	AccountName      string    `db:"account_name"`
	Passhash         string    `db:"passhash"`
	Authority        int       `db:"authority"`
	DelFlg           int       `db:"del_flg"`
	CreatedAt        time.Time `db:"created_at"`
	CommentCount     int       `db:"comment_count"`
	PostCount        int       `db:"post_count"`
	PostCommentCount int       `db:"post_comment_count"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	Created      string
	CommentCount int `db:"comment_count"`
	Comments     []Comment
	UserName     string `db:"user_name"`
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	UserName  string    `db:"user_name"`
}

type PostSummary struct {
	Count int `db:"c"`
	Sum   int `db:"s"`
}

// https://github.com/gofiber/fiber/blob/861e5d21fbdfcf1759a274a3becfa5d9cf9a173c/utils/convert.go#L22
func UnsafeBytes(s string) (bs []byte) {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	bh.Data = sh.Data
	bh.Len = sh.Len
	bh.Cap = sh.Len
	return
}

// CopyString copies a string to make it immutable
func CopyString(s string) string {
	return string(UnsafeBytes(s))
}

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM images WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}

	files, err := filepath.Glob("/home/isucon/private_isu/webapp/public/image/?????*.*")
	if err == nil {
		for _, f := range files {
			os.Remove(f)
		}
	}
}

func warmupCache() {
	users := []User{}
	db.Select(&users, "SELECT `id`, `account_name`, `passhash`, `authority`, `del_flg`,"+
		"(SELECT COUNT(id) FROM comments WHERE comments.user_id = users.id) AS `comment_count`,"+
		"(SELECT count(`id`) FROM `posts` WHERE posts.user_id = users.id) AS `post_count`,"+
		"(SELECT IFNULL(sum(posts.`comment_count`),0) FROM `posts` WHERE posts.user_id = users.id) AS `post_comment_count`"+
		"FROM `users`")
	uc := map[int]*User{}
	accounts := map[string]int{}
	delflags := map[int]interface{}{}
	for uid := range users {
		u := users[uid]
		uc[u.ID] = &u
		accounts[u.AccountName] = u.ID
		if u.DelFlg == 1 {
			delflags[u.ID] = emptyInterface
		}

	}
	userLock.Lock()
	userCache = uc
	accountCache = accounts
	delFlgCache = delflags
	userLock.Unlock()

	posts := []Post{}
	db.Select(&posts, "SELECT `id`, `user_id`, `body`, `mime`, `comment_count`,`created_at` FROM `posts`")
	postsMap := map[int]Post{}
	for _, p := range posts {
		p.Created = p.CreatedAt.Format("2006-01-02T15:04:05-07:00")
		userLock.RLock()
		u := userCache[p.UserID]
		p.UserName = u.AccountName
		userLock.RUnlock()
		postsMap[p.ID] = p
	}
	postLock.Lock()
	postCache = postsMap
	postLock.Unlock()

	recentCommentMap := map[int][]Comment{}
	comments := []Comment{}
	query := "SELECT " +
		"c.id AS `id`," +
		"c.post_id AS `post_id`," +
		"c.user_id AS `user_id`," +
		"c.comment AS `comment`," +
		"u.account_name AS `user_name` " +
		"FROM (SELECT `id`,`post_id`,`user_id`,`comment`,`created_at`, RANK() OVER (PARTITION BY `post_id` ORDER BY `created_at`) AS `r` FROM `comments`) AS c JOIN `users` u ON c.user_id = u.id WHERE `r` <= 3 ORDER BY c.created_at DESC"

	db.Select(&comments, query)
	for i := range comments {
		i = len(comments) - 1 - i
		for _, p := range posts {
			if p.ID == comments[i].PostID {
				recentCommentMap[p.ID] = append(recentCommentMap[p.ID], comments[i])
			}
		}
	}
	recentCommentLock.Lock()
	recentCommentCache = recentCommentMap
	recentCommentLock.Unlock()
}

func tryLogin(accountName, password string) *User {
	userLock.RLock()
	uid, ok := accountCache[accountName]
	if !ok {
		userLock.RUnlock()
		return nil
	}
	u := userCache[uid]
	userLock.RUnlock()

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return u
	} else {
		return nil
	}
}

var vReg1 = regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`)
var vReg2 = regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`)

func validateUser(accountName, password string) bool {
	return vReg1.MatchString(accountName) &&
		vReg2.MatchString(password)
}

func digest(src string) string {
	b := sha512.Sum512(UnsafeBytes(src))
	return hex.EncodeToString(b[:])
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(c *fiber.Ctx) *simpleCookie {
	session, err := sessionGet(c, "isuconp-go.session")
	if err != nil {
		log.Print(err)
	}
	return session
}

func getSessionUser(c *fiber.Ctx) *User {
	session := getSession(c)
	id := session.Values.UserID

	userLock.RLock()
	u, ok := userCache[id]
	userLock.RUnlock()
	if !ok {
		return &User{}
	}
	return u
}

func getFlash(c *fiber.Ctx) string {
	session := getSession(c)
	notice := session.Values.Notice

	if notice == "" {
		return ""
	} else {
		session.Values.Notice = ""
		session.Save(c)
		return notice
	}
}

func makePosts(results []int, csrfToken string, allComments bool) ([]Post, error) {
	posts := make([]Post, 0, postsPerPage)
	commentPostIDs := make([]int, 0, postsPerPage)
	totalComment := 0
	for _, i := range results {
		postLock.RLock()
		p, ok := postCache[i]
		postLock.RUnlock()
		if !ok {
			continue
		}

		if !allComments || p.CommentCount <= 3 {
			recentCommentLock.RLock()
			p.Comments = recentCommentCache[p.ID]
			recentCommentLock.RUnlock()
		}
		if p.CommentCount > 3 && allComments {
			p.Comments = make([]Comment, 0, p.CommentCount)
			commentPostIDs = append(commentPostIDs, p.ID)
			totalComment += p.CommentCount
		}

		p.CSRFToken = csrfToken
		userLock.RLock()
		_, isDel := delFlgCache[p.UserID]
		userLock.RUnlock()

		if !isDel {
			posts = append(posts, p)
		}
		if len(posts) >= postsPerPage {
			break
		}
	}

	if len(commentPostIDs) > 0 {
		b := make([]string, len(commentPostIDs))
		for i, v := range commentPostIDs {
			b[i] = strconv.Itoa(v)
		}
		query := "SELECT " +
			"c.id AS `id`," +
			"c.post_id AS `post_id`," +
			"c.user_id AS `user_id`," +
			"c.comment AS `comment`," +
			"u.account_name AS `user_name` " +
			"FROM `comments` c JOIN `users` u ON c.user_id = u.id " +
			"WHERE c.post_id IN (" +
			strings.Join(b, ",") +
			") ORDER BY c.created_at DESC"
		comments := make([]Comment, 0, totalComment+5)
		err := db.Select(&comments, query)
		if err != nil {
			return nil, err
		}

		for i := range comments {
			i = len(comments) - 1 - i
			for k := range posts {
				if posts[k].ID == comments[i].PostID {
					posts[k].Comments = append(posts[k].Comments, comments[i])
				}
			}
		}
	}

	return posts, nil
}

func isLogin(u *User) bool {
	return u.ID != 0
}

func getCSRFToken(c *fiber.Ctx) string {
	session := getSession(c)
	return session.Values.CSRFToken
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return hex.EncodeToString(k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(c *fiber.Ctx) error {
	dbInitialize()
	warmupCache()
	return c.SendStatus(fiber.StatusOK)
}

func getLogin(c *fiber.Ctx) error {
	me := getSessionUser(c)

	if isLogin(me) {
		return c.Redirect("/", fiber.StatusFound)
	}

	loginHTML(c.Status(fiber.StatusOK), me, getFlash(c))
	return nil
}

func postLogin(c *fiber.Ctx) error {
	if isLogin(getSessionUser(c)) {
		return c.Redirect("/", fiber.StatusFound)
	}

	u := tryLogin(c.FormValue("account_name"), c.FormValue("password"))

	if u != nil {
		session := getSession(c)
		session.Values.UserID = u.ID
		session.Values.CSRFToken = secureRandomStr(16)
		session.Save(c)

		return c.Redirect("/", fiber.StatusFound)
	} else {
		session := getSession(c)
		session.Values.Notice = "アカウント名かパスワードが間違っています"
		session.Save(c)

		return c.Redirect("/login", fiber.StatusFound)
	}
}

func getRegister(c *fiber.Ctx) error {
	if isLogin(getSessionUser(c)) {
		return c.Redirect("/", fiber.StatusFound)

	}

	templRegister.Execute(c.Status(fiber.StatusOK), struct {
		Me    User
		Flash string
	}{User{}, getFlash(c)})
	return nil
}

func postRegister(c *fiber.Ctx) error {
	if isLogin(getSessionUser(c)) {
		return c.Redirect("/", fiber.StatusFound)
	}

	accountName, password := c.FormValue("account_name"), c.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(c)
		session.Values.Notice = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(c)
		return c.Redirect("/register", fiber.StatusFound)
	}

	pw := calculatePasshash(accountName, password)
	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, pw)
	if err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok {
			if mysqlErr.Number == 1062 {
				session := getSession(c)
				session.Values.Notice = "アカウント名がすでに使われています"
				session.Save(c)
				return c.Redirect("/register", fiber.StatusFound)
			}
		}
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	userLock.Lock()
	userCache[int(uid)] = &User{
		ID:          int(uid),
		AccountName: CopyString(accountName),
		Passhash:    pw,
	}
	accountCache[accountName] = int(uid)
	userLock.Unlock()

	session := getSession(c)
	session.Values.UserID = int(uid)
	session.Values.CSRFToken = secureRandomStr(16)
	session.Save(c)

	return c.Redirect("/", fiber.StatusFound)
}

func getLogout(c *fiber.Ctx) error {
	session := getSession(c)
	session.Values.UserID = 0
	session.Save(c)

	return c.Redirect("/", fiber.StatusFound)
}

func updateIndex() {
	sfGroup.Do("getIndex", func() (interface{}, error) {
		results := make([]int, 0, relaxPostPerPage)

		err := db.Select(&results, "SELECT "+
			"`id` "+
			"FROM `posts` FORCE INDEX (posts_order_idx) "+
			"ORDER BY `created_at` DESC LIMIT ?", relaxPostPerPage)
		if err != nil {
			log.Print(err)
			return nil, err
		}

		posts, err := makePosts(results, "[[getCSRFToken]]", false)
		if err != nil {
			log.Print(err)
			return nil, err
		}
		var b bytes.Buffer
		postsHTML(&b, posts)

		indexLock.Lock()
		indexCache = b.Bytes()
		indexLock.Unlock()
		return nil, nil
	})
}

func getIndex(c *fiber.Ctx) error {
	me := getSessionUser(c)
	token := getCSRFToken(c)
	bToken := []byte(token)

	b := bytebufferpool.Get()
	defer func() {
		bytebufferpool.Put(b)
	}()

	i := 0
	indexLock.RLock()
	for {
		k := bytes.Index(indexCache[i:], []byte("[[getCSRFToken]]"))
		if k <= 0 {
			b.Write(indexCache[i:])
			break
		}
		b.Write(indexCache[i : i+k])
		b.Write(bToken)
		i += k + len("[[getCSRFToken]]")
	}
	indexLock.RUnlock()
	indexHTML(c.Status(fiber.StatusOK), b.Bytes(), me, token, getFlash(c))
	return nil
}

func getAccountName(c *fiber.Ctx) error {
	accountName := c.Params("accountName")

	userLock.RLock()
	uid, ok := accountCache[accountName]
	if !ok {
		userLock.RUnlock()
		return c.SendStatus(fiber.StatusNotFound)
	}
	user := userCache[uid]
	commentCount := user.CommentCount
	commentedCount := user.PostCommentCount
	postCount := user.PostCount
	userLock.RUnlock()

	if user.ID == 0 || user.DelFlg != 0 {
		return c.SendStatus(fiber.StatusNotFound)
	}

	results := make([]int, 0, relaxPostPerPage)
	err := db.Select(&results, "SELECT "+
		"`id` "+
		"FROM `posts` FORCE INDEX (posts_user_idx) WHERE `user_id` = ? "+
		"ORDER BY `created_at` DESC LIMIT ?", user.ID, relaxPostPerPage)
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	posts, err := makePosts(results, getCSRFToken(c), false)
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	me := getSessionUser(c)

	userHTML(
		c.Status(fiber.StatusOK),
		posts,
		user,
		postCount,
		commentCount,
		commentedCount,
		me,
	)
	return nil
}

func getPosts(c *fiber.Ctx) error {
	maxCreatedAt := c.Query("max_created_at")
	if maxCreatedAt == "" {
		return c.SendStatus(fiber.StatusBadRequest)
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusBadRequest)
	}

	results := make([]int, 0, relaxPostPerPage)
	err = db.Select(&results, "SELECT "+
		"`id` "+
		"FROM `posts` FORCE INDEX (posts_order_idx) "+
		"WHERE `created_at` <= ? ORDER BY `created_at` DESC LIMIT ?", t.Format(ISO8601Format), relaxPostPerPage)
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	posts, err := makePosts(results, getCSRFToken(c), false)
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	if len(posts) == 0 {
		return c.SendStatus(fiber.StatusNotFound)
	}
	postsHTML(c, posts)
	return nil
}

func getPostsID(c *fiber.Ctx) error {
	pidStr := c.Params("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	results := []int{pid}

	posts, err := makePosts(results, getCSRFToken(c), true)
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	if len(posts) == 0 {
		return c.SendStatus(fiber.StatusNotFound)
	}

	p := posts[0]

	me := getSessionUser(c)
	postIDHTML(c.Status(fiber.StatusOK), p, me)
	return nil
}

func postIndex(c *fiber.Ctx) error {
	me := getSessionUser(c)
	if !isLogin(me) {
		return c.Redirect("/login", fiber.StatusFound)
	}

	token := c.FormValue("csrf_token")
	body := c.FormValue("body")
	uploadfile, err := c.FormFile("file")

	if err != nil {
		return c.SendStatus(fiber.StatusUnprocessableEntity)
	}

	if token != getCSRFToken(c) {
		return c.SendStatus(fiber.StatusUnprocessableEntity)
	}

	if uploadfile == nil {
		session := getSession(c)
		session.Values.Notice = "画像が必須です"
		session.Save(c)
		return c.Redirect("/", fiber.StatusFound)
	}

	mime := ""

	// 投稿のContent-Typeからファイルのタイプを決定する
	contentType := uploadfile.Header["Content-Type"][0]
	if strings.Contains(contentType, "jpeg") {
		mime = "image/jpeg"
	} else if strings.Contains(contentType, "png") {
		mime = "image/png"
	} else if strings.Contains(contentType, "gif") {
		mime = "image/gif"
	} else {
		session := getSession(c)
		session.Values.Notice = "投稿できる画像形式はjpgとpngとgifだけです"
		session.Save(c)

		return c.Redirect("/", fiber.StatusFound)
	}

	if uploadfile.Size > UploadLimit {
		session := getSession(c)
		session.Values.Notice = "ファイルサイズが大きすぎます"
		session.Save(c)
		return c.Redirect("/", fiber.StatusFound)
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		"",
		body,
	)
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	id := int(pid)
	dst := imagePath(id, mime)
	c.SaveFile(uploadfile, dst)

	n := time.Now()
	postLock.Lock()
	postCache[id] = Post{
		ID:           id,
		UserID:       me.ID,
		Mime:         mime,
		Body:         CopyString(body),
		CommentCount: 0,
		CreatedAt:    n,
		Created:      n.Format("2006-01-02T15:04:05-07:00"),
		UserName:     me.AccountName,
	}
	postLock.Unlock()

	recentCommentLock.Lock()
	recentCommentCache[id] = []Comment{}
	recentCommentLock.Unlock()

	userLock.Lock()
	u := userCache[me.ID]
	u.PostCount++
	userCache[me.ID] = u
	userLock.Unlock()

	updateIndex()

	return c.Redirect("/posts/"+strconv.FormatInt(pid, 10), fiber.StatusFound)
}

func imagePath(id int, mime string) string {
	var ext string
	switch mime {
	case "image/jpeg":
		ext = ".jpg"
	case "image/png":
		ext = ".png"
	case "image/gif":
		ext = ".gif"
	}
	var b strings.Builder
	b.WriteString("/home/isucon/private_isu/webapp/public/image/")
	b.WriteString(strconv.Itoa(id))
	b.WriteString(ext)
	return b.String()
}

func writeImage(id int, mime string, data []byte) {
	fn := imagePath(id, mime)
	f, err := os.OpenFile(fn, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	f.Write(data)
	f.Close()
}

func getImage(c *fiber.Ctx) error {
	ims := c.Request().Header.Peek(fiber.HeaderIfModifiedSince)
	if len(ims) > 0 {
		return c.SendStatus(fiber.StatusNotModified)
	}

	pidStr := c.Params("id")
	ext := c.Params("ext")
	fn := "../public/image/" + pidStr + "." + ext
	stat, err := os.Stat(fn)
	if err == nil {
		switch ext {
		case "jpg":
			c.Set("Content-Type", "image/jpeg")
		case "png":
			c.Set("Content-Type", "image/png")
		case "gif":
			c.Set("Content-Type", "image/gif")
		}
		file, _ := os.Open(fn)
		c.Set("Last-Modified", "Mon, 31 May 2021 04:50:49 GMT")
		c.Set("Cache-Control", "public, max-age=300")
		return c.Status(fiber.StatusOK).SendStream(file, int(stat.Size()))
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	post := Post{}
	err = db.Get(&post, "SELECT * FROM `images` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusNotFound)
	}

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		writeImage(pid, post.Mime, post.Imgdata)
		now := time.Now().Format("Mon, 02 Jan 2006 15:04:05 MST")
		c.Set("Last-Modified", now)
		c.Set("Cache-Control", "public, max-age=300")
		c.Set("Content-Type", post.Mime)
		return c.Status(fiber.StatusOK).Send(post.Imgdata)
	}

	return c.SendStatus(fiber.StatusNotFound)
}

func postComment(c *fiber.Ctx) error {
	me := getSessionUser(c)
	if !isLogin(me) {
		return c.Redirect("/login", fiber.StatusFound)
	}

	if c.FormValue("csrf_token") != getCSRFToken(c) {
		return c.SendStatus(fiber.StatusUnprocessableEntity)
	}

	postID, err := strconv.Atoi(c.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	body := c.FormValue("comment")
	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	result, err := db.Exec(query, postID, me.ID, body)
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}
	cid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	recentCommentLock.Lock()
	pc := recentCommentCache[postID]
	pc = append(pc, Comment{
		ID:      int(cid),
		PostID:  postID,
		UserID:  me.ID,
		Comment: CopyString(body),
	})
	if len(pc) > 3 {
		pc = pc[1:3]
	}
	recentCommentCache[postID] = pc
	recentCommentLock.Unlock()

	postLock.Lock()
	p := postCache[postID]
	p.CommentCount++
	postCache[postID] = p
	postLock.Unlock()

	userLock.Lock()
	u := userCache[me.ID]
	u.CommentCount++
	userCache[me.ID] = u
	u2 := userCache[p.UserID]
	u2.PostCommentCount++
	userCache[p.UserID] = u2
	userLock.Unlock()

	return c.Redirect("/posts/"+strconv.Itoa(postID), fiber.StatusFound)
}

func getAdminBanned(c *fiber.Ctx) error {
	me := getSessionUser(c)
	if !isLogin(me) {
		return c.Redirect("/", fiber.StatusFound)
	}

	if me.Authority == 0 {
		return c.SendStatus(fiber.StatusForbidden)
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	templBanned.Execute(c.Status(fiber.StatusOK), struct {
		Users     []User
		Me        *User
		CSRFToken string
	}{users, me, getCSRFToken(c)})
	return nil
}

func postAdminBanned(c *fiber.Ctx) error {
	me := getSessionUser(c)
	if !isLogin(me) {
		return c.Redirect("/", fiber.StatusFound)
	}

	if me.Authority == 0 {
		return c.SendStatus(fiber.StatusForbidden)
	}

	if c.FormValue("csrf_token") != getCSRFToken(c) {
		return c.SendStatus(fiber.StatusUnprocessableEntity)
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	mf, err := c.MultipartForm()
	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	for _, id := range mf.Value["uid[]"] {
		db.Exec(query, 1, id)
	}
	userLock.Lock()
	for _, id := range mf.Value["uid[]"] {
		i, _ := strconv.Atoi(id)
		u := userCache[i]
		u.DelFlg = 1
		//userCache[i] = u
		delFlgCache[i] = emptyInterface
	}
	userLock.Unlock()
	return c.Redirect("/admin/banned", fiber.StatusFound)
}

func notModifiedFirst(c *fiber.Ctx) error {
	if len(c.Request().Header.Peek(fiber.HeaderIfModifiedSince)) > 0 {
		return c.SendStatus(fiber.StatusNotModified)
	}
	return c.Next()
}

var use_profiler = true

func initProfiler() {

	if !use_profiler {
		return
	}

	serviceVersion := time.Now().Format("2006.01.02.15.04")
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID == "" {
		projectID = "xenon-heading-825"
	}
	if err := profiler.Start(profiler.Config{
		Service:        "private-isu",
		ServiceVersion: serviceVersion,
		ProjectID:      projectID,
	}); err != nil {
		log.Fatal(err)
	}
}

func main() {
	initProfiler()

	templRegister = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	)
	templBanned = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	)

	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	defer db.Close()

	warmupCache()
	updateIndex()

	app := fiber.New(fiber.Config{
		BodyLimit:          UploadLimit,
		Immutable:          false,
		ReduceMemoryUsage:  true,
		DisableDefaultDate: true,
	})

	app.Use("/js", notModifiedFirst)
	app.Use("/css", notModifiedFirst)
	app.Use("/img", notModifiedFirst)
	app.Use("/favicon.ico", notModifiedFirst)

	app.Get("/initialize", getInitialize)
	app.Get("/login", getLogin)
	app.Post("/login", postLogin)
	app.Get("/register", getRegister)
	app.Post("/register", postRegister)
	app.Get("/logout", getLogout)
	app.Get("/", getIndex)

	app.Get("/posts", getPosts)
	app.Get("/posts/:id", getPostsID)
	app.Post("/", postIndex)
	app.Get("/image/:id.:ext", getImage)
	app.Post("/comment", postComment)
	app.Get("/admin/banned", getAdminBanned)
	app.Post("/admin/banned", postAdminBanned)

	app.Get("/@:accountName", getAccountName)

	app.Static("/js/main.js", "../public/js/main.js")
	app.Static("/js/timeago.min.js", "../public/js/timeago.min.js")
	app.Static("/img/ajax-loader.gif", "../public/img/ajax-loader.gif")
	app.Static("/css/style.css", "../public/css/style.css")
	app.Static("/favicon.ico", "../public/favicon.ico")
	log.Fatal(app.Listen("0.0.0.0:80"))
}

type simpleCookie struct {
	Values sessionData
	Key    string
}
type sessionData struct {
	UserID    int
	Notice    string
	CSRFToken string
}

func (s *sessionData) MarshalEnkodo(enc *enkodo.Encoder) error {
	enc.Int(s.UserID)
	enc.String(s.Notice)
	enc.String(s.CSRFToken)
	return nil
}

func (s *sessionData) UnmarshalEnkodo(dec *enkodo.Decoder) error {
	var err error
	if s.UserID, err = dec.Int(); err != nil {
		return err
	}

	if s.Notice, err = dec.String(); err != nil {
		return err
	}

	if s.CSRFToken, err = dec.String(); err != nil {
		return err
	}

	return nil
}

func (s *simpleCookie) Save(c *fiber.Ctx) error {
	bs, err := enkodo.Marshal(&s.Values)
	if err != nil {
		return err
	}
	data := base64.StdEncoding.EncodeToString(bs)

	c.Cookie(&fiber.Cookie{
		Name:  s.Key,
		Value: data,
	})
	return nil
}

func sessionGet(c *fiber.Ctx, key string) (*simpleCookie, error) {
	s := c.Locals(key)
	if s != nil {
		return s.(*simpleCookie), nil
	}
	var sd sessionData
	cookie := c.Cookies(key)
	if cookie != "" {
		data, err := base64.StdEncoding.DecodeString(cookie)
		if err != nil {
			return nil, err
		}
		if err := enkodo.Unmarshal(data, &sd); err != nil {
			return nil, err
		}
	}
	newSession := &simpleCookie{
		Values: sd,
		Key:    key,
	}
	c.Locals(key, newSession)
	return newSession, nil
}

func loginHTML(dest io.Writer, me *User, flash string) (int, error) {
	b := bytebufferpool.Get()
	defer func() {
		bytebufferpool.Put(b)
	}()
	layoutHTMLheader(b, me)
	b.WriteString(`<div class="header">
<h1>ログイン</h1>
</div>`)
	if flash != "" {
		b.WriteString(`<div id="notice-message" class="alert alert-danger">`)
		b.WriteString(flash)
		b.WriteString(`</div>`)
	}
	b.WriteString(`<div class="submit">
<form method="post" action="/login">
<div class="form-account-name">
<span>アカウント名</span>
<input type="text" name="account_name">
</div>
<div class="form-password">
<span>パスワード</span>
<input type="password" name="password">
</div>
<div class="form-submit">
<input type="submit" name="submit" value="submit">
</div>
</form>
</div>
<div class="isu-register">
<a href="/register">ユーザー登録</a>
</div>`)
	layoutHTMLfooter(b)
	return dest.Write(b.Bytes())
}

func indexHTML(dest io.Writer, posts []byte, me *User, token string, flash string) (int, error) {
	b := bytebufferpool.Get()
	defer func() {
		bytebufferpool.Put(b)
	}()
	layoutHTMLheader(b, me)
	b.WriteString(`
<div class="isu-submit">
<form method="post" action="/" enctype="multipart/form-data">
<div class="isu-form">
<input type="file" name="file" value="file">
</div>
<div class="isu-form">
<textarea name="body"></textarea>
</div>
<div class="form-submit">
<input type="hidden" name="csrf_token" value="`)
	b.WriteString(token)
	b.WriteString(`">
<input type="submit" name="submit" value="submit">
</div>`)
	if flash != "" {
		b.WriteString(`<div id="notice-message" class="alert alert-danger">`)
		b.WriteString(flash)
		b.WriteString(`</div>`)
	}
	b.WriteString(`</form>
</div>`)
	b.Write(posts)
	b.WriteString(`<div id="isu-post-more">
<button id="isu-post-more-btn">もっと見る</button>
<img class="isu-loading-icon" src="/img/ajax-loader.gif">
</div>`)
	layoutHTMLfooter(b)
	return dest.Write(b.Bytes())
}

func postIDHTML(dest io.Writer, p Post, me *User) (int, error) {
	b := bytebufferpool.Get()
	defer func() {
		bytebufferpool.Put(b)
	}()
	layoutHTMLheader(b, me)
	postHTML(b, p)
	layoutHTMLfooter(b)
	return dest.Write(b.Bytes())
}

func userHTML(
	dest io.Writer,
	ps []Post,
	user *User,
	postCount int,
	commentCount int,
	commentedCount int,
	me *User,
) (int, error) {
	b := bytebufferpool.Get()
	defer func() {
		bytebufferpool.Put(b)
	}()
	layoutHTMLheader(b, me)
	b.WriteString(`<div class="isu-user">
<div><span class="isu-user-account-name">`)
	b.WriteString(user.AccountName)
	b.WriteString(`さん</span>のページ</div>
<div>投稿数 <span class="isu-post-count">`)

	b.WriteString(strconv.Itoa(postCount))
	b.WriteString(`</span></div>
<div>コメント数 <span class="isu-comment-count">`)
	b.WriteString(strconv.Itoa(commentCount))
	b.WriteString(`</span></div>
  <div>被コメント数 <span class="isu-commented-count">`)
	b.WriteString(strconv.Itoa(commentedCount))
	b.WriteString(`</span></div>
</div>`)
	b.WriteString(`<div class="isu-posts">`)
	for _, p := range ps {
		postHTML(b, p)
	}
	b.WriteString(`</div>`)
	layoutHTMLfooter(b)
	return dest.Write(b.Bytes())
}

func escapeHTMLWriter(b *bytebufferpool.ByteBuffer, s string) {
	by := UnsafeBytes(s)
	i := 0
	for {
		if i > len(by)-1 {
			break
		}
		k := bytes.IndexByte(by[i:], '<')
		if k < 0 {
			b.Write(by[i:])
			break
		}
		b.Write(by[i : i+k])
		b.WriteString("&lt;")
		i += k + len("&lt;")
	}
}

func postsHTML(dest io.Writer, ps []Post) (int, error) {
	b := bytebufferpool.Get()
	defer func() {
		bytebufferpool.Put(b)
	}()
	b.WriteString(`<div class="isu-posts">`)
	for _, p := range ps {
		postHTML(b, p)
	}
	b.WriteString(`</div>`)
	return dest.Write(b.Bytes())
}

func layoutHTMLheader(b *bytebufferpool.ByteBuffer, me *User) (int, error) {
	b.WriteString(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Iscogram</title>
<link href="/css/style.css" media="screen" rel="stylesheet" type="text/css">
</head>
<body>
<div class="container">
<div class="header">
<div class="isu-title">
<h1><a href="/">Iscogram</a></h1>
</div>
<div class="isu-header-menu">`)
	if me.ID == 0 {
		b.WriteString(`<div><a href="/login">ログイン</a></div>`)
	} else {
		b.WriteString(`<div><a href="/@`)
		b.WriteString(me.AccountName)
		b.WriteString(`"><span class="isu-account-name">`)
		b.WriteString(me.AccountName)
		b.WriteString(`</span>さん</a></div>`)
		if me.Authority == 1 {
			b.WriteString(`<div><a href="/admin/banned">管理者用ページ</a></div>`)
		}
		b.WriteString(`<div><a href="/logout">ログアウト</a></div>`)
	}
	return b.WriteString(`</div>
</div>`)
}

func layoutHTMLfooter(b *bytebufferpool.ByteBuffer) (int, error) {
	return b.WriteString(`</div>
<script src="/js/timeago.min.js"></script>
<script src="/js/main.js"></script>
</body>
</html>`)
}

func postHTML(b *bytebufferpool.ByteBuffer, p Post) {
	sID := strconv.Itoa(p.ID)
	b.WriteString(`<div class="isu-post" id="pid_`)
	b.WriteString(sID)
	b.WriteString(`" data-created-at="`)
	b.WriteString(p.Created)
	b.WriteString(`">
<div class="isu-post-header">
<a href="/@`)
	b.WriteString(p.UserName)
	b.WriteString(`" class="isu-post-account-name">`)
	b.WriteString(p.UserName)
	b.WriteString(`</a>
<a href="/posts/`)
	b.WriteString(sID)
	b.WriteString(`" class="isu-post-permalink">
<time class="timeago" datetime="`)
	b.WriteString(p.Created)
	b.WriteString(`"></time>
</a>
</div>
<div class="isu-post-image">
<img src="/image/`)
	b.WriteString(sID)
	if p.Mime == "image/jpeg" {
		b.WriteString(`.jpg`)
	} else if p.Mime == "image/png" {
		b.WriteString(`.png`)
	} else if p.Mime == "image/gif" {
		b.WriteString(`.gif`)
	}
	b.WriteString(`" class="isu-image">
</div>
<div class="isu-post-text">
<a href="/@`)
	b.WriteString(p.UserName)
	b.WriteString(`" class="isu-post-account-name">`)
	b.WriteString(p.UserName)
	b.WriteString(`</a>`)
	escapeHTMLWriter(b, p.Body)
	b.WriteString(`</div>
<div class="isu-post-comment">
<div class="isu-post-comment-count">
comments: <b>`)
	b.WriteString(strconv.Itoa(p.CommentCount))
	b.WriteString(`</b>
</div>`)

	for _, c := range p.Comments {
		b.WriteString(`<div class="isu-comment">
<a href="/@`)
		b.WriteString(c.UserName)
		b.WriteString(`" class="isu-comment-account-name">`)
		b.WriteString(c.UserName)
		b.WriteString(`</a>
<span class="isu-comment-text">`)
		escapeHTMLWriter(b, c.Comment)
		b.WriteString(`</span>
</div>`)
	}

	b.WriteString(`<div class="isu-comment-form">
<form method="post" action="/comment">
<input type="text" name="comment">
<input type="hidden" name="post_id" value="`)
	b.WriteString(sID)
	b.WriteString(`">
<input type="hidden" name="csrf_token" value="`)
	b.WriteString(p.CSRFToken)
	b.WriteString(`">
<input type="submit" name="submit" value="submit">
</form>
</div>
</div>
</div>`)
}
