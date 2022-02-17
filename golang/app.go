package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
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

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/mojura/enkodo"
	"github.com/valyala/bytebufferpool"
	goji "goji.io"
	"goji.io/pat"
	"goji.io/pattern"
	"golang.org/x/sync/errgroup"
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
	userCache          map[int]User
	accountCache       map[string]int
	sfGroup            singleflight.Group
	indexCache         []byte
	indexLock          sync.RWMutex
)

const (
	postsPerPage     = 20
	relaxPostPerPage = 25
	ISO8601Format    = "2006-01-02T15:04:05-07:00"
	UploadLimit      = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
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
	User         User
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User
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
	db.Select(&users, "SELECT `id`, `account_name`, `passhash`, `authority`, `del_flg` FROM `users`")
	uc := map[int]User{}
	accounts := map[string]int{}
	for _, u := range users {
		uc[u.ID] = u
		accounts[u.AccountName] = u.ID

	}
	userLock.Lock()
	userCache = uc
	accountCache = accounts
	userLock.Unlock()

	posts := []Post{}
	db.Select(&posts, "SELECT `id`, `user_id`, `body`, `mime`, `comment_count`,`created_at` FROM `posts`")
	postsMap := map[int]Post{}
	for _, p := range posts {
		p.Created = p.CreatedAt.Format("2006-01-02T15:04:05-07:00")
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
		"u.id AS `user.id`, " +
		"u.account_name AS `user.account_name` " +
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
		return &u
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
	return fmt.Sprintf("%x", sha512.Sum512([]byte(src)))
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *simpleCookie {
	session, err := sessionGet(r, "isuconp-go.session")
	if err != nil {
		log.Print(err)
	}
	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	id := session.Values.UserID

	userLock.RLock()
	u, ok := userCache[id]
	userLock.RUnlock()
	if !ok {
		return User{}
	}
	return u
}

func getFlash(w http.ResponseWriter, r *http.Request) string {
	session := getSession(r)
	notice := session.Values.Notice

	if notice == "" {
		return ""
	} else {
		session.Values.Notice = ""
		session.Save(w, r)
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
		p.User = userCache[p.UserID]
		userLock.RUnlock()

		if p.User.DelFlg == 0 {
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
			"u.id AS `user.id`, " +
			"u.account_name AS `user.account_name` " +
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

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	return session.Values.CSRFToken
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	warmupCache()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	loginHTML(w, me, getFlash(w, r))
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values.UserID = u.ID
		session.Values.CSRFToken = secureRandomStr(16)
		session.Save(w, r)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values.Notice = "アカウント名かパスワードが間違っています"
		session.Save(w, r)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	templRegister.Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r)})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values.Notice = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(w, r)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values.Notice = "アカウント名がすでに使われています"
		session.Save(w, r)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	pw := calculatePasshash(accountName, password)
	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, pw)
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	userLock.Lock()
	userCache[int(uid)] = User{
		ID:          int(uid),
		AccountName: accountName,
		Passhash:    pw,
	}
	accountCache[accountName] = int(uid)
	userLock.Unlock()

	session.Values.UserID = int(uid)
	session.Values.CSRFToken = secureRandomStr(16)
	session.Save(w, r)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	session.Values.UserID = 0
	session.Save(w, r)

	http.Redirect(w, r, "/", http.StatusFound)
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

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	token := getCSRFToken(r)
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
	indexHTML(w, b.Bytes(), me, token, getFlash(w, r))
}

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := pat.Param(r, "accountName")

	userLock.RLock()
	uid, ok := accountCache[accountName]
	if !ok {
		userLock.RUnlock()
		w.WriteHeader(http.StatusNotFound)
		return
	}
	user := userCache[uid]
	userLock.RUnlock()

	if user.ID == 0 || user.DelFlg != 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var eg errgroup.Group
	posts := make([]Post, 0, postsPerPage)
	token := getCSRFToken(r)
	eg.Go(func() error {
		results := make([]int, 0, relaxPostPerPage)
		err := db.Select(&results, "SELECT "+
			"`id` "+
			"FROM `posts` FORCE INDEX (posts_user_idx) WHERE `user_id` = ? "+
			"ORDER BY `created_at` DESC LIMIT ?", user.ID, relaxPostPerPage)
		if err != nil {
			return err
		}

		posts, err = makePosts(results, token, false)
		if err != nil {
			return err
		}
		return nil
	})

	commentCount := 0
	eg.Go(func() error {
		err := db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
		if err != nil {
			return err
		}
		return nil
	})

	commentedCount := 0
	postCount := 0
	eg.Go(func() error {
		res := PostSummary{}
		err := db.Get(&res, "SELECT count(`id`) as c,IFNULL(sum(`comment_count`),0) as s FROM `posts` WHERE `user_id` = ?", user.ID)
		if err != nil {
			return err
		}
		postCount = res.Count
		commentedCount = res.Sum
		return nil
	})

	if err := eg.Wait(); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	me := getSessionUser(r)

	userHTML(
		w,
		posts,
		user,
		postCount,
		commentCount,
		commentedCount,
		me,
	)
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := make([]int, 0, relaxPostPerPage)
	err = db.Select(&results, "SELECT "+
		"`id` "+
		"FROM `posts` FORCE INDEX (posts_order_idx) "+
		"WHERE `created_at` <= ? ORDER BY `created_at` DESC LIMIT ?", t.Format(ISO8601Format), relaxPostPerPage)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	postsHTML(w, posts)
}

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := pat.Param(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []int{pid}

	posts, err := makePosts(results, getCSRFToken(r), true)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)
	postIDHTML(w, p, me)
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values.Notice = "画像が必須です"
		session.Save(w, r)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
		} else {
			session := getSession(r)
			session.Values.Notice = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(w, r)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values.Notice = "ファイルサイズが大きすぎます"
		session.Save(w, r)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	body := r.FormValue("body")
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
		return
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	id := int(pid)
	n := time.Now()
	writeImage(id, mime, filedata)

	postLock.Lock()
	postCache[id] = Post{
		ID:           id,
		UserID:       me.ID,
		Mime:         mime,
		Body:         body,
		CommentCount: 0,
		CreatedAt:    n,
		Created:      n.Format("2006-01-02T15:04:05-07:00"),
	}
	postLock.Unlock()

	recentCommentLock.Lock()
	recentCommentCache[id] = []Comment{}
	recentCommentLock.Unlock()

	updateIndex()

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
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

func getImage(w http.ResponseWriter, r *http.Request) {
	pidStr := pat.Param(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	post := Post{}
	err = db.Get(&post, "SELECT * FROM `images` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	ext := pat.Param(r, "ext")

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		writeImage(pid, post.Mime, post.Imgdata)
		w.Header().Set("Content-Type", post.Mime)
		_, err := w.Write(post.Imgdata)
		if err != nil {
			log.Print(err)
			return
		}
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}
	body := r.FormValue("comment")
	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	result, err := db.Exec(query, postID, me.ID, body)
	if err != nil {
		log.Print(err)
		return
	}
	cid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	recentCommentLock.Lock()
	pc := recentCommentCache[postID]
	pc = append(pc, Comment{
		ID:      int(cid),
		PostID:  postID,
		UserID:  me.ID,
		Comment: body,
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

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	templBanned.Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	for _, id := range r.Form["uid[]"] {
		db.Exec(query, 1, id)
	}
	userLock.Lock()
	for _, id := range r.Form["uid[]"] {
		i, _ := strconv.Atoi(id)
		u := userCache[i]
		u.DelFlg = 1
		userCache[i] = u
	}
	userLock.Unlock()
	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

type RegexpPattern struct {
	regexp *regexp.Regexp
}

func Regexp(reg *regexp.Regexp) *RegexpPattern {
	return &RegexpPattern{regexp: reg}
}

func (reg *RegexpPattern) Match(r *http.Request) *http.Request {
	ctx := r.Context()
	uPath := pattern.Path(ctx)
	if reg.regexp.MatchString(uPath) {
		values := reg.regexp.FindStringSubmatch(uPath)
		keys := reg.regexp.SubexpNames()

		for i := 1; i < len(keys); i++ {
			ctx = context.WithValue(ctx, pattern.Variable(keys[i]), values[i])
		}

		return r.WithContext(ctx)
	}

	return nil
}

func main() {
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

	mux := goji.NewMux()

	mux.HandleFunc(pat.Get("/initialize"), getInitialize)
	mux.HandleFunc(pat.Get("/login"), getLogin)
	mux.HandleFunc(pat.Post("/login"), postLogin)
	mux.HandleFunc(pat.Get("/register"), getRegister)
	mux.HandleFunc(pat.Post("/register"), postRegister)
	mux.HandleFunc(pat.Get("/logout"), getLogout)
	mux.HandleFunc(pat.Get("/"), getIndex)
	mux.HandleFunc(pat.Get("/posts"), getPosts)
	mux.HandleFunc(pat.Get("/posts/:id"), getPostsID)
	mux.HandleFunc(pat.Post("/"), postIndex)
	mux.HandleFunc(pat.Get("/image/:id.:ext"), getImage)
	mux.HandleFunc(pat.Post("/comment"), postComment)
	mux.HandleFunc(pat.Get("/admin/banned"), getAdminBanned)
	mux.HandleFunc(pat.Post("/admin/banned"), postAdminBanned)
	mux.HandleFunc(Regexp(regexp.MustCompile(`^/@(?P<accountName>[a-zA-Z]+)$`)), getAccountName)
	mux.Handle(pat.Get("/*"), http.FileServer(http.Dir("../public")))

	log.Fatal(http.ListenAndServe(":8080", mux))
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

func (s *simpleCookie) Save(w http.ResponseWriter, r *http.Request) error {
	bs, err := enkodo.Marshal(&s.Values)
	if err != nil {
		return err
	}
	data := base64.StdEncoding.EncodeToString(bs)

	cookie := &http.Cookie{
		Name:  s.Key,
		Value: data,
	}
	http.SetCookie(w, cookie)
	return nil
}

func sessionGet(r *http.Request, key string) (*simpleCookie, error) {
	s := r.Context().Value(key)
	if s != nil {
		return s.(*simpleCookie), nil
	}
	var sd sessionData
	cookie, err := r.Cookie(key)
	if err == nil {
		data, err := base64.StdEncoding.DecodeString(cookie.Value)
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
	ctx := context.WithValue(r.Context(), key, newSession)
	r = r.WithContext(ctx)
	return newSession, nil
}

func loginHTML(dest io.Writer, me User, flash string) (int, error) {
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

func indexHTML(dest io.Writer, posts []byte, me User, token string, flash string) (int, error) {
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

func postIDHTML(dest io.Writer, p Post, me User) (int, error) {
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
	user User,
	postCount int,
	commentCount int,
	commentedCount int,
	me User,
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

func layoutHTMLheader(b *bytebufferpool.ByteBuffer, me User) (int, error) {
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
	b.WriteString(p.User.AccountName)
	b.WriteString(`" class="isu-post-account-name">`)
	b.WriteString(p.User.AccountName)
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
	b.WriteString(p.User.AccountName)
	b.WriteString(`" class="isu-post-account-name">`)
	b.WriteString(p.User.AccountName)
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
		b.WriteString(c.User.AccountName)
		b.WriteString(`" class="isu-comment-account-name">`)
		b.WriteString(c.User.AccountName)
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
