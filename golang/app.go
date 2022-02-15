package main

import (
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
	"sync"

	//"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/mojura/enkodo"
	goji "goji.io"
	"goji.io/pat"
	"goji.io/pattern"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

var (
	db                 *sqlx.DB
	templRegister      *template.Template
	templIndex         *template.Template
	templUser          *template.Template
	templPosts         *template.Template
	templPostsID       *template.Template
	recentCommentLock  sync.RWMutex
	recentCommentCache map[int][]Comment
	userLock           sync.RWMutex
	userCache          map[int]User
	accountCache       map[string]int
	sfGroup            singleflight.Group
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024 // 10mb
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
	CommentCount int       `db:"comment_count"`
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
	db.Select(&users, "SELECT id,account_name,passhash,authority,del_flg FROM users")
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
	db.Select(&posts, "SELECT `id` FROM posts")

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

// 今回のGo実装では言語側のエスケープの仕組みが使えないのでOSコマンドインジェクション対策できない
// 取り急ぎPHPのescapeshellarg関数を参考に自前で実装
// cf: http://jp2.php.net/manual/ja/function.escapeshellarg.php
func escapeshellarg(arg string) string {
	return "'" + strings.Replace(arg, "'", "'\\''", -1) + "'"
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

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	posts := make([]Post, 0, postsPerPage)
	commentPostIDs := make([]int, 0, postsPerPage)
	totalComment := 0
	for _, p := range results {
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

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
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

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r)})
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

func getSFIndex(token string) ([]Post, error) {
	v, err, _ := sfGroup.Do("getIndex", func() (interface{}, error) {
		results := []Post{}

		err := db.Select(&results, "SELECT "+
			"p.id AS `id`,"+
			"p.user_id AS `user_id`,"+
			"p.body AS `body`,"+
			"p.mime AS `mime`,"+
			"p.created_at AS `created_at`, "+
			"p.comment_count AS `comment_count`,"+
			"u.id AS `user.id`, "+
			"u.account_name AS `user.account_name` "+
			"FROM `posts` p FORCE INDEX (posts_order_idx) JOIN `users` u ON p.user_id = u.id "+
			"WHERE u.del_flg = 0 "+
			"ORDER BY p.created_at DESC LIMIT ?", postsPerPage)
		if err != nil {
			log.Print(err)
			return nil, err
		}

		posts, err := makePosts(results, "[[getCSRFToken]]", false)
		if err != nil {
			log.Print(err)
			return nil, err
		}
		return posts, nil
	})
	if err != nil {
		return nil, err
	}
	ps, ok := v.([]Post)
	if !ok {
		return nil, fmt.Errorf("something wrong in sfindex")
	}
	for _, p := range ps {
		p.CSRFToken = token
	}
	return ps, nil
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	token := getCSRFToken(r)
	posts, err := getSFIndex(token)
	if err != nil {
		log.Print(err)
		return
	}
	templIndex.Execute(w, struct {
		Posts     []Post
		Me        User
		CSRFToken string
		Flash     string
	}{posts, me, token, getFlash(w, r)})
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
	var posts []Post
	token := getCSRFToken(r)
	eg.Go(func() error {
		results := []Post{}
		err := db.Select(&results, "SELECT "+
			"p.id AS `id`,"+
			"p.user_id AS `user_id`,"+
			"p.body AS `body`,"+
			"p.mime AS `mime`,"+
			"p.created_at AS `created_at`, "+
			"p.comment_count AS `comment_count`,"+
			"u.id AS `user.id`, "+
			"u.account_name AS `user.account_name` "+
			"FROM `posts` p FORCE INDEX (posts_user_idx) JOIN `users` u ON p.user_id = u.id WHERE p.user_id = ?  AND u.del_flg = 0 ORDER BY p.created_at DESC LIMIT ?", user.ID, postsPerPage)
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

	templUser.Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{posts, user, postCount, commentCount, commentedCount, me})
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

	results := []Post{}
	err = db.Select(&results, "SELECT "+
		"p.id AS `id`,"+
		"p.user_id AS `user_id`,"+
		"p.body AS `body`,"+
		"p.mime AS `mime`,"+
		"p.created_at AS `created_at`, "+
		"p.comment_count AS `comment_count`,"+
		"u.id AS `user.id`, "+
		"u.account_name AS `user.account_name` "+
		"FROM `posts` p FORCE INDEX (posts_order_idx) JOIN `users` u ON p.user_id = u.id WHERE p.created_at <= ? AND u.del_flg = 0 ORDER BY p.created_at DESC LIMIT ?", t.Format(ISO8601Format), postsPerPage)
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

	templPosts.Execute(w, posts)
}

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := pat.Param(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	err = db.Select(&results, "SELECT "+
		"p.id AS `id`,"+
		"p.user_id AS `user_id`,"+
		"p.body AS `body`,"+
		"p.mime AS `mime`,"+
		"p.created_at AS `created_at`, "+
		"p.comment_count AS `comment_count`,"+
		"u.id AS `user.id`, "+
		"u.account_name AS `user.account_name` "+
		"FROM `posts` p FORCE INDEX (PRIMARY) JOIN `users` u ON p.user_id = u.id WHERE p.id = ? AND u.del_flg = 0 LIMIT ?", pid, postsPerPage)
	if err != nil {
		log.Print(err)
		return
	}

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

	templPostsID.Execute(w, struct {
		Post Post
		Me   User
	}{p, me})
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

	query := "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		"",
		r.FormValue("body"),
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
	writeImage(int(pid), mime, filedata)

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
	if _, ok := r.Header["If-Modified-Since"]; ok {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	ext := pat.Param(r, "ext")
	pidStr := pat.Param(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	n := "../public/image/" + pidStr + "." + ext
	_, err = os.Stat(n)
	if err == nil {
		switch ext {
		case "jpg":
			w.Header().Set("Content-Type", "image/jpeg")
		case "png":
			w.Header().Set("Content-Type", "image/png")
		case "gif":
			w.Header().Set("Content-Type", "image/gif")
		}
		fh, _ := os.Open(n)
		defer fh.Close()
		w.Header().Set("Last-Modified", "Mon, 31 May 2021 04:50:49 GMT")
		w.Header().Set("Cache-Control", "public, max-age=300")
		io.Copy(w, fh)
		return
	}

	post := Post{}
	err = db.Get(&post, "SELECT * FROM `images` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		writeImage(pid, post.Mime, post.Imgdata)
		w.Header().Set("Content-Type", post.Mime)
		w.Header().Set("Last-Modified", "Mon, 31 May 2021 04:50:49 GMT")
		w.Header().Set("Cache-Control", "public, max-age=300")
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

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	).Execute(w, struct {
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

func serveStatic(path string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["If-Modified-Since"]; ok {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		http.ServeFile(w, r, path)
	}
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
	fmap := template.FuncMap{
		"imageURL": imageURL,
	}
	templRegister = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	)
	templIndex = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("index.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	))
	templUser = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("user.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	))
	templPosts = template.Must(template.New("posts.html").Funcs(fmap).ParseFiles(
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	))
	templPostsID = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("post_id.html"),
		getTemplPath("post.html"),
	))

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

	mux.HandleFunc(pat.Get("/js/main.js"), serveStatic("../public/js/main.js"))
	mux.HandleFunc(pat.Get("/js/timeago.min.js"), serveStatic("../public/js/timeago.min.js"))
	mux.HandleFunc(pat.Get("/img/ajax-loader.gif"), serveStatic("../public/img/ajax-loader.gif"))
	mux.HandleFunc(pat.Get("/css/style.css"), serveStatic("../public/css/style.css"))
	mux.HandleFunc(pat.Get("/favicon.ico"), serveStatic("../public/favicon.ico"))

	// mux.Handle(pat.Get("/*"), http.FileServer(http.Dir("../public")))

	log.Fatal(http.ListenAndServe(":80", mux))
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
