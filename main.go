package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"log"
	"unicode/utf8"
	"strconv"
	"time"
	"golang.org/x/crypto/bcrypt"
	"database/sql"
	_ "github.com/lib/pq"
	"github.com/gorilla/mux"
	"encoding/base64"
	"crypto/md5"
	"strings"
	"bytes"
	"github.com/antonlindstrom/pgstore"
)

//Socket code borrowed from https://github.com/godwhoa/wsrooms

var tpl *template.Template

type User struct {
	Username string
	Live bool
}

func init() {
	tpl = template.Must(template.ParseGlob("templates/*.gohtml"))
}

type pageData struct {
	title string
	username string
}

func main() {
	hub := NewHub()
	rtr := mux.NewRouter()
	
	
	rtr.HandleFunc("/", index)
	rtr.HandleFunc("/register", register)
	rtr.HandleFunc("/register/post", registerPOST)
	
	rtr.HandleFunc("/login", login)
	rtr.HandleFunc("/login/post", loginPOST)
	
	rtr.HandleFunc("/user/{username}", profile).Methods("GET")
	rtr.HandleFunc("/ws/{room}", hub.HandleWS).Methods("GET")
	
	
	/*
	http.HandleFunc("/privateMessages", privateMessages)
	*/
	
	rtr.HandleFunc("/rtmpLogin", rtmpLogin)
	//http.Handle("/", rtr)
	
	fmt.Println("Server is up and running\n")
	log.Fatal(http.ListenAndServe(":8080", rtr))
}

func index(w http.ResponseWriter, req *http.Request) {
	err := tpl.ExecuteTemplate(w, "index.gohtml", nil)
	if err != nil {
		log.Println(err);
	}
}

func register(w http.ResponseWriter, req *http.Request) {
	err := tpl.ExecuteTemplate(w, "register.gohtml", nil)
	if err != nil {
		log.Println(err);
	}
}

func registerPOST(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {		
		password, err := bcrypt.GenerateFromPassword([]byte(url.QueryEscape(req.FormValue("password"))), 15)
		
		if err != nil {
			log.Fatal(err)
		}
		
		username := url.QueryEscape(strings.ToLower(req.FormValue("username")))
		hashKey := md5.New()
		hashKey.Write([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
		streamKey := base64.URLEncoding.EncodeToString(hashKey.Sum(nil))
		
		if utf8.RuneCountInString(username) > 20 || utf8.RuneCountInString(username) < 4 {
			log.Println("Inappropriate username length")
			w.WriteHeader(403)
			return
		} else if utf8.RuneCountInString(url.QueryEscape(req.FormValue("password"))) > 20 || utf8.RuneCountInString(url.QueryEscape(req.FormValue("password"))) < 6{
			log.Println("Inappropriate password length")
			w.WriteHeader(403)
			return
		}
		
		db, err := sql.Open("postgres", "user=postgres password=password dbname=golit sslmode=disable")
		
		if err != nil {
			log.Fatal(err)
		}
		
		var userid int
		
		err = db.QueryRow(`INSERT INTO users(username, streamkey, password, privilege) 
		VALUES($1, $2, $3, 'user') RETURNING id`, username, streamKey, password).Scan(&userid)
		
		if err != nil {
			if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
				w.WriteHeader(403)
				return
			} else {
				log.Fatal(err)
			}
		}
		
		fmt.Println(username, " created an account!", userid)
	}
	
	http.Redirect(w, req, "http://localhost:8080", 303)
}


func login(w http.ResponseWriter, req *http.Request) {
	err := tpl.ExecuteTemplate(w, "login.gohtml", nil)
	
	if err != nil {
		log.Println(err);
	}
}

func loginPOST(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
	
		username := url.QueryEscape(strings.ToLower(req.FormValue("username")))
		password := []byte(url.QueryEscape(req.FormValue("password")))
		var passwordHashed string
		
		db, err := sql.Open("postgres", "user=postgres password=password dbname=golit sslmode=disable")
		err = db.QueryRow(` SELECT password FROM users WHERE username = $1 `, username).Scan(&passwordHashed)
		
		if err != nil {
			log.Fatal(err)
		}
				
		//rows.Scan(&passwordHashed)
		if bcrypt.CompareHashAndPassword([]byte(passwordHashed), password) != nil {
			w.WriteHeader(403)
			return
		} else {
			store, err := pgstore.NewPGStore("postgres://postgres:password@127.0.0.1:5432/golitsessions?sslmode=disable", []byte("secret-key"))
			if err != nil {
				log.Fatal(err)
			}
			
			session, err := store.Get(req, "secret-key")
			
			if err != nil {
				log.Fatalf(err.Error())
			}
			
		var streamKey string
		
		err = db.QueryRow(` SELECT streamKey FROM users WHERE username = $1 `, username).Scan(&streamKey)
		if err != nil {
			log.Fatal(err)
		}
			
			session.Values["username"] = username;			
			if err = session.Save(req, w); err != nil {
				log.Fatalf("Error saving session: %v", err)
			}

		var rtmpURL bytes.Buffer
		rtmpURL.WriteString("rtmp://localhost:1935/live/")
		rtmpURL.WriteString(session.Values["username"].(string))
		rtmpURL.WriteString("?token=")
		rtmpURL.WriteString(streamKey)
		
		w.Write(rtmpURL.Bytes())
		}
	}
}

func roomSockets(w http.ResponseWriter, req *http.Request) {

}

func profile(w http.ResponseWriter, req *http.Request) {
	params := mux.Vars(req)
	name := params["username"]
	user := User{Username: name, Live: false}
	
	
	err := tpl.ExecuteTemplate(w, "users.gohtml", user)
	if err != nil {
		log.Println(err);
	}
}

/*
func privateMessages(w http.ResponseWriter, req *http.Request) {

}
*/

func rtmpLogin(w http.ResponseWriter, req *http.Request) {	
	if req.Method == http.MethodPost {
		username := strings.ToLower(req.FormValue("name"))
		streamKeyGiven := req.FormValue("token")
		var streamKey string;
		
		db, err := sql.Open("postgres", "user=postgres password=password dbname=golit sslmode=disable")
		err = db.QueryRow(` SELECT streamKey FROM users WHERE username = $1 `, username).Scan(&streamKey)
		
		if err != nil {
			log.Println(err)
		}
		
		if(strings.Compare(streamKeyGiven, streamKey) == 0) {
			w.WriteHeader(200)
			fmt.Println("Connect Accepted")
		} else {
		
			log.Println("Given stream key: " + url.QueryEscape((streamKeyGiven)))
			log.Println("Actual stream key: " + streamKey)
			log.Println("Comparison of stream key: $1", strings.Compare(url.QueryEscape(streamKeyGiven), url.QueryEscape(streamKey)))
			
			fmt.Println("Connect rejected")
			w.WriteHeader(403)
		}
	} 
}
