package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func Index(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		token := r.URL.Query().Get("token")
		if CheckToken(token) {
			if AuthorizeAdmin(token) {
				db := dbConn()
				usersDB, _ := db.Query("SELECT * FROM User ORDER BY id DESC")

				result := []User{}
				for usersDB.Next() {
					var id int
					var username, password, role, tokenExpiredAt string

					usersDB.Scan(&id, &username, &password, &role, &tokenExpiredAt)
					user := User{
						Id:             id,
						Username:       username,
						Password:       password,
						Role:           role,
						TokenExpiredAt: tokenExpiredAt,
					}
					result = append(result, user)
				}
				response, _ := json.Marshal(result)
				w.Write(response)
				defer db.Close()
			} else {
				response, _ := json.Marshal("User Unauthorized")
				w.Write(response)
			}
		} else {
			response, _ := json.Marshal("Invalid Token")
			w.Write(response)
		}
	} else {
		response, _ := json.Marshal("Not Found")
		w.Write(response)
	}
}

func Create(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		token := r.URL.Query().Get("token")
		if CheckToken(token) {
			if AuthorizeAdmin(token) {
				db := dbConn()
				var body CreateRequestBody
				json.NewDecoder(r.Body).Decode(&body)
				db.Query(
					"INSERT INTO User(username, password, role) VALUES(?,?,?)",
					body.Username, body.Password, body.Role)
				response, _ := json.Marshal("User " + body.Username + " has been successfully created.")
				w.Write(response)
				defer db.Close()
			} else {
				response, _ := json.Marshal("User Unauthorized")
				w.Write(response)
			}
		} else {
			response, _ := json.Marshal("Invalid Token")
			w.Write(response)
		}
	} else {
		response, _ := json.Marshal("Not Found")
		w.Write(response)
	}
}

func Update(w http.ResponseWriter, r *http.Request) {
	if r.Method == "PUT" {
		token := r.URL.Query().Get("token")
		userID := r.URL.Query().Get("userID")
		userId, _ := strconv.Atoi(userID)
		if CheckToken(token) {
			if AuthorizeAdmin(token) {
				db := dbConn()
				var body User
				json.NewDecoder(r.Body).Decode(&body)
				db.Query(
					"UPDATE User SET username=?, password=?, role=?, token_expired_at=? WHERE id=?",
					body.Username, body.Password, body.Role, body.TokenExpiredAt, userId)
				response, _ := json.Marshal("User #" + userID + " has been successfully updated.")
				w.Write(response)
				defer db.Close()
			} else {
				response, _ := json.Marshal("User Unauthorized")
				w.Write(response)
			}
		} else {
			response, _ := json.Marshal("Invalid Token")
			w.Write(response)
		}
	}
}

func Show(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		db := dbConn()
		token := r.URL.Query().Get("token")
		userID := r.URL.Query().Get("userID")
		userId, _ := strconv.Atoi(userID)
		if CheckUserExist(userId, db) {
			response, _ := json.Marshal("User Not Found")
			w.Write(response)
		} else {
			if CheckToken(token) {
				if AuthorizeAdmin(token) || AuthorizeUser(token, userId) {
					userId, _ := strconv.Atoi(userID)
					user := GetUser(userId, db)
					response, _ := json.Marshal(user)
					w.Write(response)
				} else {
					response, _ := json.Marshal("User Unauthorized")
					w.Write(response)
				}
			} else {
				response, _ := json.Marshal("Invalid Token")
				w.Write(response)
			}
		}
		defer db.Close()
	} else {
		response, _ := json.Marshal("Not Found")
		w.Write(response)
	}
}

func Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		token := r.URL.Query().Get("token")
		if CheckToken(token) {
			if AuthorizeAdmin(token) {
				db := dbConn()
				userID := r.URL.Query().Get("userID")
				userId, _ := strconv.Atoi(userID)

				var response []byte
				if CheckUserExist(userId, db) {
					response, _ = json.Marshal("User Not Found")
				} else {
					db.Query("DELETE FROM User WHERE id=?", userID)
					response, _ = json.Marshal("User #" + userID + " has been deleted.")
				}
				w.Write(response)
				defer db.Close()
			} else {
				response, _ := json.Marshal("Invalid Token")
				w.Write(response)
			}
		} else {
			response, _ := json.Marshal("User Unauthorized")
			w.Write(response)
		}
	} else {
		response, _ := json.Marshal("Not Found")
		w.Write(response)
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		db := dbConn()
		var body UserCredentials
		json.NewDecoder(r.Body).Decode(&body)
		user := GetUserByUsername(body.Username, db)

		if body.Password == user.Password {
			tokenExpiredAt := time.Now().Format("2006-01-02 15:04:05")
			db.Query("UPDATE User SET token_expired_at=? WHERE username=?",
				tokenExpiredAt, body.Username)
			token := GenerateToken(user)
			response, _ := json.Marshal(token)
			w.Write(response)
		} else {
			response, _ := json.Marshal("Invalid Credentials")
			w.Write(response)
		}
		defer db.Close()
	} else {
		response, _ := json.Marshal("Not Found")
		w.Write(response)
	}
}

func main() {
	log.Println("Server started on: http://localhost:8080")
	http.HandleFunc("/login", Login)
	http.HandleFunc("/", Index)
	http.HandleFunc("/show", Show)
	http.HandleFunc("/create", Create)
	http.HandleFunc("/update", Update)
	http.HandleFunc("/delete", Delete)
	http.ListenAndServe(":8080", nil)
}
