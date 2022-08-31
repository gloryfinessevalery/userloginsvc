package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"time"
)

func CheckToken(token string) bool {
	var user User
	decodedToken := DecodeToken(token)
	json.Unmarshal(decodedToken, &user)
	tokenExpiredAt, _ := time.Parse("2006-01-02 15:04:05", user.TokenExpiredAt)
	if tokenExpiredAt.After(time.Now()) {
		return true
	} else {
		return false
	}
}

func AuthorizeAdmin(token string) bool {
	var user User
	decodedToken := DecodeToken(token)
	json.Unmarshal(decodedToken, &user)
	if user.Role == "admin" {
		return true
	} else {
		return false
	}
}

func AuthorizeUser(token string, userID int) bool {
	var user User
	decodedToken := DecodeToken(token)
	json.Unmarshal(decodedToken, &user)
	if user.Id == userID {
		return true
	} else {
		return false
	}
}

func CheckUserExist(userID int, db *sql.DB) bool {
	usersDBCount, _ := db.Query(
		"SELECT COUNT(*) FROM User WHERE id=?", userID)
	var count int
	for usersDBCount.Next() {
		usersDBCount.Scan(&count)
	}
	if count == 0 {
		return true
	} else {
		return false
	}
}

func GetUser(userID int, db *sql.DB) User {
	usersDB, _ := db.Query(
		"SELECT * FROM User WHERE id=?",
		userID)
	var user = User{}
	for usersDB.Next() {
		var id int
		var username, password, role, tokenExpiredAt string
		usersDB.Scan(&id, &username, &password, &role, &tokenExpiredAt)
		user = User{
			Id:             id,
			Username:       username,
			Password:       password,
			Role:           role,
			TokenExpiredAt: tokenExpiredAt,
		}
	}
	return user
}

func GetUserByUsername(username string, db *sql.DB) User {
	var user = User{}
	usersDB, _ := db.Query(
		"SELECT * FROM User WHERE username=?", username)
	for usersDB.Next() {
		var id int
		var username, password, role, tokenExpiredAt string
		usersDB.Scan(&id, &username, &password, &role, &tokenExpiredAt)
		user = User{
			Id:             id,
			Username:       username,
			Password:       password,
			Role:           role,
			TokenExpiredAt: tokenExpiredAt,
		}
	}
	return user
}

func GenerateToken(user User) string {
	jsonToEncode, _ := json.Marshal(user)
	byteToEncode := []byte(jsonToEncode)
	encodedToken := base64.StdEncoding.EncodeToString(byteToEncode)
	return encodedToken
}

func DecodeToken(token string) []byte {
	user, _ := base64.StdEncoding.DecodeString(token)
	return user
}
