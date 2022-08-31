package main

type User struct {
	Id             int
	Username       string
	Password       string
	Role           string
	TokenExpiredAt string
}

type CreateRequestBody struct {
	Username string
	Password string
	Role     string
}

type UserCredentials struct {
	Username string
	Password string
}
