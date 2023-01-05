package model

import (
	"github.com/dgrijalva/jwt-go/v4"
)

type Claims struct {
	jwt.StandardClaims
	Username string `json:"username"`
}

type Tokens struct {
	AccessToken  string
	RefreshToken string
}
