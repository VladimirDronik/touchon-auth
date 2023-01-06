package token

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"math/rand"
	"strconv"
	"time"
)

type Token struct {
	signingKey string
}

func New(signKey string) *Token {
	return &Token{
		signingKey: signKey,
	}
}

func (t Token) NewJWT(userId int, ttl time.Duration) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(ttl).Unix(),
		Subject:   strconv.Itoa(userId),
	})

	tokenString, err := token.SignedString([]byte(t.signingKey))
	if err != nil {
		println(err)
	}
	return tokenString, nil
}

func (t Token) NewRefreshToken() (string, error) {
	b := make([]byte, 32)

	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)

	if _, err := r.Read(b); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", b), nil
}
