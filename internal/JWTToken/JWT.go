package JWTToken

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"strconv"
	"time"
)

var (
	errParseToken   = errors.New("token parse message")
	errInvalidToken = errors.New("invalid token")
	errTokenClams   = errors.New("couldn't parse claims")
	errTokenExpired = errors.New("token is expired")
)

func KeysExtract(JWTToken string, TokenSecret string) (int, error) {

	token, err := jwt.Parse(JWTToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, nil //errParseToken
		}
		return []byte(TokenSecret), nil
	})

	if token == nil || err != nil {
		return 0, errInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, errTokenClams
	}

	exp := claims["exp"].(float64)                    //дата, до которой действует ключ
	userID, _ := strconv.Atoi(claims["sub"].(string)) //id пользователя, под которым логинились
	if int64(exp) < time.Now().Local().Unix() {
		return 0, errTokenExpired
	}

	return userID, err
}
