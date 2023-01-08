package apiserver

import (
	"encoding/json"
	"errors"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
	"touchon_auth/internal/store"
	"touchon_auth/internal/token"
	"touchon_auth/model"
)

var (
	errIncorrectLoginOrPassword = errors.New("Incorrect login or password")
	errRefreshTokenInvalid      = errors.New("refresh token invalid")
)

type server struct {
	router *mux.Router
	logger *logrus.Logger
	store  store.Store
	config Config
}

func newServer(store store.Store, config *Config) *server {
	s := &server{
		router: mux.NewRouter(),
		logger: logrus.New(),
		store:  store,
		config: *config,
	}

	s.configeureRouter()
	s.confirureLogger(config.LogLevel)

	s.logger.Info("SERVER IS RUNNING")

	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) configeureRouter() {
	s.router.Use(handlers.CORS(handlers.AllowedOrigins([]string{"*"})))
	s.router.HandleFunc("/users/create", s.handleUsersCreate()).Methods("POST")
	s.router.HandleFunc("/login", s.handleSessionsCreate()).Methods("POST")
	s.router.HandleFunc("/users/refresh_token", s.handleRefreshToken()).Methods("POST")
}

func (s *server) confirureLogger(loglevel string) error {

	level, err := logrus.ParseLevel(loglevel)
	if err != nil {
		return err
	}

	s.logger.SetLevel(level)
	return nil
}

//Вызывается при логине. Создается пара токенов AccessToken, RefreshToken
func (s *server) handleSessionsCreate() http.HandlerFunc {

	type request struct {
		ID       int    `json:"id"`
		Login    string `json:"login"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		user, err := s.store.User().GetUserByLoginOrEmail(req.Login, req.Email)
		if err != nil || !user.ComparePassword(req.Password) {
			s.error(w, r, http.StatusUnauthorized, errIncorrectLoginOrPassword)
			return
		}

		tokens, err := s.createSession(user.ID)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		s.setCookie(w, "refreshToken", tokens.RefreshToken)
		s.respond(w, r, http.StatusOK, tokens)
	}

}

//Вызывается при создании пользователя
func (s *server) handleUsersCreate() http.HandlerFunc {
	type request struct {
		ID       int    `json:"id"`
		Login    string `json:"login"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		user := &model.User{
			ID:       req.ID,
			Login:    req.Login,
			Email:    req.Email,
			Password: req.Password,
		}

		if err := s.store.User().Create(user); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
		}

		user.Sanitize()
		s.respond(w, r, http.StatusCreated, user)
	}
}

func (s *server) createSession(userId int) (model.Tokens, error) {
	var (
		tokens model.Tokens
		err    error
	)

	tokenJWT := token.New(s.config.Secret)

	accessTokenTTL, err := time.ParseDuration(s.config.AccessTokenTTL)
	if err != nil {
		return tokens, err
	}

	refreshTokenTTL, err := time.ParseDuration(s.config.RefreshTokenTTL)
	if err != nil {
		return tokens, err
	}

	tokens.AccessToken, err = tokenJWT.NewJWT(userId, accessTokenTTL)
	tokens.RefreshToken, err = tokenJWT.NewRefreshToken()

	if err := s.store.User().AddRefreshToken(userId, tokens.RefreshToken, refreshTokenTTL); err != nil {
		return tokens, err
	}

	return tokens, err
}

// Вызывается когда нужно сгенерить новую пару токенов, при протуханни  AccessToken
func (s *server) handleRefreshToken() http.HandlerFunc {

	type request struct {
		RefreshToken string `json:"refresh_token"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		user, err := s.store.User().GetUserByToken(req.RefreshToken)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errRefreshTokenInvalid)
			return
		}

		tokens, err := s.createSession(user.ID)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		s.setCookie(w, "refreshToken", tokens.RefreshToken)
		s.respond(w, r, http.StatusOK, tokens)
	}
}

func (s *server) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.respond(w, r, code, map[string]string{"error": err.Error()})
}

func (s *server) respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func (s *server) setCookie(w http.ResponseWriter, name string, value string) {

	cookie := http.Cookie{}
	cookie.Name = name
	cookie.Value = value
	http.SetCookie(w, &cookie)
}
