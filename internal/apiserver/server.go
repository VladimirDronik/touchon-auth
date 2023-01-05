package apiserver

import (
	"encoding/json"
	"errors"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
	"touchon-auth/internal/store"
	"touchon-auth/internal/token"
	"touchon-auth/model"
)

var (
	errIncorrectLoginOrPassword = errors.New("Incorrect login or password")
)

type server struct {
	router *mux.Router
	logger *logrus.Logger
	store  store.Store
	config Config
	token  token.Token
}

func newServer(store store.Store, config *Config) *server {
	s := &server{
		router: mux.NewRouter(),
		logger: logrus.New(),
		store:  store,
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
	s.router.HandleFunc("/users", s.handleUsersCreate()).Methods("POST")
	s.router.HandleFunc("/login", s.handleSessionsCreate()).Methods("POST")
}

func (s *server) confirureLogger(loglevel string) error {

	level, err := logrus.ParseLevel(loglevel)
	if err != nil {
		return err
	}

	s.logger.SetLevel(level)
	return nil
}

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

		tokens, err := s.createSession(req.ID)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		s.respond(w, r, http.StatusOK, tokens)
	}

}

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
		res model.Tokens
		err error
	)

	token.New(s.config.Secret)

	accessTokenTTL, err := time.ParseDuration(s.config.AccessTokenTTL)
	if err != nil {
		return res, err
	}

	res.AccessToken, err = s.token.NewJWT(userId, accessTokenTTL)
	res.RefreshToken, err = s.token.NewRefreshToken()

	return res, err
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
