package apiserver

import (
	"encoding/json"
	"errors"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"touchon_auth/internal/store"
	"touchon_auth/internal/token"
	"touchon_auth/model"
)

var (
	errIncorrectLoginOrPassword = errors.New("Incorrect login or password")
	errRefreshTokenInvalid      = errors.New("refresh token invalid")
	errIncorrectCode            = errors.New("Incorrect code")
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
	s.router.HandleFunc("/users/refresh_token", s.handleRefreshToken()).Methods("POST")

	if s.config.Mode == "login" {
		s.router.HandleFunc("/users/create", s.handleUsersCreate()).Methods("POST")
		s.router.HandleFunc("/login", s.handleSessionsCreate()).Methods("POST")
	} else if s.config.Mode == "call" {
		s.router.HandleFunc("/users/call", s.handleUserCall()).Methods("POST")
		s.router.HandleFunc("/users/sms", s.handleUserSMS()).Methods("POST")
		s.router.HandleFunc("/login", s.handleUserLoginByCode()).Methods("POST")
	}

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

func (s *server) handleUserCall() http.HandlerFunc {

	type request struct {
		Phone string `json:"phone"`
	}

	type response struct {
		ID      string  `json:"call_id"`
		Phone   string  `json:"phone"`
		Code    int     `json:"code"`
		Cost    float32 `json:"cost"`
		Balance float32 `json:"balance"`
	}

	//структура для второго и последующего респонса, в котором код приходит как строка
	type responseSecond struct {
		ID      string  `json:"call_id"`
		Phone   string  `json:"phone"`
		Code    string  `json:"code"`
		Cost    float32 `json:"cost"`
		Balance float32 `json:"balance"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		respStruct := &response{}
		respSecStruct := &responseSecond{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		params := url.Values{}
		params.Add("phone", req.Phone)
		params.Add("api_id", s.config.SMSRUID)

		resp, err := http.Get("https://sms.ru/code/call?" + params.Encode())
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}
		resp.Body.Close()

		if err := json.Unmarshal(body, respStruct); err != nil {
			// Если получили ошибку, значит нужно преверить на соответсвие второй вструктуре из-за того, что от смс.ру
			// приходит структура с code string
			if err := json.Unmarshal(body, respSecStruct); err != nil {
				s.error(w, r, http.StatusBadRequest, err)
			}
			return
		}

		call := &model.Call{
			ID:      respStruct.ID,
			Phone:   req.Phone,
			Cost:    respStruct.Cost,
			Balance: respStruct.Balance,
		}

		//очистить данные в таблице временных кодов для указанного номера и старых данных
		s.store.Call().RemoveOldData(req.Phone)

		//добавить данные в таблицу временных кодов
		//code, err := strconv.Atoi(req.Code)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}
		s.store.Call().AddTempCallData(respStruct.ID, req.Phone, respStruct.Code)

		//добавить данные в таблицу звонков
		s.store.Call().AddCallData(call)
		s.respond(w, r, http.StatusCreated, respStruct.ID)
	}
}

// Отправляет пользователю СМС с последним кодом, который соответсвует указанному номеру телефона
func (s *server) handleUserSMS() http.HandlerFunc {

	type request struct {
		Phone string `json:"phone"`
	}

	type response struct {
		Status  string  `json:"status"`
		Balance float32 `json:"balance"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		respStruct := &response{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		code, err := s.store.Call().GetCodeByPhone(req.Phone)

		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		params := url.Values{}
		params.Add("to", req.Phone)
		params.Add("api_id", s.config.SMSRUID)
		params.Add("msg", strconv.Itoa(code)+"-код доступа TouchOn")
		params.Add("json", "1")

		resp, err := http.Get("https://sms.ru/sms/send?" + params.Encode())

		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}
		resp.Body.Close()

		if err := json.Unmarshal(body, respStruct); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		sms := &model.SMS{
			Phone:   req.Phone,
			Balance: respStruct.Balance,
		}

		//добавить данные в таблицу звонков
		s.store.Call().AddSMSData(sms)
		s.respond(w, r, http.StatusCreated, req.Phone)
	}
}

// Авторизация пользователя с помощью номера телефона и кода, который пришел в звонке или в СМС. Если юзера нет, то
// создаем нового
func (s *server) handleUserLoginByCode() http.HandlerFunc {

	type request struct {
		ID    int    `json:"call_id"`
		Phone string `json:"phone"`
		Code  int    `json:"code"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		cnt, err := s.store.Call().GetRowByCodeANDPhone(req.Phone, req.Code)
		if cnt == 0 || err != nil {
			s.error(w, r, http.StatusUnauthorized, errIncorrectCode)
			return
		}

		user, err := s.store.User().GetByPhone(req.Phone)
		//Если не нашли пользователя, то создаем нового, если нашли, то логинимся
		if user == nil {
			user = &model.User{
				Phone: req.Phone,
			}

			user, err = s.store.User().Create(user)
			if err != nil {
				s.error(w, r, http.StatusUnprocessableEntity, err)
				return
			}
		}

		tokens, err := s.createSession(user.ID)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		s.store.Call().RemoveOldData(user.Phone)
		s.setCookie(w, "refreshToken", tokens.RefreshToken)
		s.respond(w, r, http.StatusOK, tokens)

	}
}

//Вызывается при создании пользователя при аутентификации по логину и паролю
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

		user, err := s.store.User().Create(user)
		if err != nil {
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

		user, err := s.store.User().GetByToken(req.RefreshToken)
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
