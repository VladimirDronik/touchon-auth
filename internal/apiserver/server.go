package apiserver

import (
	"context"
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
	"touchon_auth/internal/JWTToken"
	"touchon_auth/internal/store"
	"touchon_auth/internal/token"
	"touchon_auth/model"
)

const (
	ctxKeyAllow ctxKey = iota
)

var (
	errIncorrectLoginOrPassword = errors.New("Incorrect login or password")
	errTokenNotFind             = errors.New("can not find token in header")
	errRefreshTokenInvalid      = errors.New("refresh token invalid")
	errIncorrectCode            = errors.New("Incorrect code")
	errIncorrectSecret          = errors.New("Incorrect secret")
	errBasicAuth                = errors.New("Error parsing basic auth")
	errNotAllowed               = errors.New("Method not allowed")
)

type ctxKey int8

type server struct {
	router *mux.Router
	logger *logrus.Logger
	store  store.Store
	config Config
	userID int
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
	s.router.HandleFunc("/auth/refresh_token", s.handleRefreshToken()).Methods("POST")

	// Реализация с использованием логина-пароля
	s.router.HandleFunc("/user", s.handleUserCreate()).Methods("POST")            // создание пользователя
	s.router.HandleFunc("/auth/login", s.handleLoginByPassword()).Methods("POST") // аутентификация пользователя через логи-пароль

	// Реализация с использованием смс
	s.router.HandleFunc("/request/call", s.handleUserCall()).Methods("POST")      // запрос звонка
	s.router.HandleFunc("/request/sms", s.handleUserSMS()).Methods("POST")        // запрос смс
	s.router.HandleFunc("/auth/phone", s.handleUserLoginByCode()).Methods("POST") // аутентификация пользователя через номер те

	//Закрыто секцией private, доступ через аутентификацию по ключу
	private := s.router.PathPrefix("/private").Subrouter()
	private.Use(s.autenеificateUser)
	private.HandleFunc("/user", s.handleUserUpdate()).Methods("PATCH") // добавление полей для пользователя

}

func (s *server) confirureLogger(loglevel string) error {

	level, err := logrus.ParseLevel(loglevel)
	if err != nil {
		return err
	}

	s.logger.SetLevel(level)
	return nil
}

// Проверка ключа на валидность и срок годности
func (s *server) autenеificateUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] == nil {
			s.error(w, r, http.StatusForbidden, errTokenNotFind)
			return
		}

		var err error
		//Проверяем не протух ли токен и извлекаем ID юзера
		s.userID, err = JWTToken.KeysExtract(r.Header["Token"][0], s.config.Secret)
		if err != nil {
			s.error(w, r, http.StatusForbidden, err)
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyAllow, true)))
	})

}

// Проверяем введенный логин или емейл и пароль. Создается пара токенов AccessToken, RefreshToken при успешной аутентиф.
func (s *server) handleLoginByPassword() http.HandlerFunc {

	type request struct {
		Login    string `json:"login"` //Здесь либо почта, либо логин
		Password string `json:"password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		APIKey := r.Header.Get("api-key")

		if APIKey != s.config.SecretAPIKey {
			s.error(w, r, http.StatusUnauthorized, errIncorrectSecret)
			//TODO :: добавить вывод логов в сторонюю систему, где будут учситыватсья попытки взлома
			return
		}

		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		user, err := s.store.User().GetUserByLoginOrEmail(req.Login, req.Login)
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
		return
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

		APIKey := r.Header.Get("api-key")

		if APIKey != s.config.SecretAPIKey {
			s.error(w, r, http.StatusUnauthorized, errIncorrectSecret)
			//TODO :: добавить вывод логов в сторонюю систему, где будут учситыватсья попытки взлома
			return
		}

		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		u := &url.URL{Scheme: "https",
			Host:     "sms.ru",
			Path:     "code/call",
			RawQuery: "api_id=" + s.config.SMSRUID + "&phone=" + req.Phone}

		resp, err := http.Get(u.String())

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
		//if err != nil {
		//	s.error(w, r, http.StatusUnprocessableEntity, err)
		//	return
		//}
		s.store.Call().AddTempCallData(respStruct.ID, req.Phone, respStruct.Code)

		//добавить данные в таблицу звонков
		s.store.Call().AddCallData(call)
		s.respond(w, r, http.StatusCreated, respStruct.ID)
		return
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

		APIKey := r.Header.Get("api-key")

		if APIKey != s.config.SecretAPIKey {
			s.error(w, r, http.StatusUnauthorized, errIncorrectSecret)
			//TODO :: добавить вывод логов в сторонюю систему, где будут учситыватсья попытки взлома
			return
		}

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
		return
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

		APIKey := r.Header.Get("api-key")

		if APIKey != s.config.SecretAPIKey {
			s.error(w, r, http.StatusUnauthorized, errIncorrectSecret)
			//TODO :: добавить вывод логов в сторонюю систему, где будут учситыватсья попытки взлома
			return
		}

		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		cnt, err := s.store.Call().GetRowByCodeANDPhone(req.Phone, req.Code)
		if cnt == 0 || err != nil {
			s.error(w, r, http.StatusBadRequest, errIncorrectCode)
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
		return
	}
}

// Вызывается при создании пользователя при аутентификации по логину и паролю
func (s *server) handleUserCreate() http.HandlerFunc {
	type request struct {
		ID       int    `json:"id"`
		Login    string `json:"login"`
		Email    string `json:"email"`
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		if s.config.CreateUser == "call" {
			s.error(w, r, http.StatusMethodNotAllowed, errNotAllowed)
			return
		}

		APIKey := r.Header.Get("api-key")

		if APIKey != s.config.SecretAPIKey {
			s.error(w, r, http.StatusUnauthorized, errIncorrectSecret)
			//TODO :: добавить вывод логов в сторонюю систему, где будут учситыватсья попытки взлома
			return
		}

		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		user := &model.User{
			ID:       req.ID,
			Login:    req.Login,
			Email:    req.Email,
			Phone:    req.Phone,
			Password: req.Password,
		}

		user, err := s.store.User().Create(user)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
		}

		user.Sanitize()
		s.respond(w, r, http.StatusCreated, user)
		return
	}
}

// handleUserUpdate обновление данных о пользователе
func (s *server) handleUserUpdate() http.HandlerFunc {

	type request struct {
		Login    string `json:"login"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	//TODO:: подумать, что делать с номером телефона. Проверять на занятость логин и почту
	return func(w http.ResponseWriter, r *http.Request) {

		APIKey := r.Header.Get("api-key")

		if APIKey != s.config.SecretAPIKey {
			s.error(w, r, http.StatusUnauthorized, errIncorrectSecret)
			//TODO :: добавить вывод логов в сторонюю систему, где будут учситыватсья попытки взлома
			return
		}

		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		user := &model.User{
			ID:       s.userID,
			Login:    req.Login,
			Email:    req.Email,
			Password: req.Password,
		}

		err := s.store.User().Update(user)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
		}

		user.Sanitize()
		s.respond(w, r, http.StatusCreated, user)
		return
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
			s.error(w, r, http.StatusForbidden, errRefreshTokenInvalid)
			return
		}

		tokens, err := s.createSession(user.ID)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		s.store.User().RemoveToken(req.RefreshToken)

		s.setCookie(w, "refreshToken", tokens.RefreshToken)
		s.respond(w, r, http.StatusOK, tokens)
		return
	}
}

func (s *server) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	if err != nil {
		s.respond(w, r, code, map[string]string{"message": err.Error()})
		s.logger.Error(err.Error())
	} else {
		s.respond(w, r, code, nil)
	}

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
