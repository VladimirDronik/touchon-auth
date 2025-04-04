package sqlstore

import (
	"errors"
	"time"
	"touchon_auth/model"
)

type UserRepository struct {
	store *Store
}

// Create Создаем нового пользователя, при создании проверяем его на существование в БД по телефону, почте и емейлу
func (r *UserRepository) Create(user *model.User) (*model.User, error) {

	cntLogin, cntEmail, cntPhone, err := r.getCountByLoginOrEmail(user.Login, user.Email, user.Phone)

	if cntLogin > 0 {
		err = errors.New("login already exists")
		return nil, err
	}

	if cntEmail > 0 {
		err = errors.New("email already exists")
		return nil, err
	}

	if cntPhone > 0 {
		err = errors.New("phone already exists")
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	if err := user.EncryptPassword(); err != nil {
		return nil, err
	}

	_, err = r.store.db.Exec("INSERT INTO users (login, email, phone, encrypted_password) VALUES (?, ?, ?, ?)",
		user.Login, user.Email, user.Phone, user.EncryptedPassword)
	if err != nil {
		return nil, err
	}

	if err := r.store.db.QueryRow(
		"SELECT id FROM users WHERE `phone` = ? OR `login` = ? OR `email` = ?", user.Phone, user.Login, user.Email).Scan(
		&user.ID,
	); err != nil {
		return nil, err
	}

	return user, nil
}

// Update обновление данных о пользователе
func (r *UserRepository) Update(user *model.User) error {

	if err := user.EncryptPassword(); err != nil {
		return err
	}

	_, err := r.store.db.Exec("UPDATE users SET  "+
		"login = COALESCE(?, login), email = COALESCE(?, email), "+
		"encrypted_password = COALESCE(?, encrypted_password) WHERE id = ?",
		user.Login, user.Email, user.EncryptedPassword, user.ID)
	if err != nil {
		return err
	}
	return nil
}

// Находим количество пользователей с указанным именем и емейлом, это количесвто будет определять есть ли в системе
// пользователь и выдавать ощибку, если пытаемся создать с уже имеющимися данными
func (r *UserRepository) getCountByLoginOrEmail(login string, email string, phone string) (int, int, int, error) {
	cntLogin := 0
	cntEmail := 0
	cntPhone := 0

	if err := r.store.db.QueryRow(
		"SELECT COUNT(id) AS cnt FROM users WHERE phone = ?",
		phone).Scan(
		&cntPhone,
	); err != nil {
		return 0, 0, 0, err
	}

	if login != "" {
		if err := r.store.db.QueryRow(
			"SELECT COUNT(id) AS cnt FROM users WHERE login = ?",
			login).Scan(
			&cntLogin,
		); err != nil {
			return 0, 0, 0, err
		}
	}

	if email != "" {
		if err := r.store.db.QueryRow(
			"SELECT COUNT(id) AS cnt FROM users WHERE email = ?",
			email).Scan(
			&cntEmail,
		); err != nil {
			return 0, 0, 0, err
		}
	}

	return cntLogin, cntEmail, cntPhone, nil
}

func (r *UserRepository) GetCountByPhone(phone string) (int, error) {
	cntPhone := 0

	if err := r.store.db.QueryRow(
		"SELECT COUNT(id) AS cnt FROM users WHERE phone = ?",
		phone).Scan(
		&cntPhone,
	); err != nil {
		return 0, err
	}

	return cntPhone, nil
}

func (r *UserRepository) GetUserByLoginOrEmail(login string, email string) (*model.User, error) {

	user := &model.User{}
	if err := r.store.db.QueryRow(
		"SELECT id, encrypted_password FROM users WHERE email = ? OR login = ?",
		email, login).Scan(
		&user.ID,
		&user.EncryptedPassword,
	); err != nil {
		return nil, err
	}

	return user, nil
}

// Сохраняем RefreshToken в БД для указанного юзера и задаем ему срок службы
func (r *UserRepository) AddRefreshToken(userId int, refreshToken string, RefreshTokenTTL time.Duration) error {

	ttl := time.Now().Add(RefreshTokenTTL)

	_, err := r.store.db.Exec("REPLACE INTO tokens (refresh_token, token_expired, id_user) VALUES (?,?,?)",
		refreshToken, ttl, userId)
	if err != nil {
		return err
	}

	return nil
}

// Получаем юзера по его токену, одновременно проверяя не истек ли он
func (r *UserRepository) GetByToken(token string) (*model.User, error) {

	user := &model.User{}
	if err := r.store.db.QueryRow(
		"SELECT id_user FROM tokens WHERE refresh_token = ? AND token_expired > ?",
		token, time.Now()).Scan(&user.ID); err != nil {
		return nil, err
	}

	return user, nil
}

func (r *UserRepository) GetByPhone(phone string) (*model.User, error) {
	user := &model.User{}
	if err := r.store.db.QueryRow(
		"SELECT id, phone FROM users WHERE phone = ?",
		phone).Scan(
		&user.ID,
		&user.Phone); err != nil {
		return nil, err
	}

	return user, nil
}

// Удаление данных о сессии в таблице токенов
func (r *UserRepository) RemoveToken(refreshToken string) error {

	_, err := r.store.db.Exec("DELETE FROM tokens WHERE refresh_token=?",
		refreshToken)
	if err != nil {
		return err
	}

	return nil
}
