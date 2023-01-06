package sqlstore

import (
	"errors"
	"time"
	"touchon_auth/model"
)

type UserRepository struct {
	store *Store
}

func (r *UserRepository) Create(user *model.User) error {

	cntLogin, cntEmail, err := r.getCountByLoginOrEmail(user.Login, user.Email)

	if cntLogin > 0 {
		err = errors.New("login already exists")
		return err
	}

	if cntEmail > 0 {
		err = errors.New("email already exists")
		return err
	}

	if err != nil {
		return err
	}

	if err := user.BeforeCreate(); err != nil {
		return err
	}

	if err := r.store.db.QueryRow("INSERT INTO users (login, email, encrypted_password) VALUES (?, ?, ?)", user.Login, user.Email, user.EncryptedPassword).Err(); err != nil {
		return err
	}

	if err := r.store.db.QueryRow(
		"SELECT id FROM users WHERE login = ? AND email = ?", user.Login, user.Email).Scan(
		&user.ID,
	); err != nil {
		return err
	}

	return nil
}

// Находим количество пользователей с указанным именем и емейлом, это количесвто будет определять есть ли в системе
// пользователь и выдавать ощибку, если пытаемся создать с уже имеющимися данными
func (r *UserRepository) getCountByLoginOrEmail(login string, email string) (int, int, error) {
	cntLogin := 0
	cntEmail := 0

	if err := r.store.db.QueryRow(
		"SELECT COUNT(id) AS cnt FROM users WHERE login = ?",
		login).Scan(
		&cntLogin,
	); err != nil {
		return 0, 0, err
	}

	if err := r.store.db.QueryRow(
		"SELECT COUNT(id) AS cnt FROM users WHERE email = ?",
		email).Scan(
		&cntEmail,
	); err != nil {
		return 0, 0, err
	}

	return cntLogin, cntEmail, nil
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

//Сохраняем RefreshToken в БД для указанного юзера и задаем ему срок службы
func (r *UserRepository) AddRefreshToken(userId int, refreshToken string, RefreshTokenTTL time.Duration) error {

	ttl := time.Now().Add(RefreshTokenTTL)

	if err := r.store.db.QueryRow("UPDATE users SET refresh_token = ?, token_expired = ? WHERE id = ?",
		refreshToken, ttl, userId).Err(); err != nil {
		return err
	}
	return nil
}

// Получаем юзера по его токену, одновременно проверяя не истек ли он
func (r *UserRepository) GetUserByToken(token string) (*model.User, error) {

	user := &model.User{}
	if err := r.store.db.QueryRow(
		"SELECT id FROM users WHERE refresh_token = ? AND token_expired > ?",
		token, time.Now()).Scan(
		&user.ID,
	); err != nil {
		return nil, err
	}

	return user, nil
}
