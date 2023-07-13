package model

import (
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID                int    `json:"id"`
	Login             string `json:"login"`
	Email             string `json:"email"`
	Phone             string `json:"phone"`
	Password          string `json:"password,omitempty"`
	EncryptedPassword string `json:"-"`
}

// Убираем пароль из выдачи в json
func (user *User) Sanitize() {
	user.Password = ""
}

// Проверяем пароль на соответствие
func (user *User) ComparePassword(password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(user.EncryptedPassword), []byte(password)) == nil
}

func (user *User) Validate() error {
	return validation.ValidateStruct(user,
		validation.Field(user.Email, validation.Required, is.Email),
		validation.Field(user.Password, validation.By(requiredIf(user.EncryptedPassword == "")), validation.Length(6, 100)),
	)
}

// Выполняем перед созданием пользователя
func (user *User) EncryptPassword() error {
	if len(user.Password) > 0 {
		enc, err := encryptString(user.Password)
		if err != nil {
			return err
		}

		user.EncryptedPassword = enc
	}

	return nil
}

// Шифрование пароля
func encryptString(s string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
