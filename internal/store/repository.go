package store

import (
	"time"
	"touchon-auth/model"
)

type UserRepository interface {
	Create(*model.User) error
	GetUserByLoginOrEmail(string, string) (*model.User, error)
	AddRefreshToken(int, string, time.Duration) error
	GetUserByToken(string) (*model.User, error)
}
