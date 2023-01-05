package store

import "touchon-auth/model"

type UserRepository interface {
	Create(*model.User) error
	GetUserByLoginOrEmail(string, string) (*model.User, error)
}
