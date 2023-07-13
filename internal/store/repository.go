package store

import (
	"time"
	"touchon_auth/model"
)

type UserRepository interface {
	Create(*model.User) (*model.User, error)
	Update(user *model.User) error
	GetUserByLoginOrEmail(string, string) (*model.User, error)
	AddRefreshToken(int, string, time.Duration) error
	GetByToken(string) (*model.User, error)
	GetByPhone(string) (*model.User, error)
	GetCountByPhone(phone string) (int, error)
	RemoveToken(refreshToken string) error
}

type CallRepository interface {
	RemoveOldData(phone string) error
	AddTempCallData(id string, phone string, code int) error
	AddCallData(call *model.Call) error
	AddSMSData(call *model.SMS) error
	GetRowByCodeANDPhone(phone string, code int) (int, error)
	GetCodeByPhone(phone string) (int, error)
}
