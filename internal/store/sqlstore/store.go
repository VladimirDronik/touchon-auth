package sqlstore

import (
	"database/sql"
	"touchon-auth/internal/store"
)

type Store struct {
	db      *sql.DB
	userRep *UserRepository
}

// New ...
func New(db *sql.DB) *Store {
	return &Store{
		db: db,
	}
}

// Инициализация
func (s *Store) User() store.UserRepository {
	if s.userRep != nil {
		return s.userRep
	}

	s.userRep = &UserRepository{
		store: s,
	}

	return s.userRep
}
