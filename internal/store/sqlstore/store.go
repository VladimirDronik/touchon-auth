package sqlstore

import (
	"database/sql"
	"touchon_auth/internal/store"
)

type Store struct {
	db      *sql.DB
	userRep *UserRepository
	callRep *CallRepository
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

func (s *Store) Call() store.CallRepository {
	if s.callRep != nil {
		return s.callRep
	}

	s.callRep = &CallRepository{
		store: s,
	}

	return s.callRep
}
