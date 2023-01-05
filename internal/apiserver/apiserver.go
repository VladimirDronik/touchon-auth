package apiserver

import (
	"database/sql"
	"net/http"
	"touchon-auth/internal/store/sqlstore"
)

// Запуск сервера
func Start(config *Config) error {
	db, err := newDB(config.DatabaseURL)
	if err != nil {
		return err
	}

	defer db.Close()
	store := sqlstore.New(db)
	s := newServer(store, config)

	return http.ListenAndServe(config.BindAddr, s)
}

func newDB(dbURL string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dbURL)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
