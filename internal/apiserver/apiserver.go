package apiserver

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"net/http"
	"time"
	"touchon_auth/internal/store/sqlstore"
)

// Запуск сервера
func Start(config *Config, certFile string, keyFile string) error {
	db, err := newDB(config)
	if err != nil {
		return err
	}

	defer db.Close()
	store := sqlstore.New(db)
	s := newServer(store, config)

	return http.ListenAndServeTLS(config.BindAddr, certFile, keyFile, s)
}

func newDB(config *Config) (*sql.DB, error) {
	db, err := sql.Open("mysql", config.DatabaseURL)
	if err != nil {
		return nil, err
	}

	db.SetConnMaxLifetime(time.Second * config.MaxLifetime)
	db.SetConnMaxIdleTime(time.Second * config.MaxIDLETime)
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIDLEConns)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
