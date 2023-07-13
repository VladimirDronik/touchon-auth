package apiserver

import (
	"os"
	"strconv"
	"time"
)

// Config ...
type Config struct {
	BindAddr        string        `toml:"BIND_ADDR"`
	LogLevel        string        `toml:"LOG_LEVEL"`
	DatabaseURL     string        `toml:"DATABASE_URL"`
	Secret          string        `toml:"SECRET"`
	AccessTokenTTL  string        `toml:"ACCESS_TOKEN_TTL"`
	RefreshTokenTTL string        `toml:"REFRESH_TOKEN_TTL"`
	SMSRUID         string        `toml:"SMSRU_ID"`
	SecretAPIKey    string        `toml:"SECRET_API_KEY"`
	MaxLifetime     time.Duration `toml:"MAX_LIFETIME"`
	MaxIDLETime     time.Duration `toml:"MAX_IDLE_TIME"`
	MaxOpenConns    int           `toml:"MAX_OPEN_CONNS"`
	MaxIDLEConns    int           `toml:"MAX_IDLE_CONNS"`
}

// Конструктор конфигурации, присвоение значений из ENV
func NewConfig() *Config {

	bindAddr, _ := os.LookupEnv("BIND_ADDR")
	logLevel, _ := os.LookupEnv("LOG_LEVEL")
	databaseURL, _ := os.LookupEnv("DATABASE_URL")
	secret, _ := os.LookupEnv("SECRET")
	accessTokenTTL, _ := os.LookupEnv("ACCESS_TOKEN_TTL")
	refreshTokenTTL, _ := os.LookupEnv("REFRESH_TOKEN_TTL")
	SMSRUID, _ := os.LookupEnv("SMSRU_ID")
	secretAPIKey, _ := os.LookupEnv("SECRET_API_KEY")

	maxLifetimeString, _ := os.LookupEnv("MAX_LIFETIME")
	maxLifetime, _ := time.ParseDuration(maxLifetimeString)

	maxIDLETimeString, _ := os.LookupEnv("MAX_IDLE_TIME")
	maxIDLETime, _ := time.ParseDuration(maxIDLETimeString)

	maxOpenConnsString, _ := os.LookupEnv("MAX_OPEN_CONNS")
	maxOpenConns, _ := strconv.Atoi(maxOpenConnsString)

	maxIDLEConnsString, _ := os.LookupEnv("MAX_IDLE_CONNS")
	maxIDLEConns, _ := strconv.Atoi(maxIDLEConnsString)

	return &Config{
		BindAddr:        bindAddr,
		LogLevel:        logLevel,
		DatabaseURL:     databaseURL,
		Secret:          secret,
		AccessTokenTTL:  accessTokenTTL,
		RefreshTokenTTL: refreshTokenTTL,
		SMSRUID:         SMSRUID,
		SecretAPIKey:    secretAPIKey,
		MaxLifetime:     maxLifetime,
		MaxIDLETime:     maxIDLETime,
		MaxOpenConns:    maxOpenConns,
		MaxIDLEConns:    maxIDLEConns,
	}
}
