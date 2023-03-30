package apiserver

import "time"

// Config ...
type Config struct {
	BindAddr        string        `toml:"bind_addr"`
	LogLevel        string        `toml:"log_level"`
	DatabaseURL     string        `toml:"database_url"`
	Secret          string        `toml:"secret"`
	AccessTokenTTL  string        `toml:"accessTokenTTL"`
	RefreshTokenTTL string        `toml:"refreshTokenTTL"`
	Mode            string        `toml:"mode"`
	SMSRUID         string        `toml:"smsru_id"`
	SecretAPIKey    string        `toml:"secret_api_key"`
	MaxLifetime     time.Duration `toml:"max_lifetime"`
	MaxIDLETime     time.Duration `toml:"max_idle_time"`
	MaxOpenConns    int           `toml:"max_open_conns"`
	MaxIDLEConns    int           `toml:"max_idle_conns"`
}

// Конструктор конфигурации, присвоение дефолтных значений
func NewConfig() *Config {
	return &Config{
		BindAddr: ":8080",
		LogLevel: "debug",
	}
}
