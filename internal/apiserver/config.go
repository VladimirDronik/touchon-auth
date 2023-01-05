package apiserver

// Config ...
type Config struct {
	BindAddr        string `toml:"bind_addr"`
	LogLevel        string `toml:"log_level"`
	DatabaseURL     string `toml:"database_url"`
	Secret          string `toml:"secret"`
	AccessTokenTTL  string `toml:"accessTokenTTL"`
	RefreshTokenTTL string `toml:"refreshTokenTTL"`
}

// Конструктор конфигурации, присвоение дефолнтных значений
func NewConfig() *Config {
	return &Config{
		BindAddr: ":8080",
		LogLevel: "debug",
	}
}
