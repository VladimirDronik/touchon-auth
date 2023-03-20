package main

import (
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"log"
	"touchon_auth/internal/apiserver"
)

var (
	configPath string
)

func init() {
	flag.StringVar(&configPath, "configs-path", "config.toml", "path to configs file")
}

var Version string

func main() {
	fmt.Println("\n████████  ██████  ██    ██  ██████ ██   ██  ██████  ███    ██      █████  ██    ██ ████████ ██   ██ \n   ██    ██    ██ ██    ██ ██      ██   ██ ██    ██ ████   ██     ██   ██ ██    ██    ██    ██   ██ \n   ██    ██    ██ ██    ██ ██      ███████ ██    ██ ██ ██  ██     ███████ ██    ██    ██    ███████ \n   ██    ██    ██ ██    ██ ██      ██   ██ ██    ██ ██  ██ ██     ██   ██ ██    ██    ██    ██   ██ \n   ██     ██████   ██████   ██████ ██   ██  ██████  ██   ████     ██   ██  ██████     ██    ██   ██ \n")
	fmt.Println("Version: ", Version, "\n\n")

	flag.Parse()
	config := apiserver.NewConfig()
	_, err := toml.DecodeFile(configPath, config)

	if err != nil {
		log.Fatal(err)
	}

	if err := apiserver.Start(config); err != nil {
		log.Fatal(err)
	}
}
