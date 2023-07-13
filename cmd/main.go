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
	certFile   string
	keyFile    string
)

func init() {
	flag.StringVar(&configPath, "config", "", "path to configs file")
	flag.StringVar(&certFile, "certfile", "cert.pem", "certificate PEM file")
	flag.StringVar(&keyFile, "keyfile", "key.pem", "key PEM file")
}

var Version string

func main() {
	fmt.Println("\n████████  ██████  ██    ██  ██████ ██   ██  ██████  ███    ██      █████  ██    ██ ████████ ██   ██ \n   ██    ██    ██ ██    ██ ██      ██   ██ ██    ██ ████   ██     ██   ██ ██    ██    ██    ██   ██ \n   ██    ██    ██ ██    ██ ██      ███████ ██    ██ ██ ██  ██     ███████ ██    ██    ██    ███████ \n   ██    ██    ██ ██    ██ ██      ██   ██ ██    ██ ██  ██ ██     ██   ██ ██    ██    ██    ██   ██ \n   ██     ██████   ██████   ██████ ██   ██  ██████  ██   ████     ██   ██  ██████     ██    ██   ██ \n")
	fmt.Println("Version: ", Version, "\n\n")

	flag.Parse()
	config := apiserver.NewConfig()
	_, err := toml.DecodeFile(configPath, config)

	if err != nil {
		log.Println(err)
	}

	if err := apiserver.Start(config, certFile, keyFile); err != nil {
		log.Fatal(err)
	}
}
