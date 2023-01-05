package tests

import (
	"os"
	"testing"
)

var (
	databaseURL string
)

func TestMain(m *testing.M) {
	databaseURL = os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "root:Alli80ed!@tcp(127.0.0.1:3306)/smarthome_test"
	}

	os.Exit(m.Run())
}
