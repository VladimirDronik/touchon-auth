package tests

import (
	"TouchOnHeat/internal/store/sqlstore"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRepository_GetByDeviceId(t *testing.T) {
	db, teardown := sqlstore.TestDB(t, databaseURL)
	defer teardown("dashboard")

	s := sqlstore.New(db)
	deviceID := 5
	_, err := s.Dashboard().GetByDeviceId(deviceID)
	assert.Error(t, err)

	//TODO:: создать дашборд, а потом прочитать его
}
