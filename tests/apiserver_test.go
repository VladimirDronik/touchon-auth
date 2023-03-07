package tests

import (
	apiserver2 "TouchOnHeat/internal/apiserver"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIServer_HandleHello(t *testing.T) {
	s := apiserver2.New(apiserver2.NewConfig())
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/hello", nil)
	s.HandleHello().ServeHTTP(rec, req)
	assert.Equal(t, rec.Body.String(), "Hello!")
}
