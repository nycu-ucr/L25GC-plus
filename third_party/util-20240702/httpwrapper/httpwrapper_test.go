package httpwrapper

import (
	"context"
	"github.com/nycu-ucr/gonet/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRequest(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(),
		"GET", "http://localhost:8080?name=NCTU&location=Hsinchu", nil)
	if err != nil {
		t.Errorf("TestNewRequest error: %+v", err)
	}
	req.Header.Set("Location", "https://www.nctu.edu.tw/")
	request := NewRequest(req, 1000)
	assert.Equal(t, "https://www.nctu.edu.tw/", request.Header.Get("Location"))
	assert.Equal(t, "NCTU", request.Query.Get("name"))
	assert.Equal(t, "Hsinchu", request.Query.Get("location"))
	assert.Equal(t, 1000, request.Body)
}

func TestNewResponse(t *testing.T) {
	response := NewResponse(http.StatusCreated, map[string][]string{
		"Location": {"https://www.nctu.edu.tw/"},
		"Refresh":  {"url=https://free5gc.org"},
	}, 1000)
	assert.Equal(t, "https://www.nctu.edu.tw/", response.Header.Get("Location"))
	assert.Equal(t, "url=https://free5gc.org", response.Header.Get("Refresh"))
	assert.Equal(t, 1000, response.Body)
}
