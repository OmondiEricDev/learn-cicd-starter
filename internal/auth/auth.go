package auth

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != "ApiKey" {
		return "", errors.New("malformed authorization header")
	}

	return splitAuth[1], nil
}

func TestGetAPIKey(t *testing.T) {
	got, _ := GetAPIKey(http.Header{"Authorization": []string{"ApiKey 12345"}})
	want := "12345"
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetAPIKey() = %v, want %v", got, want)
	}
}
