package auth

import (
	"errors"
	"net/http"
	"strings"
)

var ErrNoAuthHeader = errors.New("authorization header missing or invalid")

// GetBearerToken extracts the token string from the Authorization header
func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return "", ErrNoAuthHeader
	}

	return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer ")), nil
}
