package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var ErrNoAuthHeader = errors.New("authorization header missing or invalid")

// GetBearerToken extracts the Bearer token from the Authorization header
func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return "", ErrNoAuthHeader
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer ")), nil
}

// MakeRefreshToken generates a secure 256-bit (32-byte) hex-encoded refresh token
func MakeRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
