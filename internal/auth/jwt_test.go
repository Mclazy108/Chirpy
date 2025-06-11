package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJWTGenerationAndValidation(t *testing.T) {
	secret := "supersecretkey"
	userID := uuid.New()

	token, err := MakeJWT(userID, secret, time.Minute)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	parsedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("token validation failed: %v", err)
	}

	if parsedID != userID {
		t.Fatalf("expected userID %v, got %v", userID, parsedID)
	}
}

func TestExpiredJWT(t *testing.T) {
	secret := "supersecretkey"
	userID := uuid.New()

	token, err := MakeJWT(userID, secret, -1*time.Minute) // already expired
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Fatal("expected error for expired token, got none")
	}
}

func TestInvalidSecret(t *testing.T) {
	secret := "correctsecret"
	wrongSecret := "wrongsecret"
	userID := uuid.New()

	token, err := MakeJWT(userID, secret, time.Minute)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Fatal("expected error for invalid secret, got none")
	}
}
