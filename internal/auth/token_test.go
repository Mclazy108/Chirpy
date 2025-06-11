package auth

import (
	"net/http"
	"testing"
)

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		header    http.Header
		wantToken string
		expectErr bool
	}{
		{
			name:      "valid token",
			header:    http.Header{"Authorization": []string{"Bearer my-token"}},
			wantToken: "my-token",
			expectErr: false,
		},
		{
			name:      "missing header",
			header:    http.Header{},
			expectErr: true,
		},
		{
			name:      "wrong prefix",
			header:    http.Header{"Authorization": []string{"Token my-token"}},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GetBearerToken(tt.header)
			if (err != nil) != tt.expectErr {
				t.Fatalf("unexpected error: %v", err)
			}
			if token != tt.wantToken {
				t.Fatalf("expected %q, got %q", tt.wantToken, token)
			}
		})
	}
}
