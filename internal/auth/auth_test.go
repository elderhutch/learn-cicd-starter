package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantKey     string
		wantErr     error
	}{
		{
			name:        "no header",
			headerValue: "",
			wantKey:     "",
			wantErr:     ErrNoAuthHeaderIncluded,
		},
		{
			name:        "malformed header - no ApiKey",
			headerValue: "Bearer sometoken",
			wantKey:     "",
			wantErr:     errors.New("malformed authorization header"),
		},
		{
			name:        "malformed header - missing token",
			headerValue: "ApiKey",
			wantKey:     "",
			wantErr:     errors.New("malformed authorization header"),
		},
		{
			name:        "valid header",
			headerValue: "ApiKey testkey123",
			wantKey:     "testkey123",
			wantErr:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.headerValue != "" {
				headers.Set("Authorization", tt.headerValue)
			}
			gotKey, err := GetAPIKey(headers)
			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}
			if (err != nil && tt.wantErr == nil) || (err == nil && tt.wantErr != nil) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
			if err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

/*
package auth

import (
	"net/http"
	"testing"
	"errors"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key != "my-secret-key" {
		t.Errorf("expected key 'my-secret-key', got '%s'", key)
	}
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	tests := []struct{
		name string
		authHeader string
	}{
		{"WrongPrefix", "Bearer token"},
		{"MissingKey", "ApiKey"},
		{"EmptyKey", "ApiKey "},
		{"NoSpace", "ApiKeymy-secret-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", tt.authHeader)
			_, err := GetAPIKey(headers)
			if err == nil || err.Error() != "malformed authorization header" {
				t.Errorf("expected malformed authorization header error, got %v", err)
			}
		})
	}
}
*/
