package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantKey    string
		wantErr    error
	}{
		{
			name:       "success with ApiKey scheme",
			authHeader: "ApiKey secret123",
			wantKey:    "secret123",
			wantErr:    nil,
		},
		{
			name:       "missing Authorization header",
			authHeader: "",
			wantKey:    "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name:       "wrong scheme",
			authHeader: "Bearer token",
			wantKey:    "",
			wantErr:    errMalformedAuthorizationHeader(),
		},
		{
			name:       "missing key after scheme",
			authHeader: "ApiKey",
			wantKey:    "",
			wantErr:    errMalformedAuthorizationHeader(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.authHeader != "" {
				h.Set("Authorization", tc.authHeader)
			}

			got, err := GetAPIKey(h)

			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.wantKey {
					t.Fatalf("got key %q, want %q", got, tc.wantKey)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error %v, got nil", tc.wantErr)
			}

			// Compare error types/messages depending on the case
			if tc.wantErr == ErrNoAuthHeaderIncluded {
				if err != ErrNoAuthHeaderIncluded {
					t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
				}
			} else {
				if err.Error() != tc.wantErr.Error() {
					t.Fatalf("unexpected error. got %q, want %q", err.Error(), tc.wantErr.Error())
				}
			}
		})
	}
}

// helper returns the exact error value produced by GetAPIKey for malformed headers
func errMalformedAuthorizationHeader() error {
	return errors.New("malformed authorization header")
}
