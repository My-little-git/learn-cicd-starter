package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantKey     string
		wantErrMsg  string
	}{
		{
			name:        "returns api key when header is valid",
			headerValue: "ApiKey super-secret-key",
			wantKey:     "super-secret-key",
			wantErrMsg:  "",
		},
		{
			name:        "returns error when authorization header is missing",
			headerValue: "",
			wantKey:     "",
			wantErrMsg:  ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:        "returns error when authorization header is malformed",
			headerValue: "Bearer token",
			wantKey:     "",
			wantErrMsg:  "malformed authorization header",
		},
		{
			name:        "returns error when api key is missing",
			headerValue: "ApiKey",
			wantKey:     "",
			wantErrMsg:  "malformed authorization header",
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
				t.Fatalf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}

			if tt.wantErrMsg == "" {
				if err != nil {
					t.Fatalf("GetAPIKey() unexpected error = %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("GetAPIKey() error = nil, want %q", tt.wantErrMsg)
			}

			if err.Error() != tt.wantErrMsg {
				t.Fatalf("GetAPIKey() error = %v, want %q", err, tt.wantErrMsg)
			}
		})
	}
}
