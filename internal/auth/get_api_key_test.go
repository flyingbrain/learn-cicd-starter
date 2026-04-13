package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectError bool
	}{
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			expectedKey: "my-secret-key",
			expectError: false,
		},
		{
			name:        "missing Authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectError: true,
		},
		{
			name: "empty Authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey: "",
			expectError: true,
		},
		{
			name: "wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-key"},
			},
			expectedKey: "",
			expectError: true,
		},
		{
			name: "malformed header - no key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectError: true,
		},
		{
			name: "malformed header - too many spaces but valid",
			headers: http.Header{
				"Authorization": []string{"ApiKey    my-secret-key"},
			},
			expectedKey: "",
			expectError: true, // because split will produce empty elements
		},
		{
			name: "extra parts but still valid",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key extra"},
			},
			expectedKey: "my-secret-key",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}
