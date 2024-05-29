package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantAPIKey string
		wantErr    error
	}{
		{
			name:       "Valid API Key",
			headers:    http.Header{"Authorization": {"ApiKey 12345"}},
			wantAPIKey: "12345",
			wantErr:    nil,
		},
		{
			name:       "No Authorization Header",
			headers:    http.Header{},
			wantAPIKey: "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name:       "Malformed Authorization Header - No ApiKey",
			headers:    http.Header{"Authorization": {"Bearer 12345"}},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name:       "Malformed Authorization Header - No Key",
			headers:    http.Header{"Authorization": {"ApiKey"}},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)
			if apiKey != tt.wantAPIKey {
				t.Errorf("GetAPIKey() apiKey = %v, want %v", apiKey, tt.wantAPIKey)
			}
			if err != nil && tt.wantErr != nil {
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != tt.wantErr {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
