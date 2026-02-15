// go
package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_TableDriven(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr string
	}{
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey 12345"}},
			wantKey: "12345",
			wantErr: "",
		},
		{
			name:    "missing authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: "no authorization header included",
		},
		{
			name:    "wrong scheme",
			headers: http.Header{"Authorization": []string{"Bearer 12345"}},
			wantKey: "",
			wantErr: "malformed authorization header",
		},
		{
			name:    "no token after scheme",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantKey: "",
			wantErr: "malformed authorization header",
		},
		{
			name:    "multiple spaces produces empty token element",
			headers: http.Header{"Authorization": []string{"ApiKey    12345"}},
			wantKey: "",
			wantErr: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := GetAPIKey(tc.headers)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.wantKey {
					t.Fatalf("got key %q, want %q", got, tc.wantKey)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %q, got nil", tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}
