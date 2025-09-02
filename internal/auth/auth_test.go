package auth


import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {

	tests := []struct {
		name		string
		headers		http.Header
		wantKey		string
		wantError 	error
	}{
		{
			name:		"no auth header",
			headers:	http.Header{},
			wantKey:	"",
			wantError:	errors.New("no authorization header included"),
		},
		{
	       		name:           "malformed header - wrong scheme",
                	headers:        http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
                	wantKey:        "",
                	wantError:      errors.New("malformed authorization header"),
		},
		{
                	name:           "malformed header - missing token",
                	headers:        http.Header{
                        	"Authorization": []string{"APIKey"},
                	},
                	wantKey:        "",
                	wantError:      errors.New("malformed authorization header"),
		},
		{
                	name:           "success!",
                	headers:        http.Header{
                	        "Authorization": []string{"ApiKey mySecret"},
                	},
                	wantKey:        "mySecret",
        	        wantError:      nil,
		},
	}


	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		gotKey, err := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}

			if (err == nil) != (tt.wantError == nil) {
				t.Errorf("expected error %v, got %v", tt.wantError, err)
			}

			// If we expect a specific error message, check it
			if err != nil && tt.wantError != nil && err.Error() != tt.wantError.Error() {
				t.Errorf("expected error %q, got %q", tt.wantError, err)
			}
		})
	}
}
