package authkey

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOAuthClient_Token_Success(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		clientID, clientSecret, ok := r.BasicAuth()
		if !ok || clientID != "test-id" || clientSecret != "test-secret" {
			t.Errorf("unexpected basic auth: %s:%s", clientID, clientSecret)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "test-access-token",
			ExpiresIn:   3600,
		})
	}))
	defer srv.Close()

	client := NewOAuthClient("test-id", "test-secret",
		WithTokenURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	token, err := client.Token()
	if err != nil {
		t.Fatalf("Token() failed: %v", err)
	}
	if token != "test-access-token" {
		t.Errorf("token = %q, want %q", token, "test-access-token")
	}

	// Second call should use cached token.
	token2, err := client.Token()
	if err != nil {
		t.Fatalf("Token() cached call failed: %v", err)
	}
	if token2 != "test-access-token" {
		t.Errorf("cached token = %q, want %q", token2, "test-access-token")
	}
	if callCount != 1 {
		t.Errorf("expected 1 HTTP call (cached), got %d", callCount)
	}
}

func TestOAuthClient_Token_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "invalid_client"}`))
	}))
	defer srv.Close()

	client := NewOAuthClient("bad-id", "bad-secret",
		WithTokenURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	_, err := client.Token()
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
}

func TestOAuthClient_Token_EmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "",
			ExpiresIn:   3600,
		})
	}))
	defer srv.Close()

	client := NewOAuthClient("test-id", "test-secret",
		WithTokenURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	_, err := client.Token()
	if err == nil {
		t.Fatal("expected error for empty access_token, got nil")
	}
}
