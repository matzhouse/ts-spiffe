package authkey

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestOAuthClient_Token_Success(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		ct := r.Header.Get("Content-Type")
		if ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", ct)
		}

		clientID, clientSecret, ok := r.BasicAuth()
		if !ok || clientID != "test-id" || clientSecret != "test-secret" {
			t.Errorf("unexpected basic auth: %s:%s (ok=%v)", clientID, clientSecret, ok)
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
	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("expected 1 HTTP call (cached), got %d", callCount)
	}
}

func TestOAuthClient_Token_ExpiryTriggersRefresh(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "token-" + string(rune('0'+n)),
			ExpiresIn:   1, // expires in 1 second (within 30s buffer, so immediately stale)
		})
	}))
	defer srv.Close()

	client := NewOAuthClient("test-id", "test-secret",
		WithTokenURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	// First call fetches.
	_, err := client.Token()
	if err != nil {
		t.Fatalf("first Token() failed: %v", err)
	}

	// With ExpiresIn=1, the 30s buffer means the token is immediately considered
	// near-expiry, so the second call should fetch again.
	_, err = client.Token()
	if err != nil {
		t.Fatalf("second Token() failed: %v", err)
	}

	if atomic.LoadInt32(&callCount) != 2 {
		t.Errorf("expected 2 HTTP calls (token expired), got %d", callCount)
	}
}

func TestOAuthClient_Token_DefaultExpiryWhenZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "test-token",
			ExpiresIn:   0, // no expiry specified
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
	if token != "test-token" {
		t.Errorf("token = %q, want %q", token, "test-token")
	}

	// The default 1h expiry should mean the token is cached.
	// Verify expiry was set to roughly 1 hour from now.
	if client.expiry.Before(time.Now().Add(59 * time.Minute)) {
		t.Error("expected default expiry of ~1 hour")
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

func TestOAuthClient_Token_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	client := NewOAuthClient("test-id", "test-secret",
		WithTokenURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	_, err := client.Token()
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestNewOAuthClient_Defaults(t *testing.T) {
	client := NewOAuthClient("id", "secret")

	if client.tokenURL != defaultTokenURL {
		t.Errorf("tokenURL = %q, want %q", client.tokenURL, defaultTokenURL)
	}
	if client.httpClient == nil {
		t.Fatal("expected non-nil httpClient")
	}
	if client.httpClient.Timeout != defaultHTTPTimeout {
		t.Errorf("httpClient.Timeout = %v, want %v", client.httpClient.Timeout, defaultHTTPTimeout)
	}
}

func TestNewOAuthClient_WithOptions(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	client := NewOAuthClient("id", "secret",
		WithTokenURL("https://custom.example.com/token"),
		WithHTTPClient(customClient),
	)

	if client.tokenURL != "https://custom.example.com/token" {
		t.Errorf("tokenURL = %q, want custom URL", client.tokenURL)
	}
	if client.httpClient != customClient {
		t.Error("expected custom HTTP client")
	}
}
