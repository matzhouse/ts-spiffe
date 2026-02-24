package authkey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetcher_CreateAuthKey_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v2/tailnet/example.com/keys" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("unexpected auth: %s", auth)
		}

		ct := r.Header.Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}

		var reqBody apiKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		if !reqBody.Capabilities.Devices.Create.Ephemeral {
			t.Error("expected ephemeral = true")
		}
		if !reqBody.Capabilities.Devices.Create.Preauthorized {
			t.Error("expected preauthorized = true")
		}
		if reqBody.Capabilities.Devices.Create.Reusable {
			t.Error("expected reusable = false")
		}
		if len(reqBody.Capabilities.Devices.Create.Tags) != 1 || reqBody.Capabilities.Devices.Create.Tags[0] != "tag:container" {
			t.Errorf("unexpected tags: %v", reqBody.Capabilities.Devices.Create.Tags)
		}
		if reqBody.ExpirySeconds != 3600 {
			t.Errorf("ExpirySeconds = %d, want 3600", reqBody.ExpirySeconds)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthKeyResponse{
			ID:        "key123",
			Key:       "tskey-auth-abc123",
			Created:   time.Now(),
			Expires:   time.Now().Add(1 * time.Hour),
			Ephemeral: true,
		})
	}))
	defer srv.Close()

	fetcher := NewFetcher(
		func(context.Context) (string, error) { return "test-token", nil },
		WithAPIBase(srv.URL+"/api/v2"),
		WithFetcherHTTPClient(srv.Client()),
	)

	resp, err := fetcher.CreateAuthKey(context.Background(), AuthKeyRequest{
		Tailnet:       "example.com",
		Ephemeral:     true,
		Preauthorized: true,
		Tags:          []string{"tag:container"},
		Expiry:        1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateAuthKey failed: %v", err)
	}

	if resp.Key != "tskey-auth-abc123" {
		t.Errorf("Key = %q, want %q", resp.Key, "tskey-auth-abc123")
	}
	if resp.ID != "key123" {
		t.Errorf("ID = %q, want %q", resp.ID, "key123")
	}
	if !resp.Ephemeral {
		t.Error("expected Ephemeral = true")
	}
}

func TestFetcher_CreateAuthKey_NonEphemeral(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody apiKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		if reqBody.Capabilities.Devices.Create.Ephemeral {
			t.Error("expected ephemeral = false")
		}
		if reqBody.Capabilities.Devices.Create.Preauthorized {
			t.Error("expected preauthorized = false")
		}
		if reqBody.ExpirySeconds != 0 {
			t.Errorf("ExpirySeconds = %d, want 0 (omitted)", reqBody.ExpirySeconds)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthKeyResponse{
			ID:  "key789",
			Key: "tskey-auth-xyz789",
		})
	}))
	defer srv.Close()

	fetcher := NewFetcher(
		func(context.Context) (string, error) { return "test-token", nil },
		WithAPIBase(srv.URL+"/api/v2"),
		WithFetcherHTTPClient(srv.Client()),
	)

	resp, err := fetcher.CreateAuthKey(context.Background(), AuthKeyRequest{
		Tailnet:       "example.com",
		Ephemeral:     false,
		Preauthorized: false,
		Tags:          []string{"tag:server"},
	})
	if err != nil {
		t.Fatalf("CreateAuthKey failed: %v", err)
	}
	if resp.Key != "tskey-auth-xyz789" {
		t.Errorf("Key = %q, want %q", resp.Key, "tskey-auth-xyz789")
	}
}

func TestFetcher_CreateAuthKey_DefaultTailnet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/tailnet/-/keys" {
			t.Errorf("expected default tailnet path, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthKeyResponse{
			ID:  "key456",
			Key: "tskey-auth-def456",
		})
	}))
	defer srv.Close()

	fetcher := NewFetcher(
		func(context.Context) (string, error) { return "test-token", nil },
		WithAPIBase(srv.URL+"/api/v2"),
		WithFetcherHTTPClient(srv.Client()),
	)

	resp, err := fetcher.CreateAuthKey(context.Background(), AuthKeyRequest{
		Tags: []string{"tag:container"},
	})
	if err != nil {
		t.Fatalf("CreateAuthKey failed: %v", err)
	}
	if resp.Key != "tskey-auth-def456" {
		t.Errorf("Key = %q, want %q", resp.Key, "tskey-auth-def456")
	}
}

func TestFetcher_CreateAuthKey_TailnetPathEscaping(t *testing.T) {
	fetcher := NewFetcher(
		func(context.Context) (string, error) { return "test-token", nil },
	)

	cases := []struct {
		name    string
		tailnet string
	}{
		{"dot-dot-slash", "../evil"},
		{"slash", "foo/bar"},
		{"double-dot", "evil..path"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fetcher.CreateAuthKey(context.Background(), AuthKeyRequest{
				Tailnet: tc.tailnet,
				Tags:    []string{"tag:test"},
			})
			if err == nil {
				t.Fatalf("expected error for tailnet %q, got nil", tc.tailnet)
			}
			if !strings.Contains(err.Error(), "invalid tailnet name") {
				t.Errorf("error = %v, want 'invalid tailnet name'", err)
			}
		})
	}
}

func TestFetcher_CreateAuthKey_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "forbidden"}`))
	}))
	defer srv.Close()

	fetcher := NewFetcher(
		func(context.Context) (string, error) { return "test-token", nil },
		WithAPIBase(srv.URL+"/api/v2"),
		WithFetcherHTTPClient(srv.Client()),
	)

	_, err := fetcher.CreateAuthKey(context.Background(), AuthKeyRequest{
		Tailnet: "example.com",
		Tags:    []string{"tag:container"},
	})
	if err == nil {
		t.Fatal("expected error for 403, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestFetcher_CreateAuthKey_TokenError(t *testing.T) {
	fetcher := NewFetcher(
		func(context.Context) (string, error) { return "", errors.New("oauth failed") },
	)

	_, err := fetcher.CreateAuthKey(context.Background(), AuthKeyRequest{
		Tailnet: "example.com",
		Tags:    []string{"tag:container"},
	})
	if err == nil {
		t.Fatal("expected error when token func fails, got nil")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should mention token: %v", err)
	}
}

func TestFetcher_CreateAuthKey_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	fetcher := NewFetcher(
		func(context.Context) (string, error) { return "test-token", nil },
		WithAPIBase(srv.URL+"/api/v2"),
		WithFetcherHTTPClient(srv.Client()),
	)

	_, err := fetcher.CreateAuthKey(context.Background(), AuthKeyRequest{
		Tailnet: "example.com",
		Tags:    []string{"tag:container"},
	})
	if err == nil {
		t.Fatal("expected error for malformed JSON response, got nil")
	}
}

func TestNewFetcher_Defaults(t *testing.T) {
	fetcher := NewFetcher(func(context.Context) (string, error) { return "", nil })

	if fetcher.apiBase != defaultAPIBase {
		t.Errorf("apiBase = %q, want %q", fetcher.apiBase, defaultAPIBase)
	}
	if fetcher.httpClient == nil {
		t.Fatal("expected non-nil httpClient")
	}
	if fetcher.httpClient.Timeout != 30*time.Second {
		t.Errorf("httpClient.Timeout = %v, want 30s", fetcher.httpClient.Timeout)
	}
}

func TestNewFetcher_WithOptions(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	fetcher := NewFetcher(
		func(context.Context) (string, error) { return "", nil },
		WithAPIBase("https://custom.example.com/api"),
		WithFetcherHTTPClient(customClient),
	)

	if fetcher.apiBase != "https://custom.example.com/api" {
		t.Errorf("apiBase = %q, want custom URL", fetcher.apiBase)
	}
	if fetcher.httpClient != customClient {
		t.Error("expected custom HTTP client")
	}
}
