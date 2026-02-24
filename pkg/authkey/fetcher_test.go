package authkey

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		func() (string, error) { return "test-token", nil },
		WithAPIBase(srv.URL+"/api/v2"),
		WithFetcherHTTPClient(srv.Client()),
	)

	resp, err := fetcher.CreateAuthKey(AuthKeyRequest{
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
		func() (string, error) { return "test-token", nil },
		WithAPIBase(srv.URL+"/api/v2"),
		WithFetcherHTTPClient(srv.Client()),
	)

	resp, err := fetcher.CreateAuthKey(AuthKeyRequest{
		Tags: []string{"tag:container"},
	})
	if err != nil {
		t.Fatalf("CreateAuthKey failed: %v", err)
	}
	if resp.Key != "tskey-auth-def456" {
		t.Errorf("Key = %q, want %q", resp.Key, "tskey-auth-def456")
	}
}

func TestFetcher_CreateAuthKey_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "forbidden"}`))
	}))
	defer srv.Close()

	fetcher := NewFetcher(
		func() (string, error) { return "test-token", nil },
		WithAPIBase(srv.URL+"/api/v2"),
		WithFetcherHTTPClient(srv.Client()),
	)

	_, err := fetcher.CreateAuthKey(AuthKeyRequest{
		Tailnet: "example.com",
		Tags:    []string{"tag:container"},
	})
	if err == nil {
		t.Fatal("expected error for 403, got nil")
	}
}
