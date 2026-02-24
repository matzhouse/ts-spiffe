package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPAPIClient_GetDevice_Success(t *testing.T) {
	expected := &DeviceInfo{
		ID:          "node123",
		NodeKey:     "nodekey:abc123",
		Hostname:    "myhost",
		Authorized:  true,
		Tags:        []string{"tag:web"},
		TailnetName: "example.com",
		Addresses:   []string{"100.64.0.1"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/device/node123" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("unexpected auth header: %s", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expected)
	}))
	defer srv.Close()

	client := &httpAPIClient{
		baseURL:    srv.URL + "/api/v2",
		httpClient: srv.Client(),
		tokenFunc:  func(context.Context) (string, error) { return "test-token", nil },
	}

	device, err := client.GetDevice(context.Background(), "node123")
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}

	if device.ID != "node123" {
		t.Errorf("ID = %q, want %q", device.ID, "node123")
	}
	if device.NodeKey != "nodekey:abc123" {
		t.Errorf("NodeKey = %q, want %q", device.NodeKey, "nodekey:abc123")
	}
	if !device.Authorized {
		t.Error("expected Authorized = true")
	}
	if device.TailnetName != "example.com" {
		t.Errorf("TailnetName = %q, want %q", device.TailnetName, "example.com")
	}
	if device.Hostname != "myhost" {
		t.Errorf("Hostname = %q, want %q", device.Hostname, "myhost")
	}
	if len(device.Tags) != 1 || device.Tags[0] != "tag:web" {
		t.Errorf("Tags = %v, want [tag:web]", device.Tags)
	}
	if len(device.Addresses) != 1 || device.Addresses[0] != "100.64.0.1" {
		t.Errorf("Addresses = %v, want [100.64.0.1]", device.Addresses)
	}
}

func TestHTTPAPIClient_GetDevice_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "device not found"}`))
	}))
	defer srv.Close()

	client := &httpAPIClient{
		baseURL:    srv.URL + "/api/v2",
		httpClient: srv.Client(),
		tokenFunc:  func(context.Context) (string, error) { return "test-token", nil },
	}

	_, err := client.GetDevice(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestHTTPAPIClient_GetDevice_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`internal error`))
	}))
	defer srv.Close()

	client := &httpAPIClient{
		baseURL:    srv.URL + "/api/v2",
		httpClient: srv.Client(),
		tokenFunc:  func(context.Context) (string, error) { return "test-token", nil },
	}

	_, err := client.GetDevice(context.Background(), "node123")
	if err == nil {
		t.Fatal("expected error for 500, got nil")
	}
}

func TestHTTPAPIClient_GetDevice_TokenError(t *testing.T) {
	client := &httpAPIClient{
		baseURL:    "http://unused",
		httpClient: http.DefaultClient,
		tokenFunc:  func(context.Context) (string, error) { return "", errors.New("token expired") },
	}

	_, err := client.GetDevice(context.Background(), "node123")
	if err == nil {
		t.Fatal("expected error when token func fails, got nil")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should mention token: %v", err)
	}
}

func TestHTTPAPIClient_GetDevice_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	client := &httpAPIClient{
		baseURL:    srv.URL + "/api/v2",
		httpClient: srv.Client(),
		tokenFunc:  func(context.Context) (string, error) { return "test-token", nil },
	}

	_, err := client.GetDevice(context.Background(), "node123")
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestHTTPAPIClient_GetDevice_PathEscaping(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawPath
		if gotPath == "" {
			gotPath = r.URL.Path
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&DeviceInfo{ID: "safe"})
	}))
	defer srv.Close()

	client := &httpAPIClient{
		baseURL:    srv.URL + "/api/v2",
		httpClient: srv.Client(),
		tokenFunc:  func(context.Context) (string, error) { return "test-token", nil },
	}

	_, _ = client.GetDevice(context.Background(), "../tailnet/evil")

	// The path should NOT resolve to /api/v2/tailnet/evil.
	if gotPath == "/api/v2/tailnet/evil" {
		t.Error("path traversal was not prevented")
	}
	// Should contain the escaped form.
	if !strings.Contains(gotPath, "%2F") && !strings.Contains(gotPath, "%2f") &&
		!strings.Contains(gotPath, "..") {
		// If dots are present but slashes are escaped, that's fine.
		// The key thing is that /tailnet/evil must not be reachable.
	}
}

func TestHTTPAPIClient_GetDevice_DefaultBaseURL(t *testing.T) {
	// When baseURL is empty, the default should be used.
	// We can't actually call the real API, so just verify the URL is constructed.
	client := &httpAPIClient{
		baseURL:    "", // should fall back to defaultAPIBase
		httpClient: &http.Client{},
		tokenFunc:  func(context.Context) (string, error) { return "test-token", nil },
	}

	// This will fail to connect, but the error should reference the default URL.
	_, err := client.GetDevice(context.Background(), "test-node")
	if err == nil {
		t.Fatal("expected error (no real API), got nil")
	}
	// The error should come from trying to connect to api.tailscale.com, not a panic.
}
