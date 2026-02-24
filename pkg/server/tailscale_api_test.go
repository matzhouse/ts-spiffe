package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		tokenFunc:  func() (string, error) { return "test-token", nil },
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
		tokenFunc:  func() (string, error) { return "test-token", nil },
	}

	_, err := client.GetDevice(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestHTTPAPIClient_GetDevice_PathEscaping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A malicious nodeID like "../tailnet/evil" should be escaped,
		// so the path should contain the escaped form, not a traversal.
		if r.URL.Path == "/api/v2/tailnet/evil" {
			t.Error("path traversal was not prevented")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&DeviceInfo{ID: "safe"})
	}))
	defer srv.Close()

	client := &httpAPIClient{
		baseURL:    srv.URL + "/api/v2",
		httpClient: srv.Client(),
		tokenFunc:  func() (string, error) { return "test-token", nil },
	}

	_, _ = client.GetDevice(context.Background(), "../tailnet/evil")
}
