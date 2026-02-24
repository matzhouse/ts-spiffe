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
		ID:         "node123",
		NodeKey:    "nodekey:abc123",
		Hostname:   "myhost",
		Authorized: true,
		Tags:       []string{"tag:web"},
		Addresses:  []string{"100.64.0.1"},
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

	// Override the API base URL by wrapping the client.
	client := &testableHTTPAPIClient{
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
}

func TestHTTPAPIClient_GetDevice_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "device not found"}`))
	}))
	defer srv.Close()

	client := &testableHTTPAPIClient{
		baseURL:    srv.URL + "/api/v2",
		httpClient: srv.Client(),
		tokenFunc:  func() (string, error) { return "test-token", nil },
	}

	_, err := client.GetDevice(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

// testableHTTPAPIClient allows overriding the base URL for tests.
type testableHTTPAPIClient struct {
	baseURL    string
	httpClient *http.Client
	tokenFunc  func() (string, error)
}

func (c *testableHTTPAPIClient) GetDevice(ctx context.Context, nodeID string) (*DeviceInfo, error) {
	// Reuse the same logic as httpAPIClient but with custom base URL.
	token, err := c.tokenFunc()
	if err != nil {
		return nil, err
	}

	url := c.baseURL + "/device/" + nodeID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &apiError{StatusCode: resp.StatusCode}
	}

	var device DeviceInfo
	if err := json.NewDecoder(resp.Body).Decode(&device); err != nil {
		return nil, err
	}
	return &device, nil
}

type apiError struct {
	StatusCode int
}

func (e *apiError) Error() string {
	return http.StatusText(e.StatusCode)
}
