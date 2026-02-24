package authkey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultAPIBase = "https://api.tailscale.com/api/v2"

// AuthKeyRequest specifies the parameters for creating a Tailscale auth key.
type AuthKeyRequest struct {
	Tailnet       string
	Ephemeral     bool
	Preauthorized bool
	Tags          []string
	Expiry        time.Duration
}

// AuthKeyResponse holds the created auth key details.
type AuthKeyResponse struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	Ephemeral bool      `json:"ephemeral"`
}

// Fetcher creates Tailscale auth keys via the API.
type Fetcher struct {
	tokenFunc  func() (string, error)
	httpClient *http.Client
	apiBase    string
}

// FetcherOption configures a Fetcher.
type FetcherOption func(*Fetcher)

// WithAPIBase overrides the Tailscale API base URL (for testing).
func WithAPIBase(url string) FetcherOption {
	return func(f *Fetcher) { f.apiBase = url }
}

// WithFetcherHTTPClient overrides the HTTP client (for testing).
func WithFetcherHTTPClient(hc *http.Client) FetcherOption {
	return func(f *Fetcher) { f.httpClient = hc }
}

// NewFetcher creates a Fetcher that uses the given token function for auth.
func NewFetcher(tokenFunc func() (string, error), opts ...FetcherOption) *Fetcher {
	f := &Fetcher{
		tokenFunc:  tokenFunc,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiBase:    defaultAPIBase,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// apiKeyRequest is the JSON body sent to the Tailscale key creation API.
type apiKeyRequest struct {
	Capabilities  apiKeyCapabilities `json:"capabilities"`
	ExpirySeconds int64              `json:"expirySeconds,omitempty"`
}

type apiKeyCapabilities struct {
	Devices apiDeviceCapabilities `json:"devices"`
}

type apiDeviceCapabilities struct {
	Create apiDeviceCreate `json:"create"`
}

type apiDeviceCreate struct {
	Reusable      bool     `json:"reusable"`
	Ephemeral     bool     `json:"ephemeral"`
	Preauthorized bool     `json:"preauthorized"`
	Tags          []string `json:"tags"`
}

// CreateAuthKey creates a new Tailscale auth key with the given parameters.
func (f *Fetcher) CreateAuthKey(req AuthKeyRequest) (*AuthKeyResponse, error) {
	token, err := f.tokenFunc()
	if err != nil {
		return nil, fmt.Errorf("failed to get API token: %w", err)
	}

	tailnet := req.Tailnet
	if tailnet == "" {
		tailnet = "-" // default tailnet
	}
	if strings.Contains(tailnet, "/") || strings.Contains(tailnet, "..") {
		return nil, fmt.Errorf("invalid tailnet name: %q", tailnet)
	}

	apiReq := apiKeyRequest{
		Capabilities: apiKeyCapabilities{
			Devices: apiDeviceCapabilities{
				Create: apiDeviceCreate{
					Reusable:      false,
					Ephemeral:     req.Ephemeral,
					Preauthorized: req.Preauthorized,
					Tags:          req.Tags,
				},
			},
		},
	}
	if req.Expiry > 0 {
		apiReq.ExpirySeconds = int64(req.Expiry.Seconds())
	}

	bodyBytes, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key request: %w", err)
	}

	reqURL := fmt.Sprintf("%s/tailnet/%s/keys", f.apiBase, url.PathEscape(tailnet))
	httpReq, err := http.NewRequest(http.MethodPost, reqURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := f.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("auth key request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth key request returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var keyResp AuthKeyResponse
	if err := json.Unmarshal(respBody, &keyResp); err != nil {
		return nil, fmt.Errorf("failed to decode key response: %w", err)
	}

	return &keyResp, nil
}
