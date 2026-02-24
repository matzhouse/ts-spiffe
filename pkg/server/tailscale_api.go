package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const defaultAPIBase = "https://api.tailscale.com/api/v2"

const defaultHTTPTimeout = 30 * time.Second

// DeviceInfo represents the relevant fields from the Tailscale API device response.
type DeviceInfo struct {
	ID          string   `json:"id"`
	NodeKey     string   `json:"nodeKey"`
	Hostname    string   `json:"hostname"`
	Name        string   `json:"name"`
	OS          string   `json:"os"`
	Authorized  bool     `json:"authorized"`
	Tags        []string `json:"tags"`
	TailnetName string   `json:"tailnetName"`
	User        string   `json:"user"`
	Addresses   []string `json:"addresses"`
}

// TailscaleAPIClient abstracts the Tailscale control plane API for testing.
type TailscaleAPIClient interface {
	GetDevice(ctx context.Context, nodeID string) (*DeviceInfo, error)
}

// httpAPIClient is the production implementation that calls the Tailscale API.
type httpAPIClient struct {
	httpClient *http.Client
	baseURL    string
	// tokenFunc returns a current Bearer token. This allows both static API keys
	// and OAuth token refresh.
	tokenFunc func(context.Context) (string, error)
}

func (c *httpAPIClient) GetDevice(ctx context.Context, nodeID string) (*DeviceInfo, error) {
	token, err := c.tokenFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get API token: %w", err)
	}

	base := c.baseURL
	if base == "" {
		base = defaultAPIBase
	}

	reqURL := fmt.Sprintf("%s/device/%s", base, url.PathEscape(nodeID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Tailscale API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Tailscale API returned status %d: %s", resp.StatusCode, string(body))
	}

	var device DeviceInfo
	if err := json.Unmarshal(body, &device); err != nil {
		return nil, fmt.Errorf("failed to decode device response: %w", err)
	}

	return &device, nil
}
