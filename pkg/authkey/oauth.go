package authkey

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const defaultTokenURL = "https://api.tailscale.com/api/v2/oauth/token"

// OAuthClient handles OAuth2 client credentials flow for the Tailscale API.
type OAuthClient struct {
	clientID     string
	clientSecret string
	tokenURL     string
	httpClient   *http.Client

	mu          sync.Mutex
	accessToken string
	expiry      time.Time
}

// OAuthOption configures an OAuthClient.
type OAuthOption func(*OAuthClient)

// WithTokenURL overrides the token endpoint (for testing).
func WithTokenURL(url string) OAuthOption {
	return func(c *OAuthClient) { c.tokenURL = url }
}

// WithHTTPClient overrides the HTTP client (for testing).
func WithHTTPClient(hc *http.Client) OAuthOption {
	return func(c *OAuthClient) { c.httpClient = hc }
}

// NewOAuthClient creates an OAuth client for Tailscale API authentication.
func NewOAuthClient(clientID, clientSecret string, opts ...OAuthOption) *OAuthClient {
	c := &OAuthClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenURL:     defaultTokenURL,
		httpClient:   http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// Token returns a valid access token, refreshing if expired or near expiry.
func (c *OAuthClient) Token() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if still valid (with 30s buffer).
	if c.accessToken != "" && time.Now().Add(30*time.Second).Before(c.expiry) {
		return c.accessToken, nil
	}

	body := strings.NewReader("grant_type=client_credentials")
	req, err := http.NewRequest(http.MethodPost, c.tokenURL, body)
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("token response missing access_token")
	}

	c.accessToken = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		c.expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		// Default to 1 hour if not specified.
		c.expiry = time.Now().Add(1 * time.Hour)
	}

	return c.accessToken, nil
}
