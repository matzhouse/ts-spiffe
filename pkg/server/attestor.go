package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"text/template"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/matzhouse/ts-spiffe/pkg/common"
	serverv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config holds the HCL configuration for the server plugin.
type Config struct {
	// APIKey is a static Tailscale API key (for dev/testing).
	APIKey string `hcl:"api_key"`

	// OAuthClientID and OAuthClientSecret enable OAuth client credentials flow.
	OAuthClientID     string `hcl:"oauth_client_id"`
	OAuthClientSecret string `hcl:"oauth_client_secret"`

	// TailnetAllowList restricts attestation to nodes in these tailnets.
	// If empty, all tailnets are allowed.
	TailnetAllowList []string `hcl:"tailnet_allow_list"`

	// AgentPathTemplate is a Go text/template for the SPIFFE ID agent path.
	AgentPathTemplate string `hcl:"agent_path_template"`

	// AllowReattestation controls whether a node can re-attest (default: false = TOFU).
	AllowReattestation bool `hcl:"allow_reattestation"`
}

// Plugin implements the SPIRE server-side node attestor.
type Plugin struct {
	serverv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	mu     sync.RWMutex
	config *Config
	logger hclog.Logger

	apiClient    TailscaleAPIClient
	pathTemplate *template.Template
}

// SetLogger implements the pluginsdk.NeedsLogger interface.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

// Configure parses HCL configuration and initialises the API client.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg := &Config{}
	if err := hcl.Decode(cfg, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	if cfg.APIKey == "" && (cfg.OAuthClientID == "" || cfg.OAuthClientSecret == "") {
		return nil, status.Error(codes.InvalidArgument, "either api_key or oauth_client_id + oauth_client_secret must be set")
	}

	tmplStr := cfg.AgentPathTemplate
	if tmplStr == "" {
		tmplStr = common.DefaultAgentPathTemplate
	}
	tmpl, err := template.New("agent_path").Parse(tmplStr)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid agent_path_template: %v", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = cfg
	p.pathTemplate = tmpl

	// Only create a real API client if one hasn't been injected (for testing).
	if p.apiClient == nil {
		var tokenFunc func() (string, error)
		if cfg.OAuthClientID != "" {
			oc := newOAuthClient(cfg.OAuthClientID, cfg.OAuthClientSecret)
			tokenFunc = oc.Token
		} else {
			apiKey := cfg.APIKey
			tokenFunc = func() (string, error) { return apiKey, nil }
		}
		p.apiClient = &httpAPIClient{
			httpClient: http.DefaultClient,
			tokenFunc:  tokenFunc,
		}
	}

	return &configv1.ConfigureResponse{}, nil
}

// Attest implements the server-side node attestor. It receives the attestation
// payload from the agent, validates it against the Tailscale API, and returns
// the SPIFFE ID and selectors.
func (p *Plugin) Attest(stream serverv1.NodeAttestor_AttestServer) error {
	p.mu.RLock()
	config := p.config
	apiClient := p.apiClient
	pathTemplate := p.pathTemplate
	p.mu.RUnlock()

	if config == nil {
		return status.Error(codes.FailedPrecondition, "plugin not configured")
	}

	// Receive the initial attestation request.
	req, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.Internal, "failed to receive attestation request: %v", err)
	}

	payloadBytes := req.GetPayload()
	if payloadBytes == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	var payload common.AttestationPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal attestation payload: %v", err)
	}

	if payload.NodeID == "" {
		return status.Error(codes.InvalidArgument, "attestation payload missing node_id")
	}

	// Verify against Tailscale API.
	ctx := stream.Context()
	device, err := apiClient.GetDevice(ctx, payload.NodeID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to verify node with Tailscale API: %v", err)
	}

	if !device.Authorized {
		return status.Error(codes.PermissionDenied, "node is not authorized in Tailscale")
	}

	// Verify node key matches what the control plane reports.
	if device.NodeKey != payload.NodeKey {
		return status.Errorf(codes.PermissionDenied,
			"node key mismatch: agent reported %q but Tailscale API reports %q",
			payload.NodeKey, device.NodeKey)
	}

	// Check tailnet allow list.
	if len(config.TailnetAllowList) > 0 {
		allowed := false
		for _, tn := range config.TailnetAllowList {
			if tn == payload.TailnetName {
				allowed = true
				break
			}
		}
		if !allowed {
			return status.Errorf(codes.PermissionDenied,
				"tailnet %q is not in the allow list", payload.TailnetName)
		}
	}

	// Compute SPIFFE ID path from template.
	var pathBuf bytes.Buffer
	if err := pathTemplate.Execute(&pathBuf, payload); err != nil {
		return status.Errorf(codes.Internal, "failed to execute agent path template: %v", err)
	}
	agentPath := pathBuf.String()

	// Build selectors.
	var selectors []string
	if payload.Hostname != "" {
		selectors = append(selectors, "hostname:"+payload.Hostname)
	}
	if payload.OS != "" {
		selectors = append(selectors, "os:"+payload.OS)
	}
	if payload.TailnetName != "" {
		selectors = append(selectors, "tailnet:"+payload.TailnetName)
	}
	if payload.UserID != "" {
		selectors = append(selectors, "user:"+payload.UserID)
	}
	if payload.NodeID != "" {
		selectors = append(selectors, "node_id:"+payload.NodeID)
	}
	for _, tag := range payload.Tags {
		selectors = append(selectors, "tag:"+tag)
	}
	for _, ip := range payload.TailscaleIPs {
		selectors = append(selectors, "ip:"+ip)
	}

	// Build the full SPIFFE ID. The trust domain is provided by SPIRE core;
	// we just return the path component and SPIRE prepends spiffe://<trust-domain>.
	spiffeID := agentPath

	if err := stream.Send(&serverv1.AttestResponse{
		Response: &serverv1.AttestResponse_AgentAttributes{
			AgentAttributes: &serverv1.AgentAttributes{
				SpiffeId:       spiffeID,
				SelectorValues: selectors,
				CanReattest:    config.AllowReattestation,
			},
		},
	}); err != nil {
		return err
	}

	return nil
}

// oauthClient handles OAuth2 client credentials flow for the Tailscale API.
type oauthClient struct {
	clientID     string
	clientSecret string
	mu           sync.Mutex
	token        string
}

func newOAuthClient(clientID, clientSecret string) *oauthClient {
	return &oauthClient{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// Token returns a valid access token, fetching a new one if needed.
func (c *oauthClient) Token() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// For simplicity, always fetch a new token. In production this should
	// cache and refresh based on expiry.
	token, err := fetchOAuthToken(c.clientID, c.clientSecret)
	if err != nil {
		return "", err
	}
	c.token = token
	return token, nil
}

func fetchOAuthToken(clientID, clientSecret string) (string, error) {
	body := strings.NewReader("grant_type=client_credentials")
	req, err := http.NewRequest(http.MethodPost, "https://api.tailscale.com/api/v2/oauth/token", body)
	if err != nil {
		return "", fmt.Errorf("failed to create oauth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("oauth token request returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode oauth token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("oauth token response missing access_token")
	}

	return tokenResp.AccessToken, nil
}
