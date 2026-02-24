package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"text/template"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/matzhouse/ts-spiffe/pkg/authkey"
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

	// APIBaseURL overrides the Tailscale API base URL (e.g. for testing).
	// When empty, defaults to https://api.tailscale.com/api/v2.
	APIBaseURL string `hcl:"api_base_url"`
}

// Plugin implements the SPIRE server-side node attestor.
type Plugin struct {
	serverv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	mu     sync.RWMutex
	config *Config
	logger hclog.Logger

	trustDomain  string
	apiClient    TailscaleAPIClient
	pathTemplate *template.Template
}

// SetLogger implements the pluginsdk.NeedsLogger interface.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.mu.Lock()
	defer p.mu.Unlock()
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

	// Extract trust domain from core configuration.
	var trustDomain string
	if req.CoreConfiguration != nil {
		trustDomain = req.CoreConfiguration.TrustDomain
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = cfg
	p.trustDomain = trustDomain
	p.pathTemplate = tmpl

	// Only create a real API client if one hasn't been injected (for testing).
	if p.apiClient == nil {
		var tokenFunc func(context.Context) (string, error)
		if cfg.OAuthClientID != "" {
			oc := authkey.NewOAuthClient(cfg.OAuthClientID, cfg.OAuthClientSecret)
			tokenFunc = oc.Token
		} else {
			apiKey := cfg.APIKey
			tokenFunc = func(context.Context) (string, error) { return apiKey, nil }
		}
		p.apiClient = &httpAPIClient{
			httpClient: &http.Client{Timeout: defaultHTTPTimeout},
			baseURL:    cfg.APIBaseURL,
			tokenFunc:  tokenFunc,
		}
	}

	return &configv1.ConfigureResponse{}, nil
}

// verifiedNodeData holds API-verified device attributes used for building
// selectors and rendering the SPIFFE ID template. This is derived from the
// Tailscale control plane response (DeviceInfo), NOT the agent-supplied payload.
type verifiedNodeData struct {
	NodeID      string
	Hostname    string
	DNSName     string
	TailnetName string
	OS          string
	User        string
	Tags        []string
	Addresses   []string
}

func newVerifiedNodeData(device *DeviceInfo) *verifiedNodeData {
	return &verifiedNodeData{
		NodeID:      device.ID,
		Hostname:    device.Hostname,
		DNSName:     device.Name,
		TailnetName: device.TailnetName,
		OS:          device.OS,
		User:        device.User,
		Tags:        device.Tags,
		Addresses:   device.Addresses,
	}
}

// Attest implements the server-side node attestor. It receives the attestation
// payload from the agent, validates it against the Tailscale API, and returns
// the SPIFFE ID and selectors derived from API-verified device data.
func (p *Plugin) Attest(stream serverv1.NodeAttestor_AttestServer) error {
	p.mu.RLock()
	config := p.config
	trustDomain := p.trustDomain
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
	if payload.NodeKey == "" {
		return status.Error(codes.InvalidArgument, "attestation payload missing node_key")
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
		return status.Error(codes.PermissionDenied, "node key mismatch")
	}

	// Build verified data from the API response — this is the source of truth
	// for selectors and SPIFFE ID, not the agent-supplied payload.
	verified := newVerifiedNodeData(device)

	// Check tailnet allow list against API-verified tailnet name.
	if len(config.TailnetAllowList) > 0 {
		allowed := false
		for _, tn := range config.TailnetAllowList {
			if tn == verified.TailnetName {
				allowed = true
				break
			}
		}
		if !allowed {
			return status.Errorf(codes.PermissionDenied,
				"tailnet %q is not in the allow list", verified.TailnetName)
		}
	}

	// Compute SPIFFE ID path from template using API-verified data.
	var pathBuf bytes.Buffer
	if err := pathTemplate.Execute(&pathBuf, verified); err != nil {
		return status.Errorf(codes.Internal, "failed to execute agent path template: %v", err)
	}
	agentPath := pathBuf.String()

	// Validate the rendered SPIFFE ID path.
	if agentPath == "" || !strings.HasPrefix(agentPath, "/") {
		return status.Errorf(codes.Internal, "agent path template produced invalid SPIFFE ID path: %q", agentPath)
	}

	// Construct the full SPIFFE ID URI. SPIRE expects the complete URI
	// (spiffe://trust-domain/path) in the AgentAttributes response.
	agentID := "spiffe://" + trustDomain + agentPath

	// Build selectors from API-verified device data.
	var selectors []string
	if verified.Hostname != "" {
		selectors = append(selectors, "hostname:"+verified.Hostname)
	}
	if verified.OS != "" {
		selectors = append(selectors, "os:"+verified.OS)
	}
	if verified.TailnetName != "" {
		selectors = append(selectors, "tailnet:"+verified.TailnetName)
	}
	if verified.User != "" {
		selectors = append(selectors, "user:"+verified.User)
	}
	if verified.NodeID != "" {
		selectors = append(selectors, "node_id:"+verified.NodeID)
	}
	for _, tag := range verified.Tags {
		selectors = append(selectors, "tag:"+tag)
	}
	for _, addr := range verified.Addresses {
		selectors = append(selectors, "ip:"+addr)
	}

	if err := stream.Send(&serverv1.AttestResponse{
		Response: &serverv1.AttestResponse_AgentAttributes{
			AgentAttributes: &serverv1.AgentAttributes{
				SpiffeId:       agentID,
				SelectorValues: selectors,
				CanReattest:    config.AllowReattestation,
			},
		},
	}); err != nil {
		return err
	}

	return nil
}
