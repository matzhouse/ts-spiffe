package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/matzhouse/ts-spiffe/pkg/common"
	serverv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

// mockAPIClient implements TailscaleAPIClient for tests.
type mockAPIClient struct {
	device  *DeviceInfo
	err     error
	gotID   string // captures the nodeID passed to GetDevice
}

func (m *mockAPIClient) GetDevice(_ context.Context, nodeID string) (*DeviceInfo, error) {
	m.gotID = nodeID
	return m.device, m.err
}

// fakeAttestStream captures sent responses and provides a canned request.
type fakeAttestStream struct {
	serverv1.NodeAttestor_AttestServer
	ctx     context.Context
	request *serverv1.AttestRequest
	sent    []*serverv1.AttestResponse
	recvErr error
	sendErr error
}

func (f *fakeAttestStream) Context() context.Context { return f.ctx }

func (f *fakeAttestStream) Recv() (*serverv1.AttestRequest, error) {
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	if f.request == nil {
		return nil, errors.New("no request")
	}
	return f.request, nil
}

func (f *fakeAttestStream) Send(resp *serverv1.AttestResponse) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, resp)
	return nil
}

func makePayload(t *testing.T, p common.AttestationPayload) []byte {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	return b
}

func configurePlugin(t *testing.T, p *Plugin, hclConfig string) {
	t.Helper()
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: hclConfig,
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}
}

func newStream(payload []byte) *fakeAttestStream {
	return &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			Request: &serverv1.AttestRequest_Payload{
				Payload: payload,
			},
		},
	}
}

// fullDevice returns a DeviceInfo with all fields populated for testing.
func fullDevice() *DeviceInfo {
	return &DeviceInfo{
		ID:          "node123",
		NodeKey:     "nodekey:abc123",
		Hostname:    "myhost",
		Name:        "myhost.example.ts.net.",
		OS:          "linux",
		Authorized:  true,
		Tags:        []string{"tag:web", "tag:prod"},
		TailnetName: "example.com",
		User:        "user@example.com",
		Addresses:   []string{"100.64.0.1"},
	}
}

// fullPayload returns an AttestationPayload matching fullDevice() for testing.
func fullPayload() common.AttestationPayload {
	return common.AttestationPayload{
		NodeID:       "node123",
		NodeKey:      "nodekey:abc123",
		Hostname:     "myhost",
		DNSName:      "myhost.example.ts.net.",
		TailnetName:  "example.com",
		OS:           "linux",
		UserID:       "42",
		Tags:         []string{"tag:web", "tag:prod"},
		TailscaleIPs: []string{"100.64.0.1"},
	}
}

// --- Attest: happy paths ---

func TestAttest_Success(t *testing.T) {
	mock := &mockAPIClient{device: fullDevice()}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := newStream(makePayload(t, fullPayload()))
	if err := p.Attest(stream); err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	if len(stream.sent) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.sent))
	}

	attrs := stream.sent[0].GetAgentAttributes()
	if attrs == nil {
		t.Fatal("expected AgentAttributes, got nil")
	}

	expectedPath := "/spire/agent/tailscale/example.com/node123"
	if attrs.SpiffeId != expectedPath {
		t.Errorf("SpiffeId = %q, want %q", attrs.SpiffeId, expectedPath)
	}

	if attrs.CanReattest {
		t.Error("expected CanReattest = false (TOFU default)")
	}

	// Check selectors are derived from API-verified DeviceInfo.
	selectorMap := make(map[string]bool)
	for _, s := range attrs.SelectorValues {
		selectorMap[s] = true
	}

	expectedSelectors := []string{
		"hostname:myhost",
		"os:linux",
		"tailnet:example.com",
		"user:user@example.com",
		"node_id:node123",
		"tag:tag:web",
		"tag:tag:prod",
		"ip:100.64.0.1",
	}
	for _, s := range expectedSelectors {
		if !selectorMap[s] {
			t.Errorf("missing selector %q", s)
		}
	}
	// Verify no extra selectors.
	if len(attrs.SelectorValues) != len(expectedSelectors) {
		t.Errorf("selector count = %d, want %d", len(attrs.SelectorValues), len(expectedSelectors))
	}
}

func TestAttest_MinimalDevice(t *testing.T) {
	// Device with only required fields — no tags, addresses, user, etc.
	mock := &mockAPIClient{
		device: &DeviceInfo{
			ID:         "node123",
			NodeKey:    "nodekey:abc123",
			Authorized: true,
		},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := newStream(makePayload(t, common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "nodekey:abc123",
	}))

	if err := p.Attest(stream); err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	attrs := stream.sent[0].GetAgentAttributes()
	// Only node_id selector should exist.
	if len(attrs.SelectorValues) != 1 {
		t.Errorf("selector count = %d, want 1 (node_id only), got %v",
			len(attrs.SelectorValues), attrs.SelectorValues)
	}
}

func TestAttest_SelectorsFromAPINotPayload(t *testing.T) {
	// The agent payload claims different values than the API response.
	// Selectors must come from the API (DeviceInfo), not the payload.
	payload := common.AttestationPayload{
		NodeID:       "node123",
		NodeKey:      "nodekey:abc123",
		Hostname:     "agent-claimed-host",
		OS:           "agent-claimed-os",
		TailnetName:  "agent-claimed-tailnet",
		UserID:       "999",
		Tags:         []string{"tag:agent-claimed"},
		TailscaleIPs: []string{"10.0.0.1"},
	}

	mock := &mockAPIClient{device: fullDevice()}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := newStream(makePayload(t, payload))
	if err := p.Attest(stream); err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	attrs := stream.sent[0].GetAgentAttributes()
	selectorMap := make(map[string]bool)
	for _, s := range attrs.SelectorValues {
		selectorMap[s] = true
	}

	// Must have API-verified values, not agent-claimed values.
	agentClaimed := []string{
		"hostname:agent-claimed-host",
		"os:agent-claimed-os",
		"tailnet:agent-claimed-tailnet",
		"user:999",
		"tag:tag:agent-claimed",
		"ip:10.0.0.1",
	}
	for _, s := range agentClaimed {
		if selectorMap[s] {
			t.Errorf("selector should not contain agent-claimed value %q", s)
		}
	}

	apiVerified := []string{
		"hostname:myhost",
		"os:linux",
		"tailnet:example.com",
		"user:user@example.com",
	}
	for _, s := range apiVerified {
		if !selectorMap[s] {
			t.Errorf("selector should contain API-verified value %q", s)
		}
	}
}

func TestAttest_PassesNodeIDToAPI(t *testing.T) {
	mock := &mockAPIClient{device: fullDevice()}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := newStream(makePayload(t, fullPayload()))
	_ = p.Attest(stream)

	if mock.gotID != "node123" {
		t.Errorf("API called with nodeID = %q, want %q", mock.gotID, "node123")
	}
}

// --- Attest: custom template ---

func TestAttest_CustomPathTemplate(t *testing.T) {
	mock := &mockAPIClient{device: fullDevice()}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `
		api_key = "tskey-api-test"
		agent_path_template = "/custom/{{ .Hostname }}/{{ .NodeID }}"
	`)

	stream := newStream(makePayload(t, fullPayload()))
	if err := p.Attest(stream); err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	attrs := stream.sent[0].GetAgentAttributes()
	expected := "/custom/myhost/node123"
	if attrs.SpiffeId != expected {
		t.Errorf("SpiffeId = %q, want %q", attrs.SpiffeId, expected)
	}
}

func TestAttest_TemplateUsesAPIData(t *testing.T) {
	// Agent claims hostname "agent-host" but API says "api-host".
	// The template should use the API value.
	device := fullDevice()
	device.Hostname = "api-host"
	mock := &mockAPIClient{device: device}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `
		api_key = "tskey-api-test"
		agent_path_template = "/spire/agent/{{ .Hostname }}"
	`)

	payload := fullPayload()
	payload.Hostname = "agent-host"
	stream := newStream(makePayload(t, payload))
	if err := p.Attest(stream); err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	attrs := stream.sent[0].GetAgentAttributes()
	if attrs.SpiffeId != "/spire/agent/api-host" {
		t.Errorf("SpiffeId = %q, want /spire/agent/api-host", attrs.SpiffeId)
	}
}

// --- Attest: reattestation ---

func TestAttest_AllowReattestation(t *testing.T) {
	mock := &mockAPIClient{
		device: &DeviceInfo{
			ID:         "node123",
			NodeKey:    "nodekey:abc123",
			Authorized: true,
		},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `
		api_key = "tskey-api-test"
		allow_reattestation = true
	`)

	stream := newStream(makePayload(t, common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "nodekey:abc123",
	}))

	if err := p.Attest(stream); err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	attrs := stream.sent[0].GetAgentAttributes()
	if !attrs.CanReattest {
		t.Error("expected CanReattest = true")
	}
}

// --- Attest: tailnet allow list ---

func TestAttest_TailnetNotAllowed(t *testing.T) {
	payload := common.AttestationPayload{
		NodeID:      "node123",
		NodeKey:     "nodekey:abc123",
		TailnetName: "good.com", // agent lies
	}

	mock := &mockAPIClient{
		device: &DeviceInfo{
			ID:          "node123",
			NodeKey:     "nodekey:abc123",
			Authorized:  true,
			TailnetName: "evil.com", // API truth
		},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `
		api_key = "tskey-api-test"
		tailnet_allow_list = ["good.com", "also-good.com"]
	`)

	stream := newStream(makePayload(t, payload))
	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for tailnet not in allow list, got nil")
	}
}

func TestAttest_TailnetAllowed(t *testing.T) {
	mock := &mockAPIClient{
		device: &DeviceInfo{
			ID:          "node123",
			NodeKey:     "nodekey:abc123",
			Authorized:  true,
			TailnetName: "good.com",
		},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `
		api_key = "tskey-api-test"
		tailnet_allow_list = ["good.com"]
	`)

	stream := newStream(makePayload(t, common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "nodekey:abc123",
	}))

	if err := p.Attest(stream); err != nil {
		t.Fatalf("Attest should succeed for allowed tailnet: %v", err)
	}
}

func TestAttest_EmptyAllowListAllowsAll(t *testing.T) {
	mock := &mockAPIClient{
		device: &DeviceInfo{
			ID:          "node123",
			NodeKey:     "nodekey:abc123",
			Authorized:  true,
			TailnetName: "any-tailnet.com",
		},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := newStream(makePayload(t, common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "nodekey:abc123",
	}))

	if err := p.Attest(stream); err != nil {
		t.Fatalf("empty allow list should allow all tailnets: %v", err)
	}
}

// --- Attest: error paths ---

func TestAttest_NodeKeyMismatch(t *testing.T) {
	mock := &mockAPIClient{
		device: &DeviceInfo{
			ID:         "node123",
			NodeKey:    "nodekey:DIFFERENT",
			Authorized: true,
		},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := newStream(makePayload(t, common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "nodekey:abc123",
	}))

	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for node key mismatch, got nil")
	}
	// Must not leak actual key values.
	if strings.Contains(err.Error(), "nodekey:DIFFERENT") {
		t.Error("error message must not contain the actual API node key")
	}
	if strings.Contains(err.Error(), "nodekey:abc123") {
		t.Error("error message must not contain the agent-claimed node key")
	}
}

func TestAttest_EmptyNodeKey(t *testing.T) {
	mock := &mockAPIClient{
		device: &DeviceInfo{ID: "node123", NodeKey: "nodekey:abc123", Authorized: true},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := newStream(makePayload(t, common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "",
	}))

	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for empty node key, got nil")
	}
}

func TestAttest_EmptyNodeID(t *testing.T) {
	mock := &mockAPIClient{
		device: &DeviceInfo{ID: "node123", NodeKey: "nodekey:abc123", Authorized: true},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := newStream(makePayload(t, common.AttestationPayload{
		NodeID:  "",
		NodeKey: "nodekey:abc123",
	}))

	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for empty node ID, got nil")
	}
}

func TestAttest_UnauthorizedDevice(t *testing.T) {
	mock := &mockAPIClient{
		device: &DeviceInfo{
			ID:         "node123",
			NodeKey:    "nodekey:abc123",
			Authorized: false,
		},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := newStream(makePayload(t, common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "nodekey:abc123",
	}))

	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for unauthorized device, got nil")
	}
}

func TestAttest_APIError(t *testing.T) {
	mock := &mockAPIClient{err: errors.New("API unreachable")}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := newStream(makePayload(t, common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "nodekey:abc123",
	}))

	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for API failure, got nil")
	}
}

func TestAttest_NotConfigured(t *testing.T) {
	p := &Plugin{}
	stream := newStream([]byte(`{}`))

	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error when not configured, got nil")
	}
}

func TestAttest_InvalidPayloadJSON(t *testing.T) {
	mock := &mockAPIClient{device: fullDevice()}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := newStream([]byte(`{not valid json`))
	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestAttest_NilPayload(t *testing.T) {
	mock := &mockAPIClient{device: fullDevice()}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			// No payload set — the oneof is empty.
		},
	}
	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for nil payload, got nil")
	}
}

func TestAttest_RecvError(t *testing.T) {
	mock := &mockAPIClient{device: fullDevice()}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := &fakeAttestStream{
		ctx:     context.Background(),
		recvErr: errors.New("stream recv failed"),
	}
	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error when Recv fails, got nil")
	}
}

func TestAttest_SendError(t *testing.T) {
	mock := &mockAPIClient{device: fullDevice()}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			Request: &serverv1.AttestRequest_Payload{
				Payload: makePayload(t, fullPayload()),
			},
		},
		sendErr: errors.New("stream send failed"),
	}
	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error when Send fails, got nil")
	}
}

func TestAttest_InvalidRenderedPath(t *testing.T) {
	mock := &mockAPIClient{device: fullDevice()}

	p := &Plugin{apiClient: mock}
	// Template that produces a path without leading slash.
	configurePlugin(t, p, `
		api_key = "tskey-api-test"
		agent_path_template = "no-leading-slash/{{ .NodeID }}"
	`)

	stream := &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			Request: &serverv1.AttestRequest_Payload{
				Payload: makePayload(t, fullPayload()),
			},
		},
	}
	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for path without leading slash, got nil")
	}
	if !strings.Contains(err.Error(), "invalid SPIFFE ID path") {
		t.Errorf("error = %v, want mention of invalid SPIFFE ID path", err)
	}
}

// --- Configure ---

func TestConfigure_APIKeyAuth(t *testing.T) {
	p := &Plugin{}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	if p.config.APIKey != "tskey-api-test" {
		t.Errorf("APIKey = %q, want %q", p.config.APIKey, "tskey-api-test")
	}
	if p.apiClient == nil {
		t.Fatal("expected apiClient to be created")
	}
}

func TestConfigure_OAuthAuth(t *testing.T) {
	p := &Plugin{}
	configurePlugin(t, p, `
		oauth_client_id     = "test-client-id"
		oauth_client_secret = "test-client-secret"
	`)

	if p.config.OAuthClientID != "test-client-id" {
		t.Errorf("OAuthClientID = %q, want %q", p.config.OAuthClientID, "test-client-id")
	}
	if p.apiClient == nil {
		t.Fatal("expected apiClient to be created")
	}
}

func TestConfigure_MissingAuth(t *testing.T) {
	p := &Plugin{}
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: `{}`,
	})
	if err == nil {
		t.Fatal("expected error when no auth config provided, got nil")
	}
}

func TestConfigure_OAuthMissingSecret(t *testing.T) {
	p := &Plugin{}
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: `oauth_client_id = "test-id"`,
	})
	if err == nil {
		t.Fatal("expected error when oauth_client_secret is missing, got nil")
	}
}

func TestConfigure_InvalidHCL(t *testing.T) {
	p := &Plugin{}
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: `{{invalid`,
	})
	if err == nil {
		t.Fatal("expected error for invalid HCL, got nil")
	}
}

func TestConfigure_InvalidTemplate(t *testing.T) {
	p := &Plugin{}
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: `
			api_key = "tskey-api-test"
			agent_path_template = "{{ .Invalid | bad"
		`,
	})
	if err == nil {
		t.Fatal("expected error for invalid template, got nil")
	}
}
