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
	device *DeviceInfo
	err    error
}

func (m *mockAPIClient) GetDevice(_ context.Context, _ string) (*DeviceInfo, error) {
	return m.device, m.err
}

// fakeAttestStream captures sent responses and provides a canned request.
type fakeAttestStream struct {
	serverv1.NodeAttestor_AttestServer
	ctx     context.Context
	request *serverv1.AttestRequest
	sent    []*serverv1.AttestResponse
}

func (f *fakeAttestStream) Context() context.Context { return f.ctx }

func (f *fakeAttestStream) Recv() (*serverv1.AttestRequest, error) {
	if f.request == nil {
		return nil, errors.New("no request")
	}
	return f.request, nil
}

func (f *fakeAttestStream) Send(resp *serverv1.AttestResponse) error {
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

func TestAttest_Success(t *testing.T) {
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
	}

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

	stream := &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			Request: &serverv1.AttestRequest_Payload{
				Payload: makePayload(t, payload),
			},
		},
	}

	if err := p.Attest(stream); err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	attrs := stream.sent[0].GetAgentAttributes()
	selectorMap := make(map[string]bool)
	for _, s := range attrs.SelectorValues {
		selectorMap[s] = true
	}

	// Must have API-verified values, not agent-claimed values.
	if selectorMap["hostname:agent-claimed-host"] {
		t.Error("selector should not contain agent-claimed hostname")
	}
	if !selectorMap["hostname:myhost"] {
		t.Error("selector should contain API-verified hostname 'myhost'")
	}
	if selectorMap["os:agent-claimed-os"] {
		t.Error("selector should not contain agent-claimed OS")
	}
	if !selectorMap["os:linux"] {
		t.Error("selector should contain API-verified OS 'linux'")
	}
	if !selectorMap["user:user@example.com"] {
		t.Error("selector should contain API-verified user")
	}
}

func TestAttest_NodeKeyMismatch(t *testing.T) {
	payload := common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "nodekey:abc123",
	}

	mock := &mockAPIClient{
		device: &DeviceInfo{
			ID:         "node123",
			NodeKey:    "nodekey:DIFFERENT",
			Authorized: true,
		},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			Request: &serverv1.AttestRequest_Payload{
				Payload: makePayload(t, payload),
			},
		},
	}

	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for node key mismatch, got nil")
	}
	// Must not leak actual key values in the error message.
	if strings.Contains(err.Error(), "nodekey:DIFFERENT") {
		t.Error("error message must not contain the actual API node key")
	}
	if strings.Contains(err.Error(), "nodekey:abc123") {
		t.Error("error message must not contain the agent-claimed node key")
	}
}

func TestAttest_EmptyNodeKey(t *testing.T) {
	payload := common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "",
	}

	mock := &mockAPIClient{
		device: &DeviceInfo{
			ID:         "node123",
			NodeKey:    "nodekey:abc123",
			Authorized: true,
		},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			Request: &serverv1.AttestRequest_Payload{
				Payload: makePayload(t, payload),
			},
		},
	}

	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for empty node key, got nil")
	}
}

func TestAttest_UnauthorizedDevice(t *testing.T) {
	payload := common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "nodekey:abc123",
	}

	mock := &mockAPIClient{
		device: &DeviceInfo{
			ID:         "node123",
			NodeKey:    "nodekey:abc123",
			Authorized: false,
		},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			Request: &serverv1.AttestRequest_Payload{
				Payload: makePayload(t, payload),
			},
		},
	}

	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for unauthorized device, got nil")
	}
}

func TestAttest_TailnetNotAllowed(t *testing.T) {
	// Agent claims "evil.com" but the API returns a different tailnet.
	// The allow list check must use the API-verified tailnet.
	payload := common.AttestationPayload{
		NodeID:      "node123",
		NodeKey:     "nodekey:abc123",
		TailnetName: "good.com", // agent lies, claiming an allowed tailnet
	}

	mock := &mockAPIClient{
		device: &DeviceInfo{
			ID:          "node123",
			NodeKey:     "nodekey:abc123",
			Authorized:  true,
			TailnetName: "evil.com", // API says the real tailnet is evil.com
		},
	}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `
		api_key = "tskey-api-test"
		tailnet_allow_list = ["good.com", "also-good.com"]
	`)

	stream := &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			Request: &serverv1.AttestRequest_Payload{
				Payload: makePayload(t, payload),
			},
		},
	}

	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for tailnet not in allow list, got nil")
	}
}

func TestAttest_TailnetAllowed(t *testing.T) {
	payload := common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "nodekey:abc123",
	}

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

	stream := &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			Request: &serverv1.AttestRequest_Payload{
				Payload: makePayload(t, payload),
			},
		},
	}

	if err := p.Attest(stream); err != nil {
		t.Fatalf("Attest should succeed for allowed tailnet: %v", err)
	}
}

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

	stream := &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			Request: &serverv1.AttestRequest_Payload{
				Payload: makePayload(t, common.AttestationPayload{
					NodeID:  "node123",
					NodeKey: "nodekey:abc123",
				}),
			},
		},
	}

	if err := p.Attest(stream); err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	attrs := stream.sent[0].GetAgentAttributes()
	if !attrs.CanReattest {
		t.Error("expected CanReattest = true")
	}
}

func TestAttest_APIError(t *testing.T) {
	payload := common.AttestationPayload{
		NodeID:  "node123",
		NodeKey: "nodekey:abc123",
	}

	mock := &mockAPIClient{err: errors.New("API unreachable")}

	p := &Plugin{apiClient: mock}
	configurePlugin(t, p, `api_key = "tskey-api-test"`)

	stream := &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			Request: &serverv1.AttestRequest_Payload{
				Payload: makePayload(t, payload),
			},
		},
	}

	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error for API failure, got nil")
	}
}

func TestAttest_NotConfigured(t *testing.T) {
	p := &Plugin{}
	stream := &fakeAttestStream{
		ctx: context.Background(),
		request: &serverv1.AttestRequest{
			Request: &serverv1.AttestRequest_Payload{
				Payload: []byte(`{}`),
			},
		},
	}

	err := p.Attest(stream)
	if err == nil {
		t.Fatal("expected error when not configured, got nil")
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

func TestConfigure_InvalidHCL(t *testing.T) {
	p := &Plugin{}
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: `{{invalid`,
	})
	if err == nil {
		t.Fatal("expected error for invalid HCL, got nil")
	}
}
