package server

import (
	"context"
	"encoding/json"
	"errors"
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

func TestAttest_Success(t *testing.T) {
	payload := common.AttestationPayload{
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

	// Check selectors.
	selectorMap := make(map[string]bool)
	for _, s := range attrs.SelectorValues {
		selectorMap[s] = true
	}

	expectedSelectors := []string{
		"hostname:myhost",
		"os:linux",
		"tailnet:example.com",
		"user:42",
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
	payload := common.AttestationPayload{
		NodeID:      "node123",
		NodeKey:     "nodekey:abc123",
		TailnetName: "evil.com",
	}

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

func TestAttest_AllowReattestation(t *testing.T) {
	payload := common.AttestationPayload{
		NodeID:      "node123",
		NodeKey:     "nodekey:abc123",
		TailnetName: "example.com",
	}

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
				Payload: makePayload(t, payload),
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
