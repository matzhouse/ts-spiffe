package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"github.com/matzhouse/ts-spiffe/pkg/common"
	agentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// mockStatusGetter implements TailscaleStatusGetter for tests.
type mockStatusGetter struct {
	status *ipnstate.Status
	err    error
}

func (m *mockStatusGetter) StatusWithoutPeers(_ context.Context) (*ipnstate.Status, error) {
	return m.status, m.err
}

// fakeStream captures the payload sent by AidAttestation.
type fakeStream struct {
	agentv1.NodeAttestor_AidAttestationServer
	ctx     context.Context
	sent    []*agentv1.PayloadOrChallengeResponse
	sendErr error
}

func (f *fakeStream) Context() context.Context { return f.ctx }

func (f *fakeStream) Send(resp *agentv1.PayloadOrChallengeResponse) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, resp)
	return nil
}

// fullStatus returns a complete tailscale status for a happy-path test.
func fullStatus() *ipnstate.Status {
	nodeKey := key.NewNode().Public()
	tags := views.SliceOf([]string{"tag:web", "tag:prod"})

	return &ipnstate.Status{
		Self: &ipnstate.PeerStatus{
			ID:           "stable123",
			PublicKey:    nodeKey,
			HostName:     "myhost",
			DNSName:      "myhost.tail1234.ts.net.",
			OS:           "linux",
			UserID:       tailcfg.UserID(42),
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
			Tags:         &tags,
		},
		CurrentTailnet: &ipnstate.TailnetStatus{
			Name: "example.com",
		},
	}
}

func configureAgent(t *testing.T, p *Plugin, hcl string) {
	t.Helper()
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: hcl,
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}
}

func aidAndUnmarshal(t *testing.T, p *Plugin) common.AttestationPayload {
	t.Helper()
	stream := &fakeStream{ctx: context.Background()}
	if err := p.AidAttestation(stream); err != nil {
		t.Fatalf("AidAttestation failed: %v", err)
	}
	if len(stream.sent) != 1 {
		t.Fatalf("expected 1 message sent, got %d", len(stream.sent))
	}
	payloadData := stream.sent[0].GetPayload()
	if payloadData == nil {
		t.Fatal("expected payload, got nil")
	}
	var payload common.AttestationPayload
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	return payload
}

func TestAidAttestation_Success(t *testing.T) {
	st := fullStatus()
	mock := &mockStatusGetter{status: st}

	p := &Plugin{tsClient: mock}
	configureAgent(t, p, `socket_path = "/tmp/test.sock"`)

	payload := aidAndUnmarshal(t, p)

	if payload.NodeID != "stable123" {
		t.Errorf("NodeID = %q, want %q", payload.NodeID, "stable123")
	}
	if payload.NodeKey != st.Self.PublicKey.String() {
		t.Errorf("NodeKey = %q, want %q", payload.NodeKey, st.Self.PublicKey.String())
	}
	if payload.Hostname != "myhost" {
		t.Errorf("Hostname = %q, want %q", payload.Hostname, "myhost")
	}
	if payload.DNSName != "myhost.tail1234.ts.net." {
		t.Errorf("DNSName = %q, want %q", payload.DNSName, "myhost.tail1234.ts.net.")
	}
	if payload.TailnetName != "example.com" {
		t.Errorf("TailnetName = %q, want %q", payload.TailnetName, "example.com")
	}
	if payload.OS != "linux" {
		t.Errorf("OS = %q, want %q", payload.OS, "linux")
	}
	if payload.UserID != "42" {
		t.Errorf("UserID = %q, want %q", payload.UserID, "42")
	}
	if len(payload.Tags) != 2 || payload.Tags[0] != "tag:web" || payload.Tags[1] != "tag:prod" {
		t.Errorf("Tags = %v, want [tag:web tag:prod]", payload.Tags)
	}
	if len(payload.TailscaleIPs) != 1 || payload.TailscaleIPs[0] != "100.64.0.1" {
		t.Errorf("TailscaleIPs = %v, want [100.64.0.1]", payload.TailscaleIPs)
	}
}

func TestAidAttestation_NilCurrentTailnet(t *testing.T) {
	st := fullStatus()
	st.CurrentTailnet = nil
	mock := &mockStatusGetter{status: st}

	p := &Plugin{tsClient: mock}
	configureAgent(t, p, `{}`)

	payload := aidAndUnmarshal(t, p)

	if payload.TailnetName != "" {
		t.Errorf("TailnetName = %q, want empty string", payload.TailnetName)
	}
}

func TestAidAttestation_ZeroUserID(t *testing.T) {
	st := fullStatus()
	st.Self.UserID = 0
	mock := &mockStatusGetter{status: st}

	p := &Plugin{tsClient: mock}
	configureAgent(t, p, `{}`)

	payload := aidAndUnmarshal(t, p)

	if payload.UserID != "" {
		t.Errorf("UserID = %q, want empty string for zero UserID", payload.UserID)
	}
}

func TestAidAttestation_NilTags(t *testing.T) {
	st := fullStatus()
	st.Self.Tags = nil
	mock := &mockStatusGetter{status: st}

	p := &Plugin{tsClient: mock}
	configureAgent(t, p, `{}`)

	payload := aidAndUnmarshal(t, p)

	if len(payload.Tags) != 0 {
		t.Errorf("Tags = %v, want empty", payload.Tags)
	}
}

func TestAidAttestation_NoTailscaleIPs(t *testing.T) {
	st := fullStatus()
	st.Self.TailscaleIPs = nil
	mock := &mockStatusGetter{status: st}

	p := &Plugin{tsClient: mock}
	configureAgent(t, p, `{}`)

	payload := aidAndUnmarshal(t, p)

	if len(payload.TailscaleIPs) != 0 {
		t.Errorf("TailscaleIPs = %v, want empty", payload.TailscaleIPs)
	}
}

func TestAidAttestation_MultipleIPs(t *testing.T) {
	st := fullStatus()
	st.Self.TailscaleIPs = []netip.Addr{
		netip.MustParseAddr("100.64.0.1"),
		netip.MustParseAddr("fd7a:115c:a1e0::1"),
	}
	mock := &mockStatusGetter{status: st}

	p := &Plugin{tsClient: mock}
	configureAgent(t, p, `{}`)

	payload := aidAndUnmarshal(t, p)

	if len(payload.TailscaleIPs) != 2 {
		t.Fatalf("TailscaleIPs count = %d, want 2", len(payload.TailscaleIPs))
	}
	if payload.TailscaleIPs[0] != "100.64.0.1" {
		t.Errorf("TailscaleIPs[0] = %q, want %q", payload.TailscaleIPs[0], "100.64.0.1")
	}
	if payload.TailscaleIPs[1] != "fd7a:115c:a1e0::1" {
		t.Errorf("TailscaleIPs[1] = %q, want %q", payload.TailscaleIPs[1], "fd7a:115c:a1e0::1")
	}
}

func TestAidAttestation_NotConfigured(t *testing.T) {
	p := &Plugin{}
	stream := &fakeStream{ctx: context.Background()}
	err := p.AidAttestation(stream)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAidAttestation_NilClient(t *testing.T) {
	// Config is set but tsClient is nil (edge case).
	p := &Plugin{config: &Config{}}
	stream := &fakeStream{ctx: context.Background()}
	err := p.AidAttestation(stream)
	if err == nil {
		t.Fatal("expected error for nil client, got nil")
	}
}

func TestAidAttestation_TailscaledError(t *testing.T) {
	mock := &mockStatusGetter{err: errors.New("connection refused")}

	p := &Plugin{tsClient: mock, config: &Config{}}
	stream := &fakeStream{ctx: context.Background()}
	err := p.AidAttestation(stream)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAidAttestation_NilSelf(t *testing.T) {
	mock := &mockStatusGetter{
		status: &ipnstate.Status{Self: nil},
	}

	p := &Plugin{tsClient: mock, config: &Config{}}
	stream := &fakeStream{ctx: context.Background()}
	err := p.AidAttestation(stream)
	if err == nil {
		t.Fatal("expected error when Self is nil, got nil")
	}
}

func TestAidAttestation_SendError(t *testing.T) {
	mock := &mockStatusGetter{status: fullStatus()}

	p := &Plugin{tsClient: mock, config: &Config{}}
	stream := &fakeStream{
		ctx:     context.Background(),
		sendErr: errors.New("stream broken"),
	}
	err := p.AidAttestation(stream)
	if err == nil {
		t.Fatal("expected error when Send fails, got nil")
	}
}

func TestConfigure_EmptyConfig(t *testing.T) {
	p := &Plugin{tsClient: &mockStatusGetter{}} // pre-inject client
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: `{}`,
	})
	if err != nil {
		t.Fatalf("Configure with empty config should succeed: %v", err)
	}
}

func TestConfigure_WithSocketPath(t *testing.T) {
	p := &Plugin{}
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: `socket_path = "/custom/path.sock"`,
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}
	if p.config.SocketPath != "/custom/path.sock" {
		t.Errorf("SocketPath = %q, want %q", p.config.SocketPath, "/custom/path.sock")
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
