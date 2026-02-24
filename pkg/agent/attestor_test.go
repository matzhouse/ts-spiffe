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
	ctx  context.Context
	sent []*agentv1.PayloadOrChallengeResponse
}

func (f *fakeStream) Context() context.Context { return f.ctx }

func (f *fakeStream) Send(resp *agentv1.PayloadOrChallengeResponse) error {
	f.sent = append(f.sent, resp)
	return nil
}

func TestAidAttestation_Success(t *testing.T) {
	nodeKey := key.NewNode().Public()
	tags := views.SliceOf([]string{"tag:web", "tag:prod"})

	mock := &mockStatusGetter{
		status: &ipnstate.Status{
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
		},
	}

	p := &Plugin{tsClient: mock}
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: `socket_path = "/tmp/test.sock"`,
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

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

	if payload.NodeID != "stable123" {
		t.Errorf("NodeID = %q, want %q", payload.NodeID, "stable123")
	}
	if payload.NodeKey != nodeKey.String() {
		t.Errorf("NodeKey = %q, want %q", payload.NodeKey, nodeKey.String())
	}
	if payload.Hostname != "myhost" {
		t.Errorf("Hostname = %q, want %q", payload.Hostname, "myhost")
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

func TestAidAttestation_NotConfigured(t *testing.T) {
	p := &Plugin{}
	stream := &fakeStream{ctx: context.Background()}
	err := p.AidAttestation(stream)
	if err == nil {
		t.Fatal("expected error, got nil")
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

func TestConfigure_InvalidHCL(t *testing.T) {
	p := &Plugin{}
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: `{{invalid`,
	})
	if err == nil {
		t.Fatal("expected error for invalid HCL, got nil")
	}
}
