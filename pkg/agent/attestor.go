package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/matzhouse/ts-spiffe/pkg/common"
	agentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config holds the HCL configuration for the agent plugin.
type Config struct {
	SocketPath string `hcl:"socket_path"`
}

// Plugin implements the SPIRE agent-side node attestor.
type Plugin struct {
	agentv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	mu     sync.RWMutex
	config *Config
	logger hclog.Logger

	// tsClient is the Tailscale local client used to query node status.
	// Set during Configure; can be overridden for testing.
	tsClient TailscaleStatusGetter
}

// SetLogger implements the pluginsdk.NeedsLogger interface.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

// Configure parses HCL configuration and initialises the Tailscale local client.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg := &Config{}
	if err := hcl.Decode(cfg, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = cfg

	// Only create a real Tailscale client if one hasn't been injected (for testing).
	if p.tsClient == nil {
		p.tsClient = newLocalClient(cfg.SocketPath)
	}

	return &configv1.ConfigureResponse{}, nil
}

// AidAttestation implements the agent-side node attestor. It queries the local
// tailscaled daemon for node identity and sends the attestation payload.
func (p *Plugin) AidAttestation(stream agentv1.NodeAttestor_AidAttestationServer) error {
	p.mu.RLock()
	config := p.config
	client := p.tsClient
	p.mu.RUnlock()

	if config == nil {
		return status.Error(codes.FailedPrecondition, "plugin not configured")
	}
	if client == nil {
		return status.Error(codes.FailedPrecondition, "tailscale client not available")
	}

	ctx := stream.Context()
	st, err := client.StatusWithoutPeers(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get tailscale status: %v", err)
	}

	if st.Self == nil {
		return status.Error(codes.Internal, "tailscale status has no Self entry; is tailscaled running?")
	}

	self := st.Self

	// Build IP list.
	var ips []string
	for _, ip := range self.TailscaleIPs {
		ips = append(ips, ip.String())
	}

	// Build tags list.
	var tags []string
	if self.Tags != nil {
		for i := range self.Tags.Len() {
			tags = append(tags, self.Tags.At(i))
		}
	}

	// Determine tailnet name.
	var tailnetName string
	if st.CurrentTailnet != nil {
		tailnetName = st.CurrentTailnet.Name
	}

	// Determine user ID.
	var userID string
	if self.UserID != 0 {
		userID = fmt.Sprintf("%d", self.UserID)
	}

	payload := common.AttestationPayload{
		NodeID:       string(self.ID),
		NodeKey:      self.PublicKey.String(),
		Hostname:     self.HostName,
		DNSName:      self.DNSName,
		TailnetName:  tailnetName,
		OS:           self.OS,
		UserID:       userID,
		Tags:         tags,
		TailscaleIPs: ips,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal attestation payload: %v", err)
	}

	if err := stream.Send(&agentv1.PayloadOrChallengeResponse{
		Data: &agentv1.PayloadOrChallengeResponse_Payload{
			Payload: payloadBytes,
		},
	}); err != nil {
		return err
	}

	return nil
}
