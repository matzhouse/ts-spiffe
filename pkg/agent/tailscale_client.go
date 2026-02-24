package agent

import (
	"context"

	"tailscale.com/ipn/ipnstate"
)

// TailscaleStatusGetter abstracts the tailscale local client for testing.
type TailscaleStatusGetter interface {
	StatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error)
}
