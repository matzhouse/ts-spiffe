package agent

import (
	"context"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
)

// localClientWrapper wraps the real tailscale local.Client to satisfy
// TailscaleStatusGetter.
type localClientWrapper struct {
	client local.Client
}

func newLocalClient(socketPath string) *localClientWrapper {
	w := &localClientWrapper{}
	if socketPath != "" {
		w.client.Socket = socketPath
	}
	return w
}

func (w *localClientWrapper) StatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error) {
	return w.client.StatusWithoutPeers(ctx)
}
