package common

// PluginName is the name used to register the plugin with SPIRE.
const PluginName = "tailscale"

// SelectorType is the type used for SPIRE selectors produced by this attestor.
const SelectorType = "tailscale"

// DefaultAgentPathTemplate is the default SPIFFE ID path template for attested agents.
const DefaultAgentPathTemplate = "/spire/agent/tailscale/{{ .TailnetName }}/{{ .NodeID }}"

// AttestationPayload is the data sent from the agent to the server during node attestation.
type AttestationPayload struct {
	NodeID       string   `json:"node_id"`
	NodeKey      string   `json:"node_key"`
	Hostname     string   `json:"hostname"`
	DNSName      string   `json:"dns_name"`
	TailnetName  string   `json:"tailnet_name"`
	OS           string   `json:"os"`
	UserID       string   `json:"user_id"`
	Tags         []string `json:"tags,omitempty"`
	TailscaleIPs []string `json:"tailscale_ips,omitempty"`
}
