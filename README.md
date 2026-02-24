# ts-spiffe

SPIFFE node attestation for [Tailscale](https://tailscale.com). A [SPIRE](https://spiffe.io/docs/latest/spire-about/) node attestor plugin that uses Tailscale node identity to issue SPIFFE IDs, plus a CLI tool for generating Tailscale auth keys for containers.

## How It Works

```
┌─────────────────────┐         ┌─────────────────────┐
│  SPIRE Agent        │         │  SPIRE Server       │
│  + Agent Plugin     │         │  + Server Plugin    │
│                     │         │                     │
│  Queries tailscaled │──JSON──▶│  Validates against  │
│  for node identity  │ payload │  Tailscale API      │
└────────┬────────────┘         └────────┬────────────┘
         │                               │
         ▼                               ▼
   ┌───────────┐                 ┌───────────────┐
   │ tailscaled │                 │ Tailscale     │
   │ (local)    │                 │ Control Plane │
   └───────────┘                 └───────────────┘
```

1. The **agent plugin** queries the local `tailscaled` daemon for the node's identity (node ID, node key, hostname, tailnet, tags, IPs, etc.)
2. It sends this as a JSON attestation payload to the SPIRE server
3. The **server plugin** calls the Tailscale control plane API to verify the node exists, is authorized, and that the node key matches
4. On success, it assigns a SPIFFE ID and selectors derived from the node's Tailscale attributes

No challenge/response is needed — verification relies on the Tailscale control plane as the source of truth (similar to how GCP IIT attestation relies on Google's JWKS).

## Building

```bash
make build
```

This produces three binaries in `bin/`:
- `nodeattestor-tailscale-agent` — SPIRE agent-side plugin
- `nodeattestor-tailscale-server` — SPIRE server-side plugin
- `ts-authkey` — Auth key fetcher CLI

Individual targets: `make build-agent`, `make build-server`, `make build-authkey`.

## SPIRE Plugin Configuration

### Agent

Add to your SPIRE agent configuration:

```hcl
NodeAttestor "tailscale" {
    plugin_cmd = "/opt/spire/plugins/nodeattestor-tailscale-agent"
    plugin_checksum = "<sha256>"
    plugin_data {
        # Optional: override the tailscaled socket path
        # socket_path = "/var/run/tailscale/tailscaled.sock"
    }
}
```

The agent plugin needs access to the tailscaled Unix socket. On most systems the default path works automatically.

### Server

Add to your SPIRE server configuration:

```hcl
NodeAttestor "tailscale" {
    plugin_cmd = "/opt/spire/plugins/nodeattestor-tailscale-server"
    plugin_checksum = "<sha256>"
    plugin_data {
        # Option 1: OAuth client credentials (recommended)
        oauth_client_id     = "your-client-id"
        oauth_client_secret = "your-client-secret"

        # Option 2: Static API key (dev/testing only)
        # api_key = "tskey-api-..."
    }
}
```

#### Server Configuration Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `api_key` | string | One of `api_key` or OAuth pair | Static Tailscale API key |
| `oauth_client_id` | string | One of `api_key` or OAuth pair | Tailscale OAuth client ID |
| `oauth_client_secret` | string | Required with `oauth_client_id` | Tailscale OAuth client secret |
| `tailnet_allow_list` | list(string) | No | Restrict attestation to these tailnets. If empty, all tailnets are allowed |
| `agent_path_template` | string | No | Go template for the SPIFFE ID path. Default: `/spire/agent/tailscale/{{ .TailnetName }}/{{ .NodeID }}` |
| `allow_reattestation` | bool | No | Allow re-attestation. Default: `false` (TOFU) |

### Example: Full SPIRE Deployment

**SPIRE Server** (`server.conf`):

```hcl
server {
    bind_address = "0.0.0.0"
    bind_port    = "8081"
    trust_domain = "example.com"
    data_dir     = "/opt/spire/data/server"
}

plugins {
    NodeAttestor "tailscale" {
        plugin_cmd = "/opt/spire/plugins/nodeattestor-tailscale-server"
        plugin_data {
            oauth_client_id     = "k1234567890abcdef"
            oauth_client_secret = "tskey-client-secret..."
            tailnet_allow_list  = ["example.com"]
        }
    }

    # ... other plugins (DataStore, KeyManager, etc.)
}
```

**SPIRE Agent** (`agent.conf`):

```hcl
agent {
    data_dir     = "/opt/spire/data/agent"
    server_address = "spire-server"
    server_port    = "8081"
    trust_domain   = "example.com"
}

plugins {
    NodeAttestor "tailscale" {
        plugin_cmd = "/opt/spire/plugins/nodeattestor-tailscale-agent"
        plugin_data {}
    }

    # ... other plugins (KeyManager, WorkloadAttestor, etc.)
}
```

## SPIFFE IDs and Selectors

### SPIFFE ID

The attested agent receives a SPIFFE ID based on the configured path template. With the default template, a node with ID `nStable123` on tailnet `example.com` gets:

```
spiffe://example.com/spire/agent/tailscale/example.com/nStable123
```

The template has access to all `AttestationPayload` fields: `NodeID`, `Hostname`, `DNSName`, `TailnetName`, `OS`, `UserID`.

Custom template example — identify by hostname:

```hcl
agent_path_template = "/spire/agent/tailscale/{{ .Hostname }}"
```

### Selectors

The server plugin produces selectors that can be used in SPIRE registration entries to target specific nodes:

| Selector | Example |
|---|---|
| `tailscale:hostname:<value>` | `tailscale:hostname:webserver-01` |
| `tailscale:os:<value>` | `tailscale:os:linux` |
| `tailscale:tailnet:<value>` | `tailscale:tailnet:example.com` |
| `tailscale:user:<value>` | `tailscale:user:42` |
| `tailscale:node_id:<value>` | `tailscale:node_id:nStable123` |
| `tailscale:tag:<value>` | `tailscale:tag:tag:web` |
| `tailscale:ip:<value>` | `tailscale:ip:100.64.0.1` |

#### Using Selectors in Registration Entries

Grant a SPIFFE ID to all Linux nodes with the `tag:web` ACL tag:

```bash
spire-server entry create \
    -spiffeID spiffe://example.com/web-service \
    -parentID "spiffe://example.com/spire/agent/tailscale/example.com/nStable123" \
    -selector tailscale:os:linux \
    -selector tailscale:tag:tag:web
```

## Auth Key Fetcher (`ts-authkey`)

A standalone CLI for generating Tailscale auth keys — useful for onboarding containers or VMs to your tailnet.

### Usage

```bash
ts-authkey \
    --client-id "$TS_OAUTH_CLIENT_ID" \
    --client-secret "$TS_OAUTH_CLIENT_SECRET" \
    --tailnet example.com \
    --tags tag:container \
    --ephemeral \
    --preauthorized \
    --expiry 1h
```

This prints the auth key to stdout:

```
tskey-auth-abc123...
```

### Flags

| Flag | Default | Env Var | Description |
|---|---|---|---|
| `--client-id` | | `TS_OAUTH_CLIENT_ID` | Tailscale OAuth client ID (required) |
| `--client-secret` | | `TS_OAUTH_CLIENT_SECRET` | Tailscale OAuth client secret (required) |
| `--tailnet` | `-` | `TS_TAILNET` | Tailscale tailnet name |
| `--ephemeral` | `true` | | Key creates ephemeral nodes |
| `--preauthorized` | `true` | | Key creates pre-authorized nodes |
| `--tags` | | | Comma-separated ACL tags (e.g. `tag:container,tag:web`) |
| `--expiry` | `1h` | | Key expiry duration |

### Example: Docker Container Onboarding

Generate an auth key and pass it to a container:

```bash
AUTH_KEY=$(ts-authkey \
    --tags tag:container \
    --ephemeral \
    --expiry 30m)

docker run -d \
    -e TS_AUTHKEY="$AUTH_KEY" \
    my-tailscale-app
```

### Example: Using as a Library

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/matzhouse/ts-spiffe/pkg/authkey"
)

func main() {
    ctx := context.Background()
    oauth := authkey.NewOAuthClient("client-id", "client-secret")
    fetcher := authkey.NewFetcher(oauth.Token)

    resp, err := fetcher.CreateAuthKey(ctx, authkey.AuthKeyRequest{
        Tailnet:       "example.com",
        Ephemeral:     true,
        Preauthorized: true,
        Tags:          []string{"tag:container"},
        Expiry:        30 * time.Minute,
    })
    if err != nil {
        panic(err)
    }

    fmt.Println("Key:", resp.Key)
    fmt.Println("Expires:", resp.Expires)
}
```

## Security Model

- **Trust-on-first-use (TOFU)**: By default, `allow_reattestation = false`. Once a node attests, it cannot re-attest with the same identity. This prevents a compromised node key from being used to impersonate the original node.
- **Node key verification**: The server compares the node key reported by the agent against what the Tailscale control plane knows, ensuring the attesting node actually holds the key registered with Tailscale.
- **Authorization check**: Only nodes marked as `authorized` in Tailscale are allowed to attest.
- **Tailnet allow list**: Optionally restrict which tailnets can attest, preventing nodes from unexpected networks.
- **OAuth client credentials**: For production, OAuth is preferred over static API keys. Tokens are automatically cached and refreshed.

## Development

```bash
make build    # Build all binaries
make test     # Run all tests
make lint     # Run go vet
make clean    # Remove build artifacts
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
