# Deploying ts-spiffe on a Real Tailnet

This guide walks through deploying the SPIRE Tailscale node attestation plugins on a production Tailnet. Both bare metal and container-based deployments are covered.

## Prerequisites

- A [Tailscale](https://tailscale.com) account with an active tailnet
- At least two machines (or containers) joined to the tailnet — one for the SPIRE server, one or more for SPIRE agents
- Go 1.25+ (if building from source)
- Docker and Docker Compose (if using the container deployment)

## Step 1: Create Tailscale OAuth Credentials

The SPIRE server plugin needs to call the Tailscale API to verify node identity. OAuth client credentials are the recommended method for production.

1. Go to the [Tailscale admin console](https://login.tailscale.com/admin/settings/oauth)
2. Click **Generate OAuth Client**
3. Grant the following scopes:
   - **Devices: Read** — required to look up and verify attesting nodes
   - **Auth Keys: Write** — only if you also plan to use `ts-authkey` to onboard containers
4. Save the **Client ID** and **Client Secret** — you will need both

## Step 2: Build the Binaries

### From source

```bash
git clone https://github.com/matzhouse/ts-spiffe.git
cd ts-spiffe
make build
```

This produces static binaries in `bin/`:

```
bin/nodeattestor-tailscale-agent
bin/nodeattestor-tailscale-server
bin/ts-authkey
```

### Generate checksums (optional but recommended)

```bash
make checksums
```

This creates `bin/checksums.txt`. You can use these SHA-256 values in the SPIRE plugin configs for integrity verification.

---

## Option A: Bare Metal Deployment

This option runs SPIRE and the plugins directly on machines that are already joined to your tailnet.

### A.1 Install Tailscale on All Machines

Every machine that will run a SPIRE agent must have Tailscale installed and authenticated:

```bash
# Install Tailscale (Linux example — see https://tailscale.com/download for other OSes)
curl -fsSL https://tailscale.com/install.sh | sh

# Authenticate
sudo tailscale up
```

Verify the node is connected:

```bash
tailscale status
```

The SPIRE server machine also needs Tailscale if it will communicate with agents over the tailnet (recommended).

### A.2 Install SPIRE

Download SPIRE from the [official releases](https://github.com/spiffe/spire/releases). For example:

```bash
SPIRE_VERSION=1.14.1

# Download and extract
curl -fsSL https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-amd64-musl.tar.gz \
  | tar xz -C /opt

# Symlink for convenience
ln -s /opt/spire-${SPIRE_VERSION} /opt/spire
```

### A.3 Deploy the Plugins

Copy the plugin binaries to the SPIRE server and agent machines:

```bash
# On the SPIRE server machine:
sudo cp bin/nodeattestor-tailscale-server /opt/spire/bin/

# On each SPIRE agent machine:
sudo cp bin/nodeattestor-tailscale-agent /opt/spire/bin/
```

### A.4 Configure the SPIRE Server

Create `/opt/spire/conf/server/server.conf`:

```hcl
server {
    bind_address = "0.0.0.0"
    bind_port    = "8081"
    trust_domain = "example.com"
    data_dir     = "/opt/spire/data/server"
    log_level    = "INFO"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type     = "sqlite3"
            connection_string = "/opt/spire/data/server/datastore.sqlite3"
        }
    }

    KeyManager "disk" {
        plugin_data {
            keys_path = "/opt/spire/data/server/keys.json"
        }
    }

    NodeAttestor "tailscale" {
        plugin_cmd = "/opt/spire/bin/nodeattestor-tailscale-server"
        plugin_data {
            oauth_client_id     = "YOUR_OAUTH_CLIENT_ID"
            oauth_client_secret = "YOUR_OAUTH_CLIENT_SECRET"

            # Restrict to your tailnet (recommended)
            tailnet_allow_list = ["example.com"]

            # TOFU: once a node attests, it cannot re-attest with the same identity.
            # Set to true during initial testing, then switch to false for production.
            allow_reattestation = false
        }
    }
}
```

Replace:
- `example.com` in `trust_domain` with your SPIFFE trust domain
- `YOUR_OAUTH_CLIENT_ID` / `YOUR_OAUTH_CLIENT_SECRET` with the values from Step 1
- `example.com` in `tailnet_allow_list` with your actual tailnet name (visible at `tailscale status` or in the admin console)

### A.5 Configure the SPIRE Agent

Create `/opt/spire/conf/agent/agent.conf` on each agent machine:

```hcl
agent {
    data_dir       = "/opt/spire/data/agent"
    log_level      = "INFO"
    server_address = "spire-server-hostname"
    server_port    = "8081"
    trust_domain   = "example.com"

    # For the first agent, you need to bootstrap trust.
    # Option 1: Use insecure bootstrap (testing only)
    # insecure_bootstrap = true

    # Option 2: Provide the server's trust bundle (production)
    trust_bundle_path = "/opt/spire/conf/agent/bootstrap.crt"
}

plugins {
    NodeAttestor "tailscale" {
        plugin_cmd = "/opt/spire/bin/nodeattestor-tailscale-agent"
        plugin_data {
            # Uses the default tailscaled socket path.
            # Uncomment to override:
            # socket_path = "/var/run/tailscale/tailscaled.sock"
        }
    }

    KeyManager "disk" {
        plugin_data {
            directory = "/opt/spire/data/agent"
        }
    }

    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
```

Replace:
- `spire-server-hostname` with the Tailscale hostname or IP of the SPIRE server (e.g., `spire-server.tail1234.ts.net` or a Tailscale IP like `100.x.y.z`)
- `example.com` with the same trust domain used on the server

**Trust bootstrapping:** For the first agent, either use `insecure_bootstrap = true` (testing only) or extract the server's CA bundle and distribute it. See the [SPIRE documentation on bootstrapping](https://spiffe.io/docs/latest/deploying/configuring/#trust-bundle-bootstrapping).

### A.6 Start the Services

On the server:

```bash
sudo mkdir -p /opt/spire/data/server
sudo /opt/spire/bin/spire-server run -config /opt/spire/conf/server/server.conf
```

On each agent (after the server is healthy):

```bash
sudo mkdir -p /opt/spire/data/agent
sudo /opt/spire/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf
```

### A.7 Verify Attestation

On the server machine, check that the agent attested successfully:

```bash
/opt/spire/bin/spire-server agent list
```

You should see an entry like:

```
Found 1 attested agent:

SPIFFE ID         : spiffe://example.com/spire/agent/tailscale/example.com/nXXXXXXXXXX
Attestation type  : tailscale
Serial number     : ...
Expires at        : ...
```

---

## Option B: Container Deployment

This option runs SPIRE and the plugins in containers. Each container joins the tailnet using Tailscale's container support.

### B.1 Project Structure

Create the following directory structure for your deployment:

```
deploy/
├── docker-compose.yml
├── Dockerfile
└── conf/
    ├── server.conf
    └── agent.conf
```

### B.2 Dockerfile

```dockerfile
# --- Build plugins ---
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /out/nodeattestor-tailscale-agent ./cmd/agent/
RUN CGO_ENABLED=0 go build -o /out/nodeattestor-tailscale-server ./cmd/server/

# --- SPIRE Server with Tailscale sidecar ---
FROM ghcr.io/spiffe/spire-server:1.14.1 AS spire-server
COPY --from=builder /out/nodeattestor-tailscale-server /opt/spire/bin/nodeattestor-tailscale-server

# --- SPIRE Agent with Tailscale sidecar ---
FROM ghcr.io/spiffe/spire-agent:1.14.1 AS spire-agent
COPY --from=builder /out/nodeattestor-tailscale-agent /opt/spire/bin/nodeattestor-tailscale-agent
```

### B.3 Docker Compose

```yaml
services:
  # --- Tailscale sidecar for the SPIRE server ---
  ts-server:
    image: tailscale/tailscale:latest
    hostname: spire-server
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    environment:
      - TS_AUTHKEY=${TS_SERVER_AUTHKEY}
      - TS_STATE_DIR=/var/lib/tailscale
      - TS_USERSPACE=false
    volumes:
      - ts-server-state:/var/lib/tailscale
    restart: unless-stopped

  # --- SPIRE Server ---
  spire-server:
    build:
      context: ..
      dockerfile: deploy/Dockerfile
      target: spire-server
    network_mode: "service:ts-server"
    depends_on:
      - ts-server
    volumes:
      - ./conf/server.conf:/opt/spire/conf/server/server.conf:ro
      - spire-server-data:/opt/spire/data/server
    restart: unless-stopped

  # --- Tailscale sidecar for the SPIRE agent ---
  ts-agent:
    image: tailscale/tailscale:latest
    hostname: spire-agent
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    environment:
      - TS_AUTHKEY=${TS_AGENT_AUTHKEY}
      - TS_STATE_DIR=/var/lib/tailscale
      - TS_USERSPACE=false
    volumes:
      - ts-agent-state:/var/lib/tailscale
      - tailscale-sock:/var/run/tailscale
    restart: unless-stopped

  # --- SPIRE Agent ---
  spire-agent:
    build:
      context: ..
      dockerfile: deploy/Dockerfile
      target: spire-agent
    network_mode: "service:ts-agent"
    depends_on:
      - ts-agent
      - spire-server
    volumes:
      - ./conf/agent.conf:/opt/spire/conf/agent/agent.conf:ro
      - tailscale-sock:/var/run/tailscale:ro
      - spire-agent-data:/opt/spire/data/agent
    restart: unless-stopped

volumes:
  ts-server-state:
  ts-agent-state:
  tailscale-sock:
  spire-server-data:
  spire-agent-data:
```

Key points:
- Each SPIRE container shares its network namespace with a Tailscale sidecar (`network_mode: "service:ts-*"`)
- The agent container mounts the `tailscale-sock` volume to access `tailscaled`'s Unix socket for attestation
- Auth keys are passed via environment variables

### B.4 Configuration Files

**`deploy/conf/server.conf`:**

```hcl
server {
    bind_address = "0.0.0.0"
    bind_port    = "8081"
    trust_domain = "example.com"
    data_dir     = "/opt/spire/data/server"
    log_level    = "INFO"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type     = "sqlite3"
            connection_string = "/opt/spire/data/server/datastore.sqlite3"
        }
    }

    KeyManager "disk" {
        plugin_data {
            keys_path = "/opt/spire/data/server/keys.json"
        }
    }

    NodeAttestor "tailscale" {
        plugin_cmd = "/opt/spire/bin/nodeattestor-tailscale-server"
        plugin_data {
            oauth_client_id     = "YOUR_OAUTH_CLIENT_ID"
            oauth_client_secret = "YOUR_OAUTH_CLIENT_SECRET"
            tailnet_allow_list  = ["example.com"]
            allow_reattestation = false
        }
    }
}
```

**`deploy/conf/agent.conf`:**

```hcl
agent {
    data_dir       = "/opt/spire/data/agent"
    log_level      = "INFO"
    server_address = "spire-server"
    server_port    = "8081"
    trust_domain   = "example.com"

    # Use insecure bootstrap for initial testing only.
    # For production, distribute the server trust bundle.
    insecure_bootstrap = true
}

plugins {
    NodeAttestor "tailscale" {
        plugin_cmd = "/opt/spire/bin/nodeattestor-tailscale-agent"
        plugin_data {
            socket_path = "/var/run/tailscale/tailscaled.sock"
        }
    }

    KeyManager "disk" {
        plugin_data {
            directory = "/opt/spire/data/agent"
        }
    }

    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
```

### B.5 Generate Auth Keys and Deploy

Use `ts-authkey` to generate auth keys for the containers, then start the stack:

```bash
# Build ts-authkey if you haven't already
make build-authkey

# Generate auth keys for each container
export TS_SERVER_AUTHKEY=$(bin/ts-authkey \
    --client-id "$TS_OAUTH_CLIENT_ID" \
    --client-secret "$TS_OAUTH_CLIENT_SECRET" \
    --tags tag:spire-server \
    --ephemeral=false \
    --expiry 10m)

export TS_AGENT_AUTHKEY=$(bin/ts-authkey \
    --client-id "$TS_OAUTH_CLIENT_ID" \
    --client-secret "$TS_OAUTH_CLIENT_SECRET" \
    --tags tag:spire-agent \
    --ephemeral \
    --expiry 10m)

# Start the stack
docker compose -f deploy/docker-compose.yml up -d --build
```

Note: the server key uses `--ephemeral=false` so the node persists across restarts. Agent keys can be ephemeral since agents can re-attest (if `allow_reattestation = true` during testing).

### B.6 Verify

Check the Tailscale admin console to confirm both containers have joined the tailnet, then verify attestation:

```bash
docker compose -f deploy/docker-compose.yml exec spire-server \
    /opt/spire/bin/spire-server agent list
```

---

## Step 3: Create Workload Registration Entries

Once agents are attested, create registration entries to assign SPIFFE IDs to workloads. Selectors from the Tailscale attestor let you target nodes by tailnet attributes.

### Example: Grant an SVID to all nodes tagged `tag:web`

```bash
spire-server entry create \
    -spiffeID spiffe://example.com/web-service \
    -parentID "spiffe://example.com/spire/agent/tailscale/example.com/nXXXXXXXX" \
    -selector tailscale:tag:tag:web
```

### Example: Grant an SVID to all Linux nodes in a specific tailnet

```bash
spire-server entry create \
    -spiffeID spiffe://example.com/linux-service \
    -parentID "spiffe://example.com/spire/agent/tailscale/example.com/nXXXXXXXX" \
    -selector tailscale:os:linux \
    -selector tailscale:tailnet:example.com
```

### Available Selectors

| Selector | Description |
|---|---|
| `tailscale:hostname:<value>` | Machine hostname |
| `tailscale:os:<value>` | Operating system |
| `tailscale:tailnet:<value>` | Tailnet name |
| `tailscale:user:<value>` | Tailscale user ID |
| `tailscale:node_id:<value>` | Tailscale node ID |
| `tailscale:tag:<value>` | ACL tag (e.g., `tag:web`) |
| `tailscale:ip:<value>` | Tailscale IP address |

---

## Tailscale ACL Recommendations

Add ACL rules to your tailnet policy to restrict which nodes can reach the SPIRE server:

```jsonc
{
  "acls": [
    // Allow SPIRE agents to reach the SPIRE server
    {
      "action": "accept",
      "src": ["tag:spire-agent"],
      "dst": ["tag:spire-server:8081"]
    }
  ],
  "tagOwners": {
    "tag:spire-server": ["autogroup:admin"],
    "tag:spire-agent":  ["autogroup:admin"]
  }
}
```

This ensures only tagged SPIRE agents can connect to the server's attestation port.

---

## Troubleshooting

### Agent fails to attest: "node not found"

- Verify the agent machine is joined to the tailnet: `tailscale status`
- Check that the OAuth credentials have the **Devices: Read** scope
- Confirm `tailnet_allow_list` on the server matches the agent's tailnet name

### Agent fails to attest: "node key mismatch"

- The node key reported by the local `tailscaled` does not match what the Tailscale API returns
- This can happen if the node re-authenticated with a new key. Remove the old device from the admin console and retry

### Agent fails to attest: "reattestation not allowed"

- `allow_reattestation` is `false` (the default) and this node has already attested
- Either set `allow_reattestation = true`, or remove the agent entry from SPIRE: `spire-server agent evict -spiffeID <id>`

### Plugin not loading

- Check that the binary is executable: `chmod +x /opt/spire/bin/nodeattestor-tailscale-*`
- Check SPIRE logs for plugin startup errors (set `log_level = "DEBUG"`)
- Verify the binary architecture matches the host (e.g., `file /opt/spire/bin/nodeattestor-tailscale-server`)

### Container cannot access tailscaled socket

- Ensure the `tailscale-sock` volume is shared between the Tailscale sidecar and the SPIRE agent container
- Verify the socket exists: `docker compose exec spire-agent ls -la /var/run/tailscale/`

### OAuth token errors

- Double-check the client ID and secret
- Ensure the OAuth client has not expired in the Tailscale admin console
- Check server logs for the specific error from the Tailscale API
