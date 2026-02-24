FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build all binaries statically.
RUN CGO_ENABLED=0 go build -o /out/nodeattestor-tailscale-agent ./cmd/agent/
RUN CGO_ENABLED=0 go build -o /out/nodeattestor-tailscale-server ./cmd/server/
RUN CGO_ENABLED=0 go build -o /out/mock-tailscale ./e2e/mock-tailscale/

# --- Mock Tailscale ---
FROM alpine:3 AS mock-tailscale
COPY --from=builder /out/mock-tailscale /usr/local/bin/mock-tailscale
ENTRYPOINT ["mock-tailscale"]

# --- SPIRE Server with plugin ---
FROM ghcr.io/spiffe/spire-server:1.14.1 AS spire-server
COPY --from=builder /out/nodeattestor-tailscale-server /opt/spire/bin/nodeattestor-tailscale-server
COPY e2e/conf/server.conf /opt/spire/conf/server/server.conf

# --- SPIRE Agent with plugin ---
FROM ghcr.io/spiffe/spire-agent:1.14.1 AS spire-agent
COPY --from=builder /out/nodeattestor-tailscale-agent /opt/spire/bin/nodeattestor-tailscale-agent
COPY e2e/conf/agent.conf /opt/spire/conf/agent/agent.conf
