#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE="docker compose"

cleanup() {
    echo "--- Cleaning up ---"
    $COMPOSE down -v 2>/dev/null || true
}
trap cleanup EXIT

dump_logs() {
    echo "--- Service logs ---"
    $COMPOSE logs 2>/dev/null || true
}

echo "=== Building E2E images ==="
$COMPOSE build

echo "=== Starting services ==="
$COMPOSE up -d

echo "=== Waiting for SPIRE server to become healthy ==="
TIMEOUT=60
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if $COMPOSE exec -T spire-server /opt/spire/bin/spire-server healthcheck 2>/dev/null; then
        echo "SPIRE server is healthy."
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "ERROR: SPIRE server did not become healthy within ${TIMEOUT}s"
    dump_logs
    exit 1
fi

echo "=== Waiting for agent attestation ==="
TIMEOUT=60
ELAPSED=0
EXPECTED_SPIFFE_ID="spiffe://e2e-test.example.com/spire/agent/tailscale/test.ts.net/e2e-test-node"

while [ $ELAPSED -lt $TIMEOUT ]; do
    AGENT_LIST=$($COMPOSE exec -T spire-server /opt/spire/bin/spire-server agent list 2>/dev/null || true)
    if echo "$AGENT_LIST" | grep -q "e2e-test-node"; then
        echo ""
        echo "=== SUCCESS: Agent attested ==="
        echo "$AGENT_LIST"

        if echo "$AGENT_LIST" | grep -q "$EXPECTED_SPIFFE_ID"; then
            echo ""
            echo "SPIFFE ID matches expected: $EXPECTED_SPIFFE_ID"
        else
            echo ""
            echo "WARNING: Expected SPIFFE ID not found: $EXPECTED_SPIFFE_ID"
        fi

        echo ""
        echo "=== E2E test PASSED ==="
        exit 0
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

echo "ERROR: Agent did not attest within ${TIMEOUT}s"
dump_logs
exit 1
