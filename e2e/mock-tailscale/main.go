package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"tailscale.com/types/key"
)

// Test data shared between both mock endpoints.
var (
	nodeKey     key.NodePublic
	nodeKeyStr  string
	nodeID      = "e2e-test-node"
	tailnetName = "test.ts.net"
	hostname    = "e2e-host"
	dnsName     = "e2e-host.test.ts.net."
	tags        = []string{"tag:e2e"}
	addresses   = []string{"100.100.100.100"}
)

func init() {
	nodeKey = key.NewNode().Public()
	nodeKeyStr = nodeKey.String()
}

func main() {
	socketPath := "/var/run/tailscale/tailscaled.sock"

	// Start Unix socket server (mock tailscaled local API).
	if err := os.MkdirAll("/var/run/tailscale", 0o755); err != nil {
		log.Fatalf("failed to create socket dir: %v", err)
	}
	os.Remove(socketPath) // clean up any stale socket

	unixListener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("failed to listen on unix socket: %v", err)
	}
	// Make socket accessible to other containers.
	if err := os.Chmod(socketPath, 0o777); err != nil {
		log.Fatalf("failed to chmod socket: %v", err)
	}

	unixMux := http.NewServeMux()
	unixMux.HandleFunc("/localapi/v0/status", handleLocalStatus)

	go func() {
		log.Printf("mock tailscaled listening on %s", socketPath)
		if err := http.Serve(unixListener, unixMux); err != nil {
			log.Fatalf("unix server error: %v", err)
		}
	}()

	// Start TCP HTTP server (mock Tailscale control plane API).
	tcpMux := http.NewServeMux()
	tcpMux.HandleFunc("/api/v2/device/", handleGetDevice)
	tcpMux.HandleFunc("/healthz", handleHealthz)

	addr := ":8080"
	log.Printf("mock Tailscale API listening on %s", addr)
	log.Printf("using node key: %s", nodeKeyStr)
	if err := http.ListenAndServe(addr, tcpMux); err != nil {
		log.Fatalf("tcp server error: %v", err)
	}
}

// handleLocalStatus serves GET /localapi/v0/status — the mock tailscaled response.
// Returns ipnstate.Status-compatible JSON.
func handleLocalStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// This matches the structure that tailscale.com/ipn/ipnstate.Status unmarshals from.
	// The agent plugin calls StatusWithoutPeers which hits /localapi/v0/status?peers=false.
	resp := map[string]any{
		"Self": map[string]any{
			"ID":           nodeID,
			"PublicKey":    nodeKeyStr,
			"HostName":     hostname,
			"DNSName":      dnsName,
			"OS":           "linux",
			"TailscaleIPs": addresses,
			"Tags":         tags,
		},
		"CurrentTailnet": map[string]any{
			"Name": tailnetName,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("failed to encode status response: %v", err)
	}
}

// handleGetDevice serves GET /api/v2/device/{nodeID} — the mock control plane API.
func handleGetDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract device ID from path: /api/v2/device/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/v2/device/")
	if path == "" {
		http.Error(w, "missing device ID", http.StatusBadRequest)
		return
	}

	// Verify the authorization header is present.
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, "missing authorization", http.StatusUnauthorized)
		return
	}

	if path != nodeID {
		http.Error(w, fmt.Sprintf("device %q not found", path), http.StatusNotFound)
		return
	}

	resp := map[string]any{
		"id":          nodeID,
		"nodeKey":     nodeKeyStr,
		"hostname":    hostname,
		"name":        dnsName,
		"os":          "linux",
		"authorized":  true,
		"tags":        tags,
		"tailnetName": tailnetName,
		"user":        "e2e-test-user",
		"addresses":   addresses,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("failed to encode device response: %v", err)
	}
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}
