package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/matzhouse/ts-spiffe/pkg/authkey"
)

func main() {
	clientID := flag.String("client-id", os.Getenv("TS_OAUTH_CLIENT_ID"), "Tailscale OAuth client ID (or TS_OAUTH_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("TS_OAUTH_CLIENT_SECRET"), "Tailscale OAuth client secret (or TS_OAUTH_CLIENT_SECRET env)")
	tailnet := flag.String("tailnet", os.Getenv("TS_TAILNET"), "Tailscale tailnet name (or TS_TAILNET env, default: '-')")
	ephemeral := flag.Bool("ephemeral", true, "Create ephemeral auth key")
	preauthorized := flag.Bool("preauthorized", true, "Create preauthorized auth key")
	tagsStr := flag.String("tags", "", "Comma-separated list of ACL tags (e.g., tag:container,tag:web)")
	expiry := flag.Duration("expiry", 1*time.Hour, "Auth key expiry duration (e.g., 1h, 30m)")
	flag.Parse()

	if *clientID == "" || *clientSecret == "" {
		fmt.Fprintln(os.Stderr, "error: --client-id and --client-secret are required (or set TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET)")
		flag.Usage()
		os.Exit(1)
	}

	var tags []string
	if *tagsStr != "" {
		for _, t := range strings.Split(*tagsStr, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}

	oauthClient := authkey.NewOAuthClient(*clientID, *clientSecret)
	fetcher := authkey.NewFetcher(oauthClient.Token)

	resp, err := fetcher.CreateAuthKey(authkey.AuthKeyRequest{
		Tailnet:       *tailnet,
		Ephemeral:     *ephemeral,
		Preauthorized: *preauthorized,
		Tags:          tags,
		Expiry:        *expiry,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(resp.Key)
}
