package main

import (
	"github.com/matzhouse/ts-spiffe/pkg/server"
	serverv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
)

func main() {
	p := new(server.Plugin)
	pluginmain.Serve(
		serverv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}
