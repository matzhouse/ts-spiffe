package main

import (
	"github.com/matzhouse/ts-spiffe/pkg/agent"
	agentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
)

func main() {
	p := new(agent.Plugin)
	pluginmain.Serve(
		agentv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}
