package main

import (
	"wl/plugin"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

func main() {
	plugin := new(plugin.Plugin)
	pluginmain.Serve(
		workloadattestorv1.WorkloadAttestorPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
