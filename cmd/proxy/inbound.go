package proxy

import (
	"github.com/spf13/cobra"
)

var inboundCmdRot inboundCfgPair

// InboundCmd is the `proxy inbound` subcommand.
var InboundCmd = newInboundCommand()

func newInboundCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inbound",
		Short: "Run a local inbound proxy that tunnels traffic through a remote configuration. Supports automatic rotation.",
		Long: `Runs a local inbound proxy on --addr:--port. Configurations are read
from --config / --file / --stdin or, if none of those are provided, the
local subscription database (populated via 'xray-knife subs fetch').`,
		Example: `  xray-knife proxy inbound                                # use DB pool, default port 9999
  xray-knife proxy inbound -c "vless://..."               # one-shot single config
  xray-knife proxy inbound -f configs.txt -t 60           # rotate every 60s from file
  xray-knife proxy inbound --chain --chain-hops 3         # 3-hop chain from DB pool`,
		RunE: runInbound,
	}

	flags := cmd.Flags()
	flags.StringVarP(&inboundCmdRot.in.inboundProtocol, "inbound", "j", "socks", "Inbound protocol to use (vless, vmess, socks)")
	flags.StringVarP(&inboundCmdRot.in.inboundTransport, "transport", "u", "tcp", "Inbound transport to use (tcp, ws, grpc, xhttp)")
	flags.StringVarP(&inboundCmdRot.in.inboundUUID, "uuid", "g", "random", "Inbound custom UUID to use (default: random)")
	flags.StringVarP(&inboundCmdRot.in.inboundConfigLink, "inbound-config", "I", "", "Custom config link for the inbound proxy")
	cmd.MarkFlagsMutuallyExclusive("inbound-config", "inbound")

	addRotationFlags(cmd, &inboundCmdRot.rot)
	addChainFlags(cmd, &inboundCmdRot.ch)
	addOutboundNetFlags(cmd, &inboundCmdRot.on)

	return cmd
}

func runInbound(cmd *cobra.Command, args []string) error {
	if err := validateChainFlags(&inboundCmdRot.ch, pf.coreType); err != nil {
		return err
	}
	links, err := resolveLinks(&pf)
	if err != nil {
		return err
	}
	cfg := buildPkgConfig("inbound", &pf, &inboundCmdRot.in, &inboundCmdRot.rot, &inboundCmdRot.ch, &inboundCmdRot.on, nil, nil)
	cfg.ConfigLinks = links
	return runService(cmd.Context(), cfg, false)
}
