package proxy

import (
	"github.com/spf13/cobra"
)

var systemCmdRot inboundCfgPair

// SystemCmd is the `proxy system` subcommand. Same flag set as
// InboundCmd but Mode="system" so pkg/proxy registers an OS-level
// proxy (sysproxy.Manager) for the lifetime of the command.
var SystemCmd = newSystemCommand()

func newSystemCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "system",
		Short: "Like 'inbound', plus register the running proxy as the OS system proxy.",
		Long: `Runs a local inbound proxy AND configures the host OS to route HTTP/HTTPS
traffic through it once the listener is up. On exit, the previous OS proxy
settings are restored.

OS-specific behavior:
  Linux:   GNOME / KDE proxy settings via gsettings / kwriteconfig5
  macOS:   networksetup -setwebproxy / -setsecurewebproxy / -setsocksfirewallproxy
  Windows: per-protocol ProxyServer registry keys + WinINet refresh`,
		Example: `  xray-knife proxy system                  # DB pool, OS proxy on 127.0.0.1:9999
  xray-knife proxy system -c "vless://..." -p 8080`,
		RunE: runSystem,
	}

	flags := cmd.Flags()
	flags.StringVar(&systemCmdRot.in.inboundProtocol, "inbound", "socks", "Inbound protocol to use (vless, vmess, socks)")
	flags.StringVar(&systemCmdRot.in.inboundTransport, "transport", "tcp", "Inbound transport to use (tcp, ws, grpc, xhttp)")
	flags.StringVar(&systemCmdRot.in.inboundUUID, "uuid", "random", "Inbound custom UUID to use (default: random)")
	flags.StringVar(&systemCmdRot.in.inboundConfigLink, "inbound-config", "", "Custom config link for the inbound proxy")
	cmd.MarkFlagsMutuallyExclusive("inbound-config", "inbound")

	addRotationFlags(cmd, &systemCmdRot.rot)
	addChainFlags(cmd, &systemCmdRot.ch)
	addOutboundNetFlags(cmd, &systemCmdRot.on)

	return cmd
}

func runSystem(cmd *cobra.Command, args []string) error {
	if err := validateChainFlags(&systemCmdRot.ch, pf.coreType); err != nil {
		return err
	}
	links, err := resolveLinks(&pf)
	if err != nil {
		return err
	}
	cfg, err := buildPkgConfig("system", &pf, &systemCmdRot.in, &systemCmdRot.rot, &systemCmdRot.ch, &systemCmdRot.on, nil, nil)
	if err != nil {
		return err
	}
	cfg.ConfigLinks = links
	return runService(cmd.Context(), cfg, false)
}
