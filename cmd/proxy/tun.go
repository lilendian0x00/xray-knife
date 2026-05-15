package proxy

import (
	"github.com/spf13/cobra"
)

var (
	tunCmdMode tunCfg
	tunCmdRot  rotationFlags
	tunCmdCh   chainFlags
	tunCmdOn   outboundNetFlags
)

// TunCmd is the `proxy tun` subcommand: host-wide TUN capture (Linux
// only). Replaces the host's default route, captures all egress
// traffic, and forwards it through the proxy. Dangerous over SSH —
// requires --i-might-lose-ssh acknowledgement.
var TunCmd = newTunCommand()

func newTunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tun",
		Short: "Capture all host egress through a TUN device (Linux only, DANGEROUS over SSH).",
		Long: `Creates a TUN interface, replaces the host's default route, and forwards
all egress through the rotating proxy. Linux only. Requires root.

WARNING: this mode replaces the default route. If you run it over an
SSH session, the route swap can drop your SSH connection. Pass
--i-might-lose-ssh to acknowledge. The default --tun-deadman of 60s
gives you a grace period to confirm the tunnel is working before the
process self-terminates.`,
		Example: `  sudo xray-knife proxy tun --bind eth0 --i-might-lose-ssh
  sudo xray-knife proxy tun --bind eth0 --i-might-lose-ssh --tun-include-private`,
		RunE: runTun,
	}

	flags := cmd.Flags()
	flags.BoolVar(&tunCmdMode.hostTunAck, "i-might-lose-ssh", false, "Required ack: confirms you understand this can kill your active SSH session.")
	flags.Uint16Var(&tunCmdMode.hostTunDeadman, "tun-deadman", 60, "Seconds to wait for ENTER after tun comes up before auto-teardown (0 = disable)")
	flags.StringVar(&tunCmdMode.hostTunExclude, "tun-exclude", "", "Comma-separated extra CIDRs to exclude from tun capture")
	flags.StringVar(&tunCmdMode.hostTunName, "tun-name", "xkt0", "TUN interface name")
	flags.StringVar(&tunCmdMode.hostTunAddr, "tun-addr", "198.18.0.1/30", "TUN address/CIDR (RFC 2544 by default to avoid LAN collision)")
	flags.Uint32Var(&tunCmdMode.hostTunMTU, "tun-mtu", 1500, "TUN MTU")
	flags.BoolVar(&tunCmdMode.hostTunIncludePrivate, "tun-include-private", false, "Capture RFC1918 / private LAN traffic too (default: excluded). Risky over LAN.")

	if err := cmd.MarkFlagRequired("i-might-lose-ssh"); err != nil {
		panic(err) // programmer error: flag was just registered above
	}

	addRotationFlags(cmd, &tunCmdRot)
	addChainFlags(cmd, &tunCmdCh)
	addOutboundNetFlags(cmd, &tunCmdOn)

	// --bind is registered by addOutboundNetFlags; mark required for tun
	// (sing-box must pin its outbound dials to the physical NIC).
	if err := cmd.MarkFlagRequired("bind"); err != nil {
		panic(err)
	}

	return cmd
}

func runTun(cmd *cobra.Command, args []string) error {
	if err := validateChainFlags(&tunCmdCh, pf.coreType); err != nil {
		return err
	}
	links, err := resolveLinks(&pf)
	if err != nil {
		return err
	}
	// Internal pkg/proxy mode string is still "host-tun" — the rename is
	// CLI-only.
	cfg := buildPkgConfig("host-tun", &pf, nil, &tunCmdRot, &tunCmdCh, &tunCmdOn, nil, &tunCmdMode)
	cfg.ConfigLinks = links
	return runService(cmd.Context(), cfg, false)
}
