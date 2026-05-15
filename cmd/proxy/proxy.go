package proxy

import (
	"github.com/spf13/cobra"
)

// ProxyCmd is the parent for the proxy subcommand family.
//
// Bare `xray-knife proxy` prints help (no RunE — cobra default).
// All real work lives in the four subcommands: inbound, system,
// app, tun.
var ProxyCmd = newProxyCommand()

func newProxyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run a local proxy that tunnels traffic through a remote configuration. Supports rotation and multiple operating modes.",
		Long: `Run a proxy in one of four modes:

  inbound  — local listener (default for most use cases)
  system   — local listener + register as the OS system proxy
  app      — per-process Linux network namespace (--shell / --namespace)
  tun      — host-wide TUN capture (Linux only, DANGEROUS over SSH)

Configurations are read from --config / --file / --stdin or, if none of
those are provided, from the local subscription database (populate with
'xray-knife subs fetch').`,
	}

	flags := cmd.PersistentFlags()
	flags.StringVarP(&pf.coreType, "core", "z", "xray", "Core type: (xray, sing-box)")
	cmd.RegisterFlagCompletionFunc("core", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"xray", "sing-box"}, cobra.ShellCompDirectiveNoFileComp
	})
	flags.StringVarP(&pf.configLink, "config", "c", "", "The single xray/sing-box config link to use")
	flags.StringVarP(&pf.configFile, "file", "f", "", "Read config links from a file")
	flags.BoolVarP(&pf.readFromSTDIN, "stdin", "i", false, "Read config link(s) from STDIN")
	flags.StringVarP(&pf.listenAddr, "addr", "a", "127.0.0.1", "Listen ip address for the proxy server")
	flags.StringVarP(&pf.listenPort, "port", "p", "9999", "Listen port number for the proxy server")
	flags.BoolVarP(&pf.verbose, "verbose", "v", false, "Enable verbose logging for the selected core")
	flags.BoolVarP(&pf.insecureTLS, "insecure", "e", false, "Allow insecure TLS connections (e.g., self-signed certs)")

	cmd.MarkFlagsMutuallyExclusive("config", "file", "stdin")

	addSubcommandPalettes(cmd)
	return cmd
}

func addSubcommandPalettes(cmd *cobra.Command) {
	cmd.AddCommand(InboundCmd)
	cmd.AddCommand(SystemCmd)
	cmd.AddCommand(AppCmd)
	cmd.AddCommand(TunCmd)
}
