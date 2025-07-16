package proxy

import (
	"bufio"
	"context"
	"os"
	"os/signal"
	"syscall"

	pkgproxy "github.com/lilendian0x00/xray-knife/v5/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v5/utils/customlog"

	"github.com/spf13/cobra"
)

// proxyCmdConfig holds the configuration for the proxy command from flags
type proxyCmdConfig struct {
	CoreType            string
	rotationInterval    uint32
	inboundProtocol     string
	inboundTransport    string
	inboundUUID         string
	mode                string
	configLinksFile     string
	readConfigFromSTDIN bool
	listenAddr          string
	listenPort          string
	configLink          string
	verbose             bool
	insecureTLS         bool
	maximumAllowedDelay uint16
	inboundConfigLink   string
}

// ProxyCmd represents the proxy command
var ProxyCmd = newProxyCommand()

// newProxyCommand creates the cobra command for the proxy service
func newProxyCommand() *cobra.Command {
	cfg := &proxyCmdConfig{}

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run a local inbound proxy that tunnels traffic through a remote configuration. Supports automatic rotation.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 1. Get config links from specified source
			links, err := pkgproxy.GetConfigLinks(cfg.configLinksFile, cfg.configLink, cfg.readConfigFromSTDIN)
			if err != nil {
				// If no links, show help, unless user intended to pipe from stdin
				if !cfg.readConfigFromSTDIN {
					cmd.Help()
				}
				return err
			}

			// 2. Create the service configuration from flags
			serviceConfig := pkgproxy.Config{
				CoreType:            cfg.CoreType,
				InboundProtocol:     cfg.inboundProtocol,
				InboundTransport:    cfg.inboundTransport,
				InboundUUID:         cfg.inboundUUID,
				ListenAddr:          cfg.listenAddr,
				ListenPort:          cfg.listenPort,
				InboundConfigLink:   cfg.inboundConfigLink,
				Mode:                cfg.mode,
				Verbose:             cfg.verbose,
				InsecureTLS:         cfg.insecureTLS,
				RotationInterval:    cfg.rotationInterval,
				MaximumAllowedDelay: cfg.maximumAllowedDelay,
				ConfigLinks:         links,
			}

			// 3. Create the new proxy service, passing nil for the logger in CLI mode.
			service, err := pkgproxy.New(serviceConfig, nil)
			if err != nil {
				return err
			}

			// 4. Set up context for graceful shutdown
			ctx, cancel := context.WithCancel(context.Background())
			signalChan := make(chan os.Signal, 1)
			signal.Notify(signalChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
			defer func() {
				signal.Stop(signalChan)
				cancel()
			}()
			go func() {
				select {
				case sig := <-signalChan:
					customlog.Printf(customlog.Processing, "Received signal: %v. Shutting down...\n", sig)
					cancel()
				case <-ctx.Done():
				}
			}()

			// 5. Set up channel for manual rotation (CLI-specific feature)
			forceRotateChan := make(chan struct{})
			if len(links) > 1 { // Only listen for Enter if in rotation mode
				go func() {
					reader := bufio.NewReader(os.Stdin)
					for {
						reader.ReadString('\n')
						select {
						case forceRotateChan <- struct{}{}:
						case <-ctx.Done():
							return
						}
					}
				}()
			}

			// 6. Run the service
			return service.Run(ctx, forceRotateChan)
		},
	}

	// Add flags to the command
	addFlags(cmd, cfg)
	return cmd
}

// addFlags configures all the command-line flags
func addFlags(cmd *cobra.Command, cfg *proxyCmdConfig) {
	flags := cmd.Flags()
	flags.BoolVarP(&cfg.readConfigFromSTDIN, "stdin", "i", false, "Read config link(s) from STDIN")
	flags.StringVarP(&cfg.configLinksFile, "file", "f", "", "Read config links from a file")
	flags.StringVarP(&cfg.configLink, "config", "c", "", "The single xray/sing-box config link to use")
	flags.Uint32VarP(&cfg.rotationInterval, "rotate", "t", 300, "How often to rotate outbounds (seconds)")
	flags.Uint16VarP(&cfg.maximumAllowedDelay, "mdelay", "d", 3000, "Maximum allowed delay (ms) for testing configs during rotation")

	flags.StringVarP(&cfg.listenAddr, "addr", "a", "127.0.0.1", "Listen ip address for the proxy server")
	flags.StringVarP(&cfg.listenPort, "port", "p", "9999", "Listen port number for the proxy server")

	flags.StringVarP(&cfg.inboundProtocol, "inbound", "j", "socks", "Inbound protocol to use (vless, vmess, socks)")
	flags.StringVarP(&cfg.inboundTransport, "transport", "u", "tcp", "Inbound transport to use (tcp, ws, grpc, xhttp)")
	flags.StringVarP(&cfg.inboundUUID, "uuid", "g", "random", "Inbound custom UUID to use (default: random)")

	flags.StringVarP(&cfg.inboundConfigLink, "inbound-config", "I", "", "Custom config link for the inbound proxy")
	flags.StringVarP(&cfg.mode, "mode", "m", "inbound", "Proxy operating mode: inbound or system (not implemented)")

	flags.StringVarP(&cfg.CoreType, "core", "z", "xray", "Core type: (xray, sing-box)")
	cmd.RegisterFlagCompletionFunc("core", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"xray", "sing-box"}, cobra.ShellCompDirectiveNoFileComp
	})

	flags.BoolVarP(&cfg.verbose, "verbose", "v", false, "Enable verbose logging for the selected core")
	flags.BoolVarP(&cfg.insecureTLS, "insecure", "e", false, "Allow insecure TLS connections (e.g., self-signed certs)")

	// Mark mutually exclusive flags
	cmd.MarkFlagsMutuallyExclusive("file", "config", "stdin")
	cmd.MarkFlagsMutuallyExclusive("inbound-config", "inbound")
}
