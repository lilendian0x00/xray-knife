package proxy

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	pkgproxy "github.com/lilendian0x00/xray-knife/v7/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v7/utils"
	"github.com/lilendian0x00/xray-knife/v7/utils/customlog"

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
	batchSize           uint16
	concurrency         uint16
	healthCheckInterval uint32
	drainTimeout        uint16
	blacklistStrikes    uint16
	blacklistDuration   uint32
}

// ProxyCmd is the proxy subcommand.
var ProxyCmd = newProxyCommand()

func newProxyCommand() *cobra.Command {
	cfg := &proxyCmdConfig{}

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run a local inbound proxy that tunnels traffic through a remote configuration. Supports automatic rotation.",
		Long: `Runs a local proxy service using configurations from the database by default.
Use --file, --config, or --stdin to provide configs for a single session without using the database.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get config links if provided via flags, otherwise leave empty.
			var links []string
			var err error
			if cfg.configLinksFile != "" {
				links = utils.ParseFileByNewline(cfg.configLinksFile)
			} else if cfg.configLink != "" {
				links = []string{cfg.configLink}
			} else if cfg.readConfigFromSTDIN {
				scanner := bufio.NewScanner(os.Stdin)
				fmt.Println("Reading config links from STDIN (press CTRL+D when done):")
				for scanner.Scan() {
					if trimmed := strings.TrimSpace(scanner.Text()); trimmed != "" {
						links = append(links, trimmed)
					}
				}
				if err := scanner.Err(); err != nil {
					return fmt.Errorf("error reading from stdin: %w", err)
				}
			}
			// If links slice is empty, the service will automatically fetch from the DB.

			// Create the service configuration from flags
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
				BatchSize:           cfg.batchSize,
				Concurrency:         cfg.concurrency,
				HealthCheckInterval: cfg.healthCheckInterval,
				DrainTimeout:        cfg.drainTimeout,
				BlacklistStrikes:    cfg.blacklistStrikes,
				BlacklistDuration:   cfg.blacklistDuration,
				ConfigLinks:         links,
			}

				// Create the new proxy service
			service, err := pkgproxy.New(serviceConfig, nil)
			if err != nil {
				return err
			}
			defer service.Close()

			// Set up context for graceful shutdown
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

			// Set up channel for manual rotation
			forceRotateChan := make(chan struct{})
			// Only listen for Enter if in rotation mode (more than 1 config, either from flags or DB)
			if service.ConfigCount() > 1 {
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

			// Run the service
			return service.Run(ctx, forceRotateChan)
		},
	}

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
	flags.StringVarP(&cfg.mode, "mode", "m", "inbound", "Proxy operating mode: inbound (local proxy) or system (set OS system proxy)")
	cmd.RegisterFlagCompletionFunc("mode", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"inbound", "system"}, cobra.ShellCompDirectiveNoFileComp
	})

	flags.StringVarP(&cfg.CoreType, "core", "z", "xray", "Core type: (xray, sing-box)")
	cmd.RegisterFlagCompletionFunc("core", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"xray", "sing-box"}, cobra.ShellCompDirectiveNoFileComp
	})

	flags.BoolVarP(&cfg.verbose, "verbose", "v", false, "Enable verbose logging for the selected core")
	flags.BoolVarP(&cfg.insecureTLS, "insecure", "e", false, "Allow insecure TLS connections (e.g., self-signed certs)")

	flags.Uint16VarP(&cfg.batchSize, "batch", "b", 0, "Number of configs to test per rotation (0=auto)")
	flags.Uint16VarP(&cfg.concurrency, "concurrency", "n", 0, "Number of concurrent test threads (0=auto)")
	flags.Uint32Var(&cfg.healthCheckInterval, "health-check", 30, "Health check interval in seconds (0=disabled)")
	flags.Uint16Var(&cfg.drainTimeout, "drain", 0, "Seconds to keep old connection alive during rotation (0=immediate)")
	flags.Uint16Var(&cfg.blacklistStrikes, "blacklist-strikes", 3, "Failures before blacklisting a config (0=disabled)")
	flags.Uint32Var(&cfg.blacklistDuration, "blacklist-duration", 600, "Seconds to blacklist a failed config")

	// Mark mutually exclusive flags
	cmd.MarkFlagsMutuallyExclusive("file", "config", "stdin")
	cmd.MarkFlagsMutuallyExclusive("inbound-config", "inbound")
}
