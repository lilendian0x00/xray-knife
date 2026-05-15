package proxy

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	pkgproxy "github.com/lilendian0x00/xray-knife/v10/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v10/utils"
	"github.com/lilendian0x00/xray-knife/v10/utils/customlog"

	"github.com/spf13/cobra"
)

// parentFlags carries every persistent flag declared on ProxyCmd.
// Subcommand RunE funcs read these directly — cobra has populated the
// fields by parse time.
type parentFlags struct {
	coreType      string
	configLink    string
	configFile    string
	readFromSTDIN bool
	listenAddr    string
	listenPort    string
	verbose       bool
	insecureTLS   bool
}

// rotationFlags carries the rotation/health/blacklist tuning knobs that
// every subcommand carries (every mode rotates).
type rotationFlags struct {
	rotationInterval    uint32
	maximumAllowedDelay uint16
	batchSize           uint16
	concurrency         uint16
	healthCheckInterval uint32
	healthFailThreshold uint16
	drainTimeout        uint16
	blacklistStrikes    uint16
	blacklistDuration   uint32
}

// chainFlags carries the multi-hop chaining knobs.
type chainFlags struct {
	chain         bool
	chainLinks    string
	chainFile     string
	chainHops     uint8
	chainRotation string
	chainAttempts uint16
}

// outboundNetFlags carries flags that shape outbound dials (interface
// pinning + DNS resolver inside the tunnel).
type outboundNetFlags struct {
	bindInterface string
	dns           string
	dnsType       string
}

// inboundCfg holds inbound-protocol flag values shared between
// InboundCmd and SystemCmd.
type inboundCfg struct {
	inboundProtocol   string
	inboundTransport  string
	inboundUUID       string
	inboundConfigLink string
}

// inboundCfgPair groups inbound-specific + the shared rotation/chain/net
// flag structs so SystemCmd can reuse the layout without name clashes.
type inboundCfgPair struct {
	in  inboundCfg
	rot rotationFlags
	ch  chainFlags
	on  outboundNetFlags
}

// appCfg / tunCfg are per-mode flag groups. Defined here so the
// buildPkgConfig signature stays in one place.
type appCfg struct {
	shell         bool
	namespaceName string
}

type tunCfg struct {
	hostTunDeadman        uint16
	hostTunExclude        string
	hostTunName           string
	hostTunAddr           string
	hostTunMTU            uint32
	hostTunIncludePrivate bool // CLI flag --tun-include-private; service expects ExcludePrivate so we negate.
}

// pf is the package-level instance bound to ProxyCmd's persistent flags
// in proxy.go. Subcommands read it directly from RunE.
var pf parentFlags

func addRotationFlags(cmd *cobra.Command, r *rotationFlags) {
	flags := cmd.Flags()
	flags.Uint32VarP(&r.rotationInterval, "rotate", "t", 300, "How often to rotate outbounds (seconds)")
	flags.Uint16VarP(&r.maximumAllowedDelay, "mdelay", "d", 3000, "Maximum allowed delay (ms) for testing configs during rotation")
	flags.Uint16VarP(&r.batchSize, "batch", "b", 0, "Number of configs to test per rotation (0=auto)")
	flags.Uint16VarP(&r.concurrency, "concurrency", "n", 0, "Number of concurrent test threads (0=auto)")
	flags.Uint32Var(&r.healthCheckInterval, "health-check", 30, "Health check interval in seconds (0=disabled)")
	flags.Uint16Var(&r.healthFailThreshold, "health-fail-threshold", 0, "Consecutive health-check failures before striking the active config (0=default)")
	flags.Uint16Var(&r.drainTimeout, "drain", 0, "Seconds to keep the current outbound serving before switching during rotation (0=switch immediately)")
	flags.Uint16Var(&r.blacklistStrikes, "blacklist-strikes", 3, "Failures before blacklisting a config (0=disabled)")
	flags.Uint32Var(&r.blacklistDuration, "blacklist-duration", 600, "Seconds to blacklist a failed config")
}

func addChainFlags(cmd *cobra.Command, c *chainFlags) {
	flags := cmd.Flags()
	flags.BoolVar(&c.chain, "chain", false, "Enable outbound chaining (multi-hop proxy)")
	flags.StringVar(&c.chainLinks, "chain-links", "", "Fixed chain hops as pipe-separated config links")
	flags.StringVar(&c.chainFile, "chain-file", "", "Fixed chain hops from file (one link per line)")
	flags.Uint8Var(&c.chainHops, "chain-hops", 2, "Number of hops when selecting from pool")
	flags.StringVar(&c.chainRotation, "chain-rotation", "none", "Chain rotation mode: none, exit, full")
	flags.Uint16Var(&c.chainAttempts, "chain-attempts", 0, "Random chain combinations to try per rotation cycle (0=default)")
	cmd.RegisterFlagCompletionFunc("chain-rotation", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"none", "exit", "full"}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.MarkFlagsMutuallyExclusive("chain-links", "chain-file")
}

func addOutboundNetFlags(cmd *cobra.Command, o *outboundNetFlags) {
	flags := cmd.Flags()
	flags.StringVar(&o.bindInterface, "bind", "", "Bind outbound dials to a specific OS interface (e.g. eth0). Linux: needs CAP_NET_RAW.")
	flags.StringVar(&o.dns, "dns", "1.1.1.1", "DNS resolver used inside the app/tun-mode tunnel (ip, ip:port, or https://host/path for --dns-type=https)")
	flags.StringVar(&o.dnsType, "dns-type", "udp", "DNS transport for the app/tun-mode tunnel: udp, tcp, tls, https")
	cmd.RegisterFlagCompletionFunc("dns-type", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"udp", "tcp", "tls", "https"}, cobra.ShellCompDirectiveNoFileComp
	})
}

// validateChainFlags runs the chain-related cross-flag checks. coreType
// is the resolved parent --core value (already defaulted to "xray").
func validateChainFlags(c *chainFlags, coreType string) error {
	// Treat "fixed chain provided" as implicitly enabling --chain so users
	// don't have to pass --chain alongside --chain-links / --chain-file.
	if c.chainLinks != "" || c.chainFile != "" {
		c.chain = true
	}
	if c.chainRotation == "" {
		c.chainRotation = "none"
	}
	if c.chainRotation != "none" && !c.chain {
		return fmt.Errorf("--chain-rotation requires --chain")
	}
	if c.chain {
		if coreType == "auto" {
			return fmt.Errorf("--chain requires an explicit core type (xray or sing-box), not auto")
		}
		if c.chainHops < 2 {
			c.chainHops = 2
		}
		if (c.chainLinks != "" || c.chainFile != "") && c.chainRotation != "none" {
			return fmt.Errorf("--chain-rotation is incompatible with --chain-links / --chain-file (fixed chains don't rotate)")
		}
	}
	return nil
}

// resolveLinks reads config links from the persistent --config / --file /
// --stdin flags (mutual exclusion is enforced by cobra on the parent).
// If none are set, returns nil — pkg/proxy then falls back to the DB pool.
func resolveLinks(p *parentFlags) ([]string, error) {
	switch {
	case p.configFile != "":
		return utils.ParseFileByNewline(p.configFile), nil
	case p.configLink != "":
		return []string{p.configLink}, nil
	case p.readFromSTDIN:
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("Reading config links from STDIN (press CTRL+D when done):")
		var links []string
		for scanner.Scan() {
			if trimmed := strings.TrimSpace(scanner.Text()); trimmed != "" {
				links = append(links, trimmed)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading from stdin: %w", err)
		}
		return links, nil
	}
	return nil, nil
}

// buildPkgConfig assembles a pkgproxy.Config from the parent flags + the
// per-subcommand flag groups. mode must be one of "inbound", "system",
// "app", "host-tun" (note "host-tun" — internal pkg/proxy still uses
// the pre-rename mode string). Pass nil for any group not relevant to mode.
func buildPkgConfig(
	mode string,
	p *parentFlags,
	in *inboundCfg,
	rot *rotationFlags,
	ch *chainFlags,
	on *outboundNetFlags,
	app *appCfg,
	tun *tunCfg,
) pkgproxy.Config {
	cfg := pkgproxy.Config{
		Mode:        mode,
		CoreType:    p.coreType,
		ListenAddr:  p.listenAddr,
		ListenPort:  p.listenPort,
		Verbose:     p.verbose,
		InsecureTLS: p.insecureTLS,
	}
	if in != nil {
		cfg.InboundProtocol = in.inboundProtocol
		cfg.InboundTransport = in.inboundTransport
		cfg.InboundUUID = in.inboundUUID
		cfg.InboundConfigLink = in.inboundConfigLink
	}
	if rot != nil {
		cfg.RotationInterval = rot.rotationInterval
		cfg.MaximumAllowedDelay = rot.maximumAllowedDelay
		cfg.BatchSize = rot.batchSize
		cfg.Concurrency = rot.concurrency
		cfg.HealthCheckInterval = rot.healthCheckInterval
		cfg.HealthFailThreshold = rot.healthFailThreshold
		cfg.DrainTimeout = rot.drainTimeout
		cfg.BlacklistStrikes = rot.blacklistStrikes
		cfg.BlacklistDuration = rot.blacklistDuration
	}
	if ch != nil {
		cfg.Chain = ch.chain
		cfg.ChainLinks = ch.chainLinks
		cfg.ChainFile = ch.chainFile
		cfg.ChainHops = ch.chainHops
		cfg.ChainRotation = ch.chainRotation
		cfg.ChainAttempts = ch.chainAttempts
	}
	if on != nil {
		cfg.BindInterface = on.bindInterface
		cfg.DNS = on.dns
		cfg.DNSType = on.dnsType
	}
	if app != nil {
		cfg.Shell = app.shell
		cfg.NamespaceName = app.namespaceName
	}
	if tun != nil {
		cfg.HostTunDeadman = tun.hostTunDeadman
		cfg.HostTunExclude = tun.hostTunExclude
		cfg.HostTunName = tun.hostTunName
		cfg.HostTunAddr = tun.hostTunAddr
		cfg.HostTunMTU = tun.hostTunMTU
		// CLI flag is --tun-include-private (default false = exclude).
		// pkg/proxy field is HostTunExcludePrivate (default true).
		cfg.HostTunExcludePrivate = !tun.hostTunIncludePrivate
	}
	return cfg
}

// runService is the common runtime path for all four subcommands: build
// the pkgproxy.Service, set up signal handling (incl. SIGHUP for tun),
// start the manual-rotation stdin reader (skipped when app+shell), and
// block on service.Run until the context is cancelled.
//
// shellInteractive is true only for AppCmd when --shell is set — it
// suppresses the stdin reader because the spawned shell takes stdin.
func runService(ctx context.Context, cfg pkgproxy.Config, shellInteractive bool) error {
	service, err := pkgproxy.New(cfg, nil)
	if err != nil {
		return err
	}
	defer service.Close()

	runCtx, cancel := context.WithCancel(ctx)
	signalChan := make(chan os.Signal, 1)
	// SIGHUP is caught for tun mode running over SSH: when the SSH
	// session drops, the kernel sends SIGHUP to the controlling
	// process group. Without catching it, the process dies before
	// service.Close() can tear down the TUN and routing rules,
	// leaving the host unreachable.
	signal.Notify(signalChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()
	go func() {
		select {
		case sig := <-signalChan:
			customlog.Printf(customlog.Processing, "Received signal: %v. Shutting down...\n", sig)
			cancel()
		case <-runCtx.Done():
		}
	}()

	forceRotateChan := make(chan struct{})
	if service.ConfigCount() > 1 && !shellInteractive {
		go func() {
			reader := bufio.NewReader(os.Stdin)
			for {
				// ReadString returns an error on EOF (e.g. when stdin
				// is /dev/null or a closed pipe). Without this guard
				// the loop spins, sending forceRotate signals as fast
				// as the rotation worker can accept them.
				if _, err := reader.ReadString('\n'); err != nil {
					return
				}
				select {
				case forceRotateChan <- struct{}{}:
				case <-runCtx.Done():
					return
				}
			}
		}()
	}

	return service.Run(runCtx, forceRotateChan)
}
