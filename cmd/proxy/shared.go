package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	pkgproxy "github.com/lilendian0x00/xray-knife/v11/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v11/utils"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
	"github.com/lilendian0x00/xray-knife/v11/utils/interrupt"

	"github.com/spf13/cobra"
	"golang.org/x/term"
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
	listenPort    uint16
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
	healthURL           string
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
	fragment      string
	noise         []string
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
	shellAsRoot   bool
	killSwitch    bool
}

type tunCfg struct {
	hostTunDeadman        uint16
	hostTunExclude        string
	hostTunName           string
	hostTunAddr           string
	hostTunAddr6          string
	hostTunMTU            uint32
	hostTunIncludePrivate bool // CLI flag --tun-include-private; service expects ExcludePrivate so we negate.
	killSwitch            bool
}

// pf is the package-level instance bound to ProxyCmd's persistent flags
// in proxy.go. Subcommands read it directly from RunE.
var pf parentFlags

func addRotationFlags(cmd *cobra.Command, r *rotationFlags) {
	flags := cmd.Flags()
	flags.Uint32VarP(&r.rotationInterval, "rotate", "R", 300, "How often to rotate outbounds (seconds; 0 = only when health checks fail)")
	flags.Uint16VarP(&r.maximumAllowedDelay, "mdelay", "d", 3000, "Maximum allowed delay (ms) for testing configs during rotation")
	flags.Uint16Var(&r.batchSize, "batch", 0, "Number of configs to test per rotation (0=auto)")

	// --concurrency renamed to --threads for consistency with http and
	// cfscanner. -t is NOT bound here: it meant --rotate in v10 and both take
	// a number, so rebinding it would silently change behaviour. It becomes
	// --threads in v12.
	flags.Uint16Var(&r.concurrency, "threads", 0, "Number of concurrent test threads (0=auto)")
	flags.Uint16Var(&r.concurrency, "concurrency", 0, "Deprecated alias for --threads")
	_ = flags.MarkDeprecated("concurrency", "use --threads")
	flags.Uint32Var(&r.healthCheckInterval, "health-check", 30, "Health check interval in seconds (0=disabled)")
	flags.Uint16Var(&r.healthFailThreshold, "health-fail-threshold", 0, "Consecutive health-check failures before striking the active config (0=default)")
	flags.Uint16Var(&r.drainTimeout, "drain", 0, "Seconds a replaced outbound keeps serving the connections it already carries after a rotation (0 = 30s); the listener itself never goes down")
	flags.Uint16Var(&r.blacklistStrikes, "blacklist-strikes", 3, "Failures before blacklisting a config (0=disabled)")
	flags.Uint32Var(&r.blacklistDuration, "blacklist-duration", 600, "Seconds to blacklist a failed config")
	flags.StringVar(&r.healthURL, "health-url", "https://cloudflare.com/cdn-cgi/trace", "URL fetched through the proxy by health checks and rotation tests")
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
	flags.StringVar(&o.fragment, "fragment", "", `Fragment the TLS handshake to get past SNI-based DPI: packets,length[,interval] (e.g. "tlshello,100-200,10-20"; "off" disables)`)
	flags.StringArrayVar(&o.noise, "noise", nil, `UDP noise sent before real traffic, xray core only: type:packet[:delay] (e.g. "rand:10-20:10-16"; repeatable)`)
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
// A missing or empty file (or empty stdin) is an error: silently falling
// back to the whole DB pool because of a typo would proxy through
// configs the user never asked for.
func resolveLinks(p *parentFlags) ([]string, error) {
	switch {
	case p.configFile != "":
		links, err := utils.ReadLinks(p.configFile)
		if err != nil {
			return nil, fmt.Errorf("--file: %w", err)
		}
		return links, nil
	case p.configLink != "":
		return []string{p.configLink}, nil
	case p.readFromSTDIN:
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintln(os.Stderr, "Reading config links from STDIN (press CTRL+D when done):")
		}
		links, err := utils.ReadLinksFrom(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("error reading from stdin: %w", err)
		}
		if len(links) == 0 {
			return nil, fmt.Errorf("--stdin: no config links read")
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
) (pkgproxy.Config, error) {
	cfg := pkgproxy.Config{
		Mode:        mode,
		CoreType:    p.coreType,
		ListenAddr:  p.listenAddr,
		ListenPort:  strconv.FormatUint(uint64(p.listenPort), 10),
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
		cfg.HealthCheckURL = rot.healthURL
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
		frag, err := fragment.Build(on.fragment, on.noise)
		if err != nil {
			return cfg, err
		}
		cfg.Fragment = frag
	}
	if app != nil {
		cfg.Shell = app.shell
		cfg.NamespaceName = app.namespaceName
		cfg.ShellAsRoot = app.shellAsRoot
		cfg.KillSwitch = app.killSwitch
	}
	if tun != nil {
		cfg.HostTunDeadman = tun.hostTunDeadman
		cfg.HostTunExclude = tun.hostTunExclude
		cfg.HostTunName = tun.hostTunName
		cfg.HostTunAddr = tun.hostTunAddr
		cfg.HostTunAddr6 = tun.hostTunAddr6
		cfg.HostTunMTU = tun.hostTunMTU
		// CLI flag is --tun-include-private (default false = exclude).
		// pkg/proxy field is HostTunExcludePrivate (default true).
		cfg.HostTunExcludePrivate = !tun.hostTunIncludePrivate
		cfg.KillSwitch = tun.killSwitch
	}
	return cfg, nil
}

// runService is the common runtime path for all four subcommands: build
// the pkgproxy.Service, set up signal handling (incl. SIGHUP for tun),
// start the stdin reader (skipped when app+shell), and block on
// service.Run until the context is cancelled.
//
// shellInteractive is true only for AppCmd when --shell is set — it
// suppresses the stdin reader because the spawned shell takes stdin.
func runService(ctx context.Context, cfg pkgproxy.Config, shellInteractive bool) error {
	// This process owns stdin: the one reader below forwards the tun
	// deadman confirmation to the service, so the service must not start
	// a second reader that would race it for the line.
	cfg.ExternalDeadmanConfirm = true
	// Nothing else in this process resolves names, so host-tun may point
	// the cores' lookups at the uplink-bound resolver.
	cfg.GlobalResolver = true

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	signalChan := make(chan os.Signal, 4)
	// SIGHUP is caught for tun mode running over SSH: when the SSH
	// session drops, the kernel sends SIGHUP to the controlling
	// process group. Without catching it, the process dies before
	// service.Close() can tear down the TUN and routing rules,
	// leaving the host unreachable.
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	// Repeated signals are ours to handle until Close has run: the root
	// handler's immediate exit would skip lifting the kill switch.
	release := interrupt.Own()
	var svc atomic.Pointer[pkgproxy.Service]
	watchDone := make(chan struct{})
	go interrupt.Watch(watchDone, signalChan, cancel, func() {
		if s := svc.Load(); s != nil {
			s.EmergencyCleanup(3 * time.Second)
		}
	}, time.Now, func() { os.Exit(exitcode.Interrupted) })
	defer func() {
		close(watchDone)
		signal.Stop(signalChan)
		release()
	}()

	service, err := pkgproxy.New(cfg, nil)
	if err != nil {
		return err
	}
	svc.Store(service)
	// Deferred after the watcher's teardown, so it runs first: a forced
	// exit stays possible while Close works.
	defer service.Close()

	// Buffered so a request made while a rotation is already running is
	// kept (one pending) instead of blocking the reader — a blocked
	// reader would swallow the deadman ENTER.
	forceRotateChan := make(chan struct{}, 1)
	needDeadman := cfg.Mode == "host-tun" && cfg.HostTunDeadman > 0
	if (service.ConfigCount() > 1 || needDeadman) && !shellInteractive {
		go dispatchStdin(runCtx, os.Stdin, service, forceRotateChan, service.ConfigCount() > 1)
	}

	return service.Run(runCtx, forceRotateChan)
}

// deadmanConfirmer is the part of *pkgproxy.Service dispatchStdin needs.
type deadmanConfirmer interface {
	ConfirmDeadman() bool
}

// dispatchStdin is the only stdin reader. Each line first goes to a
// pending tun deadman; otherwise it requests a manual rotation (when
// rotation is possible).
func dispatchStdin(ctx context.Context, in io.Reader, svc deadmanConfirmer, forceRotate chan<- struct{}, canRotate bool) {
	reader := bufio.NewReader(in)
	for {
		// ReadString returns an error on EOF (e.g. when stdin is
		// /dev/null or a closed pipe). Without this guard the loop
		// spins, sending forceRotate signals as fast as the rotation
		// worker can accept them.
		if _, err := reader.ReadString('\n'); err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if svc.ConfirmDeadman() || !canRotate {
			continue
		}
		select {
		case forceRotate <- struct{}{}:
		default: // a rotation request is already pending
		}
	}
}
