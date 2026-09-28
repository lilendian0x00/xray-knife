package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	osexec "os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	xproxy "golang.org/x/net/proxy"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	pkgsingbox "github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"
	pkgxray "github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/hosttun"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/killswitch"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/netns"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/sysproxy"
	"github.com/lilendian0x00/xray-knife/v11/utils"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/xtls/xray-core/common/uuid"
)

// Rotation tuning defaults.
const (
	// minRotationInterval is a floor on --rotate; anything tighter spins the
	// loop without giving tests room to finish.
	minRotationInterval uint32 = 5
	// defaultMaxDelayMs is the health-probe timeout (ms) used when
	// MaximumAllowedDelay is unset (0). It matches the fallback the per-site
	// timeout guards already apply (5s).
	defaultMaxDelayMs uint16 = 5000
	// defaultChainAttempts is how many random chains we'll try before giving
	// up on a rotation cycle.
	defaultChainAttempts int = 5
	// defaultHealthFailThresh is how many consecutive health-check misses
	// it takes to count the outbound as actually broken. A single flaky
	// probe shouldn't be enough to blacklist a working config.
	defaultHealthFailThresh = 3
	// defaultSocksCredLen is the length of the auto-generated SOCKS
	// username/password used when no inbound link is supplied. 16 chars of
	// alphanumeric keeps the listener safe from brute force even when
	// --addr exposes it beyond loopback.
	defaultSocksCredLen int = 16
)

// newLocalRand hands back a math/rand source seeded per call. Lets the
// rotation and chain-selection paths shuffle without piling onto the global
// source — they get called from multiple goroutines in the web service.
func newLocalRand() *rand.Rand {
	return rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(os.Getpid())))
}

// Config holds all the settings for the proxy service.
type Config struct {
	CoreType            string `json:"coreType"`
	InboundProtocol     string `json:"inboundProtocol"`
	InboundTransport    string `json:"inboundTransport"`
	InboundUUID         string `json:"inboundUUID"`
	ListenAddr          string `json:"listenAddr"`
	ListenPort          string `json:"listenPort"`
	InboundConfigLink   string `json:"inboundConfigLink"`
	Mode                string `json:"mode"`
	Verbose             bool   `json:"verbose"`
	InsecureTLS         bool   `json:"insecureTLS"`
	EnableTLS           bool   `json:"enableTls"`
	TLSSNI              string `json:"tlsSni"`
	TLSALPN             string `json:"tlsAlpn"`
	TLSCertFile         string `json:"tlsCertPath"`
	TLSKeyFile          string `json:"tlsKeyPath"`
	WSPath              string `json:"wsPath"`
	WSHost              string `json:"wsHost"`
	GRPCServiceName     string `json:"grpcServiceName"`
	GRPCAuthority       string `json:"grpcAuthority"`
	XHTTPMode           string `json:"xhttpMode"`
	XHTTPHost           string `json:"xhttpHost"`
	XHTTPPath           string `json:"xhttpPath"`
	RotationInterval    uint32 `json:"rotationInterval"` // seconds; 0 = rotate only on health-check failure / manual trigger
	MaximumAllowedDelay uint16 `json:"maximumAllowedDelay"`
	BatchSize           uint16 `json:"batchSize"`           // configs to test per rotation (0=auto)
	Concurrency         uint16 `json:"concurrency"`         // concurrent test threads (0=auto)
	HealthCheckInterval uint32 `json:"healthCheckInterval"` // seconds between health checks (0=disabled)
	HealthFailThreshold uint16 `json:"healthFailThreshold"` // consecutive health-check failures before strike (0=auto)
	DrainTimeout        uint16 `json:"drainTimeout"`        // seconds a replaced outbound keeps serving the connections it carries (0 = core default, 30s); without hot-swap: seconds to wait before switching
	BlacklistStrikes    uint16 `json:"blacklistStrikes"`    // failures before blacklisting (0=disabled)
	BlacklistDuration   uint32 `json:"blacklistDuration"`   // seconds to blacklist a config
	ChainAttempts       uint16 `json:"chainAttempts"`       // attempts to find a working chain (0=default 5)
	Shell               bool   `json:"shell"`               // launch shell in namespace (app mode)
	NamespaceName       string `json:"namespaceName"`       // named namespace (app mode)
	Chain               bool   `json:"chain"`               // enable outbound chaining (multi-hop)
	ChainLinks          string `json:"chainLinks"`          // pipe-separated fixed chain links
	ChainFile           string `json:"chainFile"`           // file with fixed chain links (one per line)
	ChainHops           uint8  `json:"chainHops"`           // number of hops when selecting from pool
	ChainRotation       string `json:"chainRotation"`       // none, exit, full
	// BindInterface pins outbound dials to a specific OS interface
	// (e.g. "eth0"). Useful when the host has multiple interfaces and
	// traffic must take a specific path regardless of the kernel's
	// default route.
	BindInterface string `json:"bindInterface,omitempty"`
	// DNS overrides the resolver inside the app-mode tunnel.
	// Empty = use netns.DefaultConfig (1.1.1.1).
	DNS string `json:"dns,omitempty"`
	// DNSType chooses the DNS transport inside the app-mode tunnel:
	// udp, tcp, tls, https. Empty = use netns.DefaultConfig (udp).
	DNSType     string `json:"dnsType,omitempty"`
	ConfigLinks []string

	// host-tun mode fields. Only honored when Mode == "host-tun".
	HostTunDeadman uint16 `json:"hostTunDeadman,omitempty"`
	HostTunExclude string `json:"hostTunExclude,omitempty"`
	HostTunName    string `json:"hostTunName,omitempty"`
	HostTunAddr    string `json:"hostTunAddr,omitempty"`
	// HostTunAddr6 is the TUN's IPv6 address. Empty selects the default
	// ULA (so IPv6 is captured like IPv4); "none" disables IPv6 capture,
	// which lets IPv6 egress bypass the tunnel.
	HostTunAddr6          string `json:"hostTunAddr6,omitempty"`
	HostTunMTU            uint32 `json:"hostTunMTU,omitempty"`
	HostTunExcludePrivate bool   `json:"hostTunExcludePrivate,omitempty"`

	// Fragment splits the TLS handshake of every outbound (and of the
	// rotation tests) to get past SNI-based DPI. FragmentSpec is the
	// "packets,length[,interval]" string form, used when Fragment is nil.
	Fragment     *fragment.Options `json:"fragment,omitempty"`
	FragmentSpec string            `json:"fragmentSpec,omitempty"`

	// HealthCheckURL is fetched through the proxy by health checks and
	// rotation tests. Empty = https://cloudflare.com/cdn-cgi/trace.
	HealthCheckURL string `json:"healthCheckUrl,omitempty"`

	// KillSwitch (tun and app modes) blocks all egress that does not go
	// through the tunnel. In tun mode the rules outlive a crash on
	// purpose (fail closed) until a clean exit or `proxy restore`.
	KillSwitch bool `json:"killSwitch,omitempty"`

	// ShellAsRoot keeps the app-mode shell as root under sudo. By default
	// the shell drops to the invoking user (SUDO_UID/SUDO_GID).
	ShellAsRoot bool `json:"shellAsRoot,omitempty"`

	// GlobalResolver lets host-tun replace net.DefaultResolver with the
	// uplink-bound resolver for the run, so the cores' own lookups of
	// proxy server names bypass the tunnel. Only the CLI sets it: in a
	// process that does other work it would race those lookups and send
	// them around the tunnel too.
	GlobalResolver bool `json:"-"`

	// ExternalDeadmanConfirm means the caller delivers the host-tun
	// deadman confirmation through ConfirmDeadman (the CLI forwards the
	// ENTER it reads from its single stdin reader; a web UI can forward
	// a button). When false the service reads stdin itself, which only
	// works if nothing else is reading it.
	ExternalDeadmanConfirm bool `json:"-"`
}

// defaultHealthCheckURL is the probe target when HealthCheckURL is unset.
const defaultHealthCheckURL = "https://cloudflare.com/cdn-cgi/trace"

// Rotation status values reported in Details.RotationStatus.
const (
	statusIdle      = "idle"
	statusTesting   = "testing"   // probing candidate configs
	statusSwitching = "switching" // handing the listener to a new outbound
	statusStalled   = "stalled"   // last rotation found nothing; retrying with backoff
)

// Details is a snapshot of the running proxy state.
type Details struct {
	Inbound        protocol.GeneralConfig `json:"inbound"`
	ActiveOutbound *pkghttp.Result        `json:"activeOutbound,omitempty"`
	RotationStatus string                 `json:"rotationStatus"` // idle, testing, switching, stalled
	// NextRotationTime is zero when no timed rotation is scheduled
	// (RotationInterval 0 = rotate only on health-check failure).
	NextRotationTime time.Time                `json:"nextRotationTime"`
	RotationInterval uint32                   `json:"rotationInterval"`
	TotalConfigs     int                      `json:"totalConfigs"`
	ChainEnabled     bool                     `json:"chainEnabled"`
	ChainHopInfos    []protocol.GeneralConfig `json:"chainHops,omitempty"`
	ChainRotation    string                   `json:"chainRotation,omitempty"`
	// DeadmanPending is true while host-tun waits for ConfirmDeadman.
	DeadmanPending bool `json:"deadmanPending,omitempty"`
}

type blacklistEntry struct {
	strikes          int
	blacklistedUntil time.Time
}

// Service is the main proxy service engine.
type Service struct {
	config            Config
	core              core.Core
	logger            *log.Logger
	inbound           protocol.Protocol
	activeOutbound    *pkghttp.Result
	activeChainHops   []protocol.Protocol // current chain hops (nil when not chaining)
	mu                sync.RWMutex
	rotationStatus    string
	nextRotationTime  time.Time
	sysProxyManager   sysproxy.Manager   // nil if mode != "system"
	prevProxySettings *sysproxy.Settings // saved OS settings before modification
	blacklist         map[string]*blacklistEntry
	nsManager         *netns.Namespace  // non-nil when mode == "app"
	nsTunnel          protocol.Instance // the sing-box tunnel inside the namespace
	nsCfg             netns.Config      // resolved netns config (for cleanup)
	hostTunInstance   protocol.Instance // non-nil when mode == "host-tun"
	hostTunCfg        hosttun.Config    // resolved host-tun config (for logging)
	restoreResolver   func()            // undoes hosttun.InstallGlobalResolver
	bootstrapDNS      []string          // resolvers the bound resolver uses
	proxyReady        chan struct{}     // closed when the first proxy instance starts
	proxyReadyOnce    sync.Once

	deadmanConfirm chan struct{} // buffered(1); fed by ConfirmDeadman
	deadmanPending atomic.Bool

	// host-tun per-upstream exceptions, following the active outbound.
	tunMu         sync.Mutex
	tunBypass     *hosttun.Bypass
	tunStaticV6   *hosttun.Bypass // IPv6 exceptions ahead of StrictRoute's unreachable rule
	killSwitch    *killswitch.Switch
	upstream      []netip.Addr // entry server addresses currently let through
	upstreamCheck time.Time    // last periodic re-resolution of the entry server
	// mark is the SO_MARK on the live listener's upstream sockets and on
	// the bootstrap resolver's (host-tun only). With it, exactly the
	// proxy's own sockets bypass the TUN and the kill switch (fwmark rule,
	// nft "meta mark"); other programs sending to the same address stay
	// in the tunnel. 0 means the destination-based fallback (the entry
	// server's addresses), used when the fwmark rule cannot be installed.
	mark     uint32
	resolver *net.Resolver // uplink-bound resolver (host-tun), nil otherwise

	deadmanArmed atomic.Bool // host-tun with a deadman that has not finished yet
	earlyEnter   atomic.Bool // a line arrived before the deadman prompt

	emergencyOnce sync.Once
}

func New(config Config, logger *log.Logger) (*Service, error) {
	// Catch a bad port now rather than letting the core or the namespace
	// tunnel blow up halfway through setup.
	if config.ListenPort == "" {
		return nil, errors.New("listen port is required")
	}
	if _, err := strconv.ParseUint(config.ListenPort, 10, 16); err != nil {
		return nil, fmt.Errorf("invalid listen port %q: %w", config.ListenPort, err)
	}
	listenAddr, err := NormalizeListenAddr(config.ListenAddr)
	if err != nil {
		return nil, err
	}
	config.ListenAddr = listenAddr

	// 0 means "no timed rotation": rotate only when health checks fail
	// (or on a manual trigger). Very small non-zero values would spin the
	// loop without giving tests room to finish, so clamp those.
	if config.RotationInterval > 0 && config.RotationInterval < minRotationInterval {
		config.RotationInterval = minRotationInterval
	}

	// MaximumAllowedDelay feeds context deadlines directly in the chain
	// rotation paths (runChainExitRotation/runChainFullRotation/
	// findWorkingChain), so a zero — which the web API sends when the field
	// is omitted — would make context.WithTimeout expire every probe
	// instantly and fail the initial chain search. Clamp it to a usable
	// default here so every consumer sees a valid timeout.
	if config.MaximumAllowedDelay == 0 {
		config.MaximumAllowedDelay = defaultMaxDelayMs
	}

	// Fixed chain hops imply chain mode, as --chain-links / --chain-file do
	// on the CLI; otherwise the hops would be ignored for plain rotation.
	if fixedChainConfig(config) {
		config.Chain = true
	}

	if config.HealthCheckURL == "" {
		config.HealthCheckURL = defaultHealthCheckURL
	}
	if u, err := url.Parse(config.HealthCheckURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid health-check URL %q: want http(s)://host/...", config.HealthCheckURL)
	}

	if config.Fragment == nil && strings.TrimSpace(config.FragmentSpec) != "" {
		f, err := fragment.Parse(config.FragmentSpec)
		if err != nil {
			return nil, err
		}
		config.Fragment = f
	}
	if err := config.Fragment.Validate(); err != nil {
		return nil, err
	}

	// App mode validation and overrides — run BEFORE any privileged side
	// effects so unprivileged invocations fail fast without touching state.
	if config.Mode == "app" {
		if runtime.GOOS != "linux" {
			return nil, errors.New("app mode is only supported on Linux")
		}
		if missing := missingCaps(capSysAdmin, capNetAdmin); len(missing) > 0 {
			return nil, fmt.Errorf("app mode needs %s (creating a network namespace and its TUN). Run with sudo", strings.Join(missing, " and "))
		}
		if config.NamespaceName != "" {
			if err := netns.ValidateName(config.NamespaceName); err != nil {
				return nil, err
			}
		}
		// Default to shell mode if neither --shell nor --namespace is set.
		if !config.Shell && config.NamespaceName == "" {
			config.Shell = true
		}
		// The namespace's TUN is driven by a sing-box instance in the host
		// namespace, which dials the listener over the host loopback.
		config.ListenAddr = "127.0.0.1"
		config.InboundProtocol = "socks"
		config.InboundConfigLink = ""
	}

	// host-tun mode validation. Fail fast before touching state.
	if config.Mode == "host-tun" {
		if runtime.GOOS != "linux" {
			return nil, errors.New("host-tun mode is only supported on Linux")
		}
		if missing := missingCaps(capNetAdmin, capNetRaw); len(missing) > 0 {
			return nil, fmt.Errorf("host-tun mode needs %s (TUN routes and interface-bound dials). Run with sudo, or grant them with setcap", strings.Join(missing, " and "))
		}
		if config.BindInterface == "" {
			return nil, errors.New("host-tun mode requires BindInterface (CLI: --bind <iface>)")
		}
		// Refuse host-tun + deadman when the confirmation would have to
		// come from a stdin that isn't a terminal: the ENTER prompt is
		// unanswerable from /dev/null. Callers that deliver the
		// confirmation themselves (ExternalDeadmanConfirm) check this on
		// their side.
		if config.HostTunDeadman > 0 && !config.ExternalDeadmanConfirm && !hosttun.StdinIsTTY() {
			return nil, errors.New("tun deadman > 0 requires an interactive terminal on stdin; for unattended use pass --tun-deadman 0 and run under tmux/setsid/systemd")
		}
		if config.HostTunAddr6 != "" && !isNone(config.HostTunAddr6) {
			if p, err := netip.ParsePrefix(config.HostTunAddr6); err != nil || !p.Addr().Is6() {
				return nil, fmt.Errorf("invalid TUN IPv6 address %q (want an IPv6 CIDR such as %s, or \"none\")", config.HostTunAddr6, hosttun.DefaultTunAddr6)
			}
		}
		// Force SOCKS inbound on loopback. host-tun's TUN dials this
		// over lo; anything else risks a routing loop.
		config.ListenAddr = "127.0.0.1"
		config.InboundProtocol = "socks"
		config.InboundConfigLink = ""
	}

	s := &Service{
		config:         config,
		logger:         logger,
		rotationStatus: statusIdle,
		blacklist:      make(map[string]*blacklistEntry),
		proxyReady:     make(chan struct{}),
		deadmanConfirm: make(chan struct{}, 1),
	}

	// Crash recovery: restore OS proxy settings a previous `proxy system`
	// left behind when it died. Only in system mode (any other instance
	// has no business touching them) and only when the process that set
	// them is gone — otherwise a second instance would switch off the
	// proxy of a live one.
	if config.Mode == "system" {
		stale, err := sysproxy.LoadState()
		switch {
		case err != nil:
			return nil, fmt.Errorf("reading saved system proxy state: %w", err)
		case stale != nil && sysproxy.OwnerAlive(stale):
			// Two instances would each save the other's settings as "the
			// original" and restore them on exit.
			return nil, fmt.Errorf("another 'proxy system' (pid %d) is managing the OS proxy settings; stop it first", stale.Owner.Pid)
		case stale != nil:
			mgr, mgrErr := sysproxy.New()
			if mgrErr == nil {
				mgrErr = mgr.Restore(stale)
			}
			if mgrErr != nil {
				// Keep the state: it holds the user's original settings.
				return nil, fmt.Errorf("restoring the system proxy settings left by a crashed instance failed (%v); fix it and run 'xray-knife proxy restore'", mgrErr)
			}
			s.logf(customlog.Info, "Restored system proxy settings left by a crashed instance.\n")
			sysproxy.ClearState()
		}
	}

	// Crash recovery: clean up namespaces left by previous unclean exits
	// whose owners are no longer running.
	if config.Mode == "app" {
		for _, name := range netns.RecoverFromCrash() {
			s.logf(customlog.Info, "Removed stale namespace %q left by a crashed instance.\n", name)
		}
	}
	if config.Mode == "app" || config.Mode == "host-tun" {
		s.recoverTunLeftovers()
	}
	if config.Mode == "host-tun" {
		// Linux with CAP_NET_ADMIN (checked above): SO_MARK is available.
		s.mark = hosttun.DefaultMark()
	}

	// If no config links are provided via flags, fetch them from the
	// database. A fixed chain carries its own links, so it needs none.
	if len(s.config.ConfigLinks) == 0 && !s.fixedChain() {
		s.logf(customlog.Processing, "No config links provided, fetching from database...\n")
		dbLinks, err := database.GetConfigsForProxy()
		if err != nil {
			return nil, fmt.Errorf("could not fetch configs from database: %w", err)
		}
		if len(dbLinks) == 0 {
			return nil, errors.New("no configs in database. Run 'xray-knife subs fetch --all' to populate, or pass --config / --file / --stdin")
		}
		s.config.ConfigLinks = dbLinks
		s.logf(customlog.Success, "Loaded %d configs from the database for rotation pool.\n", len(s.config.ConfigLinks))
	}

	// Run pool assignment through setPool so the dedup pass stays in one
	// place; a future live-reload path will want this too.
	s.setPool(s.config.ConfigLinks)

	coreOpts := core.FactoryOptions{
		InsecureTLS:   config.InsecureTLS,
		Verbose:       config.Verbose,
		BindInterface: config.BindInterface,
		Fragment:      config.Fragment,
	}
	switch config.CoreType {
	case "xray":
		s.core = core.CoreFactoryWith(core.XrayCoreType, coreOpts)
	case "sing-box":
		s.core = core.CoreFactoryWith(core.SingboxCoreType, coreOpts)
	default:
		return nil, fmt.Errorf("allowed core types: (xray, sing-box), got: %s", config.CoreType)
	}

	inbound, err := s.createInbound()
	if err != nil {
		return nil, fmt.Errorf("failed to create inbound: %w", err)
	}
	s.inbound = inbound

	// When a custom inbound link is supplied via -I / --inbound-config, the
	// listener binds to the address/port encoded in that link, not the
	// --addr/--port flags. Reconcile s.config with the real listen target so
	// every consumer that dials our own listener (health check, host-tun,
	// namespace tunnel, system-proxy) points at the right port instead of the
	// flag defaults.
	if s.config.InboundConfigLink != "" {
		g := inbound.ConvertToGeneralConfig()
		if g.Address != "" {
			addr, err := NormalizeListenAddr(g.Address)
			if err != nil {
				return nil, fmt.Errorf("inbound config link: %w", err)
			}
			s.config.ListenAddr = addr
		}
		if g.Port != "" {
			s.config.ListenPort = g.Port
		}
	}

	if err := s.core.SetInbound(inbound); err != nil {
		return nil, fmt.Errorf("failed to set inbound: %w", err)
	}

	s.logf(customlog.Info, "==========INBOUND==========")
	if s.logger != nil {
		g := inbound.ConvertToGeneralConfig()
		s.logger.Printf("Protocol: %s\nListen: %s:%s\nLink: %s\n", g.Protocol, g.Address, g.Port, g.OrigLink)
	} else {
		fmt.Printf("\n%v%s: %v\n", inbound.DetailsStr(), color.RedString("Link"), inbound.GetLink())
	}
	s.logf(customlog.Info, "============================\n\n")

	// System mode: make sure we can drive the OS proxy settings now, but
	// only point the OS at us once the listener is actually up (Run).
	if config.Mode == "system" {
		mgr, err := sysproxy.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create system proxy manager: %w", err)
		}
		s.sysProxyManager = mgr
	}

	return s, nil
}

// recoverTunLeftovers removes what crashed tun runs left: a kill switch
// that kept blocking the network after its owner died (they are ours and
// nobody else can lift them), and ip rules of dead host-tun runs.
func (s *Service) recoverTunLeftovers() {
	removed, kept, err := killswitch.RemoveStale(false)
	for _, l := range removed {
		s.logf(customlog.Warning, "Removed kill switch %s left by a crashed instance.\n", l)
	}
	for _, l := range kept {
		s.logf(customlog.Warning, "Kill switch %s of a running instance is active; its rules apply to this run too.\n", l)
	}
	if err != nil {
		s.logf(customlog.Warning, "Checking for leftover kill switches: %v (run 'xray-knife proxy restore')\n", err)
	}
	if s.config.Mode != "host-tun" {
		return
	}
	recovered, _, _ := hosttun.RecoverFromCrash()
	for _, rec := range recovered {
		if rec.Err != nil {
			s.logf(customlog.Warning, "Leftover tun rules of pid %d: %v (run 'xray-knife proxy restore')\n", rec.Pid, rec.Err)
		} else if len(rec.Removed) > 0 {
			s.logf(customlog.Warning, "Removed tun leftovers of crashed pid %d: %s\n", rec.Pid, strings.Join(rec.Removed, ", "))
		}
	}
}

// NormalizeListenAddr turns the configured listen address into an IP
// literal. The cores fall back to all interfaces for anything they cannot
// parse as an IP, which turned "--addr localhost" into an open,
// unauthenticated proxy on the LAN — so resolve the common names here
// and reject everything else. The web API validates with it too.
func NormalizeListenAddr(addr string) (string, error) {
	a := strings.TrimSpace(addr)
	a = strings.TrimSuffix(strings.TrimPrefix(a, "["), "]")
	switch strings.ToLower(a) {
	case "":
		return "127.0.0.1", nil
	case "localhost", "localhost.", "ip6-localhost":
		if strings.EqualFold(a, "ip6-localhost") {
			return "::1", nil
		}
		return "127.0.0.1", nil
	}
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return "", fmt.Errorf("listen address %q must be an IP address (e.g. 127.0.0.1, 0.0.0.0 or ::1)", addr)
	}
	if ip.Zone() != "" {
		return "", fmt.Errorf("listen address %q: zoned IPv6 addresses are not supported", addr)
	}
	return ip.Unmap().String(), nil
}

// isNone reports whether v is one of the spellings that disable an option.
func isNone(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "none", "off", "false", "0", "disable", "disabled":
		return true
	}
	return false
}

// fixedChain reports whether the chain hops are given explicitly
// (--chain-links / --chain-file) rather than drawn from the pool.
func (s *Service) fixedChain() bool { return fixedChainConfig(s.config) }

func fixedChainConfig(c Config) bool {
	return strings.TrimSpace(c.ChainLinks) != "" || strings.TrimSpace(c.ChainFile) != ""
}

// ConfirmDeadman delivers the host-tun deadman confirmation. It returns
// true when the input belongs to the deadman — a caller forwarding stdin
// lines must then not treat it as a manual rotation request:
//
//   - while the deadman waits, it confirms the tunnel;
//   - before the prompt (the tunnel is still coming up) it is held back:
//     it cannot prove SSH survives a tunnel that is not up yet, so the
//     prompt asks for a fresh ENTER.
func (s *Service) ConfirmDeadman() bool {
	if s.deadmanPending.Load() {
		select {
		case s.deadmanConfirm <- struct{}{}:
		default:
		}
		return true
	}
	if s.deadmanArmed.Load() {
		s.earlyEnter.Store(true)
		return true
	}
	return false
}

// DeadmanPending reports whether host-tun is waiting for ConfirmDeadman.
func (s *Service) DeadmanPending() bool { return s.deadmanPending.Load() }

func (s *Service) setRotationStatus(status string) {
	s.mu.Lock()
	s.rotationStatus = status
	s.mu.Unlock()
}

// GetCurrentDetails returns a snapshot of the proxy state under the read lock.
func (s *Service) GetCurrentDetails() *Details {
	s.mu.RLock()
	defer s.mu.RUnlock()

	details := &Details{
		Inbound:          s.inbound.ConvertToGeneralConfig(),
		ActiveOutbound:   s.activeOutbound,
		RotationStatus:   s.rotationStatus,
		NextRotationTime: s.nextRotationTime,
		RotationInterval: s.config.RotationInterval,
		TotalConfigs:     len(s.config.ConfigLinks),
		ChainEnabled:     s.config.Chain,
		ChainRotation:    s.config.ChainRotation,
		DeadmanPending:   s.deadmanPending.Load(),
	}
	if s.activeChainHops != nil {
		hopInfos := make([]protocol.GeneralConfig, len(s.activeChainHops))
		for i, hop := range s.activeChainHops {
			hopInfos[i] = hop.ConvertToGeneralConfig()
		}
		details.ChainHopInfos = hopInfos
	}
	return details
}

// ConfigCount returns how many config links are loaded.
func (s *Service) ConfigCount() int {
	return len(s.config.ConfigLinks)
}

// logf is a helper to direct logs to either the web logger or the CLI customlog.
func (s *Service) logf(logType customlog.Type, format string, v ...interface{}) {
	if s.logger != nil {
		s.logger.Printf(format, v...)
	} else {
		customlog.Printf(logType, format, v...)
	}
}

// healthCheck pokes the live local listener so we exercise both sides of
// the proxy (the inbound is just as likely to wedge as the outbound). When
// the inbound speaks something exotic that no standard client can reach,
// it falls back to the older outbound-only test.
func (s *Service) healthCheck(ctx context.Context) bool {
	s.refreshUpstream()
	s.mu.RLock()
	activeOutbound := s.activeOutbound
	s.mu.RUnlock()
	if activeOutbound == nil || activeOutbound.Protocol == nil {
		return false
	}

	timeout := time.Duration(s.config.MaximumAllowedDelay) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	if client, ok := s.makeLocalProxyClient(timeout); ok {
		return doHealthGET(ctx, client, s.config.HealthCheckURL, timeout)
	}

	// Fallback: outbound-only test via a fresh instance.
	client, instance, err := s.core.MakeHttpClient(ctx, activeOutbound.Protocol, timeout)
	if err != nil {
		return false
	}
	defer instance.Close()
	return doHealthGET(ctx, client, s.config.HealthCheckURL, timeout)
}

// makeLocalProxyClient returns an http.Client wired up to talk to the
// inbound listener directly. Returns ok=false when the inbound isn't
// something a vanilla SOCKS5/HTTP client can speak.
func (s *Service) makeLocalProxyClient(timeout time.Duration) (*http.Client, bool) {
	target := net.JoinHostPort(dialableAddr(s.config.ListenAddr), s.config.ListenPort)

	switch in := s.inbound.(type) {
	case *pkgxray.Socks:
		return socksHealthClient(target, in.Username, in.Password, timeout), true
	case *pkgsingbox.Socks:
		return socksHealthClient(target, in.Username, in.Password, timeout), true
	case *pkgxray.Http, *pkgsingbox.Http:
		proxyURL, err := url.Parse("http://" + target)
		if err != nil {
			return nil, false
		}
		tr := &http.Transport{
			Proxy:                 http.ProxyURL(proxyURL),
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
		}
		return &http.Client{Transport: tr, Timeout: timeout}, true
	default:
		return nil, false
	}
}

func socksHealthClient(target, user, pass string, timeout time.Duration) *http.Client {
	var auth *xproxy.Auth
	if user != "" || pass != "" {
		auth = &xproxy.Auth{User: user, Password: pass}
	}
	dialer, err := xproxy.SOCKS5("tcp", target, auth, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// The SOCKS5 dialer implements ContextDialer; use it so a
			// canceled health check (shutdown, rotation) stops dialing.
			if cd, ok := dialer.(xproxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// dialableAddr maps a wildcard listen address to the loopback address a
// local client (health check, OS proxy settings) should connect to.
func dialableAddr(listen string) string {
	switch listen {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::":
		return "::1"
	}
	return listen
}

func doHealthGET(ctx context.Context, client *http.Client, target string, timeout time.Duration) bool {
	if client == nil {
		return false
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", target, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	// Any non-error answer proves the path works; custom targets such
	// as generate_204 endpoints do not answer 200.
	return resp.StatusCode < http.StatusBadRequest
}

// setPool installs links as the rotation pool, stripping duplicates first.
// All pool assignment goes through here so a future live-reload path can't
// reintroduce dupes.
func (s *Service) setPool(links []string) {
	unique, removed := pkghttp.DeduplicateLinks(links)
	s.config.ConfigLinks = unique
	if removed > 0 {
		s.logf(customlog.Info, "Removed %d duplicate configs from pool (%d unique remain).\n", removed, len(unique))
	}
}

// recordStrike bumps the failure counter for link and, once strikes reach
// the configured threshold, marks it blacklisted for BlacklistDuration
// seconds. Safe to call with an empty link or when blacklisting is disabled.
func (s *Service) recordStrike(link, reason string) {
	if s.config.BlacklistStrikes == 0 || link == "" {
		return
	}
	entry, exists := s.blacklist[link]
	if !exists {
		entry = &blacklistEntry{}
		s.blacklist[link] = entry
	}
	entry.strikes++
	if entry.strikes >= int(s.config.BlacklistStrikes) && entry.blacklistedUntil.IsZero() {
		entry.blacklistedUntil = time.Now().Add(time.Duration(s.config.BlacklistDuration) * time.Second)
		s.logf(customlog.Warning, "Blacklisted %s for %ds after %d strikes (%s)\n", link, s.config.BlacklistDuration, entry.strikes, reason)
	}
}

// Close restores the system proxy settings if they were modified, and cleans up state.
func (s *Service) Close() {
	// Tear down host-tun first so its routes go away before the
	// upstream proxy listener does.
	s.tunMu.Lock()
	guarded := s.killSwitch != nil || s.tunBypass != nil || s.tunStaticV6 != nil
	s.tunMu.Unlock()
	if s.hostTunInstance != nil || guarded {
		s.logf(customlog.Processing, "Stopping host-tun tunnel...\n")
		s.teardownHostTun()
	}
	if s.restoreResolver != nil {
		s.restoreResolver()
		s.restoreResolver = nil
	}

	// Tear down namespace resources (reverse order: tunnel first, then namespace).
	if s.nsTunnel != nil {
		s.logf(customlog.Processing, "Stopping namespace tunnel...\n")
		if err := s.nsTunnel.Close(); err != nil {
			s.logf(customlog.Warning, "Tunnel close returned error: %v\n", err)
		}
		// Wait briefly for the TUN device to disappear from the namespace
		// before we delete the namespace itself; otherwise the kernel may
		// emit "device busy" warnings or leave a stray link.
		if s.nsManager != nil {
			s.nsManager.WaitForLinkGone(s.nsCfg.TunName, 2*time.Second)
		}
		s.nsTunnel = nil
	}
	if s.nsManager != nil {
		s.logf(customlog.Processing, "Cleaning up network namespace...\n")
		if err := s.nsManager.Close(); err != nil {
			s.logf(customlog.Failure, "Failed to clean up namespace: %v\n", err)
		} else {
			s.logf(customlog.Success, "Network namespace cleaned up.\n")
		}
		if err := netns.ClearState(); err != nil {
			s.logf(customlog.Warning, "Failed to clear namespace state: %v\n", err)
		}
		s.nsManager = nil
	}

	s.mu.Lock()
	mgr, prev := s.sysProxyManager, s.prevProxySettings
	s.sysProxyManager, s.prevProxySettings = nil, nil
	s.mu.Unlock()
	if mgr != nil && prev != nil {
		s.logf(customlog.Processing, "Restoring system proxy settings...\n")
		if err := mgr.Restore(prev); err != nil {
			// Keep the state file so the next `proxy system` run retries.
			s.logf(customlog.Failure, "Failed to restore system proxy settings: %v\n", err)
		} else {
			s.logf(customlog.Success, "System proxy settings restored.\n")
			sysproxy.ClearState()
		}
	}
}

// setupSystemProxy points the OS proxy settings at the running listener.
// Called once the listener is up, so the OS never points at a port
// nobody listens on. A failed Set is rolled back: some backends (macOS
// per-service loop, GNOME's "manual" mode written first) change part of
// the configuration before failing.
func (s *Service) setupSystemProxy() error {
	mgr := s.sysProxyManager
	prev, err := mgr.Get()
	if err != nil {
		return fmt.Errorf("failed to read current system proxy settings: %w", err)
	}
	if err := sysproxy.SaveState(prev); err != nil {
		return fmt.Errorf("failed to save system proxy state for crash recovery: %w", err)
	}
	addr := dialableAddr(s.config.ListenAddr)
	if err := mgr.Set(addr, s.config.ListenPort); err != nil {
		var manual *sysproxy.ManualConfigError
		if errors.As(err, &manual) {
			s.logf(customlog.Warning, "%v\n", err)
			s.mu.Lock()
			s.prevProxySettings = prev
			s.mu.Unlock()
			return nil
		}
		if rerr := mgr.Restore(prev); rerr != nil {
			s.logf(customlog.Failure, "Rolling back partial system proxy change failed: %v (the saved state is kept for the next run)\n", rerr)
		} else {
			sysproxy.ClearState()
		}
		return fmt.Errorf("failed to set system proxy: %w", err)
	}
	s.mu.Lock()
	s.prevProxySettings = prev
	s.mu.Unlock()
	s.logf(customlog.Success, "System proxy configured: %s\n", net.JoinHostPort(addr, s.config.ListenPort))
	return nil
}

// setupHostTun builds the exclusion list, runs preflight, then starts
// the host-tun sing-box instance in the root network namespace. Caller
// must already have a local SOCKS listener up (we dial 127.0.0.1).
func (s *Service) setupHostTun(ctx context.Context) error {
	socksUser, socksPass := s.inboundCredentials()

	port, _ := strconv.ParseUint(s.config.ListenPort, 10, 16)
	htCfg := hosttun.DefaultConfig(uint16(port))
	htCfg.PhysIface = s.config.BindInterface
	htCfg.SocksUser = socksUser
	htCfg.SocksPass = socksPass
	if s.config.HostTunName != "" {
		htCfg.TunName = s.config.HostTunName
	}
	if s.config.HostTunAddr != "" {
		htCfg.TunAddr = s.config.HostTunAddr
	}
	v6Stack, v6Enabled := hosttun.IPv6Status()
	switch {
	case !v6Stack:
		// No IPv6 in the kernel: nothing to capture, nothing can leak, and
		// sing-tun could not install IPv6 rules anyway.
		htCfg.TunAddr6 = ""
		s.logf(customlog.Info, "host-tun: this host has no IPv6 stack; capturing IPv4 only.\n")
	case !v6Enabled:
		htCfg.TunAddr6 = ""
		s.logf(customlog.Warning, "host-tun: IPv6 is disabled (net.ipv6.conf.*.disable_ipv6); not capturing IPv6. If it gets re-enabled while the tunnel runs, IPv6 bypasses it unless --kill-switch is on.\n")
	case isNone(s.config.HostTunAddr6):
		htCfg.TunAddr6 = ""
		if s.config.KillSwitch {
			s.logf(customlog.Warning, "host-tun: IPv6 capture disabled; with the kill switch IPv6 is blocked except for SSH peers and excluded ranges.\n")
		} else {
			s.logf(customlog.Warning, "host-tun: IPv6 capture disabled; IPv6 traffic bypasses the tunnel.\n")
		}
	case s.config.HostTunAddr6 != "":
		htCfg.TunAddr6 = s.config.HostTunAddr6
	}
	if s.config.HostTunMTU != 0 {
		htCfg.TunMTU = s.config.HostTunMTU
	}
	if s.config.DNS != "" {
		htCfg.DNS = s.config.DNS
	}
	if s.config.DNSType != "" {
		htCfg.DNSType = s.config.DNSType
	}

	// Build extra exclude list from user flag and (optionally) RFC1918.
	var extra []string
	if s.config.HostTunExclude != "" {
		for _, c := range strings.Split(s.config.HostTunExclude, ",") {
			c = strings.TrimSpace(c)
			if c != "" {
				extra = append(extra, c)
			}
		}
	}
	if s.config.HostTunExcludePrivate {
		extra = append(extra,
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"fc00::/7",
		)
	}

	// The proxy servers are not part of the static excludes: only the ones
	// in use are kept off the TUN, per rotation, by the bypass rules
	// (resolving the whole pool here leaked it to the ISP resolver and
	// installed a route per entry).
	ex := hosttun.BuildExcludes(ctx, hosttun.ExcludeOptions{
		PhysIface:      s.config.BindInterface,
		ExtraCIDRs:     extra,
		DNSServers:     hosttun.SystemDNSServers(),
		ResolveTimeout: 3 * time.Second,
	})
	htCfg.RouteExcludeCIDRs = ex.CIDRs
	htCfg.DirectCIDRs = ex.Direct
	s.hostTunCfg = htCfg

	for _, w := range ex.Warnings {
		s.logf(customlog.Warning, "host-tun excludes: %s\n", w)
	}
	if len(ex.SSHClients) > 0 {
		s.logf(customlog.Info, "host-tun: SSH peer(s) %s kept off the TUN.\n", strings.Join(ex.SSHClients, ", "))
	} else {
		s.logf(customlog.Info, "host-tun: no SSH session detected; skipping SSH exclusion.\n")
	}
	if len(ex.Direct) > 0 {
		s.logf(customlog.Info, "host-tun: resolver(s) %s routed into the TUN so their DNS is hijacked.\n", strings.Join(ex.Direct, ", "))
	}
	s.logf(customlog.Info, "host-tun: %d destinations excluded from TUN capture.\n", len(ex.CIDRs))

	// Preflight: refuse to bring up TUN if the planned name already
	// exists, or if the route to the SSH client is already broken.
	sshIP := ""
	if len(ex.SSHClients) > 0 {
		sshIP = ex.SSHClients[0]
	}
	if err := hosttun.Preflight(ctx, sshIP, htCfg.TunName); err != nil {
		return fmt.Errorf("host-tun preflight: %w", err)
	}

	// StrictRoute (kill switch) makes an address family without a TUN
	// address unreachable. Without an IPv6 stack that rule cannot even be
	// installed, and no IPv6 can leak.
	htCfg.StrictRoute = s.config.KillSwitch && v6Stack
	s.logf(customlog.Processing, "host-tun: starting TUN %s on %s %s ...\n", htCfg.TunName, htCfg.TunAddr, htCfg.TunAddr6)
	inst, err := hosttun.Start(ctx, &htCfg)
	if err != nil {
		return fmt.Errorf("host-tun start: %w", err)
	}
	s.hostTunInstance = inst
	s.hostTunCfg = htCfg
	if err := hosttun.SaveState(&hosttun.State{
		TunName:        htCfg.TunName,
		TableIndex:     htCfg.RouteTableIndex,
		RuleIndex:      htCfg.RouteRuleIndex,
		BypassPriority: htCfg.BypassPriority,
	}); err != nil {
		s.logf(customlog.Warning, "host-tun: could not record state for crash recovery: %v\n", err)
	}

	bypass := hosttun.NewBypass(htCfg.BypassPriority)
	s.tunMu.Lock()
	s.tunBypass = bypass
	s.tunMu.Unlock()
	if mark := s.socketMark(); mark != 0 {
		if err := bypass.SetMark(mark); err != nil {
			// The listener's sockets stay marked (harmless without a
			// rule); exceptions fall back to the entry server's addresses.
			s.logf(customlog.Warning, "host-tun: fwmark bypass rule failed (%v); falling back to per-destination rules.\n", err)
			s.tunMu.Lock()
			s.mark = 0
			s.tunMu.Unlock()
		}
	}

	// StrictRoute's IPv6 "unreachable" rule sits at the start of sing-tun's
	// block, ahead of any route exclude, so without IPv6 capture the IPv6
	// SSH peers and excluded ranges need their own rules ahead of it.
	if htCfg.StrictRoute && htCfg.TunAddr6 == "" {
		var v6 []netip.Prefix
		for _, c := range ex.CIDRs {
			if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is6() {
				v6 = append(v6, p)
			}
		}
		static := hosttun.NewBypass(htCfg.BypassPriority)
		if err := static.Set(v6); err != nil {
			s.logf(customlog.Warning, "host-tun: IPv6 exception rules: %v\n", err)
		}
		s.tunMu.Lock()
		s.tunStaticV6 = static
		s.tunMu.Unlock()
	}

	upstream := resolveServers(ctx, s.resolver, hopLinks(entryHop(s.currentHops())))
	if s.config.KillSwitch {
		mark := s.socketMark()
		ksCfg := killswitch.Config{
			TunName: htCfg.TunName,
			Allow:   append(append([]string{}, ex.CIDRs...), ex.Direct...),
			DNS:     s.bootstrapDNS,
			Mark:    mark,
		}
		if mark == 0 {
			// Fallback: without a socket mark the live upstream is let
			// through by destination (so is anything else sent there).
			ksCfg.Upstream = upstream
		}
		ks, err := killswitch.Enable(ksCfg)
		if err != nil {
			s.teardownHostTun()
			return fmt.Errorf("kill switch: %w", err)
		}
		s.tunMu.Lock()
		s.killSwitch = ks
		s.tunMu.Unlock()
		s.logf(customlog.Success, "Kill switch on (%s): traffic that does not go through %s is blocked.\n", ks.Backend(), htCfg.TunName)
	}
	s.applyUpstream(upstream)
	s.logf(customlog.Success, "host-tun: tunnel up.\n")
	return nil
}

// inboundCredentials returns the SOCKS credentials of the listener.
func (s *Service) inboundCredentials() (user, pass string) {
	switch in := s.inbound.(type) {
	case *pkgsingbox.Socks:
		return in.Username, in.Password
	case *pkgxray.Socks:
		return in.Username, in.Password
	}
	return "", ""
}

// startRunner launches the outbound runner that matches the config
// (chain, single or rotation) in its own goroutine. A panic in the runner
// is turned into an error so the caller still tears down TUN/namespace
// state instead of the process dying with host routes changed.
func (s *Service) startRunner(ctx context.Context, forceRotate <-chan struct{}) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("proxy runner panicked: %v", r)
			}
		}()
		switch {
		case s.config.Chain:
			errCh <- s.runChainMode(ctx, forceRotate)
		case len(s.config.ConfigLinks) == 1:
			errCh <- s.runSingleMode(ctx, s.config.ConfigLinks[0])
		default:
			errCh <- s.runRotationMode(ctx, forceRotate)
		}
	}()
	return errCh
}

// runWithListener starts the runner, waits for the listener to be up,
// then runs setup (which brings up whatever consumes the listener: the
// OS proxy settings, a TUN, a namespace). If setup fails the runner is
// stopped. On success it returns the runner's error channel and cancel.
func (s *Service) runWithListener(ctx context.Context, forceRotate <-chan struct{}, setup func() error) (<-chan error, context.CancelFunc, error) {
	runCtx, runCancel := context.WithCancel(ctx)
	errCh := s.startRunner(runCtx, forceRotate)

	select {
	case <-s.proxyReady:
	case err := <-errCh:
		runCancel()
		return nil, nil, err
	case <-ctx.Done():
		runCancel()
		<-errCh
		return nil, nil, nil
	}

	if err := setup(); err != nil {
		runCancel()
		<-errCh
		return nil, nil, err
	}
	return errCh, runCancel, nil
}

// runSystemMode runs the proxy and registers it as the OS proxy once the
// listener is up. Close restores the previous settings.
func (s *Service) runSystemMode(ctx context.Context, forceRotate <-chan struct{}) error {
	errCh, cancel, err := s.runWithListener(ctx, forceRotate, s.setupSystemProxy)
	if err != nil || errCh == nil {
		return err
	}
	defer cancel()
	return <-errCh
}

// runHostTunMode brings up the local SOCKS proxy, then the host-wide TUN,
// then runs the deadman timer; if the user fails to ACK in time, tears
// the TUN down to restore SSH.
func (s *Service) runHostTunMode(ctx context.Context, forceRotate <-chan struct{}) error {
	// Resolve proxy server names outside the tunnel: our own lookups use
	// s.resolver directly. The cores' lookups can only be redirected by
	// replacing net.DefaultResolver, which the CLI (GlobalResolver) does
	// before any core starts; a long-running host like the web UI does
	// not, as it would race its other lookups and send them all around
	// the tunnel.
	servers := hosttun.BootstrapDNSServers(hosttun.SystemDNSServers(), s.config.DNS)
	s.bootstrapDNS = servers
	if r, err := hosttun.NewBoundResolver(s.config.BindInterface, servers, s.socketMark()); err != nil {
		s.logf(customlog.Warning, "host-tun: could not bind the bootstrap resolver to %s: %v; configs using hostnames may stall\n", s.config.BindInterface, err)
	} else {
		s.resolver = r
		if s.config.GlobalResolver {
			s.restoreResolver = hosttun.InstallGlobalResolver(r)
		} else {
			s.logf(customlog.Warning, "host-tun: xray resolves proxy server hostnames with the system resolver here; prefer IP-based configs or the CLI.\n")
		}
	}

	if s.config.HostTunDeadman > 0 {
		s.deadmanArmed.Store(true)
		defer s.deadmanArmed.Store(false)
	}
	errCh, runCancel, err := s.runWithListener(ctx, forceRotate, func() error { return s.setupHostTun(ctx) })
	if err != nil || errCh == nil {
		return err
	}
	defer runCancel()

	// Deadman switch: prompt user to press ENTER within the configured
	// window. If they don't, tear down TUN (restore SSH path).
	deadmanDur := time.Duration(s.config.HostTunDeadman) * time.Second
	if deadmanDur > 0 {
		s.logf(customlog.Warning, "%s", hosttun.DeadmanInstructions(deadmanDur))
		if s.earlyEnter.Load() {
			s.logf(customlog.Warning, "host-tun: a key press arrived before the tunnel was up; press ENTER again now to confirm.\n")
		}
		s.deadmanPending.Store(true)
		if !s.config.ExternalDeadmanConfirm {
			// Read only now: a keystroke typed during startup must not
			// count as the confirmation.
			go func() {
				var buf [1]byte
				if _, err := os.Stdin.Read(buf[:]); err == nil {
					s.ConfirmDeadman()
				}
			}()
		}
		result := hosttun.RunDeadman(ctx, deadmanDur, s.deadmanConfirm)
		s.deadmanPending.Store(false)
		s.deadmanArmed.Store(false)
		switch result {
		case hosttun.DeadmanExpired:
			s.logf(customlog.Failure, "host-tun: deadman timer expired without confirmation. Tearing down to restore SSH.\n")
			s.teardownHostTun()
			runCancel()
			<-errCh
			return fmt.Errorf("host-tun: deadman expired")
		case hosttun.DeadmanCanceled:
			return <-errCh
		case hosttun.DeadmanConfirmed:
			s.logf(customlog.Success, "host-tun: confirmed. Running until Ctrl+C.\n")
		}
	} else {
		s.logf(customlog.Warning, "host-tun: deadman disabled. SSH loss is irrecoverable without console access.\n")
	}

	return <-errCh
}

// teardownHostTun closes the host-tun sing-box instance and lifts the
// kill switch and bypass rules with it (the deadman relies on that to
// give SSH its route back). Safe to call multiple times.
func (s *Service) teardownHostTun() {
	s.liftTunGuards()
	if s.hostTunInstance != nil {
		if err := s.hostTunInstance.Close(); err != nil {
			s.logf(customlog.Warning, "host-tun close returned error: %v\n", err)
		}
		s.hostTunInstance = nil
	}
}

// liftTunGuards removes the kill switch and the bypass rules. It is also
// the emergency path of a forced exit, so it only touches state under
// tunMu and never blocks on the running proxy.
func (s *Service) liftTunGuards() {
	s.tunMu.Lock()
	ks, bypass, static := s.killSwitch, s.tunBypass, s.tunStaticV6
	s.killSwitch, s.tunBypass, s.tunStaticV6 = nil, nil, nil
	s.tunMu.Unlock()

	if ks != nil {
		if err := ks.Disable(); err != nil {
			s.logf(customlog.Failure, "Kill switch removal failed: %v (run 'xray-knife proxy restore')\n", err)
		} else {
			s.logf(customlog.Info, "Kill switch off.\n")
		}
	}
	failed := false
	for _, b := range []*hosttun.Bypass{bypass, static} {
		if b == nil {
			continue
		}
		if err := b.Close(); err != nil {
			failed = true
			s.logf(customlog.Warning, "host-tun: removing bypass rules: %v\n", err)
		}
	}
	if bypass != nil && !failed {
		// Keep the state for 'proxy restore' when rules are still there.
		hosttun.ClearState()
	}
}

// EmergencyCleanup is the best-effort teardown for a forced exit (a
// second Ctrl+C while Close is stuck): it lifts the kill switch and the
// bypass rules and puts the OS proxy settings back, so the host is not
// left locked out or pointing at a dead proxy. It gives up after timeout.
// The TUN and the namespace go away with the process.
func (s *Service) EmergencyCleanup(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.emergencyOnce.Do(func() {
			s.liftTunGuards()
			if s.restoreResolver != nil {
				s.restoreResolver()
			}
			s.mu.RLock()
			mgr, prev := s.sysProxyManager, s.prevProxySettings
			s.mu.RUnlock()
			if mgr != nil && prev != nil {
				if err := mgr.Restore(prev); err == nil {
					sysproxy.ClearState()
				}
			}
		})
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// signalProxyReady is called once after the first proxy instance is started
// so that the app mode setup can proceed.
func (s *Service) signalProxyReady() {
	s.proxyReadyOnce.Do(func() { close(s.proxyReady) })
}

// appNamespaceName is the namespace app mode creates.
func (s *Service) appNamespaceName() string {
	if s.config.NamespaceName != "" {
		return s.config.NamespaceName
	}
	return fmt.Sprintf("xk-%d", os.Getpid())
}

// setupAppMode creates the network namespace and its TUN tunnel.
// It must be called after the proxy instance is listening.
func (s *Service) setupAppMode(ctx context.Context) error {
	nsName := s.appNamespaceName()
	socksUser, socksPass := s.inboundCredentials()

	port, _ := strconv.ParseUint(s.config.ListenPort, 10, 16)
	nsCfg := netns.DefaultConfig(uint16(port))
	nsCfg.Name = nsName
	nsCfg.ProxyAddr = dialableAddr(s.config.ListenAddr)
	nsCfg.SocksUser = socksUser
	nsCfg.SocksPass = socksPass
	if s.config.DNS != "" {
		nsCfg.DNS = s.config.DNS
	}
	if s.config.DNSType != "" {
		nsCfg.DNSType = s.config.DNSType
	}
	s.nsCfg = nsCfg

	// Persist state for crash recovery before creating anything (Pid +
	// BootID are stamped by SaveState; RecoverFromCrash uses them to skip
	// live owners).
	state := &netns.State{Name: nsName}
	if err := netns.SaveState(state); err != nil {
		return fmt.Errorf("failed to save namespace state: %w", err)
	}

	ns, err := netns.Setup(nsCfg)
	if err != nil {
		netns.ClearState()
		return fmt.Errorf("failed to set up namespace: %w", err)
	}
	s.nsManager = ns
	if dir := ns.ResolvDir(); dir != "" {
		state.ResolvDir = dir
		if err := netns.SaveState(state); err != nil {
			s.logf(customlog.Warning, "Failed to update namespace state: %v\n", err)
		}
	}

	tunnel, err := netns.StartTunnel(ctx, nsName, nsCfg)
	if err != nil {
		ns.Close()
		netns.ClearState()
		s.nsManager = nil
		return fmt.Errorf("failed to start tunnel in namespace: %w", err)
	}
	s.nsTunnel = tunnel

	if s.config.KillSwitch {
		s.enableNamespaceKillSwitch(ctx, nsName, nsCfg.TunName)
	}

	s.logf(customlog.Success, "Network namespace '%s' is ready.\n", nsName)
	return nil
}

// enableNamespaceKillSwitch adds a firewall inside the namespace that only
// lets traffic out through the TUN. The namespace already fails closed —
// it has no other interface — so this is defence in depth, and a missing
// nft is only a warning.
func (s *Service) enableNamespaceKillSwitch(ctx context.Context, nsName, tun string) {
	cmd, _, err := netns.Command(ctx, nsName, []string{"nft", "-f", "-"}, nil)
	if err == nil {
		cmd.Stdin = strings.NewReader(killswitch.NamespaceRules(tun))
		cmd.Stdout, cmd.Stderr = nil, nil
		var out []byte
		if out, err = cmd.CombinedOutput(); err != nil {
			err = fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if err != nil {
		s.logf(customlog.Warning, "Kill switch: no extra firewall inside the namespace (%v); it still fails closed because the TUN is its only way out.\n", err)
		return
	}
	s.logf(customlog.Success, "Kill switch on inside namespace '%s'.\n", nsName)
}

// Run blocks until the context is canceled, running either single or rotation mode.
func (s *Service) Run(ctx context.Context, forceRotate <-chan struct{}) error {
	if len(s.config.ConfigLinks) == 0 && !s.fixedChain() {
		return errors.New("no configuration links provided")
	}

	switch s.config.Mode {
	case "app":
		return s.runAppMode(ctx, forceRotate)
	case "host-tun":
		return s.runHostTunMode(ctx, forceRotate)
	case "system":
		return s.runSystemMode(ctx, forceRotate)
	}

	return <-s.startRunner(ctx, forceRotate)
}

// runAppMode starts the proxy in a goroutine, waits for it to be ready,
// sets up the namespace and tunnel, then either launches a shell or
// waits for the proxy to finish.
func (s *Service) runAppMode(ctx context.Context, forceRotate <-chan struct{}) error {
	errCh, runCancel, err := s.runWithListener(ctx, forceRotate, func() error { return s.setupAppMode(ctx) })
	if err != nil || errCh == nil {
		return err
	}
	defer runCancel()

	nsName := s.appNamespaceName()
	if s.config.Shell {
		var cred *netns.Credential
		if !s.config.ShellAsRoot {
			cred = netns.SudoCredential()
		}
		if cred != nil {
			s.logf(customlog.Info, "Launching shell in namespace as %s (uid %d). Type 'exit' to shut down.\n", cred.Username, cred.Uid)
		} else {
			s.logf(customlog.Info, "Launching shell in namespace. Type 'exit' to shut down.\n")
		}
		shellErr := s.nsManager.Shell(ctx, cred, func(w string) { s.logf(customlog.Warning, "%s\n", w) })
		// Shell exited — cancel the proxy and wait for it to finish.
		runCancel()
		<-errCh
		// Treat signal-induced exits (e.g. Ctrl+C → exit code 130) as clean
		// shutdowns rather than errors.
		if ee, ok := shellErr.(*osexec.ExitError); ok && ee.ExitCode() >= 128 {
			return nil
		}
		return shellErr
	}

	// Named namespace mode: print instructions and wait.
	s.logf(customlog.Info, "Use: xray-knife exec %s -- <command>   (or: sudo ip netns exec %s <command>)\n", nsName, nsName)
	s.logf(customlog.Info, "Press Ctrl+C to shut down.\n")

	return <-errCh
}

func (s *Service) runSingleMode(ctx context.Context, link string) error {
	outbound, err := s.core.CreateProtocol(link)
	if err != nil {
		return fmt.Errorf("couldn't parse the single config %s: %w", link, err)
	}
	if err := outbound.Parse(); err != nil {
		return fmt.Errorf("failed to parse single outbound config: %w", err)
	}

	s.mu.Lock()
	s.activeOutbound = &pkghttp.Result{ConfigLink: link, Protocol: outbound}
	s.mu.Unlock()

	s.logf(customlog.Info, "==========OUTBOUND==========")
	if s.logger != nil {
		g := outbound.ConvertToGeneralConfig()
		s.logger.Printf("Protocol: %s\nRemark: %s\nAddr: %s:%s\nLink: %s\n", g.Protocol, g.Remark, g.Address, g.Port, g.OrigLink)
	} else {
		fmt.Printf("\n%v%s: %v\n", outbound.DetailsStr(), color.RedString("Link"), outbound.GetLink())
	}
	s.logf(customlog.Info, "============================\n")

	instance, err := s.newListener(ctx, outbound)
	if err != nil {
		return fmt.Errorf("error making instance: %w", err)
	}
	defer func() {
		if instance != nil {
			instance.Close()
		}
	}()

	if err := instance.Start(); err != nil {
		return fmt.Errorf("error starting instance: %w", err)
	}
	s.logf(customlog.Success, "Started listening for new connections...\n")
	s.activeHopsChanged([]protocol.Protocol{outbound})
	s.signalProxyReady()

	// Single-config mode can't rotate to a different outbound when its one
	// connection dies, but we can at least try to bring the same outbound
	// back up if the local listener stops responding. Disabled when
	// HealthCheckInterval is 0.
	var healthTickerC <-chan time.Time
	if s.config.HealthCheckInterval > 0 {
		t := time.NewTicker(time.Duration(s.config.HealthCheckInterval) * time.Second)
		healthTickerC = t.C
		defer t.Stop()
	}
	threshold := int(s.config.HealthFailThreshold)
	if threshold <= 0 {
		threshold = defaultHealthFailThresh
	}
	fails := 0

	for {
		select {
		case <-ctx.Done():
			s.logf(customlog.Processing, "Shutting down proxy...\n")
			return nil
		case <-healthTickerC:
			if s.healthCheck(ctx) {
				fails = 0
				continue
			}
			fails++
			s.logf(customlog.Warning, "Health check failed (%d/%d) in single-config mode.", fails, threshold)
			if fails < threshold {
				continue
			}
			fails = 0
			// Rebuild the outbound behind the running listener when the
			// core allows it, so the port stays bound.
			if sw, ok := instance.(hotSwapper); ok {
				s.logf(customlog.Processing, "Rebuilding outbound...")
				if err := sw.Swap(ctx, []protocol.Protocol{outbound}, s.swapGrace()); err != nil {
					s.logf(customlog.Warning, "Rebuilding outbound failed: %v", err)
				}
				continue
			}
			s.logf(customlog.Processing, "Restarting outbound instance...")
			instance.Close()
			newInst, err := s.newListener(ctx, outbound)
			if err != nil {
				return fmt.Errorf("failed to rebuild instance after health failure: %w", err)
			}
			if err := newInst.Start(); err != nil {
				newInst.Close()
				return fmt.Errorf("failed to restart instance after health failure: %w", err)
			}
			instance = newInst
		}
	}
}

// healthTracker counts consecutive health-check failures so a single
// flaky probe does not trigger a rotation.
type healthTracker struct {
	threshold int
	fails     int
}

func newHealthTracker(configured uint16) *healthTracker {
	t := int(configured)
	if t <= 0 {
		t = defaultHealthFailThresh
	}
	return &healthTracker{threshold: t}
}

// record registers one probe result and reports whether it tripped the
// threshold (which also resets the count).
func (h *healthTracker) record(ok bool) bool {
	if ok {
		h.fails = 0
		return false
	}
	h.fails++
	if h.fails < h.threshold {
		return false
	}
	h.fails = 0
	return true
}

func (h *healthTracker) reset() { h.fails = 0 }

// Stall backoff bounds: a rotation that finds nothing is retried after
// 15s, then 30s, 60s, ... up to 5 minutes, instead of re-testing up to
// 200 configs every 30s forever.
const (
	stallBackoffMin = 15 * time.Second
	stallBackoffMax = 5 * time.Minute
)

type stallBackoff struct{ next time.Duration }

// failure returns the delay before the next retry and doubles it.
func (b *stallBackoff) failure() time.Duration {
	if b.next == 0 {
		b.next = stallBackoffMin
	} else if b.next *= 2; b.next > stallBackoffMax {
		b.next = stallBackoffMax
	}
	return b.next
}

func (b *stallBackoff) reset() { b.next = 0 }

// nextWait returns how long to wait before the next rotation attempt:
// the stall backoff (capped by the interval) after a failed rotation,
// else the configured interval. Zero means "no timed rotation".
func (s *Service) nextWait(stalled bool, b *stallBackoff) time.Duration {
	interval := time.Duration(s.config.RotationInterval) * time.Second
	if !stalled {
		return interval
	}
	d := b.failure()
	if interval > 0 && d > interval {
		d = interval
	}
	return d
}

// armRotation starts the rotation timer for d (nil channel when d is 0)
// and publishes the due time in Details.
func (s *Service) armRotation(d time.Duration) (*time.Timer, <-chan time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d <= 0 {
		s.nextRotationTime = time.Time{}
		return nil, nil
	}
	s.nextRotationTime = time.Now().Add(d)
	t := time.NewTimer(d)
	return t, t.C
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

func (s *Service) runRotationMode(ctx context.Context, forceRotate <-chan struct{}) error {
	examiner, err := s.createExaminer()
	if err != nil {
		return err
	}

	var currentInstance protocol.Instance
	defer func() {
		if currentInstance != nil {
			currentInstance.Close()
		}
	}()

	// Initial setup — no old listener to release yet.
	s.setRotationStatus(statusTesting)
	instance, current, err := s.findAndStartWorkingConfig(ctx, examiner, "", nil, nil)
	if err != nil {
		s.logf(customlog.Failure, "No working config found on startup: %v", err)
		return err
	}
	currentInstance = instance
	s.setRotationStatus(statusIdle)
	s.signalProxyReady()

	// Health-check ticker is optional; a zero interval disables it.
	var healthTickerC <-chan time.Time
	if s.config.HealthCheckInterval > 0 {
		healthTicker := time.NewTicker(time.Duration(s.config.HealthCheckInterval) * time.Second)
		healthTickerC = healthTicker.C
		defer healthTicker.Stop()
	}
	health := newHealthTracker(s.config.HealthFailThreshold)

	var backoff stallBackoff
	stalled := false
	for {
		wait := s.nextWait(stalled, &backoff)
		timer, timerC := s.armRotation(wait)
		switch {
		case wait > 0:
			s.logf(customlog.Info, "Next rotation in %v. Current outbound: %s", wait, current.ConfigLink)
		case s.config.HealthCheckInterval > 0:
			s.logf(customlog.Info, "Rotating only on health-check failure. Current outbound: %s", current.ConfigLink)
		}

		doRotate := false
	waitLoop:
		for {
			select {
			case <-ctx.Done():
				stopTimer(timer)
				return nil
			case <-forceRotate:
				s.logf(customlog.Processing, "Manual rotation triggered.")
				doRotate = true
				break waitLoop
			case <-timerC:
				s.logf(customlog.Processing, "Rotation interval elapsed.")
				doRotate = true
				break waitLoop
			case <-healthTickerC:
				ok := s.healthCheck(ctx)
				if ok {
					health.record(true)
					continue
				}
				if !health.record(false) {
					s.logf(customlog.Warning, "Health check failed (%d/%d).", health.fails, health.threshold)
					continue
				}
				// Threshold reached: record a strike against the current
				// outbound and trigger a rotation.
				s.logf(customlog.Warning, "Health check failed %d times in a row.", health.threshold)
				s.recordStrike(current.ConfigLink, "health check failed")
				doRotate = true
				break waitLoop
			}
		}
		stopTimer(timer)
		if !doRotate {
			continue
		}

		s.setRotationStatus(statusTesting)

		// With a hot-swappable listener the new outbound is swapped in
		// behind the bound port and releaseOld is never called. Otherwise
		// releaseOld runs synchronously just before the new instance binds
		// its inbound port, so the two listeners can't fight over the same
		// port; DrainTimeout is then the dwell time on the current outbound
		// before flipping over (a short blip in listener availability).
		releaseOld := func() {
			s.setRotationStatus(statusSwitching)
			if currentInstance == nil {
				return
			}
			if drain := time.Duration(s.config.DrainTimeout) * time.Second; drain > 0 {
				s.logf(customlog.Processing, "Holding current outbound for %v before switching...", drain)
				select {
				case <-time.After(drain):
				case <-ctx.Done():
				}
			}
			currentInstance.Close()
			currentInstance = nil
		}

		// While our listener is up, skip the current outbound: we want a
		// different one. Once it is gone (a previous switch failed), the
		// last working config is a perfectly good candidate again —
		// excluding it could leave a small pool with nothing to start.
		exclude := current.ConfigLink
		if currentInstance == nil {
			exclude = ""
		}
		instance, result, err := s.findAndStartWorkingConfig(ctx, examiner, exclude, currentInstance, releaseOld)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if currentInstance == nil {
				// We gave the listener up for candidates that then failed
				// to start: bring the previous outbound straight back
				// instead of leaving the port unbound until the retry.
				if inst, rerr := s.restartOutbound(ctx, current); rerr == nil {
					currentInstance = inst
					s.logf(customlog.Warning, "Rotation failed: %v. Restored the previous outbound.", err)
				} else {
					s.logf(customlog.Warning, "Rotation failed: %v. Previous outbound could not be restored either (%v); retrying.", err, rerr)
				}
			} else {
				s.logf(customlog.Warning, "Rotation failed: %v. Keeping current outbound.", err)
			}
			stalled = true
			s.setRotationStatus(statusStalled)
			continue
		}

		s.logf(customlog.Success, "Switched to: %s", result.ConfigLink)
		currentInstance = instance
		current = result
		// The fresh outbound starts clean: reset the health-fail counter so
		// it doesn't inherit failures accumulated against the previous
		// outbound (e.g. after a timer/manual rotation that fired at 2/3).
		health.reset()
		backoff.reset()
		stalled = false
		s.setRotationStatus(statusIdle)
	}
}

// restartOutbound brings a previously working outbound back up on the
// listener.
func (s *Service) restartOutbound(ctx context.Context, res *pkghttp.Result) (protocol.Instance, error) {
	if res == nil || res.Protocol == nil {
		return nil, errors.New("no previous outbound")
	}
	inst, err := s.newListener(ctx, res.Protocol)
	if err != nil {
		return nil, err
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, err
	}
	s.mu.Lock()
	s.activeOutbound = res
	s.mu.Unlock()
	s.activeHopsChanged([]protocol.Protocol{res.Protocol})
	return inst, nil
}

// filterBlacklisted drops links that are currently banned and expires
// bans that are over. Entries still collecting strikes (not banned yet)
// are kept, so failures in consecutive rotations add up to a ban.
func filterBlacklisted(links []string, bl map[string]*blacklistEntry, now time.Time) (kept []string, skipped int) {
	kept = make([]string, 0, len(links))
	for _, link := range links {
		entry, exists := bl[link]
		switch {
		case !exists || entry.blacklistedUntil.IsZero():
			kept = append(kept, link)
		case now.After(entry.blacklistedUntil):
			// Ban served: start again with a clean slate.
			delete(bl, link)
			kept = append(kept, link)
		default:
			skipped++
		}
	}
	return kept, skipped
}

// clearStrikes forgets the strikes of a config that just passed a test,
// so only consecutive failures lead to a ban. Active bans are kept.
func (s *Service) clearStrikes(link string) {
	if entry, ok := s.blacklist[link]; ok && entry.blacklistedUntil.IsZero() {
		delete(s.blacklist, link)
	}
}

// findAndStartWorkingConfig probes a batch from the pool and brings up the
// first candidate that survives Start. releasePort, when non-nil, fires
// once right before the first Start attempt; the rotation loop uses it to
// close the previous instance so the new one can claim the inbound port.
//
// When current is a hot-swappable listener the winner is swapped in behind
// it instead, and releasePort is not used.
func (s *Service) findAndStartWorkingConfig(
	ctx context.Context,
	examiner *pkghttp.Examiner,
	lastUsedLink string,
	current protocol.Instance,
	releasePort func(),
) (protocol.Instance, *pkghttp.Result, error) {
	availableLinks := make([]string, len(s.config.ConfigLinks))
	copy(availableLinks, s.config.ConfigLinks)
	rng := newLocalRand()
	rng.Shuffle(len(availableLinks), func(i, j int) { availableLinks[i], availableLinks[j] = availableLinks[j], availableLinks[i] })

	// Drop the previous outbound from the candidate set so we don't waste a
	// test slot on it and then discard it at selection time.
	if lastUsedLink != "" {
		for i, link := range availableLinks {
			if link == lastUsedLink {
				availableLinks = append(availableLinks[:i], availableLinks[i+1:]...)
				break
			}
		}
	}

	// Filter out blacklisted configs
	if s.config.BlacklistStrikes > 0 {
		filtered, skipped := filterBlacklisted(availableLinks, s.blacklist, time.Now())
		if len(filtered) == 0 && len(availableLinks) > 0 {
			s.logf(customlog.Warning, "All configs are blacklisted. Clearing blacklist.\n")
			s.blacklist = make(map[string]*blacklistEntry)
			filtered = availableLinks
		} else if skipped > 0 {
			s.logf(customlog.Info, "Skipped %d blacklisted configs.\n", skipped)
		}
		availableLinks = filtered
	}
	if len(availableLinks) == 0 {
		return nil, nil, errors.New("no other configs in the pool to rotate to")
	}

	// Determine batch size: use configured value or auto-derive from pool size
	batchSize := int(s.config.BatchSize)
	if batchSize == 0 {
		batchSize = len(availableLinks) / 10
		if batchSize < 10 {
			batchSize = 10
		}
		if batchSize > 200 {
			batchSize = 200
		}
	}
	if batchSize > len(availableLinks) {
		batchSize = len(availableLinks)
	}

	// Determine concurrency: use configured value or auto-derive from batch size
	concurrency := int(s.config.Concurrency)
	if concurrency == 0 {
		concurrency = batchSize
		if concurrency > 50 {
			concurrency = 50
		}
	}

	linksToTest := availableLinks[:batchSize]
	s.logf(customlog.Processing, "Testing a batch of %d configs (concurrency: %d)...\n", len(linksToTest), concurrency)

	// With the kill switch up, the tests' direct dials to candidate
	// servers must be let through for a while.
	s.allowProbes(ctx, linksToTest)

	testManager := pkghttp.NewTestManager(examiner, uint16(concurrency), false, s.logger)
	resultsChan := make(chan *pkghttp.Result, len(linksToTest))
	var results pkghttp.ConfigResults
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for res := range resultsChan {
			results = append(results, res)
		}
	}()

	testManager.RunTests(ctx, linksToTest, resultsChan, func() {
		// This callback is for progress, which isn't used here, but is fine to keep.
	})
	close(resultsChan)
	wg.Wait()

	// If the context was cancelled (e.g. Ctrl+C), return immediately.
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}

	sort.Sort(results)

	// Strike anything that failed in the examiner so persistently broken
	// configs eventually leave the rotation pool; a pass wipes the slate.
	for _, res := range results {
		if res.ConfigLink == "" {
			continue
		}
		if res.Status == "passed" {
			s.clearStrikes(res.ConfigLink)
			continue
		}
		reason := res.Status
		if res.Reason != "" {
			reason = res.Reason
		}
		s.recordStrike(res.ConfigLink, reason)
	}

	if instance, res, ok := s.startFirstPassing(ctx, results, current, releasePort); ok {
		return instance, res, nil
	}

	// FIX #3: Provide a useful error message summarizing the failures.
	errorSummary := make(map[string]int)
	var brokenCount int
	for _, res := range results {
		if res.Status != "passed" {
			if res.Reason != "" {
				errorSummary[res.Reason]++
			} else if res.Status == "broken" {
				brokenCount++
			}
		}
	}

	var errorStrings []string
	if brokenCount > 0 {
		errorStrings = append(errorStrings, fmt.Sprintf("%d were broken (invalid link format)", brokenCount))
	}
	// To avoid overly long error messages, you might want to limit how many reasons are shown.
	for reason, count := range errorSummary {
		errorStrings = append(errorStrings, fmt.Sprintf("%d failed with: %s", count, reason))
	}

	if len(errorStrings) > 0 {
		return nil, nil, fmt.Errorf(
			"no new working configs found in batch. Error summary: %s",
			strings.Join(errorStrings, "; "),
		)
	}

	return nil, nil, errors.New("failed to find any new working outbound configuration in this batch")
}

// startFirstPassing brings up the first passed result. With a
// hot-swappable current listener the result is swapped in behind it;
// otherwise a new listener is built and started, and releasePort fires at
// most once, right before the first Start, so a run of Start failures
// does not bounce the listener in and out.
func (s *Service) startFirstPassing(ctx context.Context, results []*pkghttp.Result, current protocol.Instance, releasePort func()) (protocol.Instance, *pkghttp.Result, bool) {
	sw, canSwap := current.(hotSwapper)
	portReleased := false
	for _, res := range results {
		if res.Status != "passed" || res.Protocol == nil {
			continue
		}
		s.logf(customlog.Success, "Found working config: %s (Delay: %dms)\n", res.ConfigLink, res.Delay)
		s.logf(customlog.Info, "==========OUTBOUND==========")
		if s.logger != nil {
			g := res.Protocol.ConvertToGeneralConfig()
			s.logger.Printf("Protocol: %s\nRemark: %s\nAddr: %s:%s\nLink: %s\n", g.Protocol, g.Remark, g.Address, g.Port, g.OrigLink)
		} else {
			fmt.Printf("%v", res.Protocol.DetailsStr())
		}
		s.logf(customlog.Info, "============================\n")

		if canSwap {
			s.setRotationStatus(statusSwitching)
			if err := sw.Swap(ctx, []protocol.Protocol{res.Protocol}, s.swapGrace()); err != nil {
				s.logf(customlog.Failure, "Error switching to '%s': %v\n", res.ConfigLink, err)
				s.recordStrike(res.ConfigLink, fmt.Sprintf("swap: %v", err))
				continue
			}
			s.mu.Lock()
			s.activeOutbound = res
			s.mu.Unlock()
			s.activeHopsChanged([]protocol.Protocol{res.Protocol})
			return sw, res, true
		}

		// Build the instance first — that part does not touch the network.
		instance, err := s.newListener(ctx, res.Protocol)
		if err != nil {
			s.logf(customlog.Failure, "Error making core instance with '%s': %v\n", res.ConfigLink, err)
			s.recordStrike(res.ConfigLink, fmt.Sprintf("MakeInstance: %v", err))
			continue
		}
		if !portReleased && releasePort != nil {
			releasePort()
			portReleased = true
		}
		if err := instance.Start(); err != nil {
			instance.Close()
			s.logf(customlog.Failure, "Error starting core instance with '%s': %v\n", res.ConfigLink, err)
			s.recordStrike(res.ConfigLink, fmt.Sprintf("Start: %v", err))
			continue
		}
		s.mu.Lock()
		s.activeOutbound = res
		s.mu.Unlock()
		s.activeHopsChanged([]protocol.Protocol{res.Protocol})
		return instance, res, true
	}
	return nil, nil, false
}

// chainHealthCheck is the chain-mode twin of healthCheck — probe through
// the live listener first, only spin up a temporary chained instance when
// the inbound type leaves us no other choice.
func (s *Service) chainHealthCheck(ctx context.Context) bool {
	s.refreshUpstream()
	s.mu.RLock()
	hops := s.activeChainHops
	s.mu.RUnlock()
	if len(hops) < 2 {
		return false
	}

	timeout := time.Duration(s.config.MaximumAllowedDelay) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	if client, ok := s.makeLocalProxyClient(timeout); ok {
		return doHealthGET(ctx, client, s.config.HealthCheckURL, timeout)
	}

	client, instance, err := s.makeChainedHttpClient(ctx, hops, timeout)
	if err != nil {
		return false
	}
	defer instance.Close()
	return doHealthGET(ctx, client, s.config.HealthCheckURL, timeout)
}

// makeChainedInstance delegates to the concrete core's MakeChainedInstance.
func (s *Service) makeChainedInstance(ctx context.Context, hops []protocol.Protocol) (protocol.Instance, error) {
	switch c := s.core.(type) {
	case *pkgxray.Core:
		return c.MakeChainedInstance(ctx, hops)
	case *pkgsingbox.Core:
		return c.MakeChainedInstance(ctx, hops)
	default:
		return nil, fmt.Errorf("chaining is not supported with core type: %T", s.core)
	}
}

// makeChainedHttpClient delegates to the concrete core's MakeChainedHttpClient.
func (s *Service) makeChainedHttpClient(ctx context.Context, hops []protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	switch c := s.core.(type) {
	case *pkgxray.Core:
		return c.MakeChainedHttpClient(ctx, hops, maxDelay)
	case *pkgsingbox.Core:
		return c.MakeChainedHttpClient(ctx, hops, maxDelay)
	default:
		return nil, nil, fmt.Errorf("chaining is not supported with core type: %T", s.core)
	}
}

// runChainMode runs the proxy in chain mode with optional rotation.
func (s *Service) runChainMode(ctx context.Context, forceRotate <-chan struct{}) error {
	rotation := s.config.ChainRotation
	if rotation == "" {
		rotation = "none"
	}

	// Fixed chains never rotate.
	if s.fixedChain() {
		return s.runFixedChainMode(ctx)
	}

	switch rotation {
	case "none":
		return s.runChainNoRotation(ctx)
	case "exit":
		return s.runChainExitRotation(ctx, forceRotate)
	case "full":
		return s.runChainFullRotation(ctx, forceRotate)
	default:
		return fmt.Errorf("unknown chain rotation mode: %s", rotation)
	}
}

// runFixedChainMode parses a fixed chain and runs it without rotation.
func (s *Service) runFixedChainMode(ctx context.Context) error {
	hops, err := resolveFixedChain(s.core, s.config.ChainLinks, s.config.ChainFile)
	if err != nil {
		return fmt.Errorf("failed to resolve fixed chain: %w", err)
	}
	return s.runStaticChain(ctx, hops, "fixed")
}

// runChainNoRotation selects hops from the pool once and runs without rotation.
func (s *Service) runChainNoRotation(ctx context.Context) error {
	hops, err := selectChainFromPool(s.core, s.config.ConfigLinks, s.chainHops())
	if err != nil {
		return fmt.Errorf("failed to select chain from pool: %w", err)
	}
	return s.runStaticChain(ctx, hops, "no rotation")
}

// runStaticChain serves one chain until ctx is done.
func (s *Service) runStaticChain(ctx context.Context, hops []protocol.Protocol, kind string) error {
	s.logChainHops(hops)

	// The swappable listener, even without rotation: it is the one that
	// carries the socket mark host-tun relies on.
	instance, err := s.newChainListener(ctx, hops)
	if err != nil {
		return fmt.Errorf("failed to create chained instance: %w", err)
	}
	defer instance.Close()

	if err := instance.Start(); err != nil {
		return fmt.Errorf("failed to start chained instance: %w", err)
	}

	s.mu.Lock()
	s.activeChainHops = hops
	s.mu.Unlock()
	s.activeHopsChanged(hops)

	s.logf(customlog.Success, "Chain proxy started (%s, %d hops).\n", kind, len(hops))
	s.signalProxyReady()

	<-ctx.Done()
	s.logf(customlog.Processing, "Shutting down chain proxy...\n")
	return nil
}

func (s *Service) chainHops() int {
	if n := int(s.config.ChainHops); n >= 2 {
		return n
	}
	return 2
}

func (s *Service) chainAttempts() int {
	if n := int(s.config.ChainAttempts); n > 0 {
		return n
	}
	return defaultChainAttempts
}

// swapChain replaces the running chain instance with one for newHops.
// On a Start failure it brings the old chain back so the listener is not
// left unbound. It returns the instance that is now serving.
func (s *Service) swapChain(ctx context.Context, current protocol.Instance, oldHops, newHops []protocol.Protocol) (protocol.Instance, bool) {
	if sw, ok := current.(hotSwapper); ok {
		s.setRotationStatus(statusSwitching)
		if err := sw.Swap(ctx, newHops, s.swapGrace()); err != nil {
			s.logf(customlog.Warning, "Could not switch to the new chain: %v\n", err)
			return current, false
		}
		s.mu.Lock()
		s.activeChainHops = newHops
		s.mu.Unlock()
		s.activeHopsChanged(newHops)
		return current, true
	}

	newInstance, err := s.newChainListener(ctx, newHops)
	if err != nil {
		s.logf(customlog.Warning, "Could not create new chained instance: %v\n", err)
		return current, false
	}

	s.setRotationStatus(statusSwitching)
	if current != nil {
		if drain := time.Duration(s.config.DrainTimeout) * time.Second; drain > 0 {
			s.logf(customlog.Processing, "Holding current chain for %v before switching...", drain)
			select {
			case <-time.After(drain):
			case <-ctx.Done():
			}
		}
		current.Close()
	}

	if err := newInstance.Start(); err != nil {
		newInstance.Close()
		s.logf(customlog.Warning, "Could not start new chained instance: %v\n", err)
		if restored, rerr := s.newChainListener(ctx, oldHops); rerr == nil {
			if rerr = restored.Start(); rerr == nil {
				s.logf(customlog.Warning, "Restored the previous chain.\n")
				return restored, false
			}
			restored.Close()
		}
		return nil, false
	}

	s.mu.Lock()
	s.activeChainHops = newHops
	s.mu.Unlock()
	s.activeHopsChanged(newHops)
	return newInstance, true
}

// runChainExitRotation keeps the entry hops (all but the last) fixed and
// rotates the exit hop — the one whose IP the destination sees. When no
// exit candidate works with the current entry for a whole attempt budget,
// the entry is presumed dead and the whole chain is re-selected.
func (s *Service) runChainExitRotation(ctx context.Context, forceRotate <-chan struct{}) error {
	timeout := time.Duration(s.config.MaximumAllowedDelay) * time.Millisecond

	hops, err := s.findWorkingChain(ctx, s.chainHops(), timeout)
	if err != nil {
		return fmt.Errorf("failed to find initial working chain: %w", err)
	}

	var currentInstance protocol.Instance
	currentInstance, err = s.newChainListener(ctx, hops)
	if err != nil {
		return fmt.Errorf("failed to create initial chained instance: %w", err)
	}
	defer func() {
		if currentInstance != nil {
			currentInstance.Close()
		}
	}()
	if err := currentInstance.Start(); err != nil {
		return fmt.Errorf("failed to start initial chained instance: %w", err)
	}

	s.mu.Lock()
	s.activeChainHops = hops
	s.mu.Unlock()
	s.activeHopsChanged(hops)

	s.logChainHops(hops)
	s.logf(customlog.Success, "Chain proxy started (exit rotation, %d hops).\n", len(hops))
	s.setRotationStatus(statusIdle)
	s.signalProxyReady()

	return s.chainRotationLoop(ctx, forceRotate, &currentInstance, &hops, func() ([]protocol.Protocol, error) {
		entry := hops[:len(hops)-1]
		lastExit := hops[len(hops)-1].GetLink()
		for attempt := 0; attempt < s.chainAttempts(); attempt++ {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			candidate, err := selectExitHopFromPool(s.core, s.config.ConfigLinks, entry, lastExit)
			if err != nil {
				break
			}
			if s.probeChain(ctx, candidate, timeout) {
				return candidate, nil
			}
			lastExit = candidate[len(candidate)-1].GetLink()
		}
		s.logf(customlog.Warning, "No exit hop works with the current entry; re-selecting the whole chain.\n")
		return s.findWorkingChain(ctx, len(hops), timeout)
	}, "Chain exit hop rotated.")
}

// runChainFullRotation rotates the entire chain on each cycle.
func (s *Service) runChainFullRotation(ctx context.Context, forceRotate <-chan struct{}) error {
	timeout := time.Duration(s.config.MaximumAllowedDelay) * time.Millisecond

	// Select and test initial chain.
	hops, err := s.findWorkingChain(ctx, s.chainHops(), timeout)
	if err != nil {
		return fmt.Errorf("failed to find initial working chain: %w", err)
	}

	var currentInstance protocol.Instance
	currentInstance, err = s.newChainListener(ctx, hops)
	if err != nil {
		return fmt.Errorf("failed to create initial chained instance: %w", err)
	}
	defer func() {
		if currentInstance != nil {
			currentInstance.Close()
		}
	}()

	if err := currentInstance.Start(); err != nil {
		return fmt.Errorf("failed to start initial chained instance: %w", err)
	}

	s.mu.Lock()
	s.activeChainHops = hops
	s.mu.Unlock()
	s.activeHopsChanged(hops)

	s.logChainHops(hops)
	s.logf(customlog.Success, "Chain proxy started (full rotation, %d hops).\n", len(hops))
	s.setRotationStatus(statusIdle)
	s.signalProxyReady()

	return s.chainRotationLoop(ctx, forceRotate, &currentInstance, &hops, func() ([]protocol.Protocol, error) {
		return s.findWorkingChain(ctx, len(hops), timeout)
	}, "Full chain rotated.")
}

// chainRotationLoop is the wait/rotate loop shared by the chain rotation
// modes. pick returns the next tested chain.
func (s *Service) chainRotationLoop(
	ctx context.Context,
	forceRotate <-chan struct{},
	current *protocol.Instance,
	hops *[]protocol.Protocol,
	pick func() ([]protocol.Protocol, error),
	rotatedMsg string,
) error {
	var healthTickerC <-chan time.Time
	if s.config.HealthCheckInterval > 0 {
		healthTicker := time.NewTicker(time.Duration(s.config.HealthCheckInterval) * time.Second)
		healthTickerC = healthTicker.C
		defer healthTicker.Stop()
	}
	health := newHealthTracker(s.config.HealthFailThreshold)

	var backoff stallBackoff
	stalled := false
	for {
		timer, timerC := s.armRotation(s.nextWait(stalled, &backoff))
		doRotate := false
	waitLoop:
		for {
			select {
			case <-ctx.Done():
				stopTimer(timer)
				return nil
			case <-forceRotate:
				s.logf(customlog.Processing, "Manual chain rotation triggered.\n")
				doRotate = true
				break waitLoop
			case <-timerC:
				doRotate = true
				break waitLoop
			case <-healthTickerC:
				if !health.record(s.chainHealthCheck(ctx)) {
					if health.fails > 0 {
						s.logf(customlog.Warning, "Chain health check failed (%d/%d).\n", health.fails, health.threshold)
					}
					continue
				}
				s.logf(customlog.Warning, "Chain health check failed %d times in a row. Rotating.\n", health.threshold)
				doRotate = true
				break waitLoop
			}
		}
		stopTimer(timer)
		if !doRotate {
			continue
		}

		s.setRotationStatus(statusTesting)
		newHops, err := pick()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logf(customlog.Warning, "No new working chain: %v. Keeping current chain.\n", err)
			stalled = true
			s.setRotationStatus(statusStalled)
			continue
		}

		inst, switched := s.swapChain(ctx, *current, *hops, newHops)
		*current = inst
		if !switched {
			stalled = true
			s.setRotationStatus(statusStalled)
			continue
		}
		*hops = newHops
		s.logChainHops(newHops)
		s.logf(customlog.Success, "%s\n", rotatedMsg)
		health.reset()
		backoff.reset()
		stalled = false
		s.setRotationStatus(statusIdle)
	}
}

// findWorkingChain tries multiple random chain combinations from the pool
// and returns the first one that passes a health check. The attempt budget
// is configurable via Config.ChainAttempts so callers with small pools (or
// flaky relays) can tune it.
func (s *Service) findWorkingChain(ctx context.Context, numHops int, timeout time.Duration) ([]protocol.Protocol, error) {
	maxAttempts := s.chainAttempts()
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		hops, err := selectChainFromPool(s.core, s.config.ConfigLinks, numHops)
		if err != nil {
			continue
		}
		if s.probeChain(ctx, hops, timeout) {
			return hops, nil
		}
	}
	return nil, fmt.Errorf("could not find a working chain after %d attempts", maxAttempts)
}

// probeChain builds a throwaway client for hops and checks the health
// endpoint through it.
func (s *Service) probeChain(ctx context.Context, hops []protocol.Protocol, timeout time.Duration) bool {
	s.allowProbes(ctx, hopLinks(hops[:1])) // only the entry is dialed directly
	client, testInst, err := s.makeChainedHttpClient(ctx, hops, timeout)
	if err != nil {
		return false
	}
	defer testInst.Close()
	return doHealthGET(ctx, client, s.config.HealthCheckURL, timeout)
}

// logChainHops logs the details of the chain hops.
func (s *Service) logChainHops(hops []protocol.Protocol) {
	s.logf(customlog.Info, "==========CHAIN==========\n")
	for i, hop := range hops {
		role := "relay"
		if i == 0 {
			role = "entry"
		} else if i == len(hops)-1 {
			role = "exit"
		}
		g := hop.ConvertToGeneralConfig()
		if s.logger != nil {
			s.logger.Printf("Hop %d (%s): %s %s:%s [%s]\n", i+1, role, g.Protocol, g.Address, g.Port, g.Remark)
		} else {
			fmt.Printf("  Hop %d (%s): %s %s:%s [%s]\n", i+1, role, g.Protocol, g.Address, g.Port, g.Remark)
		}
	}
	s.logf(customlog.Info, "=========================\n")
}

func (s *Service) createExaminer() (*pkghttp.Examiner, error) {
	return pkghttp.NewExaminer(pkghttp.Options{
		Core:                   s.config.CoreType,
		MaxDelay:               s.config.MaximumAllowedDelay,
		Verbose:                s.config.Verbose,
		InsecureTLS:            s.config.InsecureTLS,
		TestEndpoint:           s.config.HealthCheckURL,
		TestEndpointHttpMethod: "GET",
		DoSpeedtest:            false,
		// The exit IP/country comes free with the default trace endpoint;
		// with a custom health URL it would cost an extra request to
		// cloudflare.com per test, which may itself be blocked.
		DoIPInfo: s.config.HealthCheckURL == defaultHealthCheckURL,
		// Keep test-time dials on the same interface the live outbound
		// uses, otherwise a passing test can hide a runtime --bind failure.
		BindInterface: s.config.BindInterface,
		// Test through the same fragmentation the live outbound uses: a
		// config that only works fragmented must pass here too.
		Fragment: s.config.Fragment,
	})
}

func (s *Service) createInbound() (protocol.Protocol, error) {
	if s.config.InboundConfigLink != "" {
		inbound, err := s.core.CreateProtocol(s.config.InboundConfigLink)
		if err != nil {
			return nil, fmt.Errorf("failed to create inbound from config link: %w", err)
		}
		if err := inbound.Parse(); err != nil {
			return nil, fmt.Errorf("failed to parse inbound config link: %w", err)
		}
		// In system mode the OS proxy settings will point at this listener,
		// and browsers / most apps only talk HTTP or SOCKS. Reject anything
		// fancier up front so we don't end up advertising an unreachable
		// proxy to the rest of the system.
		if s.config.Mode == "system" {
			switch inbound.(type) {
			case *pkgxray.Http, *pkgxray.Socks, *pkgsingbox.Http, *pkgsingbox.Socks:
				// OK
			default:
				g := inbound.ConvertToGeneralConfig()
				return nil, fmt.Errorf("system mode requires an http or socks inbound, got %q", g.Protocol)
			}
		}
		return inbound, nil
	}

	if s.config.Mode == "system" {
		// The OS settings point HTTP, HTTPS *and* SOCKS at this listener,
		// so it must speak both. xray's socks inbound also serves HTTP
		// proxy requests (its plain http inbound does not speak SOCKS);
		// sing-box's "http" type here is a mixed HTTP+SOCKS inbound. No
		// auth: OS proxy settings cannot carry credentials.
		switch s.config.CoreType {
		case "xray":
			return &pkgxray.Socks{
				Remark: "Listener", Address: s.config.ListenAddr, Port: s.config.ListenPort,
			}, nil
		case "sing-box":
			return &pkgsingbox.Http{
				Remark: "Listener", Address: s.config.ListenAddr, Port: s.config.ListenPort,
			}, nil
		}
		return nil, fmt.Errorf("unsupported core type for system mode: %s", s.config.CoreType)
	}

	u := uuid.New()
	uuidV4 := s.config.InboundUUID
	if uuidV4 == "random" || uuidV4 == "" {
		uuidV4 = u.String()
	}

	switch s.config.CoreType {
	case "xray":
		return createXrayInbound(s.config, uuidV4)
	case "sing-box":
		return createSingboxInbound(s.config)
	}
	return nil, fmt.Errorf("inbound could not be created for core type: %s", s.config.CoreType)
}

func createXrayInbound(cfg Config, uuid string) (protocol.Protocol, error) {
	switch cfg.InboundProtocol {
	case "socks":
		user, err := utils.GeneratePassword(defaultSocksCredLen)
		if err != nil {
			return nil, fmt.Errorf("failed to generate socks username: %w", err)
		}
		pass, err := utils.GeneratePassword(defaultSocksCredLen)
		if err != nil {
			return nil, fmt.Errorf("failed to generate socks password: %w", err)
		}
		return &pkgxray.Socks{
			Remark: "Listener", Address: cfg.ListenAddr, Port: cfg.ListenPort,
			Username: user, Password: pass,
		}, nil
	case "vmess":
		vmess := &pkgxray.Vmess{
			Remark:  "Listener",
			Address: cfg.ListenAddr,
			Port:    cfg.ListenPort,
			ID:      uuid,
		}
		switch cfg.InboundTransport {
		case "tcp":
			vmess.Network = "tcp"
		case "ws":
			vmess.Network = "ws"
			vmess.Path = cfg.WSPath
			vmess.Host = cfg.WSHost
		case "grpc":
			vmess.Network = "grpc"
			vmess.Path = cfg.GRPCServiceName // For VMESS, Path is used for ServiceName
			vmess.Host = cfg.GRPCAuthority
		case "xhttp":
			vmess.Network = "xhttp"
			vmess.Type = cfg.XHTTPMode
			vmess.Host = cfg.XHTTPHost
			vmess.Path = cfg.XHTTPPath
			vmess.Security = "none"
		default:
			return nil, fmt.Errorf("unsupported vmess transport: %s", cfg.InboundTransport)
		}

		if cfg.EnableTLS {
			vmess.TLS = "tls"
			vmess.CertFile = cfg.TLSCertFile
			vmess.KeyFile = cfg.TLSKeyFile
			vmess.SNI = cfg.TLSSNI
			vmess.ALPN = cfg.TLSALPN
		}

		return vmess, nil
	case "vless":
		vless := &pkgxray.Vless{
			Remark:  "Listener",
			Address: cfg.ListenAddr,
			Port:    cfg.ListenPort,
			ID:      uuid,
		}
		switch cfg.InboundTransport {
		case "tcp":
			vless.Type = "tcp"
		case "ws":
			vless.Type = "ws"
			vless.Path = cfg.WSPath
			vless.Host = cfg.WSHost
		case "grpc":
			vless.Type = "grpc"
			vless.ServiceName = cfg.GRPCServiceName
			vless.Authority = cfg.GRPCAuthority
		case "xhttp":
			vless.Type = "xhttp"
			vless.Host = cfg.XHTTPHost
			vless.Path = cfg.XHTTPPath
			vless.Security = "none"
			vless.Mode = cfg.XHTTPMode
		default:
			return nil, fmt.Errorf("unsupported vless transport: %s", cfg.InboundTransport)
		}

		if cfg.EnableTLS {
			vless.Security = "tls"
			vless.CertFile = cfg.TLSCertFile
			vless.KeyFile = cfg.TLSKeyFile
			vless.SNI = cfg.TLSSNI
			vless.ALPN = cfg.TLSALPN
		}
		return vless, nil
	}
	return nil, fmt.Errorf("unsupported xray inbound protocol/transport: %s/%s", cfg.InboundProtocol, cfg.InboundTransport)
}

func createSingboxInbound(cfg Config) (protocol.Protocol, error) {
	// Currently, only SOCKS is implemented for Singbox inbound in this logic
	if cfg.InboundProtocol == "socks" {
		user, err := utils.GeneratePassword(defaultSocksCredLen)
		if err != nil {
			return nil, fmt.Errorf("failed to generate socks username: %w", err)
		}
		pass, err := utils.GeneratePassword(defaultSocksCredLen)
		if err != nil {
			return nil, fmt.Errorf("failed to generate socks password: %w", err)
		}
		return &pkgsingbox.Socks{
			Remark: "Listener", Address: cfg.ListenAddr, Port: cfg.ListenPort,
			Username: user, Password: pass,
		}, nil
	}
	return nil, fmt.Errorf("unsupported sing-box inbound protocol: %s", cfg.InboundProtocol)
}
