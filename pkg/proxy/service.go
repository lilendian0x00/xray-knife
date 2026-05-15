package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	osexec "os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	xproxy "golang.org/x/net/proxy"

	"github.com/lilendian0x00/xray-knife/v10/database"
	"github.com/lilendian0x00/xray-knife/v10/pkg/core"
	"github.com/lilendian0x00/xray-knife/v10/pkg/core/protocol"
	pkgsingbox "github.com/lilendian0x00/xray-knife/v10/pkg/core/singbox"
	pkgxray "github.com/lilendian0x00/xray-knife/v10/pkg/core/xray"
	pkghttp "github.com/lilendian0x00/xray-knife/v10/pkg/http"
	"github.com/lilendian0x00/xray-knife/v10/pkg/proxy/hosttun"
	"github.com/lilendian0x00/xray-knife/v10/pkg/proxy/netns"
	"github.com/lilendian0x00/xray-knife/v10/pkg/proxy/sysproxy"
	"github.com/lilendian0x00/xray-knife/v10/utils"
	"github.com/lilendian0x00/xray-knife/v10/utils/customlog"
	"github.com/xtls/xray-core/common/uuid"
)

// Rotation tuning defaults.
const (
	// minRotationInterval is a floor on --rotate; anything tighter spins the
	// loop without giving tests room to finish.
	minRotationInterval uint32 = 5
	// defaultChainAttempts is how many random chains we'll try before giving
	// up on a rotation cycle.
	defaultChainAttempts int = 5
	// defaultHealthFailThresh is how many consecutive health-check misses
	// it takes to count the outbound as actually broken. A single flaky
	// probe shouldn't be enough to blacklist a working config.
	defaultHealthFailThresh = 3
	// defaultSocksCredLen is the length of the auto-generated SOCKS
	// username/password used when no inbound link is supplied. 16 chars of
	// alphanumeric is enough that the inbound port can be safely exposed on
	// 0.0.0.0 in app mode without becoming a brute-force target.
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
	RotationInterval    uint32 `json:"rotationInterval"`
	MaximumAllowedDelay uint16 `json:"maximumAllowedDelay"`
	BatchSize           uint16 `json:"batchSize"`           // configs to test per rotation (0=auto)
	Concurrency         uint16 `json:"concurrency"`         // concurrent test threads (0=auto)
	HealthCheckInterval uint32 `json:"healthCheckInterval"` // seconds between health checks (0=disabled)
	HealthFailThreshold uint16 `json:"healthFailThreshold"` // consecutive health-check failures before strike (0=auto)
	DrainTimeout        uint16 `json:"drainTimeout"`        // seconds to keep current outbound serving before switching (0=immediate switch)
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
	HostTunDeadman        uint16 `json:"hostTunDeadman,omitempty"`
	HostTunExclude        string `json:"hostTunExclude,omitempty"`
	HostTunName           string `json:"hostTunName,omitempty"`
	HostTunAddr           string `json:"hostTunAddr,omitempty"`
	HostTunMTU            uint32 `json:"hostTunMTU,omitempty"`
	HostTunExcludePrivate bool   `json:"hostTunExcludePrivate,omitempty"`
}

// Details is a snapshot of the running proxy state.
type Details struct {
	Inbound          protocol.GeneralConfig   `json:"inbound"`
	ActiveOutbound   *pkghttp.Result          `json:"activeOutbound,omitempty"`
	RotationStatus   string                   `json:"rotationStatus"` // idle, testing, switching, stalled
	NextRotationTime time.Time                `json:"nextRotationTime"`
	RotationInterval uint32                   `json:"rotationInterval"`
	TotalConfigs     int                      `json:"totalConfigs"`
	ChainEnabled     bool                     `json:"chainEnabled"`
	ChainHopInfos    []protocol.GeneralConfig `json:"chainHops,omitempty"`
	ChainRotation    string                   `json:"chainRotation,omitempty"`
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
	nsManager         *netns.Namespace   // non-nil when mode == "app"
	nsTunnel          protocol.Instance  // the sing-box tunnel inside the namespace
	nsCfg             netns.Config       // resolved netns config (for cleanup)
	hostTunInstance   protocol.Instance  // non-nil when mode == "host-tun"
	hostTunCfg        hosttun.Config     // resolved host-tun config (for logging)
	proxyReady        chan struct{}      // closed when the first proxy instance starts
	proxyReadyOnce    sync.Once
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

	// --rotate 0 used to drop us into a tight loop; clamp very small values
	// to a sane floor instead.
	if config.RotationInterval > 0 && config.RotationInterval < minRotationInterval {
		config.RotationInterval = minRotationInterval
	}

	// App mode validation and overrides — run BEFORE any privileged side
	// effects so unprivileged invocations fail fast without touching state.
	if config.Mode == "app" {
		if runtime.GOOS != "linux" {
			return nil, errors.New("app mode is only supported on Linux")
		}
		if os.Getuid() != 0 {
			return nil, errors.New("app mode requires root privileges. Run with sudo")
		}
		// Default to shell mode if neither --shell nor --namespace is set.
		if !config.Shell && config.NamespaceName == "" {
			config.Shell = true
		}
		// The namespace reaches the proxy via the veth pair, but the veth
		// host endpoint doesn't exist yet at bind time — so we have to
		// listen on 0.0.0.0 and rely on the generated SOCKS credentials
		// for access control.
		config.ListenAddr = "0.0.0.0"
		config.InboundProtocol = "socks"
		config.InboundConfigLink = ""
	}

	// Crash recovery: restore stale system proxy settings from a previous unclean exit.
	if stale, err := sysproxy.LoadState(); err == nil && stale != nil {
		if mgr, mgrErr := sysproxy.New(); mgrErr == nil {
			mgr.Restore(stale)
		}
		sysproxy.ClearState()
	}

	// host-tun mode validation. Fail fast before touching state.
	if config.Mode == "host-tun" {
		if runtime.GOOS != "linux" {
			return nil, errors.New("host-tun mode is only supported on Linux")
		}
		if os.Getuid() != 0 {
			return nil, errors.New("host-tun mode requires root privileges. Run with sudo")
		}
		if config.BindInterface == "" {
			return nil, errors.New("host-tun mode requires BindInterface (CLI: --bind <iface>)")
		}
		// Refuse host-tun + deadman when stdin isn't a tty: the deadman
		// ENTER prompt is unanswerable from /dev/null. Forces the user
		// to either run interactively, or pass --host-tun-deadman 0 and
		// detach (tmux/setsid/systemd).
		if config.HostTunDeadman > 0 && !hosttun.StdinIsTTY() {
			return nil, errors.New("host-tun deadman > 0 requires an interactive terminal on stdin; for unattended use pass --host-tun-deadman 0 and run under tmux/setsid/systemd")
		}
		// Force SOCKS inbound on loopback. host-tun's TUN dials this
		// over lo; anything else risks a routing loop.
		config.ListenAddr = "127.0.0.1"
		config.InboundProtocol = "socks"
		config.InboundConfigLink = ""
	}

	// Crash recovery: clean up stale network namespace from a previous
	// unclean exit. Only runs in app mode; the function itself also
	// verifies the recorded owner is no longer running before reclaiming.
	if config.Mode == "app" {
		netns.RecoverFromCrash()
		if logger != nil {
			logger.Printf("WARNING: app mode binds SOCKS listener on 0.0.0.0:%s; rely on the generated SOCKS credentials or restrict via firewall.\n", config.ListenPort)
		} else {
			customlog.Printf(customlog.Warning, "app mode binds SOCKS listener on 0.0.0.0:%s; rely on the generated SOCKS credentials or restrict via firewall.\n", config.ListenPort)
		}
	}

	s := &Service{
		config:         config,
		logger:         logger,
		rotationStatus: "idle",
		blacklist:      make(map[string]*blacklistEntry),
		proxyReady:     make(chan struct{}),
	}

	// If no config links are provided via flags, fetch them from the database.
	if len(s.config.ConfigLinks) == 0 {
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

	// If system mode, configure the OS to route traffic through our local SOCKS proxy.
	if config.Mode == "system" {
		mgr, err := sysproxy.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create system proxy manager: %w", err)
		}
		prev, err := mgr.Get()
		if err != nil {
			return nil, fmt.Errorf("failed to read current system proxy settings: %w", err)
		}
		if err := sysproxy.SaveState(prev); err != nil {
			return nil, fmt.Errorf("failed to save system proxy state for crash recovery: %w", err)
		}
		if err := mgr.Set(config.ListenAddr, config.ListenPort); err != nil {
			sysproxy.ClearState()
			return nil, fmt.Errorf("failed to set system proxy: %w", err)
		}
		s.sysProxyManager = mgr
		s.prevProxySettings = prev
		s.logf(customlog.Success, "System proxy configured: http://%s:%s\n", config.ListenAddr, config.ListenPort)
	}

	return s, nil
}

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
		return doHealthGET(ctx, client, timeout)
	}

	// Fallback: outbound-only test via a fresh instance.
	client, instance, err := s.core.MakeHttpClient(ctx, activeOutbound.Protocol, timeout)
	if err != nil {
		return false
	}
	defer instance.Close()
	return doHealthGET(ctx, client, timeout)
}

// makeLocalProxyClient returns an http.Client wired up to talk to the
// inbound listener directly. Returns ok=false when the inbound isn't
// something a vanilla SOCKS5/HTTP client can speak.
func (s *Service) makeLocalProxyClient(timeout time.Duration) (*http.Client, bool) {
	addr := s.config.ListenAddr
	if addr == "0.0.0.0" || addr == "" {
		addr = "127.0.0.1"
	}
	target := net.JoinHostPort(addr, s.config.ListenPort)

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
			// xproxy.Dialer doesn't expose a DialContext form, so honor the
			// ctx deadline approximately via the outer Client timeout.
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

func doHealthGET(ctx context.Context, client *http.Client, timeout time.Duration) bool {
	if client == nil {
		return false
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", "https://cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
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
	if s.hostTunInstance != nil {
		s.logf(customlog.Processing, "Stopping host-tun tunnel...\n")
		s.teardownHostTun()
	}

	// Tear down namespace resources (reverse order: tunnel first, then namespace).
	if s.nsTunnel != nil {
		s.logf(customlog.Processing, "Stopping namespace tunnel...\n")
		if err := s.nsTunnel.Close(); err != nil {
			s.logf(customlog.Warning, "Tunnel close returned error: %v\n", err)
		}
		// Wait briefly for the gvisor TUN device to disappear from the
		// namespace before we delete the namespace itself; otherwise the
		// kernel may emit "device busy" warnings or leave a stray link.
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

	if s.sysProxyManager != nil {
		s.logf(customlog.Processing, "Restoring system proxy settings...\n")
		if err := s.sysProxyManager.Restore(s.prevProxySettings); err != nil {
			s.logf(customlog.Failure, "Failed to restore system proxy settings: %v\n", err)
		} else {
			s.logf(customlog.Success, "System proxy settings restored.\n")
		}
		sysproxy.ClearState()
		s.sysProxyManager = nil
	}
}

// setupHostTun builds the exclusion list, runs preflight, then starts
// the host-tun sing-box instance in the root network namespace. Caller
// must already have a local SOCKS listener up (we dial 127.0.0.1).
func (s *Service) setupHostTun(ctx context.Context) error {
	// Extract SOCKS credentials from the inbound for the tunnel's dial.
	var socksUser, socksPass string
	switch in := s.inbound.(type) {
	case *pkgsingbox.Socks:
		socksUser = in.Username
		socksPass = in.Password
	case *pkgxray.Socks:
		socksUser = in.Username
		socksPass = in.Password
	}

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

	excludes, sshIP, warns := hosttun.BuildExcludes(
		ctx,
		s.config.BindInterface,
		s.config.ConfigLinks,
		extra,
		3*time.Second,
	)
	htCfg.RouteExcludeCIDRs = excludes
	s.hostTunCfg = htCfg

	for _, w := range warns {
		s.logf(customlog.Warning, "host-tun excludes: %s\n", w)
	}
	if sshIP != "" {
		s.logf(customlog.Info, "host-tun: SSH client %s detected via $SSH_CONNECTION; excluding from TUN.\n", sshIP)
	} else {
		s.logf(customlog.Info, "host-tun: $SSH_CONNECTION not set; skipping SSH exclusion (not running over SSH?)\n")
	}
	s.logf(customlog.Info, "host-tun: %d destinations excluded from TUN capture.\n", len(excludes))

	// Preflight: refuse to bring up TUN if the planned name already
	// exists, or if the route to the SSH client is already broken.
	if err := hosttun.Preflight(ctx, sshIP, htCfg.TunName); err != nil {
		return fmt.Errorf("host-tun preflight: %w", err)
	}

	s.logf(customlog.Processing, "host-tun: starting TUN %s on %s ...\n", htCfg.TunName, htCfg.TunAddr)
	inst, err := hosttun.Start(ctx, htCfg)
	if err != nil {
		return fmt.Errorf("host-tun start: %w", err)
	}
	s.hostTunInstance = inst
	s.logf(customlog.Success, "host-tun: tunnel up.\n")
	return nil
}

// runHostTunMode brings up the local SOCKS proxy, then the host-wide TUN,
// then runs the deadman timer; if the user fails to ACK in time, tears
// the TUN down to restore SSH.
func (s *Service) runHostTunMode(ctx context.Context, forceRotate <-chan struct{}) error {
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	errCh := make(chan error, 1)
	go func() {
		switch {
		case s.config.Chain:
			errCh <- s.runChainMode(runCtx, forceRotate)
		case len(s.config.ConfigLinks) == 1:
			errCh <- s.runSingleMode(runCtx, s.config.ConfigLinks[0])
		default:
			errCh <- s.runRotationMode(runCtx, forceRotate)
		}
	}()

	// Wait for the local listener to be ready.
	select {
	case <-s.proxyReady:
	case err := <-errCh:
		return err
	}

	if err := s.setupHostTun(ctx); err != nil {
		runCancel()
		<-errCh
		return err
	}

	// Deadman switch: prompt user to press ENTER within the configured
	// window. If they don't, tear down TUN (restore SSH path).
	deadmanDur := time.Duration(s.config.HostTunDeadman) * time.Second
	if deadmanDur > 0 {
		s.logf(customlog.Warning, "%s", hosttun.DeadmanInstructions(deadmanDur))
		confirm := make(chan struct{}, 1)
		go func() {
			var buf [1]byte
			if _, err := os.Stdin.Read(buf[:]); err == nil {
				select {
				case confirm <- struct{}{}:
				default:
				}
			}
		}()
		switch hosttun.RunDeadman(ctx, deadmanDur, confirm) {
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

// teardownHostTun closes the host-tun sing-box instance. Safe to call
// multiple times.
func (s *Service) teardownHostTun() {
	if s.hostTunInstance == nil {
		return
	}
	if err := s.hostTunInstance.Close(); err != nil {
		s.logf(customlog.Warning, "host-tun close returned error: %v\n", err)
	}
	s.hostTunInstance = nil
}

// signalProxyReady is called once after the first proxy instance is started
// so that the app mode setup can proceed.
func (s *Service) signalProxyReady() {
	s.proxyReadyOnce.Do(func() { close(s.proxyReady) })
}

// setupAppMode creates the network namespace, veth pair, and TUN tunnel.
// It must be called after the proxy instance is listening.
func (s *Service) setupAppMode(ctx context.Context) error {
	nsName := s.config.NamespaceName
	if nsName == "" {
		nsName = fmt.Sprintf("xk-%d", os.Getpid())
	}

	// Extract SOCKS credentials from the inbound so the tunnel can authenticate.
	var socksUser, socksPass string
	switch in := s.inbound.(type) {
	case *pkgsingbox.Socks:
		socksUser = in.Username
		socksPass = in.Password
	case *pkgxray.Socks:
		socksUser = in.Username
		socksPass = in.Password
	}

	port, _ := strconv.ParseUint(s.config.ListenPort, 10, 16)
	// Derive a unique suffix for veth names from the PID so parallel
	// `xray-knife proxy --mode app` invocations don't collide on the
	// shared "xk-veth-h"/"xk-veth-ns" constants.
	nsCfg := netns.DefaultConfig(uint16(port), strconv.Itoa(os.Getpid()))
	nsCfg.Name = nsName
	nsCfg.SocksUser = socksUser
	nsCfg.SocksPass = socksPass
	if s.config.DNS != "" {
		nsCfg.DNS = s.config.DNS
	}
	if s.config.DNSType != "" {
		nsCfg.DNSType = s.config.DNSType
	}
	s.nsCfg = nsCfg

	// Persist state for crash recovery (Pid + BootID are stamped by
	// SaveState; RecoverFromCrash uses them to skip live owners).
	if err := netns.SaveState(&netns.State{
		Name:     nsName,
		VethHost: nsCfg.VethHost,
		VethNS:   nsCfg.VethNS,
	}); err != nil {
		return fmt.Errorf("failed to save namespace state: %w", err)
	}

	ns, err := netns.Setup(nsCfg)
	if err != nil {
		netns.ClearState()
		return fmt.Errorf("failed to set up namespace: %w", err)
	}
	s.nsManager = ns

	tunnel, err := netns.StartTunnel(ctx, nsName, nsCfg)
	if err != nil {
		ns.Close()
		netns.ClearState()
		s.nsManager = nil
		return fmt.Errorf("failed to start tunnel in namespace: %w", err)
	}
	s.nsTunnel = tunnel

	s.logf(customlog.Success, "Network namespace '%s' is ready.\n", nsName)
	return nil
}

// Run blocks until the context is canceled, running either single or rotation mode.
func (s *Service) Run(ctx context.Context, forceRotate <-chan struct{}) error {
	if len(s.config.ConfigLinks) == 0 {
		return errors.New("no configuration links provided")
	}

	if s.config.Mode == "app" {
		return s.runAppMode(ctx, forceRotate)
	}

	if s.config.Mode == "host-tun" {
		return s.runHostTunMode(ctx, forceRotate)
	}

	if s.config.Chain {
		return s.runChainMode(ctx, forceRotate)
	}

	if len(s.config.ConfigLinks) == 1 {
		return s.runSingleMode(ctx, s.config.ConfigLinks[0])
	}

	return s.runRotationMode(ctx, forceRotate)
}

// runAppMode starts the proxy in a goroutine, waits for it to be ready,
// sets up the namespace and tunnel, then either launches a shell or
// waits for the proxy to finish.
func (s *Service) runAppMode(ctx context.Context, forceRotate <-chan struct{}) error {
	// Derive a context that we can cancel when the shell exits.
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	// Pick the right runner for the namespace's proxy. Chain mode and the
	// single-config path both need to be honored here; the namespace just
	// happens to be the outer container around them.
	errCh := make(chan error, 1)
	go func() {
		switch {
		case s.config.Chain:
			errCh <- s.runChainMode(runCtx, forceRotate)
		case len(s.config.ConfigLinks) == 1:
			errCh <- s.runSingleMode(runCtx, s.config.ConfigLinks[0])
		default:
			errCh <- s.runRotationMode(runCtx, forceRotate)
		}
	}()

	// Wait for the proxy to start listening.
	select {
	case <-s.proxyReady:
	case err := <-errCh:
		return err
	}

	// Set up namespace + tunnel.
	if err := s.setupAppMode(ctx); err != nil {
		runCancel()
		<-errCh
		return err
	}

	if s.config.Shell {
		s.logf(customlog.Info, "Launching shell in namespace. Type 'exit' to shut down.\n")
		shellErr := s.nsManager.Shell(ctx)
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
	nsName := s.config.NamespaceName
	if nsName == "" {
		nsName = fmt.Sprintf("xk-%d", os.Getpid())
	}
	s.logf(customlog.Info, "Use: xray-knife exec %s -- <command>\n", nsName)
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

	instance, err := s.core.MakeInstance(ctx, outbound)
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
			s.logf(customlog.Processing, "Restarting outbound instance...")
			instance.Close()
			newInst, err := s.core.MakeInstance(ctx, outbound)
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

	var lastUsedLink string

	// Initial setup — no old listener to release yet.
	s.setRotationStatus("rotating")
	instance, result, err := s.findAndStartWorkingConfig(ctx, examiner, "", nil)
	if err != nil {
		s.logf(customlog.Failure, "No working config found on startup: %v", err)
		return err
	}
	currentInstance = instance
	lastUsedLink = result.ConfigLink
	s.setRotationStatus("idle")
	s.signalProxyReady()

	// Health-check ticker is optional; a zero interval disables it.
	var healthTicker *time.Ticker
	var healthTickerC <-chan time.Time
	if s.config.HealthCheckInterval > 0 {
		healthTicker = time.NewTicker(time.Duration(s.config.HealthCheckInterval) * time.Second)
		healthTickerC = healthTicker.C
		defer healthTicker.Stop()
	}

	healthFailThreshold := int(s.config.HealthFailThreshold)
	if healthFailThreshold <= 0 {
		healthFailThreshold = defaultHealthFailThresh
	}
	healthFails := 0

	for {
		rotationDuration := time.Duration(s.config.RotationInterval) * time.Second
		s.mu.RLock()
		isStalled := s.rotationStatus == "stalled"
		s.mu.RUnlock()
		if isStalled {
			rotationDuration = 30 * time.Second // back off a bit when we couldn't find anything
		}

		s.mu.Lock()
		s.nextRotationTime = time.Now().Add(rotationDuration)
		s.mu.Unlock()

		s.logf(customlog.Info, "Next rotation in %v. Current outbound: %s", rotationDuration, lastUsedLink)

		timer := time.NewTimer(rotationDuration)

		doRotate := false
	waitLoop:
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-forceRotate:
				s.logf(customlog.Processing, "Manual rotation triggered.")
				timer.Stop()
				doRotate = true
				break waitLoop
			case <-timer.C:
				s.logf(customlog.Processing, "Rotation interval elapsed.")
				doRotate = true
				break waitLoop
			case <-healthTickerC:
				if s.healthCheck(ctx) {
					healthFails = 0
					continue
				}
				healthFails++
				s.logf(customlog.Warning, "Health check failed (%d/%d).", healthFails, healthFailThreshold)
				if healthFails < healthFailThreshold {
					continue
				}
				// Threshold reached: record a strike against the current
				// outbound and trigger a rotation.
				s.recordStrike(lastUsedLink, "health check failed")
				healthFails = 0
				timer.Stop()
				doRotate = true
				break waitLoop
			}
		}

		if !doRotate {
			continue
		}

		s.setRotationStatus("rotating")

		// releaseOld runs synchronously just before the new instance binds
		// its inbound port. Doing it in-line means the two listeners can't
		// fight over the same port — which is what happened when the old
		// connection was closed asynchronously. DrainTimeout, when set, is
		// the dwell time we spend on the current outbound before flipping
		// over; it shows up as a short blip in listener availability.
		releaseOld := func() {
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

		instance, result, err := s.findAndStartWorkingConfig(ctx, examiner, lastUsedLink, releaseOld)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if currentInstance == nil {
				s.logf(customlog.Warning, "Rotation failed and old listener already released: %v. Retrying soon.", err)
			} else {
				s.logf(customlog.Warning, "Rotation failed: %v. Keeping current outbound.", err)
			}
			s.setRotationStatus("stalled")
			continue
		}

		s.logf(customlog.Success, "Switched to: %s", result.ConfigLink)
		currentInstance = instance
		lastUsedLink = result.ConfigLink
		s.setRotationStatus("idle")
	}
}

// findAndStartWorkingConfig probes a batch from the pool and brings up the
// first candidate that survives Start. releasePort, when non-nil, fires
// once right before the first Start attempt; the rotation loop uses it to
// close the previous instance so the new one can claim the inbound port.
func (s *Service) findAndStartWorkingConfig(
	ctx context.Context,
	examiner *pkghttp.Examiner,
	lastUsedLink string,
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
		now := time.Now()
		filtered := make([]string, 0, len(availableLinks))
		for _, link := range availableLinks {
			entry, exists := s.blacklist[link]
			if !exists {
				filtered = append(filtered, link)
			} else if now.After(entry.blacklistedUntil) {
				delete(s.blacklist, link)
				filtered = append(filtered, link)
			}
		}
		if len(filtered) == 0 {
			s.logf(customlog.Warning, "All configs are blacklisted. Clearing blacklist.\n")
			s.blacklist = make(map[string]*blacklistEntry)
			filtered = availableLinks
		} else if len(filtered) < len(availableLinks) {
			s.logf(customlog.Info, "Skipped %d blacklisted configs.\n", len(availableLinks)-len(filtered))
		}
		availableLinks = filtered
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
	// configs eventually leave the rotation pool.
	for _, res := range results {
		if res.Status != "passed" && res.ConfigLink != "" {
			reason := res.Status
			if res.Reason != "" {
				reason = res.Reason
			}
			s.recordStrike(res.ConfigLink, reason)
		}
	}

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

		// Build the instance first — that part does not touch the network.
		instance, err := s.core.MakeInstance(ctx, res.Protocol)
		if err != nil {
			s.logf(customlog.Failure, "Error making core instance with '%s': %v\n", res.ConfigLink, err)
			s.recordStrike(res.ConfigLink, fmt.Sprintf("MakeInstance: %v", err))
			continue
		}
		// Hand the port over from the old listener right before the new one
		// tries to bind. Only do this once per call so a sequence of Start
		// failures doesn't bounce in and out of "no listener".
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

// chainHealthCheck is the chain-mode twin of healthCheck — probe through
// the live listener first, only spin up a temporary chained instance when
// the inbound type leaves us no other choice.
func (s *Service) chainHealthCheck(ctx context.Context) bool {
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
		return doHealthGET(ctx, client, timeout)
	}

	client, instance, err := s.makeChainedHttpClient(ctx, hops, timeout)
	if err != nil {
		return false
	}
	defer instance.Close()
	return doHealthGET(ctx, client, timeout)
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
	isFixedChain := s.config.ChainLinks != "" || s.config.ChainFile != ""
	rotation := s.config.ChainRotation
	if rotation == "" {
		rotation = "none"
	}

	// Fixed chains never rotate.
	if isFixedChain {
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

	s.logChainHops(hops)

	instance, err := s.makeChainedInstance(ctx, hops)
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

	s.logf(customlog.Success, "Chain proxy started (fixed, %d hops).\n", len(hops))
	s.signalProxyReady()

	<-ctx.Done()
	s.logf(customlog.Processing, "Shutting down chain proxy...\n")
	return nil
}

// runChainNoRotation selects hops from the pool once and runs without rotation.
func (s *Service) runChainNoRotation(ctx context.Context) error {
	numHops := int(s.config.ChainHops)
	if numHops < 2 {
		numHops = 2
	}

	hops, err := selectChainFromPool(s.core, s.config.ConfigLinks, numHops)
	if err != nil {
		return fmt.Errorf("failed to select chain from pool: %w", err)
	}

	s.logChainHops(hops)

	instance, err := s.makeChainedInstance(ctx, hops)
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

	s.logf(customlog.Success, "Chain proxy started (no rotation, %d hops).\n", len(hops))
	s.signalProxyReady()

	<-ctx.Done()
	s.logf(customlog.Processing, "Shutting down chain proxy...\n")
	return nil
}

// runChainExitRotation keeps the first N-1 hops fixed and rotates the exit hop.
func (s *Service) runChainExitRotation(ctx context.Context, forceRotate <-chan struct{}) error {
	numHops := int(s.config.ChainHops)
	if numHops < 2 {
		numHops = 2
	}

	// Select initial chain.
	hops, err := selectChainFromPool(s.core, s.config.ConfigLinks, numHops)
	if err != nil {
		return fmt.Errorf("failed to select initial chain from pool: %w", err)
	}

	// The fixed entry hops are all but the last.
	fixedHops := make([]protocol.Protocol, len(hops)-1)
	copy(fixedHops, hops[:len(hops)-1])

	// Test the initial chain.
	timeout := time.Duration(s.config.MaximumAllowedDelay) * time.Millisecond
	client, testInst, err := s.makeChainedHttpClient(ctx, hops, timeout)
	if err != nil {
		return fmt.Errorf("failed to build initial chain for testing: %w", err)
	}
	if !s.testChainViaClient(ctx, client, timeout) {
		testInst.Close()
		return fmt.Errorf("initial chain failed health check")
	}
	testInst.Close()

	// Start the real instance.
	var currentInstance protocol.Instance
	currentInstance, err = s.makeChainedInstance(ctx, hops)
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

	s.logChainHops(hops)
	s.logf(customlog.Success, "Chain proxy started (exit rotation, %d hops).\n", len(hops))
	s.setRotationStatus("idle")
	s.signalProxyReady()

	var lastExitLink string
	if len(hops) > 0 {
		lastExitLink = hops[len(hops)-1].GetLink()
	}

	// Set up health check ticker.
	var healthTicker *time.Ticker
	var healthTickerC <-chan time.Time
	if s.config.HealthCheckInterval > 0 {
		healthTicker = time.NewTicker(time.Duration(s.config.HealthCheckInterval) * time.Second)
		healthTickerC = healthTicker.C
		defer healthTicker.Stop()
	}

	for {
		rotationDuration := time.Duration(s.config.RotationInterval) * time.Second
		s.mu.Lock()
		s.nextRotationTime = time.Now().Add(rotationDuration)
		s.mu.Unlock()

		timer := time.NewTimer(rotationDuration)
		doRotate := false

	exitWaitLoop:
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-forceRotate:
				s.logf(customlog.Processing, "Manual chain rotation triggered.\n")
				timer.Stop()
				doRotate = true
				break exitWaitLoop
			case <-timer.C:
				doRotate = true
				break exitWaitLoop
			case <-healthTickerC:
				if !s.chainHealthCheck(ctx) {
					s.logf(customlog.Warning, "Chain health check failed! Triggering rotation.\n")
					timer.Stop()
					doRotate = true
					break exitWaitLoop
				}
			}
		}

		if !doRotate {
			continue
		}

		s.setRotationStatus("rotating")

		// Pick a fresh exit hop that isn't already in the chain or the one
		// we're rotating away from.
		newHops, err := selectExitHopFromPool(s.core, s.config.ConfigLinks, fixedHops, lastExitLink)
		if err != nil {
			s.logf(customlog.Warning, "No new exit hop available: %v. Keeping current chain.\n", err)
			s.setRotationStatus("stalled")
			continue
		}

		// Probe the candidate chain end-to-end before we touch the live one.
		testClient, testInst, err := s.makeChainedHttpClient(ctx, newHops, timeout)
		if err != nil {
			s.logf(customlog.Warning, "Could not build candidate chain for testing: %v\n", err)
			s.setRotationStatus("stalled")
			continue
		}
		if !s.testChainViaClient(ctx, testClient, timeout) {
			testInst.Close()
			s.logf(customlog.Warning, "Candidate chain failed health check. Keeping current chain.\n")
			s.setRotationStatus("stalled")
			continue
		}
		testInst.Close()

		// Build the new instance first (cheap, no socket use), free the old
		// listener, then bind the new one. Same ordering as the non-chain
		// loop — both new and old instances configure the same inbound
		// port, so they can't be alive at once.
		newInstance, err := s.makeChainedInstance(ctx, newHops)
		if err != nil {
			s.logf(customlog.Warning, "Could not create new chained instance: %v\n", err)
			s.setRotationStatus("stalled")
			continue
		}

		if currentInstance != nil {
			if drain := time.Duration(s.config.DrainTimeout) * time.Second; drain > 0 {
				s.logf(customlog.Processing, "Holding current chain for %v before switching...", drain)
				select {
				case <-time.After(drain):
				case <-ctx.Done():
				}
			}
			currentInstance.Close()
			currentInstance = nil
		}

		if err := newInstance.Start(); err != nil {
			newInstance.Close()
			s.logf(customlog.Warning, "Could not start new chained instance: %v\n", err)
			s.setRotationStatus("stalled")
			continue
		}

		currentInstance = newInstance
		hops = newHops
		lastExitLink = hops[len(hops)-1].GetLink()

		s.mu.Lock()
		s.activeChainHops = hops
		s.mu.Unlock()

		s.logChainHops(hops)
		s.logf(customlog.Success, "Chain exit hop rotated.\n")
		s.setRotationStatus("idle")
	}
}

// runChainFullRotation rotates the entire chain on each cycle.
func (s *Service) runChainFullRotation(ctx context.Context, forceRotate <-chan struct{}) error {
	numHops := int(s.config.ChainHops)
	if numHops < 2 {
		numHops = 2
	}
	timeout := time.Duration(s.config.MaximumAllowedDelay) * time.Millisecond

	// Select and test initial chain.
	hops, err := s.findWorkingChain(ctx, numHops, timeout)
	if err != nil {
		return fmt.Errorf("failed to find initial working chain: %w", err)
	}

	var currentInstance protocol.Instance
	currentInstance, err = s.makeChainedInstance(ctx, hops)
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

	s.logChainHops(hops)
	s.logf(customlog.Success, "Chain proxy started (full rotation, %d hops).\n", len(hops))
	s.setRotationStatus("idle")
	s.signalProxyReady()

	// Set up health check ticker.
	var healthTicker *time.Ticker
	var healthTickerC <-chan time.Time
	if s.config.HealthCheckInterval > 0 {
		healthTicker = time.NewTicker(time.Duration(s.config.HealthCheckInterval) * time.Second)
		healthTickerC = healthTicker.C
		defer healthTicker.Stop()
	}

	for {
		rotationDuration := time.Duration(s.config.RotationInterval) * time.Second
		s.mu.Lock()
		s.nextRotationTime = time.Now().Add(rotationDuration)
		s.mu.Unlock()

		timer := time.NewTimer(rotationDuration)
		doRotate := false

	fullWaitLoop:
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-forceRotate:
				s.logf(customlog.Processing, "Manual chain rotation triggered.\n")
				timer.Stop()
				doRotate = true
				break fullWaitLoop
			case <-timer.C:
				doRotate = true
				break fullWaitLoop
			case <-healthTickerC:
				if !s.chainHealthCheck(ctx) {
					s.logf(customlog.Warning, "Chain health check failed! Triggering full rotation.\n")
					timer.Stop()
					doRotate = true
					break fullWaitLoop
				}
			}
		}

		if !doRotate {
			continue
		}

		s.setRotationStatus("rotating")

		newHops, err := s.findWorkingChain(ctx, numHops, timeout)
		if err != nil {
			s.logf(customlog.Warning, "No new working chain: %v. Keeping current chain.\n", err)
			s.setRotationStatus("stalled")
			continue
		}

		newInstance, err := s.makeChainedInstance(ctx, newHops)
		if err != nil {
			s.logf(customlog.Warning, "Could not create new chained instance: %v\n", err)
			s.setRotationStatus("stalled")
			continue
		}

		if currentInstance != nil {
			if drain := time.Duration(s.config.DrainTimeout) * time.Second; drain > 0 {
				s.logf(customlog.Processing, "Holding current chain for %v before switching...", drain)
				select {
				case <-time.After(drain):
				case <-ctx.Done():
				}
			}
			currentInstance.Close()
			currentInstance = nil
		}

		if err := newInstance.Start(); err != nil {
			newInstance.Close()
			s.logf(customlog.Warning, "Could not start new chained instance: %v\n", err)
			s.setRotationStatus("stalled")
			continue
		}

		currentInstance = newInstance
		hops = newHops

		s.mu.Lock()
		s.activeChainHops = hops
		s.mu.Unlock()

		s.logChainHops(hops)
		s.logf(customlog.Success, "Full chain rotated.\n")
		s.setRotationStatus("idle")
	}
}

// findWorkingChain tries multiple random chain combinations from the pool
// and returns the first one that passes a health check. The attempt budget
// is configurable via Config.ChainAttempts so callers with small pools (or
// flaky relays) can tune it.
func (s *Service) findWorkingChain(ctx context.Context, numHops int, timeout time.Duration) ([]protocol.Protocol, error) {
	maxAttempts := int(s.config.ChainAttempts)
	if maxAttempts <= 0 {
		maxAttempts = defaultChainAttempts
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		hops, err := selectChainFromPool(s.core, s.config.ConfigLinks, numHops)
		if err != nil {
			continue
		}

		client, testInst, err := s.makeChainedHttpClient(ctx, hops, timeout)
		if err != nil {
			continue
		}

		if s.testChainViaClient(ctx, client, timeout) {
			testInst.Close()
			return hops, nil
		}
		testInst.Close()
	}
	return nil, fmt.Errorf("could not find a working chain after %d attempts", maxAttempts)
}

// testChainViaClient sends a test HTTP request through the given client.
func (s *Service) testChainViaClient(ctx context.Context, client *http.Client, timeout time.Duration) bool {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", "https://cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
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
		TestEndpoint:           "https://cloudflare.com/cdn-cgi/trace",
		TestEndpointHttpMethod: "GET",
		DoSpeedtest:            false,
		DoIPInfo:               true,
		// Keep test-time dials on the same interface the live outbound
		// uses, otherwise a passing test can hide a runtime --bind failure.
		BindInterface: s.config.BindInterface,
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
		// System mode uses an HTTP inbound (xray) or mixed HTTP+SOCKS inbound (sing-box)
		// so the OS system proxy settings work with all browsers.
		switch s.config.CoreType {
		case "xray":
			return &pkgxray.Http{
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
