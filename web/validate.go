package web

import (
	"fmt"
	"math/bits"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v11/pkg/scanner"
)

// Scanner limits. Without sampling a scan walks every address, so a range
// larger than the IP cap is refused with a hint instead of silently scanning
// only its first addresses (an IPv6 /32 would never finish anyway).
const (
	defaultScannerThreads = 100
	maxScannerThreads     = 4096
	maxIPsPerScan         = 1 << 24
	// maxSamplePerSubnet is a /16 worth of addresses per sampled block.
	maxSamplePerSubnet = 1 << 16
)

// prefixSize returns the number of addresses in p, saturating at MaxUint64
// (IPv6 prefixes can be far larger than any counter).
func prefixSize(p netip.Prefix) uint64 {
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits >= 64 {
		return ^uint64(0)
	}
	return 1 << hostBits
}

// buildCfScanJob validates a scanner request and fills CLI defaults.
func buildCfScanJob(cfg scanner.ScannerConfig) (cfScanJob, error) {
	prefixes, err := scanner.ParsePrefixes(cfg.Subnets)
	if err != nil {
		return cfScanJob{}, badRequest("%v", err)
	}
	if len(prefixes) == 0 {
		return cfScanJob{}, badRequest("no subnets to scan")
	}
	if cfg.SamplePerSubnet < 0 || cfg.SamplePerSubnet > maxSamplePerSubnet {
		return cfScanJob{}, badRequest("samplePerSubnet must be between 0 and %d", maxSamplePerSubnet)
	}
	if cfg.MaxIPs < 0 || cfg.MaxIPs > maxIPsPerScan {
		return cfScanJob{}, badRequest("maxIPs must be between 0 (default %d) and %d", scanner.DefaultMaxIPs, maxIPsPerScan)
	}
	limit := uint64(scanner.DefaultMaxIPs)
	if cfg.MaxIPs > 0 {
		limit = uint64(cfg.MaxIPs)
	}
	subnets := make([]string, 0, len(prefixes))
	var total uint64
	for _, p := range prefixes {
		var carry uint64
		total, carry = bits.Add64(total, prefixSize(p), 0)
		if carry != 0 {
			total = ^uint64(0)
		}
		subnets = append(subnets, p.String())
	}
	if cfg.SamplePerSubnet == 0 && total > limit {
		hint := "set samplePerSubnet (e.g. 2) to test a few IPs from every block, or narrow the ranges"
		if total < maxIPsPerScan {
			hint += fmt.Sprintf(", or raise maxIPs (up to %d)", maxIPsPerScan)
		}
		return cfScanJob{}, badRequest("the ranges hold more addresses than the %d-IP cap; %s", limit, hint)
	}
	cfg.Subnets = subnets

	if cfg.ThreadCount == 0 {
		cfg.ThreadCount = defaultScannerThreads
	}
	if cfg.ThreadCount < 1 || cfg.ThreadCount > maxScannerThreads {
		return cfScanJob{}, badRequest("threadCount must be between 1 and %d", maxScannerThreads)
	}
	for name, v := range map[string]int{
		"timeout":              cfg.RequestTimeout,
		"retry":                cfg.RetryCount,
		"downloadMB":           cfg.DownloadMB,
		"uploadMB":             cfg.UploadMB,
		"speedtestTop":         cfg.SpeedtestTop,
		"speedtestConcurrency": cfg.SpeedtestConcurrency,
		"speedtestTimeout":     cfg.SpeedtestTimeout,
	} {
		if v < 0 {
			return cfScanJob{}, badRequest("%s must not be negative", name)
		}
	}
	if cfg.DoSpeedtest {
		if cfg.DownloadMB == 0 {
			cfg.DownloadMB = 20
		}
		if cfg.UploadMB == 0 {
			cfg.UploadMB = 10
		}
	}
	if cfg.Port == 0 {
		cfg.Port = 443
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return cfScanJob{}, badRequest("port must be between 1 and 65535")
	}
	cfg.ConfigLink = strings.TrimSpace(cfg.ConfigLink)
	// The web runner always writes CSV (the history endpoints read it).
	cfg.OutputFormat = ""
	if cfg.SaveToDB {
		if err := dbReady(); err != nil {
			return cfScanJob{}, err
		}
	}
	return cfScanJob{cfg: cfg}, nil
}

// proxyStartRequest is the proxy start body: pkg/proxy Config plus a few
// web-only fields.
type proxyStartRequest struct {
	proxy.Config
	// ConfigLinksLower accepts the lowercase spelling of ConfigLinks.
	ConfigLinksLower []string `json:"configLinks"`
	// HostTunExcludePrivatePtr distinguishes "omitted" (default true, as in
	// the CLI) from an explicit false.
	HostTunExcludePrivatePtr *bool `json:"hostTunExcludePrivate"`
	// HostTunDeadmanPtr distinguishes "omitted" (the CLI's 60s) from 0 (off).
	HostTunDeadmanPtr *uint16 `json:"hostTunDeadman"`
}

// defaultHostTunDeadman matches `xray-knife proxy tun --tun-deadman`.
const defaultHostTunDeadman = 60

var namespaceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)

// validateProxyConfig checks a proxy start request and fills CLI defaults.
// app and host-tun modes reconfigure host networking as root, so they are
// only accepted when the server was started with --allow-host-modes.
func validateProxyConfig(req *proxyStartRequest, allowHostModes bool) (proxy.Config, error) {
	cfg := req.Config
	if len(cfg.ConfigLinks) == 0 && len(req.ConfigLinksLower) > 0 {
		cfg.ConfigLinks = req.ConfigLinksLower
	}
	cfg.ConfigLinks = cleanLinks(cfg.ConfigLinks)

	switch cfg.Mode {
	case "", "inbound", "system":
	case "app", "host-tun":
		if !allowHostModes {
			cliCmd := map[string]string{"app": "proxy app", "host-tun": "proxy tun"}[cfg.Mode]
			return cfg, badRequest("mode %q changes host networking and is disabled in the web UI; restart webui with --allow-host-modes or use `xray-knife %s`", cfg.Mode, cliCmd)
		}
	default:
		return cfg, badRequest("unknown mode %q (want inbound, system, app or host-tun)", cfg.Mode)
	}
	if cfg.KillSwitch && cfg.Mode != "app" && cfg.Mode != "host-tun" {
		return cfg, badRequest("killSwitch only applies to the app and host-tun modes")
	}
	if cfg.Mode == "app" && cfg.NamespaceName != "" && (!namespaceNameRe.MatchString(cfg.NamespaceName) || strings.Contains(cfg.NamespaceName, "..")) {
		return cfg, badRequest("namespaceName may only contain letters, digits, '_', '.' and '-' (max 32)")
	}
	if cfg.Mode == "app" && cfg.Shell {
		return cfg, badRequest("shell=true needs a terminal; use a named namespace from the web UI")
	}
	// The web server never reads stdin: the deadman is confirmed through
	// POST /proxy/deadman/confirm instead.
	cfg.ExternalDeadmanConfirm = true
	if cfg.Mode == "host-tun" {
		cfg.HostTunDeadman = defaultHostTunDeadman
		if req.HostTunDeadmanPtr != nil {
			cfg.HostTunDeadman = *req.HostTunDeadmanPtr
		}
		cfg.HostTunExcludePrivate = req.HostTunExcludePrivatePtr == nil || *req.HostTunExcludePrivatePtr
	} else {
		if req.HostTunDeadmanPtr != nil {
			cfg.HostTunDeadman = *req.HostTunDeadmanPtr
		}
		if req.HostTunExcludePrivatePtr != nil {
			cfg.HostTunExcludePrivate = *req.HostTunExcludePrivatePtr
		}
	}

	addr, err := proxy.NormalizeListenAddr(cfg.ListenAddr)
	if err != nil {
		return cfg, badRequest("listenAddr: %v", err)
	}
	cfg.ListenAddr = addr
	if cfg.ListenPort == "" {
		cfg.ListenPort = "9999"
	}
	port, err := strconv.Atoi(strings.TrimSpace(cfg.ListenPort))
	if err != nil || port < 1 || port > 65535 {
		return cfg, badRequest("listenPort must be a number between 1 and 65535")
	}
	cfg.ListenPort = strconv.Itoa(port)

	// With no links the proxy draws its pool from the database.
	// Fixed chain hops imply chain mode (proxy.New) and need no pool.
	if len(cfg.ConfigLinks) == 0 && strings.TrimSpace(cfg.ChainLinks) == "" && strings.TrimSpace(cfg.ChainFile) == "" {
		if err := dbReady(); err != nil {
			return cfg, badRequest("no config links given and the database is unavailable: %v", err)
		}
	}
	switch cfg.ChainRotation {
	case "", "none", "exit", "full":
	default:
		return cfg, badRequest("chainRotation must be none, exit or full")
	}
	return cfg, nil
}

// dbReady opens the database if needed; failures map to 503.
func dbReady() error {
	if _, err := database.Conn(); err != nil {
		return &apiError{status: 503, code: codeDBUnavailable, msg: fmt.Sprintf("database unavailable: %v", err)}
	}
	return nil
}
