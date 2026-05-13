package hosttun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Static exclusions always applied in host-tun mode. Each entry is a
// CIDR prefix that must NOT be captured by the TUN routes.
//
//   - 127.0.0.0/8       — loopback; the SOCKS dialer talks here.
//   - 169.254.0.0/16    — link-local + cloud metadata (169.254.169.254).
//   - 224.0.0.0/4       — multicast.
//   - 240.0.0.0/4       — reserved.
//   - ::1/128           — IPv6 loopback.
//   - fe80::/10         — IPv6 link-local.
var mandatoryExcludes = []string{
	"127.0.0.0/8",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::1/128",
	"fe80::/10",
}

// SSHClientIP returns the SSH client IP derived from the SSH_CONNECTION
// env var, or "" if not running under SSH. The env var format is:
//
//	"client_ip client_port server_ip server_port"
func SSHClientIP() string {
	conn := os.Getenv("SSH_CONNECTION")
	if conn == "" {
		return ""
	}
	parts := strings.Fields(conn)
	if len(parts) < 1 {
		return ""
	}
	if ip := net.ParseIP(parts[0]); ip != nil {
		return ip.String()
	}
	return ""
}

// InterfaceCIDRs returns all assigned CIDRs on the given interface.
// Used to keep traffic to/from the local NIC's subnet off the TUN.
func InterfaceCIDRs(iface string) ([]string, error) {
	if iface == "" {
		return nil, nil
	}
	link, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}
	addrs, err := link.Addrs()
	if err != nil {
		return nil, fmt.Errorf("addrs on %q: %w", iface, err)
	}
	var out []string
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		out = append(out, ipNet.String())
	}
	return out, nil
}

// ResolveHosts resolves each entry in hosts (hostname or IP) to its IPv4
// and IPv6 addresses, returns CIDR /32 or /128 strings. Resolution runs
// concurrently with a per-host timeout. Hosts that fail to resolve are
// silently skipped — caller has already-resolved IPs covered.
func ResolveHosts(ctx context.Context, hosts []string, perHostTimeout time.Duration) []string {
	if perHostTimeout <= 0 {
		perHostTimeout = 3 * time.Second
	}
	seen := map[string]struct{}{}
	var seenMu sync.Mutex
	var out []string
	var outMu sync.Mutex
	var wg sync.WaitGroup

	// Cap concurrency to avoid hammering the resolver.
	sem := make(chan struct{}, 32)

	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		seenMu.Lock()
		if _, dup := seen[host]; dup {
			seenMu.Unlock()
			continue
		}
		seen[host] = struct{}{}
		seenMu.Unlock()

		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Already an IP literal?
			if ip := net.ParseIP(h); ip != nil {
				outMu.Lock()
				out = append(out, ipToCIDR(ip))
				outMu.Unlock()
				return
			}

			lookupCtx, cancel := context.WithTimeout(ctx, perHostTimeout)
			defer cancel()
			addrs, err := (&net.Resolver{}).LookupNetIP(lookupCtx, "ip", h)
			if err != nil {
				return
			}
			outMu.Lock()
			for _, a := range addrs {
				out = append(out, addrToCIDR(a))
			}
			outMu.Unlock()
		}(host)
	}
	wg.Wait()
	return dedup(out)
}

// HostsFromConfigLinks returns the hostnames/IPs from a slice of
// xray/sing-box-style URLs. Best-effort: a malformed link contributes
// nothing rather than blocking the rest.
func HostsFromConfigLinks(links []string) []string {
	var out []string
	for _, l := range links {
		h := hostFromLink(l)
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

func hostFromLink(link string) string {
	link = strings.TrimSpace(link)
	if link == "" {
		return ""
	}
	// vmess:// is base64-encoded JSON, handled separately below.
	if strings.HasPrefix(link, "vmess://") {
		return ""
	}
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	if u.Host == "" {
		return ""
	}
	host := u.Hostname()
	return host
}

func ipToCIDR(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String() + "/32"
	}
	return ip.String() + "/128"
}

func addrToCIDR(a netip.Addr) string {
	if a.Is4() {
		return a.String() + "/32"
	}
	return a.String() + "/128"
}

func dedup(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// BuildExcludes assembles the full exclusion list:
//
//   - mandatory loopback / link-local / multicast / reserved
//   - SSH client IP (from $SSH_CONNECTION) if present
//   - all CIDRs on physIface (local LAN reachability + management plane)
//   - all configured DNS server IPs (resolved via system resolver)
//   - all upstream config-link hosts (resolved)
//   - any extra user-supplied CIDRs
//
// Returns (excludes, sshClientIP, errors-merged-as-warnings).
func BuildExcludes(ctx context.Context, physIface string, configLinks []string, extraCIDRs []string, resolveTimeout time.Duration) ([]string, string, []string) {
	var warns []string
	out := append([]string{}, mandatoryExcludes...)

	sshIP := SSHClientIP()
	if sshIP != "" {
		out = append(out, ipToCIDR(net.ParseIP(sshIP)))
	}

	if physIface != "" {
		cidrs, err := InterfaceCIDRs(physIface)
		if err != nil {
			warns = append(warns, err.Error())
		} else {
			out = append(out, cidrs...)
		}
	}

	hosts := HostsFromConfigLinks(configLinks)
	resolved := ResolveHosts(ctx, hosts, resolveTimeout)
	out = append(out, resolved...)

	if len(hosts) > 0 && len(resolved) == 0 {
		warns = append(warns, "no upstream config hosts could be resolved — TUN may loop")
	}

	out = append(out, extraCIDRs...)

	return dedup(out), sshIP, warns
}
