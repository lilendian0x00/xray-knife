package hosttun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/netbind"
)

var resolverMu sync.Mutex

// BootstrapDNSServers picks the resolvers used for the proxy servers' own
// names while the TUN is up: the host's non-loopback nameservers, else
// the tunnel DNS when it is an IP literal, else 1.1.1.1.
func BootstrapDNSServers(system []string, tunnelDNS string) []string {
	if len(system) > 0 {
		return system
	}
	host := strings.TrimSpace(tunnelDNS)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && !a.IsLoopback() {
		return []string{a.String()}
	}
	return []string{"1.1.1.1"}
}

// NewBoundResolver returns a Go resolver that sends its queries to
// servers over sockets bound to iface and, when mark is non-zero, marked
// with it (so the bypass rule and the kill switch let them out). Proxy
// server names resolved through it never enter the TUN.
func NewBoundResolver(iface string, servers []string, mark uint32) (*net.Resolver, error) {
	if len(servers) == 0 {
		return nil, errors.New("no bootstrap DNS servers")
	}
	binder, err := netbind.New(iface)
	if err != nil {
		return nil, err
	}
	var next atomic.Uint32
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 5 * time.Second}
			if mark != 0 {
				if ctl := markControl(mark); ctl != nil {
					d.Control = ctl
				}
			}
			binder.ApplyDialer(d)
			srv := servers[int(next.Add(1)-1)%len(servers)]
			return d.DialContext(ctx, network, net.JoinHostPort(srv, "53"))
		},
	}, nil
}

// InstallGlobalResolver makes r the process-wide net.DefaultResolver and
// returns a function that puts the previous one back.
//
// xray's dialer resolves a proxy server's hostname through
// net.DefaultResolver and only binds the final TCP socket, so without
// this, on a host whose resolver traffic enters the TUN, every
// domain-based config would wait on a lookup routed through itself.
// Replacing the global is only safe in a process that does nothing else
// (the CLI), and before any core starts: net.DefaultResolver is read
// without synchronisation, and every lookup of the process — not just the
// proxy's — leaves outside the tunnel while it is installed.
func InstallGlobalResolver(r *net.Resolver) (restore func()) {
	resolverMu.Lock()
	prev := net.DefaultResolver
	net.DefaultResolver = r
	resolverMu.Unlock()
	return func() {
		resolverMu.Lock()
		if net.DefaultResolver == r {
			net.DefaultResolver = prev
		}
		resolverMu.Unlock()
	}
}
