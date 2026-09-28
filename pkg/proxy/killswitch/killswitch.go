// Package killswitch blocks every egress (and forwarded) packet that does
// not leave through the proxy tunnel, so a crashed or stalled proxy can
// never fall back to the ISP route (fail closed).
//
// The rules live in a table (nftables) or chains (iptables) of their own,
// named after the owning process ID. They deliberately survive a crash:
// traffic stays blocked until the owner exits cleanly, `xray-knife proxy
// restore` runs, or the next `proxy tun`/`proxy app` start removes kill
// switches whose owner is gone. Exceptions are the tunnel interface,
// loopback, DHCP and the neighbour-discovery ICMPv6 types, the static
// allow-list (LAN, user excludes, SSH peers), the host resolvers on port
// 53, packets carrying the proxy's own socket mark (its upstream dials)
// and, as a destination-based fallback, the active upstream servers and,
// briefly, candidate servers being tested.
package killswitch

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Prefix is the name prefix of every kill-switch table and chain.
const (
	nftPrefix      = "xk_ks_"
	iptablesPrefix = "XK_KS_"
)

// Config describes one kill switch.
type Config struct {
	// ID names the table/chain; the owning PID by default.
	ID string
	// TunName is the tunnel interface whose egress is allowed.
	TunName string
	// Allow are prefixes reachable outside the tunnel on any port
	// (LAN, --tun-exclude ranges, SSH peers, link-local, multicast).
	Allow []string
	// DNS are resolvers reachable outside the tunnel on port 53 only.
	DNS []string
	// Mark, when non-zero, is the SO_MARK the proxy puts on its own
	// upstream sockets; such packets pass whatever their destination, so
	// no other program gets a hole in the kill switch.
	Mark uint32
	// Upstream is the initial destination-based upstream allow-list
	// (fallback for sockets that cannot be marked).
	Upstream []netip.Addr
}

// Switch is an installed kill switch.
type Switch struct {
	cfg     Config
	backend backend

	mu       sync.Mutex
	upstream []netip.Prefix
	probes   map[netip.Prefix]time.Time // expiry (iptables bookkeeping)
}

// backend is one firewall implementation.
type backend interface {
	name() string
	install(r ruleset) error
	// update replaces the upstream set and adds probe entries.
	update(r ruleset) error
	remove() error
}

// ruleset is the full desired state handed to a backend.
type ruleset struct {
	id       string
	tun      string
	mark     uint32
	allow    []netip.Prefix
	dns      []netip.Prefix
	upstream []netip.Prefix
	probes   []netip.Prefix
	probeTTL time.Duration
}

// DefaultID is the table/chain suffix for this process.
func DefaultID() string { return strconv.Itoa(os.Getpid()) }

// Enable installs the kill switch with nftables, falling back to
// iptables/ip6tables.
func Enable(cfg Config) (*Switch, error) {
	if cfg.ID == "" {
		cfg.ID = DefaultID()
	}
	if cfg.TunName == "" {
		return nil, fmt.Errorf("kill switch needs the tunnel interface name")
	}
	b, err := pickBackend(cfg.ID)
	if err != nil {
		return nil, err
	}
	s := &Switch{cfg: cfg, backend: b, probes: map[netip.Prefix]time.Time{}, upstream: hostPrefixes(cfg.Upstream)}
	if err := b.install(s.ruleset(nil, 0)); err != nil {
		_ = b.remove()
		return nil, fmt.Errorf("install %s kill switch: %w", b.name(), err)
	}
	return s, nil
}

// Backend names the firewall in use ("nftables" or "iptables").
func (s *Switch) Backend() string { return s.backend.name() }

// SetUpstream replaces the set of proxy servers reachable outside the
// tunnel (the active outbound's server, or every hop of a chain whose
// entry is dialed directly).
func (s *Switch) SetUpstream(addrs []netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstream = hostPrefixes(addrs)
	return s.backend.update(s.ruleset(nil, 0))
}

// AllowProbe lets the rotation tests reach candidate servers for ttl.
func (s *Switch) AllowProbe(addrs []netip.Addr, ttl time.Duration) error {
	if len(addrs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	fresh := hostPrefixes(addrs)
	for _, p := range fresh {
		s.probes[p] = now.Add(ttl)
	}
	return s.backend.update(s.ruleset(fresh, ttl))
}

// Disable removes the rules. Safe to call more than once.
func (s *Switch) Disable() error {
	if s == nil {
		return nil
	}
	return s.backend.remove()
}

func (s *Switch) ruleset(newProbes []netip.Prefix, ttl time.Duration) ruleset {
	now := time.Now()
	var probes []netip.Prefix
	for p, exp := range s.probes {
		if now.After(exp) {
			delete(s.probes, p)
			continue
		}
		probes = append(probes, p)
	}
	sortPrefixes(probes)
	// nftables only ever adds the new probe elements (the kernel expires
	// them); iptables diffs against the full list of live probes.
	if _, isNft := s.backend.(*nftBackend); isNft {
		probes = newProbes
	}
	return ruleset{
		id:       s.cfg.ID,
		tun:      s.cfg.TunName,
		mark:     s.cfg.Mark,
		allow:    parsePrefixes(s.cfg.Allow),
		dns:      parsePrefixes(s.cfg.DNS),
		upstream: s.upstream,
		probes:   probes,
		probeTTL: ttl,
	}
}

func hostPrefixes(addrs []netip.Addr) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		a = a.Unmap()
		p := netip.PrefixFrom(a, a.BitLen())
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sortPrefixes(out)
	return out
}

// parsePrefixes accepts CIDRs and bare addresses; invalid entries are
// dropped (the caller validated them already). The result is collapsed:
// no prefix contains another, which nftables interval sets require
// ("conflicting intervals") and which keeps the iptables rules minimal.
func parsePrefixes(in []string) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		var p netip.Prefix
		if strings.Contains(s, "/") {
			q, err := netip.ParsePrefix(s)
			if err != nil {
				continue
			}
			p = q.Masked()
		} else {
			a, err := netip.ParseAddr(strings.Trim(s, "[]"))
			if err != nil {
				continue
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return collapse(out)
}

// collapse drops every prefix contained in another one. CIDR blocks are
// either nested or disjoint, so after sorting by start address (shorter
// first on ties) a contained prefix always follows its container
// directly among the kept ones.
func collapse(in []netip.Prefix) []netip.Prefix {
	p := append([]netip.Prefix(nil), in...)
	for i := range p {
		p[i] = p[i].Masked()
	}
	sortPrefixes(p)
	out := p[:0]
	for _, x := range p {
		if n := len(out); n > 0 && out[n-1].Bits() <= x.Bits() && out[n-1].Contains(x.Addr()) {
			continue
		}
		out = append(out, x)
	}
	return out
}

func sortPrefixes(p []netip.Prefix) {
	sort.Slice(p, func(i, j int) bool {
		if c := p[i].Addr().Compare(p[j].Addr()); c != 0 {
			return c < 0
		}
		return p[i].Bits() < p[j].Bits()
	})
}

func split(p []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, x := range p {
		if x.Addr().Is4() {
			v4 = append(v4, x)
		} else {
			v6 = append(v6, x)
		}
	}
	return v4, v6
}

// Leftover is a kill switch found on the system.
type Leftover struct {
	Backend string
	ID      string
}

func (l Leftover) String() string { return l.Backend + " " + l.ID }

// ownerAlive reports whether the process a kill switch is named after is
// still running. Kernel firewall state does not survive a reboot, so a
// PID check is enough.
func ownerAlive(id string) bool {
	pid, err := strconv.Atoi(id)
	if err != nil || pid <= 0 {
		return false
	}
	if pid == os.Getpid() {
		return true
	}
	return processAlive(pid)
}
