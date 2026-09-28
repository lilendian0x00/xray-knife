package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	pkgsingbox "github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"
	pkgxray "github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/hosttun"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
)

// hotSwapper is a running listener whose outbound (or chain) can be
// replaced without the listening port ever being unbound: new
// connections move to the new outbound at once, connections in flight
// finish on the old one for the grace period.
type hotSwapper interface {
	protocol.Instance
	Swap(ctx context.Context, hops []protocol.Protocol, grace time.Duration) error
}

var errSwapUnsupported = errors.New("core cannot hot-swap outbounds")

// makeSwappable builds a hot-swappable listener routed through hops.
// In host-tun the listener marks its upstream sockets with s.mark, which
// is what lets them (and only them) past the TUN and the kill switch.
func (s *Service) makeSwappable(ctx context.Context, hops []protocol.Protocol) (hotSwapper, error) {
	switch c := s.core.(type) {
	case *pkgxray.Core:
		sw, err := c.MakeSwappableInstance(ctx, hops, s.xraySwapOptions()...)
		if err != nil {
			return nil, err
		}
		return sw, nil
	case *pkgsingbox.Core:
		sw, err := c.MakeSwappableInstance(ctx, hops, s.singboxSwapOptions()...)
		if err != nil {
			return nil, err
		}
		return sw, nil
	}
	return nil, errSwapUnsupported
}

// socketMark returns s.mark (setupHostTun may clear it concurrently).
func (s *Service) socketMark() uint32 {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	return s.mark
}

func (s *Service) xraySwapOptions() []pkgxray.SwapOption {
	if m := s.socketMark(); m != 0 {
		return []pkgxray.SwapOption{pkgxray.WithSocketMark(m)}
	}
	return nil
}

func (s *Service) singboxSwapOptions() []pkgsingbox.SwapOption {
	if m := s.socketMark(); m != 0 {
		return []pkgsingbox.SwapOption{pkgsingbox.WithSocketMark(m)}
	}
	return nil
}

// newListener builds the listener instance for one outbound, hot-swappable
// when the core supports it.
func (s *Service) newListener(ctx context.Context, p protocol.Protocol) (protocol.Instance, error) {
	sw, err := s.makeSwappable(ctx, []protocol.Protocol{p})
	if err == nil {
		return sw, nil
	}
	if !errors.Is(err, errSwapUnsupported) {
		return nil, err
	}
	return s.core.MakeInstance(ctx, p)
}

// newChainListener is newListener for a chain.
func (s *Service) newChainListener(ctx context.Context, hops []protocol.Protocol) (protocol.Instance, error) {
	sw, err := s.makeSwappable(ctx, hops)
	if err == nil {
		return sw, nil
	}
	if !errors.Is(err, errSwapUnsupported) {
		return nil, err
	}
	return s.makeChainedInstance(ctx, hops)
}

// swapGrace is how long a replaced outbound keeps serving the connections
// it already carries (0 selects the core's default).
func (s *Service) swapGrace() time.Duration {
	return time.Duration(s.config.DrainTimeout) * time.Second
}

// hopLinks returns the share links of hops.
func hopLinks(hops []protocol.Protocol) []string {
	links := make([]string, 0, len(hops))
	for _, h := range hops {
		links = append(links, h.GetLink())
	}
	return links
}

// probeTTL is how long a tested candidate's address stays open in the
// kill switch; a rotation's test batch finishes well within it.
const probeTTL = 2 * time.Minute

// upstreamRefresh is how often the entry server's name is re-resolved
// (CDN and round-robin hosts change addresses under a live outbound).
const upstreamRefresh = time.Minute

// resolveServers resolves the server hosts of links with r (the
// uplink-bound resolver in host-tun, so the answers match what the cores
// dial).
func resolveServers(ctx context.Context, r *net.Resolver, links []string) []netip.Addr {
	cidrs := hosttun.ResolveHostsWith(ctx, r, hosttun.HostsFromConfigLinks(links), 3*time.Second)
	addrs := make([]netip.Addr, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			addrs = append(addrs, p.Addr())
		}
	}
	return addrs
}

// entryHop returns the hop this machine dials directly: the only one
// that needs a way out of the tunnel (later hops are reached through it).
func entryHop(hops []protocol.Protocol) []protocol.Protocol {
	if len(hops) == 0 {
		return nil
	}
	return hops[:1]
}

// activeHopsChanged keeps host-tun's per-upstream exceptions — the bypass
// rules and the kill switch's upstream set — pointed at the entry server
// now in use. A no-op outside host-tun.
func (s *Service) activeHopsChanged(hops []protocol.Protocol) {
	if !s.tunGuarded() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs := resolveServers(ctx, s.resolver, hopLinks(entryHop(hops)))
	if len(addrs) == 0 && len(hops) > 0 {
		s.logf(customlog.Warning, "host-tun: could not resolve the active server; keeping the previous exceptions.\n")
		return
	}
	s.applyUpstream(addrs)
}

func (s *Service) tunGuarded() bool {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	return s.tunBypass != nil || s.killSwitch != nil
}

// applyUpstream makes addrs the upstream exceptions. The previous
// addresses stay open (as timed probe entries) for the drain period, so
// connections still draining on the old outbound are not cut off.
func (s *Service) applyUpstream(addrs []netip.Addr) {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	old := s.upstream
	s.upstream = addrs
	s.upstreamCheck = time.Now()

	if s.tunBypass != nil && s.mark == 0 {
		// Destination-based fallback; with a mark the fwmark rule covers
		// every upstream socket already.
		if err := s.tunBypass.Set(hosttun.HostPrefixes(append(append([]netip.Addr{}, addrs...), old...))); err != nil {
			s.logf(customlog.Warning, "host-tun: updating bypass rules: %v\n", err)
		}
		if len(old) > 0 {
			go s.dropBypassLater(addrs, s.drainPeriod())
		}
	}
	if s.killSwitch == nil || s.mark != 0 {
		return
	}
	if len(old) > 0 {
		if err := s.killSwitch.AllowProbe(old, s.drainPeriod()); err != nil {
			s.logf(customlog.Warning, "kill switch: keeping the previous upstream open: %v\n", err)
		}
	}
	if err := s.killSwitch.SetUpstream(addrs); err != nil {
		s.logf(customlog.Warning, "kill switch: updating the upstream allow-list: %v\n", err)
	}
}

// dropBypassLater narrows the bypass rules to keep once the old outbound
// has drained.
func (s *Service) dropBypassLater(keep []netip.Addr, after time.Duration) {
	time.Sleep(after)
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	if s.tunBypass == nil || !sameAddrs(s.upstream, keep) {
		return // torn down, or superseded by a newer rotation
	}
	if err := s.tunBypass.Set(hosttun.HostPrefixes(keep)); err != nil {
		s.logf(customlog.Warning, "host-tun: updating bypass rules: %v\n", err)
	}
}

func sameAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// drainPeriod is how long a replaced outbound may still carry traffic.
func (s *Service) drainPeriod() time.Duration {
	g := s.swapGrace()
	if g <= 0 {
		g = 30 * time.Second
	}
	return g + 30*time.Second
}

// refreshUpstream re-resolves the entry server now and then (called from
// the health checks), so a CDN or round-robin host that moves to a new
// address keeps working through the bypass and the kill switch.
func (s *Service) refreshUpstream() {
	s.tunMu.Lock()
	due := (s.tunBypass != nil || s.killSwitch != nil) && time.Since(s.upstreamCheck) >= upstreamRefresh
	cur := s.upstream
	s.tunMu.Unlock()
	if !due {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs := resolveServers(ctx, s.resolver, hopLinks(entryHop(s.currentHops())))
	if len(addrs) == 0 || sameAddrs(addrs, cur) {
		s.tunMu.Lock()
		s.upstreamCheck = time.Now()
		s.tunMu.Unlock()
		return
	}
	s.applyUpstream(addrs)
}

// allowProbes lets rotation tests reach the servers of links through the
// kill switch for probeTTL. A no-op without a kill switch.
func (s *Service) allowProbes(ctx context.Context, links []string) {
	s.tunMu.Lock()
	ks := s.killSwitch
	s.tunMu.Unlock()
	if ks == nil {
		return
	}
	addrs := resolveServers(ctx, s.resolver, links)
	if err := ks.AllowProbe(addrs, probeTTL); err != nil {
		s.logf(customlog.Warning, "kill switch: allowing test targets: %v\n", err)
	}
}

// currentHops returns the hops of the active outbound or chain.
func (s *Service) currentHops() []protocol.Protocol {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.activeChainHops) > 0 {
		return append([]protocol.Protocol(nil), s.activeChainHops...)
	}
	if s.activeOutbound != nil && s.activeOutbound.Protocol != nil {
		return []protocol.Protocol{s.activeOutbound.Protocol}
	}
	return nil
}
