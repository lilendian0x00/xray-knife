package hosttun

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Bypass keeps traffic off the TUN with rules one priority above
// sing-tun's own block:
//
//   - "fwmark <mark> lookup main" for the sockets the proxy itself opens
//     to its upstream servers (SetMark). Only those sockets carry the
//     mark, so other programs cannot use the proxy server's address as a
//     way around the tunnel (CDN "clean IPs" host arbitrary websites).
//   - "to <prefix> lookup main" for destinations (Set): the fallback when
//     marking is unavailable, and the static IPv6 exceptions needed when
//     StrictRoute makes IPv6 unreachable.
type Bypass struct {
	priority int
	mu       sync.Mutex
	rules    map[netip.Prefix]bool
	mark     uint32
}

// NewBypass manages bypass rules at the given priority.
func NewBypass(priority int) *Bypass {
	return &Bypass{priority: priority, rules: map[netip.Prefix]bool{}}
}

func (b *Bypass) rule(p netip.Prefix) *netlink.Rule {
	r := netlink.NewRule()
	r.Priority = b.priority
	r.Table = unix.RT_TABLE_MAIN
	r.Dst = &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
	if p.Addr().Is4() {
		r.Family = unix.AF_INET
	} else {
		r.Family = unix.AF_INET6
	}
	return r
}

func (b *Bypass) markRule(family int, mark uint32) *netlink.Rule {
	r := netlink.NewRule()
	r.Priority = b.priority
	r.Table = unix.RT_TABLE_MAIN
	r.Family = family
	r.Mark = mark
	mask := uint32(0xffffffff)
	r.Mask = &mask
	return r
}

// SetMark installs the fwmark rules (IPv4 and, when the host has an IPv6
// stack, IPv6).
func (b *Bypass) SetMark(mark uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := netlink.RuleAdd(b.markRule(unix.AF_INET, mark)); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	if err := netlink.RuleAdd(b.markRule(unix.AF_INET6, mark)); err != nil && !errors.Is(err, unix.EEXIST) && !errors.Is(err, unix.EAFNOSUPPORT) {
		_ = netlink.RuleDel(b.markRule(unix.AF_INET, mark))
		return err
	}
	b.mark = mark
	return nil
}

// Set makes the destination bypass list exactly prefixes. New rules are
// added before stale ones are removed, so a prefix in both lists never
// loses its rule.
func (b *Bypass) Set(prefixes []netip.Prefix) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	add, del := diffPrefixes(b.rules, prefixes)
	var errs []error
	for _, p := range add {
		if err := netlink.RuleAdd(b.rule(p)); err != nil && !errors.Is(err, unix.EEXIST) {
			errs = append(errs, err)
			continue
		}
		b.rules[p] = true
	}
	for _, p := range del {
		if err := netlink.RuleDel(b.rule(p)); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, err)
			continue
		}
		delete(b.rules, p)
	}
	return errors.Join(errs...)
}

// Close removes every rule this Bypass installed.
func (b *Bypass) Close() error {
	err := b.Set(nil)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.mark != 0 {
		_ = netlink.RuleDel(b.markRule(unix.AF_INET, b.mark))
		_ = netlink.RuleDel(b.markRule(unix.AF_INET6, b.mark))
		b.mark = 0
	}
	return err
}
