package killswitch

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

func iptablesChain(id string) string { return iptablesPrefix + unsafeID.ReplaceAllString(id, "_") }

// forwardSuffix names the FORWARD chain next to the OUTPUT one.
const forwardSuffix = "_F"

// iptablesBackend is the fallback for hosts without nft. Dynamic entries
// are inserted and deleted one by one ahead of the final REJECT, so an
// update never opens a window where the chain is empty.
type iptablesBackend struct {
	chain     string
	installed map[netip.Prefix]bool // dynamic ACCEPT rules (upstream + probes)
}

func (b *iptablesBackend) name() string { return "iptables" }

type ipt struct {
	tool   string
	v6     bool
	reject []string
}

var ipts = []ipt{
	{tool: "iptables", reject: []string{"-j", "REJECT", "--reject-with", "icmp-admin-prohibited"}},
	{tool: "ip6tables", v6: true, reject: []string{"-j", "REJECT", "--reject-with", "icmp6-adm-prohibited"}},
}

// icmpv6OutTypes mirrors icmpv6Out (router/neighbour solicitation,
// neighbour advertisement, MLDv1/v2 reports).
var icmpv6OutTypes = []string{"router-solicitation", "neighbour-solicitation", "neighbour-advertisement", "131", "143"}

func (b *iptablesBackend) cmd(t ipt, args ...string) error {
	out, err := run("", t.tool, append([]string{"-w"}, args...)...)
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", t.tool, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}

func allowRules(t ipt, r ruleset) [][]string {
	var rules [][]string
	for _, p := range collapse(r.allow) {
		if p.Addr().Is6() == t.v6 {
			rules = append(rules, []string{"-d", p.String(), "-j", "ACCEPT"})
		}
	}
	return rules
}

// staticRules are the fixed OUTPUT rules of one family, in order.
func staticRules(t ipt, r ruleset) [][]string {
	rules := [][]string{{"-o", "lo", "-j", "ACCEPT"}, {"-o", r.tun, "-j", "ACCEPT"}}
	if r.mark != 0 {
		rules = append(rules, []string{"-m", "mark", "--mark", "0x" + strconv.FormatUint(uint64(r.mark), 16), "-j", "ACCEPT"})
	}
	if t.v6 {
		rules = append(rules, []string{"-p", "udp", "--sport", "546", "--dport", "547", "-j", "ACCEPT"})
		for _, typ := range icmpv6OutTypes {
			rules = append(rules, []string{"-p", "ipv6-icmp", "--icmpv6-type", typ, "-j", "ACCEPT"})
		}
	} else {
		rules = append(rules, []string{"-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"})
	}
	rules = append(rules, allowRules(t, r)...)
	for _, p := range collapse(r.dns) {
		if p.Addr().Is6() == t.v6 {
			rules = append(rules,
				[]string{"-d", p.String(), "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
				[]string{"-d", p.String(), "-p", "tcp", "--dport", "53", "-j", "ACCEPT"})
		}
	}
	return append(rules, t.reject)
}

// forwardRules keep routed traffic in the tunnel (or on the LAN).
func forwardRules(t ipt, r ruleset) [][]string {
	rules := [][]string{
		{"-o", r.tun, "-j", "ACCEPT"},
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	rules = append(rules, allowRules(t, r)...)
	return append(rules, t.reject)
}

// newChain (re)creates chain filled with rules, then hooks it into hook.
func (b *iptablesBackend) newChain(t ipt, chain, hook string, rules [][]string) error {
	_ = b.cmd(t, "-D", hook, "-j", chain)
	_ = b.cmd(t, "-F", chain)
	_ = b.cmd(t, "-X", chain)
	if err := b.cmd(t, "-N", chain); err != nil {
		return err
	}
	for _, rule := range rules {
		if err := b.cmd(t, append([]string{"-A", chain}, rule...)...); err != nil {
			return err
		}
	}
	// Hooked only once complete, so there is no half-built window.
	return b.cmd(t, "-I", hook, "1", "-j", chain)
}

func (b *iptablesBackend) install(r ruleset) error {
	b.installed = map[netip.Prefix]bool{}
	for _, t := range ipts {
		if err := b.newChain(t, b.chain, "OUTPUT", staticRules(t, r)); err != nil {
			return err
		}
		if err := b.newChain(t, b.chain+forwardSuffix, "FORWARD", forwardRules(t, r)); err != nil {
			return err
		}
	}
	return b.update(r)
}

func (b *iptablesBackend) update(r ruleset) error {
	want := map[netip.Prefix]bool{}
	for _, p := range r.upstream {
		want[p] = true
	}
	for _, p := range r.probes {
		want[p] = true
	}
	// Add first, then delete, so an address in both sets stays reachable.
	for p := range want {
		if b.installed[p] {
			continue
		}
		if err := b.cmd(familyOf(p), "-I", b.chain, "1", "-d", p.String(), "-j", "ACCEPT"); err != nil {
			return err
		}
		b.installed[p] = true
	}
	for p := range b.installed {
		if want[p] {
			continue
		}
		_ = b.cmd(familyOf(p), "-D", b.chain, "-d", p.String(), "-j", "ACCEPT")
		delete(b.installed, p)
	}
	return nil
}

func familyOf(p netip.Prefix) ipt {
	if p.Addr().Is6() {
		return ipts[1]
	}
	return ipts[0]
}

func (b *iptablesBackend) remove() error {
	var errs []string
	for _, t := range ipts {
		for _, c := range []struct{ chain, hook string }{{b.chain, "OUTPUT"}, {b.chain + forwardSuffix, "FORWARD"}} {
			_ = b.cmd(t, "-D", c.hook, "-j", c.chain)
			_ = b.cmd(t, "-F", c.chain)
			if err := b.cmd(t, "-X", c.chain); err != nil && !strings.Contains(err.Error(), "No chain") && !strings.Contains(err.Error(), "does not exist") {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
