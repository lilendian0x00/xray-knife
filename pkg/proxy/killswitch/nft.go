package killswitch

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

var unsafeID = regexp.MustCompile(`[^A-Za-z0-9_]`)

func nftTable(id string) string { return nftPrefix + unsafeID.ReplaceAllString(id, "_") }

// nftBackend drives nft(8) with whole-transaction scripts, so every
// change is atomic: there is never a moment with half a rule set.
type nftBackend struct {
	table string
}

func (b *nftBackend) name() string { return "nftables" }

func (b *nftBackend) install(r ruleset) error {
	return nftApply(renderNft(r))
}

func (b *nftBackend) update(r ruleset) error {
	return nftApply(renderNftUpdate(r))
}

func (b *nftBackend) remove() error {
	out, err := run("", "nft", "delete", "table", "inet", b.table)
	if err != nil && !strings.Contains(string(out), "No such file") {
		return fmt.Errorf("nft delete table %s: %s: %w", b.table, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func nftApply(script string) error {
	out, err := run(script, "nft", "-f", "-")
	if err != nil {
		return fmt.Errorf("nft: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func nftElements(p []netip.Prefix) string {
	parts := make([]string, len(p))
	for i, x := range p {
		if x.IsSingleIP() {
			parts[i] = x.Addr().String()
		} else {
			parts[i] = x.String()
		}
	}
	return strings.Join(parts, ", ")
}

// icmpv6Out are the ICMPv6 types a host must send to keep IPv6 working
// on its LAN (router discovery, neighbour discovery, MLD).
var icmpv6Out = []string{"nd-router-solicit", "nd-neighbor-solicit", "nd-neighbor-advert", "mld-listener-report", "mld2-listener-report"}

// renderNft returns the script that (re)creates the whole table.
func renderNft(r ruleset) string {
	t := nftTable(r.id)
	var b strings.Builder
	// "table" then "delete table" makes a re-install idempotent within the
	// same atomic transaction.
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n", t, t)
	fmt.Fprintf(&b, "table inet %s {\n", t)
	allow4, allow6 := split(collapse(r.allow))
	dns4, dns6 := split(collapse(r.dns))
	up4, up6 := split(r.upstream)
	set := func(name, typ, flags string, elems []netip.Prefix) {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n\t\tflags %s\n", name, typ, flags)
		if flags == "interval" {
			// Lets the kernel merge adjacent or overlapping elements
			// instead of rejecting them.
			b.WriteString("\t\tauto-merge\n")
		}
		if len(elems) > 0 {
			fmt.Fprintf(&b, "\t\telements = { %s }\n", nftElements(elems))
		}
		b.WriteString("\t}\n")
	}
	set("allow4", "ipv4_addr", "interval", allow4)
	set("allow6", "ipv6_addr", "interval", allow6)
	set("dns4", "ipv4_addr", "interval", dns4)
	set("dns6", "ipv6_addr", "interval", dns6)
	set("up4", "ipv4_addr", "interval", up4)
	set("up6", "ipv6_addr", "interval", up6)
	set("probe4", "ipv4_addr", "timeout", nil)
	set("probe6", "ipv6_addr", "timeout", nil)

	out := []string{
		`oifname "lo" accept`,
		fmt.Sprintf("oifname %q accept", r.tun),
	}
	if r.mark != 0 {
		out = append(out, fmt.Sprintf("meta mark 0x%x accept", r.mark))
	}
	out = append(out,
		"udp sport 68 udp dport 67 accept",
		"udp sport 546 udp dport 547 accept",
		fmt.Sprintf("icmpv6 type { %s } accept", strings.Join(icmpv6Out, ", ")),
		"ip daddr @allow4 accept",
		"ip6 daddr @allow6 accept",
		"ip daddr @up4 accept",
		"ip6 daddr @up6 accept",
		"ip daddr @probe4 accept",
		"ip6 daddr @probe6 accept",
		"ip daddr @dns4 udp dport 53 accept",
		"ip daddr @dns4 tcp dport 53 accept",
		"ip6 daddr @dns6 udp dport 53 accept",
		"ip6 daddr @dns6 tcp dport 53 accept",
		"counter reject with icmpx type admin-prohibited",
	)
	// Routed traffic (containers, VMs, a LAN behind this host) must not
	// escape either: only into the tunnel, replies, and the LAN.
	fwd := []string{
		fmt.Sprintf("oifname %q accept", r.tun),
		"ct state established,related accept",
		"ip daddr @allow4 accept",
		"ip6 daddr @allow6 accept",
		"counter reject with icmpx type admin-prohibited",
	}
	chain := func(name, hook string, rules []string) {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority 0; policy accept;\n", name, hook)
		for _, rule := range rules {
			fmt.Fprintf(&b, "\t\t%s\n", rule)
		}
		b.WriteString("\t}\n")
	}
	chain("output", "output", out)
	chain("forward", "forward", fwd)
	b.WriteString("}\n")
	return b.String()
}

// renderNftUpdate replaces the upstream sets and adds probe elements in
// one transaction.
func renderNftUpdate(r ruleset) string {
	t := nftTable(r.id)
	var b strings.Builder
	up4, up6 := split(r.upstream)
	for _, s := range []struct {
		name  string
		elems []netip.Prefix
	}{{"up4", up4}, {"up6", up6}} {
		fmt.Fprintf(&b, "flush set inet %s %s\n", t, s.name)
		if len(s.elems) > 0 {
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", t, s.name, nftElements(s.elems))
		}
	}
	p4, p6 := split(r.probes)
	ttl := int(r.probeTTL.Seconds())
	if ttl < 1 {
		ttl = 1
	}
	for _, s := range []struct {
		name  string
		elems []netip.Prefix
	}{{"probe4", p4}, {"probe6", p6}} {
		if len(s.elems) == 0 {
			continue
		}
		parts := make([]string, len(s.elems))
		for i, x := range s.elems {
			parts[i] = fmt.Sprintf("%s timeout %ds", x.Addr(), ttl)
		}
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", t, s.name, strings.Join(parts, ", "))
	}
	return b.String()
}

// NamespaceRules is a minimal kill switch for inside an app-mode
// namespace: only loopback and the tunnel may carry traffic.
func NamespaceRules(tun string) string {
	t := nftPrefix + "ns"
	return fmt.Sprintf("table inet %[1]s\ndelete table inet %[1]s\ntable inet %[1]s {\n\tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n\t\toifname \"lo\" accept\n\t\toifname %[2]q accept\n\t\tcounter reject with icmpx type admin-prohibited\n\t}\n}\n", t, tun)
}
