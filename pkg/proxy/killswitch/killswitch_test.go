package killswitch

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

type recorder struct {
	calls []string
	stdin []string
}

func (r *recorder) run(stdin, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	r.stdin = append(r.stdin, stdin)
	return nil, nil
}

func withRecorder(t *testing.T) *recorder {
	r := &recorder{}
	old := run
	run = r.run
	t.Cleanup(func() { run = old })
	return r
}

func testRuleset() ruleset {
	return ruleset{
		id:       "4242",
		tun:      "xkt0",
		allow:    parsePrefixes([]string{"192.168.0.0/16", "203.0.113.7", "fe80::/10"}),
		dns:      parsePrefixes([]string{"192.168.1.1"}),
		upstream: hostPrefixes([]netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8::1")}),
	}
}

func TestRenderNft(t *testing.T) {
	script := renderNft(testRuleset())
	for _, want := range []string{
		"table inet xk_ks_4242\ndelete table inet xk_ks_4242\n",
		"type filter hook output priority 0; policy accept;",
		`oifname "lo" accept`,
		`oifname "xkt0" accept`,
		"elements = { 192.168.0.0/16, 203.0.113.7 }",
		"elements = { fe80::/10 }",
		"elements = { 198.51.100.1 }",
		"elements = { 2001:db8::1 }",
		"ip daddr @dns4 udp dport 53 accept",
		"counter reject with icmpx type admin-prohibited",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q:\n%s", want, script)
		}
	}
	// In each chain the reject must come last.
	for _, name := range []string{"output", "forward"} {
		body := script[strings.Index(script, "chain "+name+" {"):]
		body = body[:strings.Index(body, "\t}\n")]
		if i, j := strings.Index(body, "reject"), strings.LastIndex(body, "accept;"); i < 0 || strings.LastIndex(body, " accept\n") > i || j > i {
			t.Fatalf("chain %s: an accept rule comes after the final reject:\n%s", name, body)
		}
	}
	// Empty sets carry no elements line (nft rejects "elements = { }").
	if strings.Contains(script, "elements = {  }") {
		t.Fatal("empty elements block rendered")
	}
}

func TestRenderNftUpdate(t *testing.T) {
	r := testRuleset()
	r.probes = hostPrefixes([]netip.Addr{netip.MustParseAddr("9.9.9.9")})
	r.probeTTL = 10 * time.Minute
	script := renderNftUpdate(r)
	for _, want := range []string{
		"flush set inet xk_ks_4242 up4\nadd element inet xk_ks_4242 up4 { 198.51.100.1 }",
		"flush set inet xk_ks_4242 up6\nadd element inet xk_ks_4242 up6 { 2001:db8::1 }",
		"add element inet xk_ks_4242 probe4 { 9.9.9.9 timeout 600s }",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("update missing %q:\n%s", want, script)
		}
	}
}

func TestNftSwitchLifecycle(t *testing.T) {
	rec := withRecorder(t)
	s := &Switch{cfg: Config{ID: "7", TunName: "xkt0"}, backend: &nftBackend{table: nftTable("7")}, probes: map[netip.Prefix]time.Time{}}
	if err := s.backend.install(s.ruleset(nil, 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUpstream([]netip.Addr{netip.MustParseAddr("1.2.3.4")}); err != nil {
		t.Fatal(err)
	}
	// SetUpstream must not re-add probes (nft expires them itself).
	if strings.Contains(rec.stdin[1], "probe") {
		t.Fatalf("SetUpstream touched probes:\n%s", rec.stdin[1])
	}
	if err := s.AllowProbe([]netip.Addr{netip.MustParseAddr("5.6.7.8")}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.stdin[2], "probe4 { 5.6.7.8 timeout 60s }") {
		t.Fatalf("probe not added:\n%s", rec.stdin[2])
	}
	if err := s.Disable(); err != nil {
		t.Fatal(err)
	}
	if last := rec.calls[len(rec.calls)-1]; last != "nft delete table inet xk_ks_7" {
		t.Fatalf("last call = %q", last)
	}
}

func TestIptablesDiffUpdates(t *testing.T) {
	rec := withRecorder(t)
	b := &iptablesBackend{chain: iptablesChain("7")}
	r := testRuleset()
	if err := b.install(r); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rec.calls, "\n")
	for _, want := range []string{
		"iptables -w -N XK_KS_7",
		"iptables -w -A XK_KS_7 -o xkt0 -j ACCEPT",
		"iptables -w -A XK_KS_7 -d 192.168.1.1/32 -p udp --dport 53 -j ACCEPT",
		"iptables -w -A XK_KS_7 -j REJECT --reject-with icmp-admin-prohibited",
		"ip6tables -w -A XK_KS_7 -p ipv6-icmp --icmpv6-type neighbour-solicitation -j ACCEPT",
		"iptables -w -N XK_KS_7_F",
		"iptables -w -A XK_KS_7_F -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"iptables -w -I FORWARD 1 -j XK_KS_7_F",
		"iptables -w -I OUTPUT 1 -j XK_KS_7",
		"iptables -w -I XK_KS_7 1 -d 198.51.100.1/32 -j ACCEPT",
		"ip6tables -w -I XK_KS_7 1 -d 2001:db8::1/128 -j ACCEPT",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	// The chain is filled before OUTPUT jumps to it.
	if strings.Index(joined, "-I OUTPUT 1 -j XK_KS_7") < strings.Index(joined, "-A XK_KS_7 -j REJECT") {
		t.Fatal("OUTPUT hooked before the chain was complete")
	}

	rec.calls = nil
	r.upstream = hostPrefixes([]netip.Addr{netip.MustParseAddr("198.51.100.9")})
	if err := b.update(r); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"iptables -w -I XK_KS_7 1 -d 198.51.100.9/32 -j ACCEPT",
		"iptables -w -D XK_KS_7 -d 198.51.100.1/32 -j ACCEPT",
		"ip6tables -w -D XK_KS_7 -d 2001:db8::1/128 -j ACCEPT",
	}
	got := slices.Clone(rec.calls)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("update calls = %v, want %v", rec.calls, want)
	}
	// Additions happen before deletions.
	if !strings.Contains(rec.calls[0], "-I XK_KS_7") {
		t.Fatalf("first call %q is not an insert", rec.calls[0])
	}
}

func TestParseLeftovers(t *testing.T) {
	nft := "table inet filter\ntable inet xk_ks_1234\ntable ip nat\ntable inet xk_ks_ns\n"
	if got := parseNftTables(nft); len(got) != 1 || got[0] != (Leftover{"nftables", "1234"}) {
		t.Fatalf("nft leftovers = %v", got)
	}
	ipt := "-P OUTPUT ACCEPT\n-N XK_KS_99\n-N XK_KS_99_F\n-A OUTPUT -j XK_KS_99\n-N DOCKER\n"
	if got := dedupLeftovers(parseIptablesChains(ipt)); len(got) != 1 || got[0] != (Leftover{"iptables", "99"}) {
		t.Fatalf("iptables leftovers = %v", got)
	}
}

func TestNamespaceRules(t *testing.T) {
	r := NamespaceRules("tun0")
	if !strings.Contains(r, `oifname "tun0" accept`) || !strings.Contains(r, "reject") {
		t.Fatalf("rules:\n%s", r)
	}
}

// The allow-list setupHostTun hands over contains nested prefixes
// (interface subnets inside the private ranges, link-local /64 inside
// fe80::/10, the SSH peer inside its LAN). An nftables interval set
// rejects those as "conflicting intervals", so they must be collapsed.
func TestAllowListIsCollapsed(t *testing.T) {
	allow := []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::1/128", "fe80::/10", "ff00::/8",
		"203.0.113.5/32", "192.168.1.10/24", "fe80::a00:27ff:fe4e:66a1/64", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"fc00::/7", "192.168.1.50", "10.1.2.0/24"}
	p := parsePrefixes(allow)
	for i := range p {
		for j := range p {
			if i != j && p[i].Overlaps(p[j]) {
				t.Fatalf("overlap left in allow-list: %v and %v", p[i], p[j])
			}
		}
	}
	for _, want := range []string{"192.168.0.0/16", "10.0.0.0/8", "fe80::/10"} {
		if !slices.Contains(p, netip.MustParsePrefix(want)) {
			t.Errorf("container %s lost", want)
		}
	}
	for _, gone := range []string{"192.168.1.0/24", "fe80::/64", "10.1.2.0/24", "192.168.1.50/32"} {
		if slices.Contains(p, netip.MustParsePrefix(gone)) {
			t.Errorf("contained prefix %s kept", gone)
		}
	}
	rec := withRecorder(t)
	if err := (&iptablesBackend{chain: iptablesChain("1")}).install(ruleset{id: "1", tun: "xkt0", allow: p}); err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.calls {
		if strings.Contains(c, "-d 192.168.1.0/24 ") || strings.Contains(c, "-d 10.1.2.0/24 ") {
			t.Fatalf("iptables rule for a contained prefix: %s", c)
		}
	}
	script := renderNft(ruleset{id: "1", tun: "xkt0", allow: p, dns: parsePrefixes([]string{"192.168.1.1", "192.168.1.0/24"})})
	if strings.Count(script, "auto-merge") != 6 {
		t.Fatalf("interval sets without auto-merge:\n%s", script)
	}
	if strings.Contains(script, "192.168.1.1,") || strings.Contains(script, "{ 192.168.1.0/24, 192.168.1.1 }") {
		t.Fatalf("dns set not collapsed:\n%s", script)
	}
}

func TestMarkAndForwardRules(t *testing.T) {
	r := testRuleset()
	r.mark = 0x786b1234
	script := renderNft(r)
	for _, want := range []string{
		"meta mark 0x786b1234 accept",
		"chain forward {\n\t\ttype filter hook forward priority 0; policy accept;",
		"ct state established,related accept",
		"icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-report, mld2-listener-report } accept",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %q in:\n%s", want, script)
		}
	}
	if strings.Contains(script, "meta l4proto ipv6-icmp accept") {
		t.Fatal("all ICMPv6 allowed")
	}
	rec := withRecorder(t)
	b := &iptablesBackend{chain: iptablesChain("7")}
	if err := b.install(r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rec.calls, "\n"), "iptables -w -A XK_KS_7 -m mark --mark 0x786b1234 -j ACCEPT") {
		t.Fatalf("mark rule missing:\n%s", strings.Join(rec.calls, "\n"))
	}
}

func TestInitialUpstreamInstalled(t *testing.T) {
	withRecorder(t)
	s := &Switch{cfg: Config{ID: "8", TunName: "xkt0", Upstream: []netip.Addr{netip.MustParseAddr("198.51.100.4")}},
		backend: &nftBackend{table: nftTable("8")}, probes: map[netip.Prefix]time.Time{}}
	s.upstream = hostPrefixes(s.cfg.Upstream)
	if script := renderNft(s.ruleset(nil, 0)); !strings.Contains(script, "elements = { 198.51.100.4 }") {
		t.Fatalf("initial upstream not in the first rule set:\n%s", script)
	}
}
