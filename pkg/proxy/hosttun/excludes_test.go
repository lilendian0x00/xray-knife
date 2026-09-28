package hosttun

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestParseProcAddr(t *testing.T) {
	a, port, ok := parseProcAddr("0100007F:0016")
	if !ok || a.String() != "127.0.0.1" || port != 22 {
		t.Fatalf("v4: %v %d %v", a, port, ok)
	}
	// 2001:db8::1 as /proc/net/tcp6 prints it (host-order 32-bit words).
	a, port, ok = parseProcAddr("B80D0120000000000000000001000000:01BB")
	if !ok || a.String() != "2001:db8::1" || port != 443 {
		t.Fatalf("v6: %v %d %v", a, port, ok)
	}
	// v4-mapped addresses come back as plain IPv4.
	a, _, ok = parseProcAddr("0000000000000000FFFF00000A01A8C0:0016")
	if !ok || a.String() != "192.168.1.10" {
		t.Fatalf("mapped: %v %v", a, ok)
	}
	if _, _, ok := parseProcAddr("zz:0016"); ok {
		t.Fatal("garbage accepted")
	}
}

const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0F02000A:0016 0A01A8C0:D431 01 00000000:00000000 02:0004C5D7 00000000     0        0 2 4 0000000000000000 20 4 30 10 -1
   2: 0F02000A:C350 22222222:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:0016 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 4 1 0000000000000000 20 4 30 10 -1
`

func TestEstablishedPeers(t *testing.T) {
	got := establishedPeers([]byte(procNetTCP), map[int]bool{22: true})
	// Only the established, non-loopback sshd connection (row 1).
	if len(got) != 1 || got[0].String() != "192.168.1.10" {
		t.Fatalf("peers = %v", got)
	}
}

func TestParentPID(t *testing.T) {
	if got := parentPID([]byte("1234 (sudo (weird) name) S 987 1234 1234 34816")); got != 987 {
		t.Fatalf("ppid = %d", got)
	}
	if got := parentPID([]byte("garbage")); got != 0 {
		t.Fatalf("ppid = %d", got)
	}
}

// sudo strips SSH_CONNECTION; the invoking shell (our parent) still has it.
func TestSSHClientIPsUnderSudo(t *testing.T) {
	files := map[string]string{
		"/proc/100/environ":    "PATH=/usr/bin\x00SSH_CONNECTION=203.0.113.7 51000 10.0.2.15 2222\x00",
		"/proc/100/stat":       "100 (bash) S 1 100 100 0",
		"/etc/ssh/sshd_config": "Port 2222\n",
		"/proc/net/tcp": `  sl  local_address rem_address   st
   1: 0F02000A:08AE 0A01A8C0:D431 01 00000000:00000000
`,
	}
	src := sysSource{
		getenv: func(string) string { return "" },
		readFile: func(p string) ([]byte, error) {
			if v, ok := files[p]; ok {
				return []byte(v), nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(string) ([]string, error) { return nil, nil },
		ppid: 100,
	}
	got := sshClientIPs(src)
	want := []string{"203.0.113.7", "192.168.1.10"}
	if !slices.Equal(got, want) {
		t.Fatalf("ssh peers = %v, want %v", got, want)
	}
}

func TestParseSSHEnv(t *testing.T) {
	if ip, port := parseSSHEnv("SSH_CLIENT", "2001:db8::5 51000 22"); ip != "2001:db8::5" || port != 22 {
		t.Fatalf("%q %d", ip, port)
	}
	if ip, _ := parseSSHEnv("SSH_CONNECTION", "not-an-ip 1 2 3"); ip != "" {
		t.Fatalf("%q", ip)
	}
}

func TestHostFromLink(t *testing.T) {
	vmessJSON := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","add":"vm.example.com","port":"443","id":"x"}`))
	legacySS := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass@ss.example.net:8388"))
	cases := map[string]string{
		"vless://uuid@v.example.org:443?security=tls#x":               "v.example.org",
		"vmess://" + vmessJSON:                                        "vm.example.com",
		"vmess://" + vmessJSON + "#remark":                            "vm.example.com",
		"ss://" + legacySS + "#tag":                                   "ss.example.net",
		"ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#sip002":             "1.2.3.4",
		"hysteria2://pw@hy.example.com:443,20000-30000/?sni=a#hop":    "hy.example.com",
		"trojan://pw@[2001:db8::7]:443#v6":                            "2001:db8::7",
		"tg://proxy?server=tg.example.com&port=443&secret=dd00":       "tg.example.com",
		"https://t.me/proxy?server=9.9.9.9&port=443&secret=dd00":      "9.9.9.9",
		"wireguard://key@wg.example.com:51820?address=10.0.0.2/32#wg": "wg.example.com",
		"not a link": "",
	}
	for link, want := range cases {
		if got := hostFromLink(link); got != want {
			t.Errorf("hostFromLink(%q) = %q, want %q", link, got, want)
		}
	}
}

func TestNormalizeCIDR(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.0/8":    "10.0.0.0/8",
		"10.1.2.3/8":    "10.0.0.0/8",
		"203.0.113.9":   "203.0.113.9/32",
		"[2001:db8::1]": "2001:db8::1/128",
	} {
		got, err := NormalizeCIDR(in)
		if err != nil || got != want {
			t.Errorf("NormalizeCIDR(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := NormalizeCIDR("example.com"); err == nil {
		t.Error("hostname accepted as CIDR")
	}
}

func TestSubtractAddr(t *testing.T) {
	p := netip.MustParsePrefix("192.168.0.0/16")
	a := netip.MustParseAddr("192.168.1.1")
	parts := subtractAddr(p, a)
	if len(parts) != 16 {
		t.Fatalf("got %d prefixes, want 16", len(parts))
	}
	for _, q := range parts {
		if q.Contains(a) {
			t.Fatalf("%v still contains %v", q, a)
		}
		if !p.Contains(q.Addr()) {
			t.Fatalf("%v escapes %v", q, p)
		}
	}
	// Sizes add up to the parent minus one address.
	var total uint64
	for _, q := range parts {
		total += 1 << (32 - q.Bits())
	}
	if total != 1<<16-1 {
		t.Fatalf("covered %d addresses, want %d", total, 1<<16-1)
	}
	for _, probe := range []string{"192.168.1.0", "192.168.1.2", "192.168.255.255", "192.168.0.1"} {
		ok := false
		for _, q := range parts {
			ok = ok || q.Contains(netip.MustParseAddr(probe))
		}
		if !ok {
			t.Fatalf("%s lost by the subtraction", probe)
		}
	}
	if got := subtractAddr(p, netip.MustParseAddr("10.0.0.1")); len(got) != 1 || got[0] != p {
		t.Fatalf("unrelated address changed the prefix: %v", got)
	}
}

func TestCarveOutDNS(t *testing.T) {
	excludes := []string{"127.0.0.0/8", "192.168.0.0/16", "192.168.1.50/32"}
	out, direct := carveOutDNS(excludes, []string{"192.168.1.1", "8.8.8.8", "192.168.1.50", "127.0.0.53"}, []string{"192.168.1.50/32"})

	if !slices.Equal(direct, []string{"192.168.1.1/32"}) {
		t.Fatalf("direct = %v", direct)
	}
	contains := func(ip string) bool {
		a := netip.MustParseAddr(ip)
		for _, c := range out {
			if netip.MustParsePrefix(c).Contains(a) {
				return true
			}
		}
		return false
	}
	if contains("192.168.1.1") {
		t.Fatal("LAN resolver still excluded: its queries would bypass the TUN")
	}
	if !contains("192.168.1.50") {
		t.Fatal("kept SSH/upstream address was carved out")
	}
	if !contains("192.168.7.7") || !contains("127.0.0.1") {
		t.Fatal("the rest of the excluded ranges was lost")
	}
}

func TestBuildExcludesChainAndExtras(t *testing.T) {
	ex := buildExcludes(context.Background(), ExcludeOptions{
		ConfigLinks: []string{"vless://u@198.51.100.1:443#pool", "trojan://p@198.51.100.2:443#chain-hop"},
		ExtraCIDRs:  []string{"203.0.113.9", "bogus"},
	}, []string{"192.0.2.10"})
	for _, want := range []string{"198.51.100.1/32", "198.51.100.2/32", "203.0.113.9/32", "192.0.2.10/32", "fe80::/10"} {
		if !slices.Contains(ex.CIDRs, want) {
			t.Errorf("missing exclude %s in %v", want, ex.CIDRs)
		}
	}
	if len(ex.Warnings) != 1 || !strings.Contains(ex.Warnings[0], "bogus") {
		t.Errorf("warnings = %v", ex.Warnings)
	}
	if !slices.Equal(ex.SSHClients, []string{"192.0.2.10"}) {
		t.Errorf("ssh = %v", ex.SSHClients)
	}
}

func TestSystemDNSServers(t *testing.T) {
	files := map[string]string{
		"/etc/resolv.conf":                 "nameserver 127.0.0.53\noptions edns0\n",
		"/run/systemd/resolve/resolv.conf": "# upstream\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\nnameserver 2001:db8::53\n",
	}
	got := systemDNSServers(func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("missing")
	})
	if !slices.Equal(got, []string{"192.168.1.1", "2001:db8::53"}) {
		t.Fatalf("servers = %v", got)
	}
	if got := BootstrapDNSServers(nil, "8.8.4.4:53"); !slices.Equal(got, []string{"8.8.4.4"}) {
		t.Fatalf("bootstrap = %v", got)
	}
	if got := BootstrapDNSServers(nil, "https://dns.google/dns-query"); !slices.Equal(got, []string{"1.1.1.1"}) {
		t.Fatalf("bootstrap = %v", got)
	}
}

func TestFreeRuleBlock(t *testing.T) {
	if got := freeRuleBlock(map[int]bool{9000: true}); got != ruleSearchStart {
		t.Fatalf("got %d", got)
	}
	used := map[int]bool{9105: true, 9125: true}
	if got := freeRuleBlock(used); got != 9140 {
		t.Fatalf("got %d, want 9140", got)
	}
}

func TestFreeRuleBlockReservesBypassSlot(t *testing.T) {
	// 9111 is the last slot of the 9100 block (bypass + 11 sing-tun rules).
	if got := freeRuleBlock(map[int]bool{9111: true}); got != 9120 {
		t.Fatalf("got %d, want 9120", got)
	}
}

func TestDiffPrefixes(t *testing.T) {
	a, b, c := netip.MustParsePrefix("1.1.1.1/32"), netip.MustParsePrefix("2.2.2.2/32"), netip.MustParsePrefix("2001:db8::1/128")
	have := map[netip.Prefix]bool{a: true, b: true}
	add, del := diffPrefixes(have, []netip.Prefix{b, c})
	if !slices.Equal(add, []netip.Prefix{c}) || !slices.Equal(del, []netip.Prefix{a}) {
		t.Fatalf("add=%v del=%v", add, del)
	}
	if got := HostPrefixes([]netip.Addr{netip.MustParseAddr("::ffff:9.9.9.9")}); len(got) != 1 || got[0].String() != "9.9.9.9/32" {
		t.Fatalf("HostPrefixes = %v", got)
	}
}

func TestStateRoundTrip(t *testing.T) {
	t.Setenv("XRAY_KNIFE_HOME", t.TempDir())
	if err := SaveState(&State{TunName: "xkt0", TableIndex: 31000, RuleIndex: 9101, BypassPriority: 9100}); err != nil {
		t.Fatal(err)
	}
	states, _, bad, err := LoadStates()
	if err != nil || len(states) != 1 || len(bad) != 0 || states[0].RuleIndex != 9101 || !ownerAlive(states[0]) {
		t.Fatalf("states = %+v, bad = %v, %v", states, bad, err)
	}
	// Our own state is never reclaimed.
	if rec, kept, _ := RecoverFromCrash(); len(rec) != 0 || len(kept) != 1 {
		t.Fatalf("recovered=%v kept=%v", rec, kept)
	}
	if err := ClearState(); err != nil {
		t.Fatal(err)
	}
	if states, _, _, _ := LoadStates(); len(states) != 0 {
		t.Fatal("state not cleared")
	}
}

// Recovery acts as root on these values: anything Start could not have
// produced is rejected instead of deleting arbitrary rules.
func TestStateValidation(t *testing.T) {
	good := State{Pid: 42, TunName: "xkt0", TableIndex: 31000, RuleIndex: 9101, BypassPriority: 9100}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*State){
		"main table":      func(s *State) { s.TableIndex = 254 },
		"rule 0":          func(s *State) { s.RuleIndex = 0 },
		"kernel rules":    func(s *State) { s.RuleIndex = 32760 },
		"bypass mismatch": func(s *State) { s.BypassPriority = 100 },
		"tun path":        func(s *State) { s.TunName = "../eth0" },
		"no pid":          func(s *State) { s.Pid = 0 },
	} {
		s := good
		mutate(&s)
		if s.Validate() == nil {
			t.Errorf("%s: forged state accepted", name)
		}
	}
	// A forged file is reported and left alone.
	t.Setenv("XRAY_KNIFE_HOME", t.TempDir())
	forged := good
	forged.TableIndex = 254
	if err := SaveState(&forged); err != nil {
		t.Fatal(err)
	}
	if states, _, bad, _ := LoadStates(); len(states) != 0 || len(bad) != 1 {
		t.Fatalf("states=%v bad=%v", states, bad)
	}
}
