package hosttun

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/utils"
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
//   - ff00::/8          — IPv6 multicast.
var mandatoryExcludes = []string{
	"127.0.0.0/8",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::1/128",
	"fe80::/10",
	"ff00::/8",
}

// sysSource abstracts the host facts SSH detection reads so tests can
// feed canned /proc contents.
type sysSource struct {
	getenv   func(string) string
	readFile func(string) ([]byte, error)
	glob     func(string) ([]string, error)
	ppid     int
}

func hostSource() sysSource {
	return sysSource{getenv: os.Getenv, readFile: os.ReadFile, glob: filepath.Glob, ppid: os.Getppid()}
}

// SSHClientIP returns the first SSH client IP found by SSHClientIPs, or
// "" when this process does not look like it runs over SSH.
func SSHClientIP() string {
	if ips := SSHClientIPs(); len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// SSHClientIPs returns the peers of the SSH sessions that must survive
// the TUN. $SSH_CONNECTION alone is not enough: sudo's env_reset strips
// it, and the documented usage is `sudo xray-knife proxy tun ...`. So,
// in order, it consults:
//
//  1. $SSH_CONNECTION / $SSH_CLIENT of this process,
//  2. the same variables in the environment of our ancestors (sudo keeps
//     the invoking shell alive as its parent),
//  3. every ESTABLISHED TCP connection on an sshd port (/proc/net/tcp{,6}),
//     which also covers other admins' sessions.
//
// Excluding an address that is not actually an SSH peer only keeps its
// traffic on the physical interface, so erring towards more is safe.
func SSHClientIPs() []string {
	return sshClientIPs(hostSource())
}

func sshClientIPs(src sysSource) []string {
	var out []string
	seen := map[string]bool{}
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	ports := map[int]bool{}

	fromEnv := func(get func(string) string) {
		for _, key := range []string{"SSH_CONNECTION", "SSH_CLIENT"} {
			ip, port := parseSSHEnv(key, get(key))
			add(ip)
			if port > 0 {
				ports[port] = true
			}
		}
	}
	fromEnv(src.getenv)

	// Walk up the process tree: sudo → user shell → sshd session.
	pid := src.ppid
	for depth := 0; depth < 8 && pid > 1; depth++ {
		env, err := src.readFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err == nil {
			vars := parseEnviron(env)
			fromEnv(func(k string) string { return vars[k] })
		}
		stat, err := src.readFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			break
		}
		pid = parentPID(stat)
	}

	for _, p := range sshdPorts(src) {
		ports[p] = true
	}
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := src.readFile(file)
		if err != nil {
			continue
		}
		for _, a := range establishedPeers(data, ports) {
			add(a.String())
		}
	}
	return out
}

// parseSSHEnv extracts the client IP and, for SSH_CONNECTION, the server
// port from "client_ip client_port server_ip server_port" (SSH_CLIENT is
// "client_ip client_port server_port").
func parseSSHEnv(key, val string) (string, int) {
	parts := strings.Fields(val)
	if len(parts) < 1 {
		return "", 0
	}
	ip := net.ParseIP(parts[0])
	if ip == nil {
		return "", 0
	}
	port := 0
	switch {
	case key == "SSH_CONNECTION" && len(parts) >= 4:
		port, _ = strconv.Atoi(parts[3])
	case key == "SSH_CLIENT" && len(parts) >= 3:
		port, _ = strconv.Atoi(parts[2])
	}
	return ip.String(), port
}

// parseEnviron splits a NUL-separated /proc/<pid>/environ blob.
func parseEnviron(b []byte) map[string]string {
	vars := map[string]string{}
	for _, kv := range bytes.Split(b, []byte{0}) {
		k, v, ok := bytes.Cut(kv, []byte{'='})
		if ok {
			vars[string(k)] = string(v)
		}
	}
	return vars
}

// parentPID reads the ppid field of /proc/<pid>/stat. The comm field may
// contain spaces and parentheses, so parse from the last ')'.
func parentPID(stat []byte) int {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0
	}
	fields := strings.Fields(string(stat[i+1:]))
	// fields[0] is the state, fields[1] the ppid.
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

// sshdPorts returns the ports sshd listens on per its config, defaulting
// to 22.
func sshdPorts(src sysSource) []int {
	files := []string{"/etc/ssh/sshd_config"}
	if extra, err := src.glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		files = append(files, extra...)
	}
	var ports []int
	for _, f := range files {
		data, err := src.readFile(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 && strings.EqualFold(fields[0], "Port") {
				if p, err := strconv.Atoi(fields[1]); err == nil && p > 0 && p < 65536 {
					ports = append(ports, p)
				}
			}
		}
	}
	if len(ports) == 0 {
		ports = []int{22}
	}
	return ports
}

// establishedPeers parses /proc/net/tcp or tcp6 and returns the remote
// addresses of ESTABLISHED sockets whose local port is in ports.
func establishedPeers(data []byte, ports map[int]bool) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != "01" { // 01 = TCP_ESTABLISHED
			continue
		}
		_, localPort, ok := parseProcAddr(fields[1])
		if !ok || !ports[localPort] {
			continue
		}
		remote, _, ok := parseProcAddr(fields[2])
		if !ok || remote.IsLoopback() || remote.IsUnspecified() {
			continue
		}
		out = append(out, remote)
	}
	return out
}

// parseProcAddr decodes "0100007F:0016" (IPv4) or the 32-hex-digit IPv6
// form. The address is stored as host-order 32-bit words.
func parseProcAddr(s string) (netip.Addr, int, bool) {
	hexIP, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	raw, err := hex.DecodeString(hexIP)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, false
	}
	// The kernel prints each 32-bit word of the address as a host-order
	// integer, so the bytes come back in the machine's native order.
	for w := 0; w+4 <= len(raw); w += 4 {
		binary.NativeEndian.PutUint32(raw[w:], binary.BigEndian.Uint32(raw[w:]))
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, 0, false
	}
	return addr.Unmap(), int(port), true
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

// ResolveHosts resolves hosts with net.DefaultResolver (see
// ResolveHostsWith).
func ResolveHosts(ctx context.Context, hosts []string, perHostTimeout time.Duration) []string {
	return ResolveHostsWith(ctx, net.DefaultResolver, hosts, perHostTimeout)
}

// ResolveHostsWith resolves each entry in hosts (hostname or IP) to its
// IPv4 and IPv6 addresses with r, returning CIDR /32 or /128 strings.
// Resolution runs concurrently with a per-host timeout. Hosts that fail
// to resolve are silently skipped.
func ResolveHostsWith(ctx context.Context, r *net.Resolver, hosts []string, perHostTimeout time.Duration) []string {
	if r == nil {
		r = net.DefaultResolver
	}
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
			addrs, err := r.LookupNetIP(lookupCtx, "ip", h)
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
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok {
		return ""
	}
	switch strings.ToLower(scheme) {
	case "vmess":
		return vmessHost(rest)
	case "ss":
		if h := legacySSHost(rest); h != "" {
			return h
		}
	case "tg":
		// tg://proxy?server=host&port=...
		if u, err := url.Parse(link); err == nil {
			return trimHost(u.Query().Get("server"))
		}
		return ""
	}
	u, err := url.Parse(link)
	if err == nil && u.Host != "" {
		if strings.EqualFold(u.Host, "t.me") || strings.EqualFold(u.Host, "telegram.me") {
			return trimHost(u.Query().Get("server"))
		}
		if h := u.Hostname(); h != "" {
			return h
		}
	}
	// url.Parse rejects some real links, e.g. Hysteria2 port hopping
	// ("host:443,20000-30000"). Fall back to slicing out the authority.
	return authorityHost(rest)
}

// vmessHost decodes the base64 JSON body of a vmess:// link and returns
// its "add" field. v2rayN also emits "vmess://uuid@host:port?..." URLs,
// handled by the authority fallback.
func vmessHost(body string) string {
	if i := strings.IndexAny(body, "#?"); i >= 0 && !strings.Contains(body[:i], "@") {
		body = body[:i]
	}
	decoded, err := utils.Base64Decode(body)
	if err != nil {
		return authorityHost(body)
	}
	var v struct {
		Add string `json:"add"`
	}
	if err := json.Unmarshal(decoded, &v); err != nil {
		return ""
	}
	return trimHost(v.Add)
}

// legacySSHost handles "ss://BASE64(method:pass@host:port)#tag".
func legacySSHost(body string) string {
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	if strings.Contains(body, "@") {
		return "" // SIP002: url.Parse handles it
	}
	if i := strings.IndexByte(body, '?'); i >= 0 {
		body = body[:i]
	}
	decoded, err := utils.Base64Decode(body)
	if err != nil {
		return ""
	}
	at := strings.LastIndexByte(string(decoded), '@')
	if at < 0 {
		return ""
	}
	return authorityHost(string(decoded[at+1:]))
}

// authorityHost extracts the host from "userinfo@host:port/path?q#f",
// tolerating port lists and ranges ("host:443,2000-3000").
func authorityHost(s string) string {
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	if strings.HasPrefix(s, "[") {
		if j := strings.IndexByte(s, ']'); j > 0 {
			return s[1:j]
		}
		return ""
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return trimHost(s)
}

func trimHost(h string) string {
	return strings.Trim(strings.TrimSpace(h), "[]")
}

func ipToCIDR(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String() + "/32"
	}
	return ip.String() + "/128"
}

func addrToCIDR(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		return a.String() + "/32"
	}
	return a.String() + "/128"
}

// NormalizeCIDR accepts a CIDR or a bare IP (turned into a host prefix).
func NormalizeCIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", err
		}
		return p.Masked().String(), nil
	}
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return "", fmt.Errorf("%q is neither a CIDR nor an IP address", s)
	}
	return addrToCIDR(a), nil
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

// SystemDNSServers returns the non-loopback nameservers the host is
// configured with: /etc/resolv.conf plus systemd-resolved's upstream
// list (when resolv.conf only points at the 127.0.0.53 stub).
func SystemDNSServers() []string {
	return systemDNSServers(os.ReadFile)
}

func systemDNSServers(readFile func(string) ([]byte, error)) []string {
	var out []string
	for _, f := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		data, err := readFile(f)
		if err != nil {
			continue
		}
		out = append(out, parseResolvConf(data)...)
	}
	return dedup(out)
}

func parseResolvConf(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		// Strip an IPv6 zone ("fe80::1%eth0") before parsing.
		ip, _, _ := strings.Cut(fields[1], "%")
		a, err := netip.ParseAddr(ip)
		if err != nil || a.IsLoopback() || a.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, a.Unmap().String())
	}
	return out
}

// ExcludeOptions is the input to BuildExcludes.
type ExcludeOptions struct {
	// PhysIface is the uplink; its own subnets stay off the TUN.
	PhysIface string
	// ConfigLinks are the pool and chain links. Their server addresses
	// are excluded so upstream dials cannot loop back into the TUN.
	ConfigLinks []string
	// ExtraCIDRs are user/private exclusions (CIDRs or bare IPs).
	ExtraCIDRs []string
	// DNSServers are the host's resolvers. When one of them falls inside
	// an excluded range (typically the LAN router), it is carved back
	// out so its queries enter the TUN and get hijacked instead of
	// leaking — possibly poisoned — to the ISP.
	DNSServers     []string
	ResolveTimeout time.Duration
}

// Excludes is the result of BuildExcludes.
type Excludes struct {
	// CIDRs are the destination prefixes excluded from TUN capture.
	CIDRs []string
	// Direct are host prefixes that the TUN captures only so DNS to them
	// can be hijacked; everything else to them must go out directly on
	// the uplink (so e.g. the router's web UI keeps working).
	Direct []string
	// SSHClients are the SSH peers found (already part of CIDRs).
	SSHClients []string
	Warnings   []string
}

// BuildExcludes assembles the full exclusion list:
//
//   - mandatory loopback / link-local / multicast / reserved
//   - SSH client IPs (see SSHClientIPs)
//   - all CIDRs on the physical interface (local LAN + management plane)
//   - all upstream config-link hosts (resolved)
//   - any extra user-supplied CIDRs
//
// minus the host's DNS servers (see ExcludeOptions.DNSServers).
func BuildExcludes(ctx context.Context, opts ExcludeOptions) Excludes {
	return buildExcludes(ctx, opts, SSHClientIPs())
}

func buildExcludes(ctx context.Context, opts ExcludeOptions, sshIPs []string) Excludes {
	var res Excludes
	out := append([]string{}, mandatoryExcludes...)
	var keep []string // host prefixes that must stay excluded

	for _, ip := range sshIPs {
		if parsed := net.ParseIP(ip); parsed != nil {
			c := ipToCIDR(parsed)
			out = append(out, c)
			keep = append(keep, c)
			res.SSHClients = append(res.SSHClients, ip)
		}
	}

	if opts.PhysIface != "" {
		cidrs, err := InterfaceCIDRs(opts.PhysIface)
		if err != nil {
			res.Warnings = append(res.Warnings, err.Error())
		} else {
			out = append(out, cidrs...)
		}
	}

	hosts := HostsFromConfigLinks(opts.ConfigLinks)
	resolved := ResolveHosts(ctx, hosts, opts.ResolveTimeout)
	out = append(out, resolved...)
	keep = append(keep, resolved...)
	if len(hosts) > 0 && len(resolved) == 0 {
		res.Warnings = append(res.Warnings, "no upstream config hosts could be resolved — TUN may loop")
	}

	for _, c := range opts.ExtraCIDRs {
		n, err := NormalizeCIDR(c)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("ignoring exclude %q: %v", c, err))
			continue
		}
		out = append(out, n)
	}
	out = dedup(out)

	res.CIDRs, res.Direct = carveOutDNS(out, opts.DNSServers, keep)
	return res
}

// carveOutDNS removes each DNS server address from the exclusion
// prefixes that contain it, unless the address itself must stay
// excluded (an SSH peer or an upstream proxy server). It returns the new
// exclusion list and the carved-out host prefixes.
func carveOutDNS(excludes, dnsServers, keep []string) ([]string, []string) {
	keepSet := map[netip.Addr]bool{}
	for _, k := range keep {
		if p, err := netip.ParsePrefix(k); err == nil && p.IsSingleIP() {
			keepSet[p.Addr()] = true
		}
	}
	prefixes := make([]netip.Prefix, 0, len(excludes))
	for _, c := range excludes {
		if p, err := netip.ParsePrefix(c); err == nil {
			prefixes = append(prefixes, p.Masked())
		}
	}
	var direct []string
	for _, d := range dnsServers {
		a, err := netip.ParseAddr(d)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if keepSet[a] || a.IsLoopback() || a.IsLinkLocalUnicast() {
			continue
		}
		contained := false
		for _, p := range prefixes {
			if p.Contains(a) {
				contained = true
				break
			}
		}
		if !contained {
			continue // already routed into the TUN
		}
		next := make([]netip.Prefix, 0, len(prefixes)+a.BitLen())
		for _, p := range prefixes {
			next = append(next, subtractAddr(p, a)...)
		}
		prefixes = next
		direct = append(direct, addrToCIDR(a))
	}
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return dedup(out), direct
}

// subtractAddr returns p minus the single address a, as a set of
// prefixes (one per bit between p.Bits() and a.BitLen()).
func subtractAddr(p netip.Prefix, a netip.Addr) []netip.Prefix {
	if !p.Contains(a) {
		return []netip.Prefix{p}
	}
	var out []netip.Prefix
	for p.Bits() < a.BitLen() {
		bits := p.Bits() + 1
		inner, _ := a.Prefix(bits) // the half that contains a
		out = append(out, siblingPrefix(inner))
		p = inner
	}
	return out
}

// siblingPrefix returns the other half of p's parent prefix.
func siblingPrefix(p netip.Prefix) netip.Prefix {
	b := p.Addr().AsSlice()
	bit := p.Bits() - 1
	b[bit/8] ^= 0x80 >> (bit % 8)
	addr, _ := netip.AddrFromSlice(b)
	return netip.PrefixFrom(addr, p.Bits())
}
