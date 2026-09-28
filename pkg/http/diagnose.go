package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	utls "github.com/refraction-networking/utls"

	"github.com/lilendian0x00/xray-knife/v11/pkg/netbind"
)

// Failure kinds (Result.FailureKind) say WHY a config did not pass, in a form
// scripts can group on. The split that matters in censored networks is
// "blocked on the way" (dns-poisoned, tcp-reset, tls-reset, …) versus "the
// server or the config is wrong" (tcp-refused, proxy-protocol, config).
//
// Kinds prefixed by a transport layer (dns, tcp, tls) come from checking the
// server directly, outside the tunnel. Without that check (--diagnose=false,
// or UDP-based transports that cannot be probed over TCP) the raw error class
// is reported instead: timeout, reset, refused, unreachable, eof, tls, other.
const (
	FailConfig        = "config"          // the link could not be parsed or the core refused to build it
	FailDNS           = "dns"             // the server name did not resolve
	FailDNSPoisoned   = "dns-poisoned"    // system DNS answered a censorship/bogon address, or failed where the --resolver answered
	FailTCPRefused    = "tcp-refused"     // the server port answered with RST: nothing listening, or a port block
	FailTCPTimeout    = "tcp-timeout"     // no answer to SYN: server down, or the IP is blackholed
	FailTCPReset      = "tcp-reset"       // the connection was reset while opening
	FailTCPUnreach    = "tcp-unreachable" // no route to the server (ICMP unreachable, no IPv6, ...)
	FailTLSReset      = "tls-reset"       // reset right after the ClientHello: the classic SNI-filtering signal
	FailTLSTimeout    = "tls-timeout"     // ClientHello sent, no ServerHello: SNI blackholing
	FailTLSCert       = "tls-cert"        // the tunnel's TLS certificate did not verify
	FailProxyAuth     = "proxy-auth"      // the server said the credentials are wrong
	FailProxyProtocol = "proxy-protocol"  // server reachable, but it dropped or rejected the tunnel handshake (uuid/password, path, transport)
	FailProxyTimeout  = "proxy-timeout"   // connected, then the proxy handshake never answered
	FailHTTPStatus    = "http-status"     // the tunnel works, the test URL answered an unexpected status
	FailHTTPTimeout   = "http-timeout"    // server reachable, the request through the tunnel timed out
	FailSlow          = "slow"            // answered, but slower than --mdelay
	FailCanceled      = "canceled"        // the run stopped before the test finished
	FailOther         = "other"
)

// Raw error classes, used as the kind when the server was not checked.
const (
	classTimeout     = "timeout"
	classReset       = "reset"
	classRefused     = "refused"
	classUnreachable = "unreachable"
	classEOF         = "eof"
	classTLSCert     = "tls-cert"
	classTLS         = "tls"
	classDNS         = "dns"
	classAuth        = "auth"
	classOther       = FailOther
)

// classifyError maps a transport error to a raw class. It mirrors
// pkg/dpi.Classify (kept separate so pkg/dpi can build on pkg/http without an
// import cycle) and adds certificate, unreachable and credential classes.
func classifyError(err error) string {
	if err == nil {
		return ""
	}
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return classTimeout
	case errors.Is(err, syscall.ECONNRESET):
		return classReset
	case errors.Is(err, syscall.ECONNREFUSED):
		return classRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return classUnreachable
	case errors.As(err, &dnsErr):
		return classDNS
	case errors.As(err, &certErr), errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &invalidCert):
		return classTLSCert
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return classTimeout
	}
	// Cores wrap transport errors in their own types, so fall back to text.
	s := strings.ToLower(err.Error())
	switch {
	case containsAny(s, "wrong secret", "invalid user", "unauthorized", "authentication failed", "auth failed", "bad password", "invalid password", "407 proxy"):
		return classAuth
	case containsAny(s, "timeout", "deadline exceeded", "timed out"):
		return classTimeout
	case containsAny(s, "connection reset", "reset by peer"):
		return classReset
	case strings.Contains(s, "connection refused"):
		return classRefused
	case containsAny(s, "no route to host", "network is unreachable", "host is unreachable"):
		return classUnreachable
	case containsAny(s, "no such host", "lookup "):
		return classDNS
	case containsAny(s, "x509", "certificate"):
		return classTLSCert
	case containsAny(s, "eof", "closed pipe", "use of closed", "broken pipe"):
		return classEOF
	case containsAny(s, "tls", "handshake"):
		return classTLS
	}
	return classOther
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// sinkholeRanges are addresses censors answer for blocked names (Iran's
// 10.10.34.34-36, Turkey's TTNET block page). A name resolving there whose
// server then does not answer is conclusively DNS-poisoned.
var sinkholeRanges = []netip.Prefix{
	netip.MustParsePrefix("10.10.34.0/24"),    // Iran: DNS hijack answers for blocked names
	netip.MustParsePrefix("195.175.254.2/32"), // Turkey: TTNET block-page sinkhole
}

// bogonRanges are addresses a public server's name does not normally resolve
// to. They are only a hint: fake-IP TUNs (clash, sing-box: 198.18/15),
// Tailscale (100.64/10) and LAN names legitimately answer them and do connect,
// so a bogon answer is never a verdict on its own.
var bogonRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network": a null answer
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC 1918
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC 1918
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC 1918
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT, Tailscale
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking; the fake-IP range of clash/sing-box
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, incl. 255.255.255.255
	netip.MustParsePrefix("::/128"),          // unspecified
	netip.MustParsePrefix("::1/128"),         // loopback
	netip.MustParsePrefix("fc00::/7"),        // unique local
	netip.MustParsePrefix("fe80::/10"),       // link-local
	netip.MustParsePrefix("ff00::/8"),        // multicast
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

func inRanges(addr netip.Addr, ranges []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range ranges {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// isCensoredAddr reports whether addr is a known sinkhole or a bogon.
func isCensoredAddr(addr netip.Addr) bool {
	return inRanges(addr, sinkholeRanges) || inRanges(addr, bogonRanges)
}

func anyIn(addrs []netip.Addr, ranges []netip.Prefix) bool {
	for _, a := range addrs {
		if inRanges(a, ranges) {
			return true
		}
	}
	return false
}

// Resolver resolves server names for diagnostics. It is never used inside
// the cores, which keep their own DNS behaviour.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]netip.Addr, error)
	String() string
}

type systemResolver struct{}

func (systemResolver) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, err
}

func (systemResolver) String() string { return "system DNS" }

// udpResolver asks one DNS server over UDP (falling back to TCP for
// truncated answers, as the Go resolver does).
type udpResolver struct {
	server string
	r      *net.Resolver
}

func (u *udpResolver) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := u.r.LookupNetIP(ctx, "ip", host)
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, err
}

func (u *udpResolver) String() string { return "resolver " + u.server }

// dohResolver speaks DNS-over-HTTPS (RFC 8484, GET with ?dns=).
type dohResolver struct {
	endpoint string
	client   *http.Client
}

func (d *dohResolver) String() string { return "resolver " + d.endpoint }

func (d *dohResolver) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	var firstErr error
	notFound := false
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		addrs, nx, err := d.query(ctx, host, qtype)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		notFound = notFound || nx
		out = append(out, addrs...)
	}
	if len(out) > 0 {
		return out, nil
	}
	if firstErr != nil {
		return nil, &net.DNSError{Err: firstErr.Error(), Name: host, Server: d.endpoint}
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, Server: d.endpoint, IsNotFound: notFound}
}

func (d *dohResolver) query(ctx context.Context, host string, qtype dnsmessage.Type) ([]netip.Addr, bool, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, false, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, false, err
	}
	u := d.endpoint + "?dns=" + base64.RawURLEncoding.EncodeToString(packed)
	if strings.Contains(d.endpoint, "?") {
		u = d.endpoint + "&dns=" + base64.RawURLEncoding.EncodeToString(packed)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("DoH server answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, false, err
	}
	var reply dnsmessage.Message
	if err := reply.Unpack(body); err != nil {
		return nil, false, fmt.Errorf("bad DoH answer: %w", err)
	}
	if reply.RCode == dnsmessage.RCodeNameError {
		return nil, true, nil
	}
	var addrs []netip.Addr
	for _, ans := range reply.Answers {
		switch rr := ans.Body.(type) {
		case *dnsmessage.AResource:
			addrs = append(addrs, netip.AddrFrom4(rr.A))
		case *dnsmessage.AAAAResource:
			addrs = append(addrs, netip.AddrFrom16(rr.AAAA).Unmap())
		}
	}
	return addrs, false, nil
}

// NewResolver builds a diagnostics resolver from a --resolver value:
//
//	""/"system"              the system resolver
//	doh://host[/path]        DNS-over-HTTPS (path defaults to /dns-query)
//	https://host/dns-query   DNS-over-HTTPS
//	udp://host[:port], host[:port]  plain DNS (port 53 by default)
//
// Its own dials honour bindInterface, like the rest of the diagnostics.
func NewResolver(spec, bindInterface string) (Resolver, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "system" {
		return systemResolver{}, nil
	}
	binder, err := netbind.New(bindInterface)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	binder.ApplyDialer(dialer)

	switch {
	case strings.HasPrefix(spec, "doh://"), strings.HasPrefix(spec, "https://"):
		u, err := url.Parse(strings.Replace(spec, "doh://", "https://", 1))
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("invalid DoH resolver %q", spec)
		}
		if u.Path == "" || u.Path == "/" {
			u.Path = "/dns-query"
		}
		transport := &http.Transport{DialContext: dialer.DialContext, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 5 * time.Second}
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: dohRedirectPolicy}
		return &dohResolver{endpoint: u.String(), client: client}, nil
	default:
		server := strings.TrimPrefix(spec, "udp://")
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(strings.Trim(server, "[]"), "53")
		}
		host, _, _ := net.SplitHostPort(server)
		if _, err := netip.ParseAddr(host); err != nil {
			return nil, fmt.Errorf("invalid resolver %q: want an IP[:port], udp://IP[:port], doh://host or https://host/dns-query", spec)
		}
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, server)
			},
		}
		return &udpResolver{server: server, r: r}, nil
	}
}

// dohRedirectPolicy only follows a DoH redirect that stays on https and on
// the same host: a query must not be bounced to a plaintext or third-party
// resolver (which a censor could inject).
func dohRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("DoH: too many redirects")
	}
	if req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host {
		return fmt.Errorf("DoH: refusing redirect to %s://%s", req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// ServerCheck describes the server end of a config for a direct check.
type ServerCheck struct {
	Host string
	Port string
	// SNI is the TLS server name the config presents (Host when empty).
	SNI string
	// TLS makes the check also send a ClientHello after connecting.
	TLS bool
	// UDP marks transports that cannot be probed over TCP; only DNS is
	// checked for them.
	UDP bool
}

// ServerDiagnosis is the outcome of a direct check. Kind is empty when the
// server looked reachable at every layer checked.
type ServerDiagnosis struct {
	Kind   string
	Detail string
}

// Diagnoser checks a config's server directly, outside any tunnel, to tell
// "blocked on the way" from "the proxy itself fails". Zero fields use real
// network defaults; tests replace dial and handshake with fakes.
type Diagnoser struct {
	// System is the resolver the cores use (nil = system DNS).
	System Resolver
	// Trusted, when set (--resolver), is compared with System to spot a
	// poisoned system resolver.
	Trusted Resolver
	// Timeout bounds each step (resolve, connect, handshake).
	Timeout time.Duration

	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	handshake func(ctx context.Context, conn net.Conn, sni string) error

	// cache remembers verdicts per server: a batch often holds many configs
	// for one server, and each dead one would otherwise wait out its own
	// connect timeout again. Verdicts expire after diagnosisTTL, so a
	// long-lived Diagnoser (the proxy's rotation examiner runs for days)
	// notices a server that recovered or got blocked since.
	cacheMu   sync.Mutex
	cache     map[ServerCheck]cachedDiagnosis
	lastSweep time.Time
	now       func() time.Time // time.Now when nil; tests override it
}

// diagnosisTTL is how long a server verdict is reused.
const diagnosisTTL = 5 * time.Minute

type cachedDiagnosis struct {
	diag ServerDiagnosis
	at   time.Time
}

func (d *Diagnoser) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

// cached returns c's verdict while it is fresh.
func (d *Diagnoser) cached(c ServerCheck) (ServerDiagnosis, bool) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	e, ok := d.cache[c]
	if !ok || d.clock().Sub(e.at) >= diagnosisTTL {
		return ServerDiagnosis{}, false
	}
	return e.diag, true
}

// remember stores c's verdict. Expired entries are swept at most once per
// TTL, so the map holds only the servers seen recently.
func (d *Diagnoser) remember(c ServerCheck, diag ServerDiagnosis) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	now := d.clock()
	if d.cache == nil {
		d.cache = make(map[ServerCheck]cachedDiagnosis)
		d.lastSweep = now
	}
	if now.Sub(d.lastSweep) >= diagnosisTTL {
		for k, e := range d.cache {
			if now.Sub(e.at) >= diagnosisTTL {
				delete(d.cache, k)
			}
		}
		d.lastSweep = now
	}
	d.cache[c] = cachedDiagnosis{diag: diag, at: now}
}

// NewDiagnoser returns a Diagnoser whose dials honour bindInterface.
func NewDiagnoser(trusted Resolver, bindInterface string, timeout time.Duration) (*Diagnoser, error) {
	binder, err := netbind.New(bindInterface)
	if err != nil {
		return nil, err
	}
	d := &Diagnoser{System: systemResolver{}, Trusted: trusted, Timeout: timeout}
	d.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		binder.ApplyDialer(dialer)
		return dialer.DialContext(ctx, network, addr)
	}
	return d, nil
}

func (d *Diagnoser) stepTimeout() time.Duration {
	if d.Timeout <= 0 {
		return 5 * time.Second
	}
	return d.Timeout
}

func (d *Diagnoser) dialFunc() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.dial != nil {
		return d.dial
	}
	return (&net.Dialer{}).DialContext
}

func (d *Diagnoser) handshakeFunc() func(ctx context.Context, conn net.Conn, sni string) error {
	if d.handshake != nil {
		return d.handshake
	}
	return func(ctx context.Context, conn net.Conn, sni string) error {
		// A browser ClientHello, as the cores send: DPI keys on the
		// fingerprint as well as the SNI. Only reaching the ServerHello
		// matters, so the certificate is not verified.
		uc := utls.UClient(conn, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
		return uc.HandshakeContext(ctx)
	}
}

// resolution is what DNS said about a server name.
type resolution struct {
	addrs   []netip.Addr // what the system resolver (the cores' resolver) answered
	trusted []netip.Addr // what --resolver answered, when configured and it succeeded
	// poisoned is set when the answers alone prove poisoning: the system
	// resolver failed where the trusted one answered. Everything else is a
	// hint that only counts if the server then does not answer.
	poisoned *ServerDiagnosis
	diag     *ServerDiagnosis // resolution failed outright
}

// Resolve resolves host like the cores would (system DNS), next to the
// trusted resolver when one is configured. It returns the addresses to probe,
// or a diagnosis when nothing can be probed. Suspicious (bogon or sinkhole)
// answers are still returned: they are judged by Server once dialed.
func (d *Diagnoser) Resolve(ctx context.Context, host string) ([]netip.Addr, *ServerDiagnosis) {
	res := d.resolve(ctx, host)
	if res.diag != nil {
		return nil, res.diag
	}
	if res.poisoned != nil {
		return nil, res.poisoned
	}
	return res.addrs, nil
}

func (d *Diagnoser) resolve(ctx context.Context, host string) resolution {
	host = strings.Trim(host, "[]")
	if ip, err := netip.ParseAddr(host); err == nil {
		return resolution{addrs: []netip.Addr{ip.Unmap()}}
	}
	system := d.System
	if system == nil {
		system = systemResolver{}
	}
	lookup := func(r Resolver) ([]netip.Addr, error) {
		cctx, cancel := context.WithTimeout(ctx, d.stepTimeout())
		defer cancel()
		return r.LookupHost(cctx, host)
	}
	sys, sysErr := lookup(system)
	var res resolution
	if d.Trusted != nil {
		if trusted, err := lookup(d.Trusted); err == nil && len(trusted) > 0 {
			res.trusted = trusted
		}
	}
	switch {
	case sysErr != nil && len(res.trusted) > 0:
		res.poisoned = &ServerDiagnosis{Kind: FailDNSPoisoned,
			Detail: fmt.Sprintf("%s failed for %s (%v) but %s answered %s", system, host, dnsReason(sysErr), d.Trusted, joinAddrs(res.trusted))}
	case sysErr != nil:
		res.diag = &ServerDiagnosis{Kind: FailDNS, Detail: fmt.Sprintf("%s did not resolve: %v", host, dnsReason(sysErr))}
	case len(sys) == 0:
		res.diag = &ServerDiagnosis{Kind: FailDNS, Detail: fmt.Sprintf("%s has no addresses", host)}
	default:
		res.addrs = sortAddrs(sys)
	}
	return res
}

// poisonVerdict explains a server that did not answer on the addresses the
// system resolver gave, when the answers themselves look wrong. It returns
// nil when the answers look like any other dead server's.
func (d *Diagnoser) poisonVerdict(host string, res resolution) *ServerDiagnosis {
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil || isLocalName(host) {
		return nil // an IP literal or a LAN name: DNS said nothing suspicious
	}
	system := d.System
	if system == nil {
		system = systemResolver{}
	}
	trustedClean := len(res.trusted) > 0 && !anyIn(res.trusted, sinkholeRanges) && !anyIn(res.trusted, bogonRanges)
	switch {
	case anyIn(res.addrs, sinkholeRanges):
		detail := fmt.Sprintf("%s answered %s for %s, a known censorship sinkhole, and it does not answer", system, joinAddrs(res.addrs), host)
		if trustedClean {
			detail += fmt.Sprintf("; %s answered %s", d.Trusted, joinAddrs(res.trusted))
		}
		return &ServerDiagnosis{Kind: FailDNSPoisoned, Detail: detail}
	case anyIn(res.addrs, bogonRanges) && trustedClean:
		return &ServerDiagnosis{Kind: FailDNSPoisoned,
			Detail: fmt.Sprintf("%s answered %s for %s (a private/bogon address that does not answer) but %s answered %s",
				system, joinAddrs(res.addrs), host, d.Trusted, joinAddrs(res.trusted))}
	}
	return nil
}

// Server checks name resolution, then a TCP connect, then (for TLS configs)
// a ClientHello with the config's SNI.
func (d *Diagnoser) Server(ctx context.Context, c ServerCheck) ServerDiagnosis {
	if diag, ok := d.cached(c); ok {
		return diag
	}
	diag := d.server(ctx, c)
	if diag.Kind != FailCanceled && ctx.Err() == nil {
		d.remember(c, diag)
	}
	return diag
}

func (d *Diagnoser) server(ctx context.Context, c ServerCheck) ServerDiagnosis {
	res := d.resolve(ctx, c.Host)
	if res.diag != nil {
		return *res.diag
	}
	if res.poisoned != nil {
		return *res.poisoned
	}
	if c.UDP {
		return ServerDiagnosis{}
	}
	conn, target, diag := d.connect(ctx, res.addrs, c.Port)
	if diag != nil {
		if diag.Kind == FailCanceled {
			return *diag
		}
		// The server did not answer. Only now do suspicious DNS answers count.
		if p := d.poisonVerdict(c.Host, res); p != nil {
			return *p
		}
		if anyIn(res.addrs, bogonRanges) && !isLocalName(c.Host) {
			diag.Detail += fmt.Sprintf(" (the system resolver answered a private/bogon address for %s: possible DNS poisoning; --resolver can confirm)", c.Host)
		}
		return *diag
	}
	defer conn.Close()
	if !c.TLS {
		return ServerDiagnosis{}
	}
	sni := c.SNI
	if sni == "" {
		sni = strings.Trim(c.Host, "[]")
	}
	hctx, cancel := context.WithTimeout(ctx, d.stepTimeout())
	defer cancel()
	_ = conn.SetDeadline(time.Now().Add(d.stepTimeout()))
	err := d.handshakeFunc()(hctx, conn, sni)
	switch classifyError(err) {
	case classReset, classEOF:
		return ServerDiagnosis{Kind: FailTLSReset, Detail: fmt.Sprintf("%s accepted TCP but the TLS handshake with SNI %q was cut: %v", target, sni, err)}
	case classTimeout:
		return ServerDiagnosis{Kind: FailTLSTimeout, Detail: fmt.Sprintf("%s accepted TCP but never answered a ClientHello with SNI %q", target, sni)}
	}
	// Success, or the server answered with a TLS alert: it is reachable.
	return ServerDiagnosis{}
}

// Connection attempts per server, and the head start each gets before the
// next address is tried in parallel (Happy Eyeballs, RFC 8305).
const (
	maxDialAddrs = 4
	dialStagger  = 250 * time.Millisecond
)

// connect dials the resolved addresses, families interleaved, starting a new
// attempt every dialStagger while earlier ones are pending; the first to
// connect wins. Success on any address counts as reachable, as it would for
// the cores' own dialer. The first failure explains an overall failure.
func (d *Diagnoser) connect(ctx context.Context, addrs []netip.Addr, port string) (net.Conn, string, *ServerDiagnosis) {
	addrs = interleaveFamilies(addrs)
	if len(addrs) > maxDialAddrs {
		addrs = addrs[:maxDialAddrs]
	}
	if len(addrs) == 0 {
		return nil, "", &ServerDiagnosis{Kind: FailDNS, Detail: "no address to connect to"}
	}
	type attempt struct {
		i      int
		conn   net.Conn
		err    error
		target string
	}
	dctx, cancel := context.WithTimeout(ctx, d.stepTimeout()+time.Duration(len(addrs)-1)*dialStagger)
	defer cancel()
	results := make(chan attempt, len(addrs))
	launch := func(i int) {
		target := net.JoinHostPort(addrs[i].String(), port)
		go func() {
			actx, acancel := context.WithTimeout(dctx, d.stepTimeout())
			defer acancel()
			conn, err := d.dialFunc()(actx, "tcp", target)
			results <- attempt{i: i, conn: conn, err: err, target: target}
		}()
	}
	next, pending := 0, 0
	launch(next)
	next, pending = next+1, pending+1
	failures := make([]attempt, len(addrs))
	stagger := time.NewTimer(dialStagger)
	defer stagger.Stop()
	for pending > 0 {
		select {
		case a := <-results:
			pending--
			if a.err == nil {
				// Close the winners that lose the race, once they arrive.
				go func(left int) {
					for ; left > 0; left-- {
						if late := <-results; late.conn != nil {
							late.conn.Close()
						}
					}
				}(pending)
				return a.conn, a.target, nil
			}
			failures[a.i] = a
			if next < len(addrs) {
				// A failure frees the slot at once rather than waiting.
				launch(next)
				next, pending = next+1, pending+1
			}
		case <-stagger.C:
			if next < len(addrs) {
				launch(next)
				next, pending = next+1, pending+1
				stagger.Reset(dialStagger)
			}
		}
	}
	if ctx.Err() != nil {
		return nil, "", &ServerDiagnosis{Kind: FailCanceled, Detail: "canceled"}
	}
	first := failures[0]
	kind := FailTCPTimeout
	switch classifyError(first.err) {
	case classRefused:
		kind = FailTCPRefused
	case classReset, classEOF:
		kind = FailTCPReset
	case classUnreachable:
		kind = FailTCPUnreach
	}
	detail := fmt.Sprintf("direct TCP connect to %s: %v", first.target, first.err)
	if len(addrs) > 1 {
		detail += fmt.Sprintf(" (and %d other address(es) failed)", len(addrs)-1)
	}
	return nil, "", &ServerDiagnosis{Kind: kind, Detail: detail}
}

// interleaveFamilies orders addresses IPv4, IPv6, IPv4, ... keeping each
// family's own order, so a broken family does not delay the other.
func interleaveFamilies(addrs []netip.Addr) []netip.Addr {
	var v4, v6 []netip.Addr
	for _, a := range addrs {
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	out := make([]netip.Addr, 0, len(addrs))
	for i := 0; i < len(v4) || i < len(v6); i++ {
		if i < len(v4) {
			out = append(out, v4[i])
		}
		if i < len(v6) {
			out = append(out, v6[i])
		}
	}
	return out
}

// isLocalName reports names that legitimately resolve to private addresses.
func isLocalName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if !strings.Contains(h, ".") {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".lan", ".home.arpa", ".internal"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

func dnsReason(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return "no such host"
		}
		if dnsErr.IsTimeout {
			return "timeout"
		}
		return dnsErr.Err
	}
	return err.Error()
}

func sortAddrs(addrs []netip.Addr) []netip.Addr {
	sort.SliceStable(addrs, func(i, j int) bool { return addrs[i].Is4() && !addrs[j].Is4() })
	return addrs
}

func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, 0, len(addrs))
	for i, a := range addrs {
		if i == 4 {
			parts = append(parts, "...")
			break
		}
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

// tunnelKind maps a tunnel-level error class once the server is known to be
// reachable (or could not be checked, when reachable is false).
func tunnelKind(class string, reachable bool) string {
	if class == classAuth {
		return FailProxyAuth
	}
	if !reachable {
		return class // raw class: the layer that failed is unknown
	}
	switch class {
	case classTimeout:
		return FailHTTPTimeout
	case classReset, classEOF, classRefused, classTLS:
		return FailProxyProtocol
	case classTLSCert:
		return FailTLSCert
	case classDNS:
		return FailDNS
	}
	return FailOther
}

// proberKind classifies a native probe's error (MTProto). The prober does its
// own dial, so its error already says which layer failed.
func proberKind(err error) string {
	class := classifyError(err)
	s := strings.ToLower(err.Error())
	switch {
	case class == classAuth:
		return FailProxyAuth
	case strings.HasPrefix(s, "dial "):
		switch class {
		case classRefused:
			return FailTCPRefused
		case classReset, classEOF:
			return FailTCPReset
		case classUnreachable:
			return FailTCPUnreach
		case classDNS:
			return FailDNS
		}
		return FailTCPTimeout
	case strings.Contains(s, "faketls") && (class == classReset || class == classEOF):
		return FailTLSReset
	case strings.Contains(s, "faketls") && class == classTimeout:
		return FailTLSTimeout
	case class == classTimeout:
		return FailProxyTimeout
	case class == classDNS:
		return FailDNS
	}
	return FailProxyProtocol
}

// FailureSummary renders "12 failed: 7 tls-reset, 3 tcp-timeout, 2 proxy-auth"
// for the non-passed results, or "" when every result passed.
func FailureSummary(results []*Result) string {
	counts := map[string]int{}
	failed := 0
	for _, r := range results {
		if r == nil || r.Status == StatusPassed {
			continue
		}
		failed++
		kind := r.FailureKind
		if kind == "" {
			kind = FailOther
		}
		counts[kind]++
	}
	if failed == 0 {
		return ""
	}
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool {
		if counts[kinds[i]] != counts[kinds[j]] {
			return counts[kinds[i]] > counts[kinds[j]]
		}
		return kinds[i] < kinds[j]
	})
	var b bytes.Buffer
	fmt.Fprintf(&b, "%d not passed:", failed)
	for i, k := range kinds {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, " %d %s", counts[k], k)
	}
	return b.String()
}

// diagnosisPrefix marks the note ExamineConfig appends to Reason when a
// direct server check explains a failure, e.g. "diagnosis: tls-reset: ...".
const diagnosisPrefix = "diagnosis: "

// KindFromReason recovers a failure kind from a stored status and reason, for
// rows persisted without a failure_kind (older runs, the DB before it had the
// column). It prefers an explicit diagnosis note and otherwise classifies the
// reason text.
func KindFromReason(status, reason string) string {
	switch status {
	case StatusPassed:
		return ""
	case StatusBroken:
		return FailConfig
	case StatusCanceled:
		return FailCanceled
	case StatusTimeout:
		return FailSlow
	}
	if i := strings.LastIndex(reason, diagnosisPrefix); i >= 0 {
		rest := reason[i+len(diagnosisPrefix):]
		if kind, _, ok := strings.Cut(rest, ":"); ok && kind != "" && !strings.Contains(kind, " ") {
			return kind
		}
	}
	if strings.Contains(reason, "unexpected HTTP status") || strings.Contains(reason, "endpoints reachable") {
		return FailHTTPStatus
	}
	if reason == "" {
		return FailOther
	}
	return tunnelKind(classifyError(errors.New(reason)), false)
}
