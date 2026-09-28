// Package dpi finds censorship workarounds for one known config: it tests
// the config without changes (the baseline), then with each candidate TLS
// fragmentation setting (and optional SNI overrides), and reports which
// ones get through on the current network. It also dials the server
// directly to tell "blocked by IP/port" from "blocked by SNI" from
// "server down".
package dpi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
	"github.com/lilendian0x00/xray-knife/v11/pkg/netbind"
)

// DefaultTestURL answers 204 with no body, so each attempt costs one
// handshake and almost no transfer.
const DefaultTestURL = "https://www.gstatic.com/generate_204"

// Status of a profile after all its attempts.
const (
	StatusPass    = "pass"    // every attempt succeeded
	StatusPartial = "partial" // some attempts succeeded (flaky, or rate-limited DPI)
	StatusFail    = "fail"    // no attempt succeeded
	StatusError   = "error"   // the profile could not be built
	StatusSkipped = "skipped" // not run (stopped early)
)

// Verdicts summarise the whole run.
const (
	VerdictNoInterference = "no-interference"    // baseline passes: nothing to work around
	VerdictFragmentHelps  = "fragment-helps"     // baseline fails, some profile passes
	VerdictPartial        = "partial"            // only flaky profiles
	VerdictUnreachable    = "server-unreachable" // TCP to the server fails: IP/port blocked or server down
	VerdictSNIBlocked     = "sni-blocked"        // TCP works, TLS to the server is cut, no profile helps
	VerdictNoWorkaround   = "no-workaround"      // server reachable but nothing tried got through
	VerdictCanceled       = "canceled"
)

// Options configures a run. Only Link is required.
type Options struct {
	Link string
	// CoreType selects the core; AutoCoreType routes by scheme.
	CoreType core.CoreType
	// TestURL is fetched through the proxy on every attempt.
	TestURL string
	// Timeout bounds each attempt (dial + handshake + request).
	Timeout time.Duration
	// Attempts per profile. More attempts catch DPI that lets the first
	// handshake through and resets later ones.
	Attempts int
	// Threads is how many profiles run at once. Keep it low: bursts of
	// handshakes to one server can themselves trigger rate-based blocking.
	Threads int
	// Mode picks the built-in candidate list when Specs is empty.
	Mode Mode
	// Specs overrides the built-in list with explicit --fragment values.
	Specs []string
	// SNIs are extra server names to try, each with every fragment spec.
	SNIs []string
	// MixedCaseSNI adds the link's own SNI in mixed case as an extra SNI.
	MixedCaseSNI bool
	// StopAfter ends the run once this many profiles have passed (0 = run all).
	StopAfter int
	// Insecure skips certificate checks in the cores.
	Insecure bool
	// BindInterface pins every dial to an OS interface.
	BindInterface string
	// Verbose enables core logs.
	Verbose bool

	// OnStart is called once with the profiles about to run.
	OnStart func(profiles []Profile)
	// OnResult is called after each profile finishes (serialised).
	OnResult func(Result)

	// newCore builds a core for one profile; tests replace it.
	newCore func(core.CoreType, core.FactoryOptions) core.Core
}

// Result is one profile's outcome.
type Result struct {
	Index     int     `json:"index"`
	Profile   Profile `json:"profile"`
	Status    string  `json:"status"`
	Attempts  int     `json:"attempts"`
	Successes int     `json:"successes"`
	// Delays of the successful attempts in ms.
	Delays   []int64 `json:"delays,omitempty"`
	MinDelay int64   `json:"minDelay"`
	// MedianDelay of the successful attempts in ms (-1 when none succeeded).
	MedianDelay int64 `json:"medianDelay"`
	// Failures counts failed attempts by kind (see Classify).
	Failures  map[string]int `json:"failures,omitempty"`
	LastError string         `json:"lastError,omitempty"`
	// Link is the exact link tested (differs from the input with an SNI override).
	Link string `json:"link,omitempty"`
}

// SuccessRate is Successes/Attempts in [0,1].
func (r Result) SuccessRate() float64 {
	if r.Attempts == 0 {
		return 0
	}
	return float64(r.Successes) / float64(r.Attempts)
}

// DirectCheck is the result of dialing the proxy server without the proxy.
type DirectCheck struct {
	Address string `json:"address"`
	// Transport is "tcp" or "udp"; UDP servers can't be checked directly.
	Transport string `json:"transport"`
	Checked   bool   `json:"checked"`
	TCPOK     bool   `json:"tcpOk"`
	TCPDelay  int64  `json:"tcpDelay"`
	TCPError  string `json:"tcpError,omitempty"`
	// TLS is checked with the link's SNI when the link uses TLS.
	TLSChecked bool   `json:"tlsChecked"`
	TLSOK      bool   `json:"tlsOk"`
	TLSDelay   int64  `json:"tlsDelay"`
	TLSError   string `json:"tlsError,omitempty"`
	TLSKind    string `json:"tlsKind,omitempty"`
	SNI        string `json:"sni,omitempty"`
}

// Report is the outcome of a run.
type Report struct {
	Link     string      `json:"link"`
	Protocol string      `json:"protocol"`
	Core     string      `json:"core"`
	Direct   DirectCheck `json:"direct"`
	Results  []Result    `json:"results"`
	// Best is the recommended profile (nil when none passed).
	Best    *Result `json:"best,omitempty"`
	Verdict string  `json:"verdict"`
	// Advice is a one-paragraph human explanation of the verdict.
	Advice   string        `json:"advice"`
	Duration time.Duration `json:"duration"`
}

func (o *Options) setDefaults() {
	if o.TestURL == "" {
		o.TestURL = DefaultTestURL
	}
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	if o.Attempts <= 0 {
		o.Attempts = 3
	}
	if o.Threads <= 0 {
		o.Threads = 4
	}
	if o.Mode == "" {
		o.Mode = ModeQuick
	}
	if o.newCore == nil {
		o.newCore = defaultNewCore
	}
}

func (o *Options) validate() error {
	if strings.TrimSpace(o.Link) == "" {
		return errors.New("no config link given")
	}
	if o.Attempts > 50 {
		return errors.New("attempts must be at most 50")
	}
	if o.Threads > 64 {
		return errors.New("threads must be at most 64")
	}
	if o.StopAfter < 0 {
		return errors.New("stop-after must not be negative")
	}
	u, err := url.Parse(o.TestURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid test URL %q", o.TestURL)
	}
	return nil
}

func defaultNewCore(t core.CoreType, opts core.FactoryOptions) core.Core {
	if t == core.AutoCoreType {
		return core.NewAutomaticCoreWith(opts)
	}
	return core.CoreFactoryWith(t, opts)
}

// Run tests every profile against opts.Link and ranks them.
func Run(ctx context.Context, opts Options) (*Report, error) {
	opts.setDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}
	opts.Link = strings.TrimSpace(opts.Link)
	started := time.Now()

	// Parse once without a fragment to learn what we are dealing with.
	probeCore := opts.newCore(opts.CoreType, core.FactoryOptions{InsecureTLS: opts.Insecure, BindInterface: opts.BindInterface})
	if probeCore == nil {
		return nil, errors.New("unknown core type")
	}
	proto, err := probeCore.CreateProtocol(opts.Link)
	if err != nil {
		return nil, fmt.Errorf("invalid config link: %w", err)
	}
	if err := proto.Parse(); err != nil {
		return nil, fmt.Errorf("invalid config link: %w", err)
	}
	if _, ok := proto.(protocol.Prober); ok {
		return nil, errors.New("MTProto proxies are not tunnelled through a core; test them with `xray-knife http`")
	}
	gc := proto.ConvertToGeneralConfig()
	scheme := strings.ToLower(gc.Protocol)
	coreName := effectiveCore(proto, opts.CoreType, scheme)
	rep := &Report{Link: opts.Link, Protocol: scheme, Core: coreName}

	udp := isUDP(gc)
	specs := opts.Specs
	switch {
	case udp && coreName == "xray" && scheme == protocol.WireguardIdentifier:
		// Fragmentation needs TCP; WireGuard can only be helped by noise
		// (added below unless the caller gave explicit specs).
	case udp:
		return nil, fmt.Errorf("%s runs over UDP (QUIC/KCP): TLS fragmentation does not apply to it", scheme)
	case coreName == "sing-box" && !singboxCanFragment(proto, gc):
		return nil, fmt.Errorf("sing-box can't fragment this %s link (%s); try --core xray", scheme, singboxFragmentReason(proto, gc))
	case len(specs) > 0:
	case coreName == "sing-box":
		specs = append([]string(nil), singboxSpecs...)
	default:
		specs = Specs(opts.Mode)
	}

	snis := slices.Clone(opts.SNIs)
	if opts.MixedCaseSNI && gc.SNI != "" {
		if mixed := RandomCase(unbracket(gc.SNI)); mixed != gc.SNI {
			snis = append(snis, mixed)
		}
	}
	profiles, err := BuildProfiles(specs, snis)
	if err != nil {
		return nil, err
	}
	if udp && scheme == protocol.WireguardIdentifier && len(opts.Specs) == 0 {
		profiles = append(profiles, noiseProfiles()...)
	}
	for i := range profiles {
		profiles[i].Args = profiles[i].Flags()
	}
	if len(snis) > 0 && !hasTLS(gc) {
		return nil, errors.New("SNI overrides need a TLS config (the link has no TLS)")
	}

	rep.Direct = directCheck(ctx, gc, udp, opts)

	if opts.OnStart != nil {
		opts.OnStart(slices.Clone(profiles))
	}
	rep.Results = runProfiles(ctx, opts, profiles)
	rep.Duration = time.Since(started)
	rank(rep)
	if ctx.Err() != nil && rep.Best == nil {
		rep.Verdict = VerdictCanceled
		rep.Advice = "The run was stopped before a working setting was found."
	}
	return rep, nil
}

// effectiveCore names the core that will run the link. The automatic
// core moves some links (insecure TLS, h2/quic transports, SS plugins,
// QUIC protocols) to sing-box, so read it off the parsed protocol.
func effectiveCore(p protocol.Protocol, t core.CoreType, scheme string) string {
	switch p.(type) {
	case xray.Protocol:
		return "xray"
	case singbox.Protocol:
		return "sing-box"
	}
	switch t {
	case core.XrayCoreType:
		return "xray"
	case core.SingboxCoreType:
		return "sing-box"
	}
	switch scheme {
	case protocol.Hysteria2Identifier, "hy2", protocol.HysteriaIdentifier, protocol.TuicIdentifier,
		protocol.AnyTLSIdentifier, protocol.SSHIdentifier:
		return "sing-box"
	}
	return "xray"
}

// isUDP reports whether the link runs over UDP, where TCP fragmentation
// has nothing to split.
func isUDP(gc protocol.GeneralConfig) bool {
	switch strings.ToLower(gc.Protocol) {
	case protocol.Hysteria2Identifier, "hy2", protocol.WireguardIdentifier, protocol.TuicIdentifier, protocol.HysteriaIdentifier:
		return true
	}
	for _, n := range []string{gc.Network, gc.Type} {
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "kcp", "mkcp", "quic":
			return true
		}
	}
	return false
}

func noiseProfiles() []Profile {
	specs := [][]string{
		{"rand:10-20:10-16"},
		{"rand:50-100:10-16"},
		{"rand:1-8:1-3", "rand:1-8:1-3"},
		{"str:GET / HTTP/1.1:5"},
	}
	out := make([]Profile, 0, len(specs))
	for _, s := range specs {
		o, err := fragment.Build("", s)
		if err != nil {
			continue
		}
		out = append(out, Profile{Name: "noise " + strings.Join(s, " "), Fragment: o})
	}
	return out
}

func runProfiles(ctx context.Context, opts Options, profiles []Profile) []Result {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([]Result, len(profiles))
	for i, p := range profiles {
		results[i] = Result{Index: i, Profile: p, Status: StatusSkipped, MedianDelay: -1, MinDelay: -1}
	}

	var (
		mu     sync.Mutex
		passed int
		wg     sync.WaitGroup
	)
	sem := make(chan struct{}, opts.Threads)
	for i := range profiles {
		select {
		case sem <- struct{}{}:
		case <-runCtx.Done():
		}
		if runCtx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			r := testProfile(runCtx, opts, i, profiles[i])
			mu.Lock()
			defer mu.Unlock()
			if runCtx.Err() != nil && r.Successes == 0 && r.Status != StatusError {
				// Interrupted before it could finish: don't report a
				// cancellation as a DPI failure.
				r.Status = StatusSkipped
			}
			results[i] = r
			if r.Status == StatusPass {
				passed++
				if opts.StopAfter > 0 && passed >= opts.StopAfter {
					cancel()
				}
			}
			if opts.OnResult != nil {
				opts.OnResult(r)
			}
		}(i)
	}
	wg.Wait()
	return results
}

func testProfile(ctx context.Context, opts Options, idx int, p Profile) (r Result) {
	r = Result{Index: idx, Profile: p, MedianDelay: -1, MinDelay: -1, Link: opts.Link}
	defer func() {
		if rec := recover(); rec != nil {
			r.Status = StatusError
			r.LastError = fmt.Sprintf("panic: %v", rec)
		}
	}()

	link := opts.Link
	if p.SNI != "" {
		l, err := WithSNI(link, p.SNI)
		if err != nil {
			r.Status, r.LastError = StatusError, err.Error()
			return r
		}
		link = l
	}
	r.Link = link

	c := opts.newCore(opts.CoreType, core.FactoryOptions{
		InsecureTLS:   opts.Insecure,
		Verbose:       opts.Verbose,
		BindInterface: opts.BindInterface,
		Fragment:      p.Fragment.Clone(),
	})
	proto, err := c.CreateProtocol(link)
	if err == nil {
		err = proto.Parse()
	}
	if err != nil {
		r.Status, r.LastError = StatusError, err.Error()
		return r
	}
	client, instance, err := c.MakeHttpClient(ctx, proto, opts.Timeout)
	if err != nil {
		r.Status, r.LastError = StatusError, err.Error()
		return r
	}
	defer instance.Close()

	for a := 0; a < opts.Attempts; a++ {
		if ctx.Err() != nil {
			break
		}
		r.Attempts++
		d, err := attempt(ctx, client, opts.TestURL, opts.Timeout)
		if err != nil && ctx.Err() != nil {
			// Cut off by StopAfter or cancellation: the attempt says
			// nothing about the network, so don't count it.
			r.Attempts--
			break
		}
		if err != nil {
			if r.Failures == nil {
				r.Failures = map[string]int{}
			}
			kind := Classify(err)
			if errors.As(err, new(*statusError)) {
				kind = KindHTTP
			}
			r.Failures[kind]++
			r.LastError = err.Error()
			continue
		}
		r.Successes++
		r.Delays = append(r.Delays, d)
	}
	finish(&r)
	return r
}

type statusError struct{ code int }

func (e *statusError) Error() string { return fmt.Sprintf("unexpected HTTP status %d", e.code) }

func attempt(ctx context.Context, client *http.Client, testURL string, timeout time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	d := time.Since(start).Milliseconds()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, &statusError{code: resp.StatusCode}
	}
	if d < 1 {
		d = 1
	}
	return d, nil
}

func finish(r *Result) {
	switch {
	case r.Attempts == 0:
		r.Status = StatusSkipped
	case r.Successes == r.Attempts:
		r.Status = StatusPass
	case r.Successes > 0:
		r.Status = StatusPartial
	default:
		r.Status = StatusFail
	}
	if len(r.Delays) > 0 {
		s := slices.Clone(r.Delays)
		slices.Sort(s)
		r.MinDelay = s[0]
		r.MedianDelay = s[len(s)/2]
		if len(s)%2 == 0 {
			r.MedianDelay = (s[len(s)/2-1] + s[len(s)/2]) / 2
		}
	}
}

// rank picks the best profile and sets the verdict.
func rank(rep *Report) {
	candidates := make([]*Result, 0, len(rep.Results))
	var baseline *Result
	for i := range rep.Results {
		r := &rep.Results[i]
		if r.Profile.Name == "baseline" && r.Profile.SNI == "" {
			baseline = r
		}
		if r.Successes > 0 {
			candidates = append(candidates, r)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.SuccessRate() != b.SuccessRate() {
			return a.SuccessRate() > b.SuccessRate()
		}
		// Within 15% latency, prefer the gentler profile.
		if !similar(a.MedianDelay, b.MedianDelay) {
			return a.MedianDelay < b.MedianDelay
		}
		return gentleness(a.Profile) > gentleness(b.Profile)
	})
	if len(candidates) > 0 {
		best := *candidates[0]
		rep.Best = &best
	}

	switch {
	case baseline != nil && baseline.Status == StatusPass:
		rep.Verdict = VerdictNoInterference
		rep.Advice = "The config works without fragmentation on this network. Fragmenting would only add latency."
		b := *baseline
		rep.Best = &b
	case rep.Best != nil && rep.Best.Status == StatusPass:
		rep.Verdict = VerdictFragmentHelps
		rep.Advice = fmt.Sprintf("The config is blocked as-is but works with %s. %s.",
			rep.Best.Profile.Label(), howToApply(rep.Best.Profile))
	case rep.Best != nil:
		rep.Verdict = VerdictPartial
		rep.Advice = fmt.Sprintf("Only flaky results: %s got %d/%d through. The filter may be rate-based; retry with more attempts or at another time.",
			rep.Best.Profile.Label(), rep.Best.Successes, rep.Best.Attempts)
	case rep.Direct.Checked && !rep.Direct.TCPOK:
		rep.Verdict = VerdictUnreachable
		rep.Advice = "The server's IP/port can't be reached directly (" + rep.Direct.TCPError + "). Fragmentation can't help: the address is blocked or the server is down. Try a clean IP (xray-knife cfscanner) or another port."
	case rep.Direct.TLSChecked && !rep.Direct.TLSOK && (rep.Direct.TLSKind == KindReset || rep.Direct.TLSKind == KindTimeout || rep.Direct.TLSKind == KindEOF):
		rep.Verdict = VerdictSNIBlocked
		rep.Advice = "TCP to the server works but the TLS handshake is cut (" + rep.Direct.TLSKind + "), which points at SNI filtering, and no tried setting got past it. Try --mode full, other SNIs (--sni), or a different front domain."
	default:
		rep.Verdict = VerdictNoWorkaround
		rep.Advice = "The server is reachable but no tried setting worked through the proxy. The config itself may be broken (wrong credentials/path) or blocked by something other than SNI."
	}
}

// howToApply tells the user how to reproduce a profile outside the finder.
func howToApply(p Profile) string {
	flags := p.Flags()
	switch {
	case flags != "" && p.SNI != "":
		return "Use it with `" + flags + "` and the SNI set to " + p.SNI + " in the link"
	case flags != "":
		return "Use it with `" + flags + "`"
	case p.SNI != "":
		return "Set sni=" + p.SNI + " in the link (no fragmentation needed)"
	}
	return "No changes are needed"
}

func similar(a, b int64) bool {
	if a == b {
		return true
	}
	lo, hi := min(a, b), max(a, b)
	return lo > 0 && float64(hi-lo)/float64(lo) <= 0.15
}

// singboxCanFragment reports whether sing-box would really fragment the
// link's handshake: it only splits plain TLS over TCP (not REALITY, not QUIC).
func singboxCanFragment(p protocol.Protocol, gc protocol.GeneralConfig) bool {
	if _, ok := p.(singbox.Protocol); ok {
		supported, _ := singbox.FragmentSupported(p)
		return supported
	}
	return hasTLS(gc)
}

func singboxFragmentReason(p protocol.Protocol, gc protocol.GeneralConfig) string {
	if _, ok := p.(singbox.Protocol); ok {
		if _, reason := singbox.FragmentSupported(p); reason != "" {
			return reason
		}
	}
	if !hasTLS(gc) {
		return "no TLS handshake to fragment"
	}
	return "unsupported"
}

func hasTLS(gc protocol.GeneralConfig) bool {
	security := strings.ToLower(gc.Security + " " + gc.TLS)
	return strings.Contains(security, "tls") || strings.Contains(security, "reality")
}

func unbracket(h string) string {
	return strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
}

// directCheck dials the proxy server without any proxy: TCP connect, then
// a TLS handshake with the link's SNI when the link uses TLS.
func directCheck(ctx context.Context, gc protocol.GeneralConfig, udp bool, opts Options) DirectCheck {
	host := unbracket(gc.Address)
	port := gc.Port
	if h, p, err := net.SplitHostPort(gc.Address); err == nil && port == "" {
		host, port = h, p
	}
	dc := DirectCheck{Address: net.JoinHostPort(host, port), Transport: "tcp"}
	if udp {
		dc.Transport = "udp"
		return dc
	}
	if host == "" || port == "" {
		return dc
	}
	dc.Checked = true

	d := &net.Dialer{Timeout: opts.Timeout}
	if opts.BindInterface != "" {
		if b, err := netbind.New(opts.BindInterface); err == nil {
			b.ApplyDialer(d)
		}
	}
	dctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	start := time.Now()
	conn, err := d.DialContext(dctx, "tcp", dc.Address)
	if err != nil {
		dc.TCPError = fmt.Sprintf("%s: %v", Classify(err), err)
		return dc
	}
	defer conn.Close()
	dc.TCPOK = true
	dc.TCPDelay = max(time.Since(start).Milliseconds(), 1)

	if !hasTLS(gc) {
		return dc
	}
	sni := unbracket(gc.SNI)
	if sni == "" {
		sni = unbracket(gc.Host)
	}
	if sni == "" && net.ParseIP(host) == nil {
		sni = host
	}
	dc.TLSChecked = true
	dc.SNI = sni
	tconn := tls.Client(conn, &tls.Config{
		ServerName: sni,
		// Only reachability matters here, not who answers.
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"h2", "http/1.1"},
	})
	start = time.Now()
	if err := tconn.HandshakeContext(dctx); err != nil {
		dc.TLSKind = Classify(err)
		dc.TLSError = err.Error()
		return dc
	}
	dc.TLSOK = true
	dc.TLSDelay = max(time.Since(start).Milliseconds(), 1)
	return dc
}
