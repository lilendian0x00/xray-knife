package http

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alitto/pond/v2"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

const (
	// defaultPrescanWorkers is the fallback concurrency for TCP dials. A plain
	// SYN handshake is cheap (no core instance), so this can be far higher than
	// the full-test thread count.
	defaultPrescanWorkers = 512
	// defaultPrescanTimeout bounds a single TCP dial.
	defaultPrescanTimeout = 2 * time.Second
)

// PrescanOptions configures the TCP reachability pre-check.
type PrescanOptions struct {
	// Workers is the number of concurrent TCP dials. Values <= 0 use the
	// default, and it is capped at the number of unique endpoints.
	Workers int
	// Timeout is the per-endpoint TCP dial timeout. Values <= 0 use the default.
	Timeout time.Duration
	// BindInterface pins dials to a specific OS interface, mirroring the
	// examiner so reachability matches the real test path. Empty disables it.
	BindInterface string
	// Resolver, when set, is compared with the system resolver so an endpoint
	// whose name the system DNS poisons is reported as dns-poisoned.
	Resolver Resolver
}

// PrescanDrop is a link the pre-check filtered out, and why.
type PrescanDrop struct {
	Link     string
	Endpoint string
	Kind     string // a Fail* kind: dns, dns-poisoned, tcp-refused, tcp-timeout, ...
	Detail   string
}

// PrescanResult summarizes a single pre-scan pass.
type PrescanResult struct {
	// Reachable holds the links that survived the pre-check (TCP-reachable
	// plus bypassed), in the original input order.
	Reachable []string
	// TCPReachable is the number of links kept because their endpoint answered
	// a TCP dial.
	TCPReachable int
	// Bypassed is the number of links kept without dialing (UDP-based
	// protocols, or links that could not be parsed / had no dialable endpoint).
	Bypassed int
	// FilteredOut is the number of links dropped as unreachable.
	FilteredOut int
	// UniqueEndpoints is the number of distinct host:port pairs dialed.
	UniqueEndpoints int
	// Dropped lists the filtered-out links with the failure kind, in input
	// order, so callers can report them instead of silently losing them.
	Dropped []PrescanDrop
	// ReachableParsed is Reachable as parsed links (RunPrescanParsed only),
	// ready for TestManager.RunParsed without parsing again.
	ReachableParsed []*ParsedLink
}

// DroppedResults turns the filtered-out links into failed results. Links
// the pre-scan never checked because it was stopped (kind FailCanceled)
// are left out: they are not a verdict, and saving them as failures would
// mark untested configs dead.
func (r *PrescanResult) DroppedResults() []*Result {
	out := make([]*Result, 0, len(r.Dropped))
	for _, d := range r.Dropped {
		if d.Kind == FailCanceled {
			continue
		}
		res := newResult(d.Link)
		res.Status = StatusFailed
		res.FailureKind = d.Kind
		res.Reason = "prescan: " + diagnosisPrefix + d.Kind + ": " + d.Detail
		out = append(out, &res)
	}
	return out
}

// RunPrescan performs a fast TCP reachability pre-check over links and returns
// the subset worth handing to the full HTTP test.
//
// Links are grouped by their destination host:port so each unique endpoint is
// dialed only once; the verdict is then fanned back out to every config that
// shares it. UDP-based protocols (Hysteria2, WireGuard) and UDP transports
// (mKCP, QUIC) cannot be TCP-probed, so they bypass the check and are kept.
// Links that fail to parse or lack a dialable endpoint are also kept, so the
// full test can report them as broken exactly as it would without a pre-scan.
//
// onStart, if non-nil, is called once with the number of unique endpoints
// before dialing begins. onProgress, if non-nil, is called once per endpoint
// dialed. Both may be nil.
func RunPrescan(ctx context.Context, c core.Core, links []string, opts PrescanOptions, onStart func(uniqueEndpoints int), onProgress func()) (*PrescanResult, error) {
	// Links that are empty after trimming are kept as bypassed, as before.
	parsed := make([]*ParsedLink, len(links))
	for i, link := range links {
		parsed[i] = ParseLink(c, link)
	}
	res, err := RunPrescanParsed(ctx, parsed, opts, onStart, onProgress)
	if res != nil {
		res.ReachableParsed = nil // string callers re-parse per test
	}
	return res, err
}

// RunPrescanParsed is RunPrescan over links parsed by ParseLinks. Dropped
// links release their parsed protocol; survivors are in ReachableParsed.
func RunPrescanParsed(ctx context.Context, links []*ParsedLink, opts PrescanOptions, onStart func(uniqueEndpoints int), onProgress func()) (*PrescanResult, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultPrescanTimeout
	}
	// Interface binding is resolved once so a bad --bind value fails fast.
	diag, err := NewDiagnoser(opts.Resolver, opts.BindInterface, timeout)
	if err != nil {
		return nil, err
	}

	// Decide each link's fate up front: "" means bypass (keep without dialing),
	// otherwise the value is the "host:port" to dial. Grouping happens via uniq.
	endpoints := make([]string, len(links))
	uniq := make(map[string]struct{})
	res := &PrescanResult{}
	for i, pl := range links {
		ep := endpointForProto(pl.Proto)
		endpoints[i] = ep
		if ep == "" {
			continue
		}
		uniq[ep] = struct{}{}
	}
	res.UniqueEndpoints = len(uniq)

	if onStart != nil {
		onStart(len(uniq))
	}

	// Dial each unique endpoint once, concurrently.
	verdicts := make(map[string]ServerDiagnosis, len(uniq))
	var mu sync.Mutex

	workers := opts.Workers
	if workers <= 0 {
		workers = defaultPrescanWorkers
	}
	if len(uniq) > 0 && workers > len(uniq) {
		workers = len(uniq)
	}
	if workers < 1 {
		workers = 1
	}

	pool := pond.NewPool(workers)
	defer pool.Stop()
	group := pool.NewGroupContext(ctx)

	for ep := range uniq {
		endpoint := ep
		group.Submit(func() {
			host, port, _ := net.SplitHostPort(endpoint)
			verdict := diag.Server(group.Context(), ServerCheck{Host: host, Port: port})
			mu.Lock()
			verdicts[endpoint] = verdict
			mu.Unlock()
			if onProgress != nil {
				onProgress()
			}
		})
	}
	group.Wait()

	// Assemble survivors, preserving input order.
	res.Reachable = make([]string, 0, len(links))
	res.ReachableParsed = make([]*ParsedLink, 0, len(links))
	for i, pl := range links {
		link := pl.Link
		ep := endpoints[i]
		if ep == "" {
			res.Bypassed++
			res.Reachable = append(res.Reachable, link)
			res.ReachableParsed = append(res.ReachableParsed, pl)
			continue
		}
		v, dialed := verdicts[ep]
		if dialed && v.Kind == "" {
			res.TCPReachable++
			res.Reachable = append(res.Reachable, link)
			res.ReachableParsed = append(res.ReachableParsed, pl)
			continue
		}
		pl.release()
		if !dialed || v.Kind == FailCanceled {
			v = ServerDiagnosis{Kind: FailCanceled, Detail: "pre-scan stopped before this endpoint was checked"}
		}
		res.FilteredOut++
		res.Dropped = append(res.Dropped, PrescanDrop{Link: link, Endpoint: ep, Kind: v.Kind, Detail: v.Detail})
	}

	return res, nil
}

// endpointForProto returns the "host:port" to TCP-dial for a parsed config,
// or "" when it should bypass the TCP check (UDP-based, unparseable (nil),
// or no dialable endpoint).
func endpointForProto(proto protocol.Protocol) string {
	if proto == nil {
		return ""
	}
	gc := proto.ConvertToGeneralConfig()
	if isUDPBased(gc) {
		return ""
	}
	// Address may already be bracketed for IPv6 (e.g. "[::1]"); strip so
	// net.JoinHostPort does not double-wrap.
	host := strings.TrimSpace(gc.Address)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if host == "" || gc.Port == "" {
		return ""
	}
	if _, err := strconv.Atoi(strings.TrimSpace(gc.Port)); err != nil {
		// Non-numeric port: let the full test report it as broken.
		return ""
	}
	return net.JoinHostPort(host, strings.TrimSpace(gc.Port))
}

// isUDPBased reports whether a config runs over UDP (or is otherwise not
// TCP-dialable), so a TCP pre-check would produce a false negative.
func isUDPBased(gc protocol.GeneralConfig) bool {
	switch strings.ToLower(gc.Protocol) {
	case protocol.Hysteria2Identifier, "hy2", protocol.WireguardIdentifier, protocol.TunIdentifier, protocol.TuicIdentifier, protocol.HysteriaIdentifier:
		return true
	}
	// The transport network lives in different GeneralConfig fields depending
	// on the protocol (vmess -> Network, vless/trojan -> Type), so check both.
	for _, n := range []string{gc.Network, gc.Type} {
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "kcp", "mkcp", "quic":
			return true
		}
	}
	return false
}
