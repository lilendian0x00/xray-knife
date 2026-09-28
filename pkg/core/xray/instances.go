package xray

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

// Several xray instances live in one process (a proxy listener next to
// its health checks, the http tester's workers, web jobs), but xray-core
// keeps two process-globals in transport/internet: the DNS client and the
// outbound manager that sockopt.dialerProxy is resolved against. Every
// core.New overwrites both (internet.InitSystemDialer), and DialSystem
// reads the manager, unlocked, for every dialerProxy dial. Two instances
// using dialerProxy therefore race, and a lookup can land in the wrong
// instance (whichever was created last).
//
// xray-knife never needs that global:
//
//   - Fragmentation is a per-stream finalmask (see applyFragment), not a
//     freedom outbound reached through dialerProxy.
//   - Chain hops (hop i dialing its server through hop i-1) are marked in
//     the hop's sockopt.interface as chainMarker+tag, and chainDialer —
//     installed once as xray's system dialer, before any instance exists
//     — hands such dials to the tagged handler of the instance that owns
//     it (tags carry a per-instance "xk<N>-" prefix). This is exactly what
//     dialerProxy does, without the global. A chained hop never opens a
//     socket itself, so its interface setting has no other use.
//   - Nothing sets sockopt.domainStrategy, so the global DNS client is
//     never read either.
//
// The remaining global writes happen inside core.New; newCoreInstance
// serialises them so they don't race each other. They race with nothing
// else: no reader runs for xray-knife's configs.

// chainMarker prefixes the handler tag in a chained hop's sockopt.interface.
const chainMarker = "xk-chain:"

var (
	instanceSeq atomic.Uint64
	// createMu serialises core.New: InitSystemDialer writes the globals.
	createMu sync.Mutex
)

var instances = struct {
	sync.RWMutex
	byID map[uint64]weak.Pointer[core.Instance]
}{byID: map[uint64]weak.Pointer[core.Instance]{}}

func init() {
	internet.UseAlternativeSystemDialer(&chainDialer{base: &internet.DefaultSystemDialer{}})
}

// newCoreInstance creates instance id, serialised with every other
// instance creation, and registers it for chainDialer.
func newCoreInstance(id uint64, cfg *core.Config) (*core.Instance, error) {
	createMu.Lock()
	inst, err := core.New(cfg)
	createMu.Unlock()
	if err != nil {
		return nil, err
	}
	instances.Lock()
	for k, w := range instances.byID {
		if w.Value() == nil {
			delete(instances.byID, k)
		}
	}
	instances.byID[id] = weak.Make(inst)
	instances.Unlock()
	return inst, nil
}

// handlerFor finds the outbound handler tagged tag in the instance whose
// prefix the tag carries.
func handlerFor(tag string) outbound.Handler {
	id, ok := instanceOf(tag)
	if !ok {
		return nil
	}
	instances.RLock()
	w, ok := instances.byID[id]
	instances.RUnlock()
	if !ok {
		return nil
	}
	inst := w.Value()
	if inst == nil {
		return nil
	}
	m, _ := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if m == nil {
		return nil
	}
	return m.GetHandler(tag)
}

// chainDialer is xray's system dialer: plain dials go to the default
// dialer; a dial marked with chainMarker goes through the marked handler.
type chainDialer struct {
	base internet.SystemDialer
}

func (d *chainDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (xnet.Conn, error) {
	if sockopt != nil {
		if tag, ok := strings.CutPrefix(sockopt.Interface, chainMarker); ok {
			h := handlerFor(tag)
			if h == nil {
				return nil, errors.New("chain hop " + displayTag(tag) + " is gone")
			}
			return redirect(ctx, dest, tag, h), nil
		}
	}
	return d.base.Dial(ctx, src, dest, sockopt)
}

func (d *chainDialer) DestIpAddress() xnet.IP { return d.base.DestIpAddress() }

// redirect returns a connection to dst carried by handler h, as
// xray-core's dialerProxy does (transport/internet/dialer.go).
func redirect(ctx context.Context, dst xnet.Destination, tag string, h outbound.Handler) xnet.Conn {
	outbounds := session.OutboundsFromContext(ctx)
	ctx = session.ContextWithOutbounds(ctx, append(outbounds, &session.Outbound{Target: dst, Tag: tag}))
	ur, uw := pipe.New(pipe.OptionsFromContext(ctx)...)
	dr, dw := pipe.New(pipe.OptionsFromContext(ctx)...)
	go h.Dispatch(context.WithoutCancel(ctx), &transport.Link{Reader: ur, Writer: dw})
	readerOpt := cnc.ConnectionOutputMulti(dr)
	if dst.Network != xnet.Network_TCP {
		readerOpt = cnc.ConnectionOutputMultiUDP(dr)
	}
	return cnc.NewConnection(
		cnc.ConnectionInputMulti(uw),
		readerOpt,
		cnc.ConnectionOnClose(common.ChainedClosable{uw, dw}),
	)
}

// chainThrough makes ob dial its server through the handler tagged prev
// (same instance, prefixed later by renameTags). The hop keeps its own
// transport (ws, grpc, xhttp, ...) and TLS/REALITY.
func chainThrough(ob *conf.OutboundDetourConfig, prev string) {
	if ob.StreamSetting == nil {
		ob.StreamSetting = &conf.StreamConfig{}
	}
	if ob.StreamSetting.SocketSettings == nil {
		ob.StreamSetting.SocketSettings = &conf.SocketConfig{}
	}
	ob.StreamSetting.SocketSettings.Interface = chainMarker + prev
	inheritSockopt(ob.StreamSetting)
}

// tagPrefix is the unique tag prefix of instance id.
func tagPrefix(id uint64) string { return "xk" + strconv.FormatUint(id, 10) + "-" }

// renameTags gives every tagged outbound in obs the instance prefix and
// rewrites the references between them (chain markers, proxy settings).
func renameTags(prefix string, obs []*conf.OutboundDetourConfig) {
	rename := map[string]string{}
	for _, ob := range obs {
		if ob.Tag != "" && !strings.HasPrefix(ob.Tag, prefix) {
			rename[ob.Tag] = prefix + ob.Tag
		}
	}
	for _, ob := range obs {
		if nt, ok := rename[ob.Tag]; ok {
			ob.Tag = nt
		}
		if ob.ProxySettings != nil {
			if nt, ok := rename[ob.ProxySettings.Tag]; ok {
				ob.ProxySettings.Tag = nt
			}
		}
		if ob.StreamSetting != nil && ob.StreamSetting.SocketSettings != nil {
			so := ob.StreamSetting.SocketSettings
			if prev, ok := strings.CutPrefix(so.Interface, chainMarker); ok {
				if nt, ok := rename[prev]; ok {
					so.Interface = chainMarker + nt
				}
			}
		}
	}
}

// displayTag strips the instance prefix for messages.
func displayTag(tag string) string {
	if _, ok := instanceOf(tag); ok {
		return tag[strings.IndexByte(tag, '-')+1:]
	}
	return tag
}

// instanceOf parses the instance id out of a prefixed tag.
func instanceOf(tag string) (uint64, bool) {
	if !strings.HasPrefix(tag, "xk") {
		return 0, false
	}
	end := strings.IndexByte(tag, '-')
	if end < 3 {
		return 0, false
	}
	id, err := strconv.ParseUint(tag[2:end], 10, 64)
	return id, err == nil
}
