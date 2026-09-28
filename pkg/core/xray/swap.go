package xray

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport"
)

// switchTag is the default outbound of a swappable instance. It owns no
// connection of its own: it hands every new connection to the outbound
// that is current at that moment.
const switchTag = "xk-switch"

// DefaultSwapGrace is how long a replaced outbound stays registered for
// the connections that were already using it when the caller passes no
// grace period.
const DefaultSwapGrace = 30 * time.Second

// switchHandler is an outbound.Handler that forwards each dispatch to the
// currently selected inner handler. Swapping the pointer is atomic, so a
// connection accepted at any instant finds a handler — there is no window
// in which the listener is up but has nowhere to send traffic.
type switchHandler struct {
	current atomic.Pointer[outbound.Handler]
}

func (h *switchHandler) Start() error { return nil }
func (h *switchHandler) Close() error { return nil }
func (h *switchHandler) Tag() string  { return switchTag }

func (h *switchHandler) Dispatch(ctx context.Context, link *transport.Link) {
	cur := h.current.Load()
	if cur == nil {
		// Only possible before the first outbound was installed.
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return
	}
	(*cur).Dispatch(ctx, link)
}

func (h *switchHandler) SenderSettings() *serial.TypedMessage {
	if cur := h.current.Load(); cur != nil {
		return (*cur).SenderSettings()
	}
	return nil
}

func (h *switchHandler) ProxySettings() *serial.TypedMessage {
	if cur := h.current.Load(); cur != nil {
		return (*cur).ProxySettings()
	}
	return nil
}

// SwappableInstance is an xray instance whose inbound stays bound for its
// whole life while the outbound (or chain) behind it is replaced. New
// connections switch to the new outbound immediately; connections already
// in flight finish on the old one, which is removed after a grace period.
type SwappableInstance struct {
	core   *Core
	inst   *core.Instance
	prefix string // per-instance tag prefix (see instances.go)
	ohm    outbound.Manager
	sw     *switchHandler
	mark   uint32 // SO_MARK for upstream sockets (WithSocketMark), 0 = none

	// swapMu serialises Swap: two concurrent swaps would both retire the
	// same old generation and leak the one installed in between.
	swapMu sync.Mutex

	mu      sync.Mutex
	gen     int
	current []string // tags of the active generation, entry first
	timers  []*time.Timer
	closed  bool
}

// SwapOption configures a SwappableInstance.
type SwapOption func(*SwappableInstance)

// WithSocketMark sets SO_MARK (Linux; ignored elsewhere) on the sockets
// every generation opens to its upstream, so policy routing and firewall
// rules can tell them from the traffic they carry. 0 leaves sockets
// unmarked.
func WithSocketMark(mark uint32) SwapOption {
	return func(s *SwappableInstance) { s.mark = mark }
}

// MakeSwappableInstance builds a swappable instance whose first outbound
// is hops (one hop: a plain outbound; more: a chain, entry first). The
// core's inbound becomes the instance's listener.
func (c *Core) MakeSwappableInstance(ctx context.Context, hops []protocol.Protocol, opts ...SwapOption) (*SwappableInstance, error) {
	if err := c.buildable(); err != nil {
		return nil, err
	}
	id := instanceSeq.Add(1)
	cfg, err := c.instanceConfig(nil)
	if err != nil {
		return nil, err
	}
	inst, err := newCoreInstance(id, cfg)
	if err != nil {
		return nil, err
	}
	s := &SwappableInstance{core: c, inst: inst, prefix: tagPrefix(id), sw: &switchHandler{}}
	for _, opt := range opts {
		opt(s)
	}
	ohm, ok := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		inst.Close()
		return nil, errors.New("xray instance has no outbound manager")
	}
	s.ohm = ohm
	// Registered first, so it is the default handler for the inbound.
	if err := ohm.AddHandler(ctx, s.sw); err != nil {
		inst.Close()
		return nil, err
	}
	if err := s.install(ctx, hops); err != nil {
		inst.Close()
		return nil, err
	}
	return s, nil
}

// Start starts the instance (binds the inbound).
func (s *SwappableInstance) Start() error { return s.inst.Start() }

// Close stops the instance and every outbound, including ones still in
// their grace period.
func (s *SwappableInstance) Close() error {
	s.mu.Lock()
	s.closed = true
	for _, t := range s.timers {
		t.Stop()
	}
	s.timers = nil
	s.mu.Unlock()
	return s.inst.Close()
}

// Instance exposes the underlying xray instance (for core.Dial in tests).
func (s *SwappableInstance) Instance() *core.Instance { return s.inst }

// Swap routes new connections through hops. The previous outbound keeps
// serving connections it already carries and is removed after grace
// (DefaultSwapGrace when grace <= 0). On error the current outbound stays
// in place.
func (s *SwappableInstance) Swap(ctx context.Context, hops []protocol.Protocol, grace time.Duration) error {
	s.swapMu.Lock()
	defer s.swapMu.Unlock()
	s.mu.Lock()
	closed := s.closed
	old := s.current
	s.mu.Unlock()
	if closed {
		return errors.New("instance is closed")
	}
	if err := s.install(ctx, hops); err != nil {
		return err
	}
	if grace <= 0 {
		grace = DefaultSwapGrace
	}
	s.retireLater(old, grace)
	return nil
}

// install builds hops under fresh tags, registers them and points the
// switch at the exit hop.
func (s *SwappableInstance) install(ctx context.Context, hops []protocol.Protocol) error {
	if len(hops) == 0 {
		return errors.New("no outbound to install")
	}
	s.mu.Lock()
	s.gen++
	gen := s.gen
	s.mu.Unlock()

	obs, err := s.core.swapOutbounds(hops, gen)
	if err != nil {
		return err
	}
	s.markEntry(obs[0])
	renameTags(s.prefix, obs)
	var added []string
	for _, ob := range obs {
		if err := s.addHandler(ctx, ob); err != nil {
			s.remove(added)
			return err
		}
		added = append(added, ob.Tag)
	}
	exit := s.ohm.GetHandler(added[len(added)-1])
	if exit == nil {
		s.remove(added)
		return errors.New("installed outbound vanished")
	}
	s.sw.current.Store(&exit)

	s.mu.Lock()
	s.current = added
	s.mu.Unlock()
	return nil
}

// markEntry sets the socket mark on the entry hop, the only outbound of a
// generation that opens sockets (later hops dial through it, and
// fragmentation is a finalmask on this same stream).
func (s *SwappableInstance) markEntry(ob *conf.OutboundDetourConfig) {
	if s.mark == 0 {
		return
	}
	if ob.StreamSetting == nil {
		ob.StreamSetting = &conf.StreamConfig{}
	}
	if ob.StreamSetting.SocketSettings == nil {
		ob.StreamSetting.SocketSettings = &conf.SocketConfig{}
	}
	ob.StreamSetting.SocketSettings.Mark = int32(s.mark)
	inheritSockopt(ob.StreamSetting) // xhttp download leg and ECH lookups too
}

func (s *SwappableInstance) addHandler(ctx context.Context, ob *conf.OutboundDetourConfig) error {
	built, err := buildOutbound(ob)
	if err != nil {
		return err
	}
	raw, err := core.CreateObject(s.inst, built)
	if err != nil {
		return err
	}
	h, ok := raw.(outbound.Handler)
	if !ok {
		return errors.New("not an outbound handler")
	}
	return s.ohm.AddHandler(ctx, h)
}

// retireLater removes and closes the outbounds tagged tags after grace.
func (s *SwappableInstance) retireLater(tags []string, grace time.Duration) {
	if len(tags) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	var t *time.Timer
	t = time.AfterFunc(grace, func() {
		s.remove(tags)
		s.mu.Lock()
		for i, x := range s.timers {
			if x == t {
				s.timers = append(s.timers[:i], s.timers[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
	})
	s.timers = append(s.timers, t)
}

// remove unregisters and closes the given handlers, exit first so no hop
// is closed while a later hop still dials through it.
func (s *SwappableInstance) remove(tags []string) {
	for i := len(tags) - 1; i >= 0; i-- {
		h := s.ohm.GetHandler(tags[i])
		_ = s.ohm.RemoveHandler(context.Background(), tags[i])
		if h != nil {
			_ = h.Close()
		}
	}
}

// swapOutbounds builds the outbound configs for hops under generation
// gen: hop 0 is the entry (bound, fragmented), each later hop dials
// through the one before it, and the last is the exit.
func (c *Core) swapOutbounds(hops []protocol.Protocol, gen int) ([]*conf.OutboundDetourConfig, error) {
	obs := make([]*conf.OutboundDetourConfig, len(hops))
	for i, hop := range hops {
		out, err := asProtocol(hop)
		if err != nil {
			return nil, fmt.Errorf("hop %d: %w", i, err)
		}
		c.warnInsecure(out)
		ob, err := out.BuildOutboundDetourConfig(c.AllowInsecure)
		if err != nil {
			return nil, fmt.Errorf("hop %d: %w", i, err)
		}
		ob.Tag = fmt.Sprintf("xk-g%d-%d", gen, i)
		if i > 0 {
			// Same socket-level chaining as MakeChainedInstance.
			chainThrough(ob, obs[i-1].Tag)
		}
		obs[i] = ob
	}
	if err := c.prepareEntry(obs[0], hops[0].ConvertToGeneralConfig().Address); err != nil {
		return nil, fmt.Errorf("hop 0: %w", err)
	}
	return obs, nil
}
