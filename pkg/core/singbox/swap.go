package singbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	boxOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// switchType/switchTag name the outbound a swappable instance routes
// everything to. It owns no connection: it hands each new connection to
// the outbound that is current at that moment.
const (
	switchType = "xk-switch"
	switchTag  = "xk-switch"
)

// DefaultSwapGrace is how long a replaced outbound stays registered for
// the connections that were already using it when no grace is given.
const DefaultSwapGrace = 30 * time.Second

type switchOptions struct{}

// switchOutbound forwards dials to the outbound (or endpoint) whose tag
// is current. The tag is swapped atomically, so there is no moment when
// the listener accepts a connection it cannot route.
type switchOutbound struct {
	boxOutbound.Adapter
	manager adapter.OutboundManager
	target  atomic.Pointer[string]
}

func newSwitchOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ switchOptions) (adapter.Outbound, error) {
	return &switchOutbound{
		Adapter: boxOutbound.NewAdapter(switchType, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		manager: service.FromContext[adapter.OutboundManager](ctx),
	}, nil
}

func (s *switchOutbound) current() (adapter.Outbound, error) {
	tag := s.target.Load()
	if tag == nil {
		return nil, errors.New("no outbound installed yet")
	}
	out, ok := s.manager.Outbound(*tag)
	if !ok {
		return nil, fmt.Errorf("outbound %s not found", *tag)
	}
	return out, nil
}

func (s *switchOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	out, err := s.current()
	if err != nil {
		return nil, err
	}
	return out.DialContext(ctx, network, destination)
}

func (s *switchOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	out, err := s.current()
	if err != nil {
		return nil, err
	}
	return out.ListenPacket(ctx, destination)
}

// SwappableInstance is a sing-box instance whose inbound stays bound for
// its whole life while the outbound (or chain) behind it is replaced. New
// connections switch to the new outbound immediately; connections already
// in flight finish on the old one, which is removed after a grace period.
type SwappableInstance struct {
	core *Core
	box  *box.Box
	ctx  context.Context
	sw   *switchOutbound

	// mu is held for the whole of Swap, a retirement and Close. sing-box's
	// managers panic ("invalid inbound index") when an outbound is removed
	// from a closed instance, so a retire timer must never overlap Close;
	// and two overlapping Swaps would both retire the same generation and
	// leak the one in between.
	mu      sync.Mutex
	gen     int
	current []created // active generation, entry first
	timers  []*time.Timer
	closed  bool

	mark uint32 // socket mark for every generation's entry hop (0: none)
}

// SwapOption adjusts the options of a swappable instance.
type SwapOption func(*option.Options)

// WithSocketMark marks every socket the instance opens upstream with mark
// (SO_MARK; sing-box supports this on Linux only), so host-tun's fwmark
// bypass rule and kill switch recognise the proxy's own traffic. 0 leaves
// sockets unmarked.
func WithSocketMark(mark uint32) SwapOption {
	return func(o *option.Options) {
		if mark == 0 {
			return
		}
		if o.Route == nil {
			o.Route = &option.RouteOptions{}
		}
		o.Route.DefaultMark = option.FwMark(mark)
	}
}

// created records one outbound or endpoint added at runtime.
type created struct {
	tag      string
	endpoint bool
}

// MakeSwappableInstance builds a swappable instance routing through hops
// (one hop: a plain outbound; more: a chain, entry first), with the core's
// inbound as the listener.
func (c *Core) MakeSwappableInstance(ctx context.Context, hops []protocol.Protocol, swapOpts ...SwapOption) (*SwappableInstance, error) {
	if len(hops) == 0 {
		return nil, errors.New("no outbound to install")
	}
	opts, err := c.swapBoxOptions(swapOpts...)
	if err != nil {
		return nil, err
	}

	boxCtx := boxContext(ctx)
	registry, ok := service.FromContext[adapter.OutboundRegistry](boxCtx).(*boxOutbound.Registry)
	if !ok {
		return nil, errors.New("sing-box outbound registry not found")
	}
	boxOutbound.Register[switchOptions](registry, switchType, newSwitchOutbound)

	instance, err := box.New(box.Options{Options: opts, Context: boxCtx})
	if err != nil {
		return nil, err
	}
	out, _ := instance.Outbound().Outbound(switchTag)
	sw, ok := out.(*switchOutbound)
	if !ok {
		instance.Close()
		return nil, errors.New("switch outbound missing")
	}
	s := &SwappableInstance{core: c, box: instance, ctx: boxCtx, sw: sw, mark: uint32(opts.Route.DefaultMark)}
	// The first generation is created before Start; the managers start it
	// together with the rest of the instance.
	s.mu.Lock()
	err = s.installLocked(hops)
	s.mu.Unlock()
	if err != nil {
		instance.Close()
		return nil, err
	}
	return s, nil
}

// swapBoxOptions builds the options of a swappable instance: the switch
// outbound as the only route, the core's inbound, logging and binding, then
// swapOpts on top.
func (c *Core) swapBoxOptions(swapOpts ...SwapOption) (option.Options, error) {
	opts := option.Options{
		Outbounds: []option.Outbound{{Type: switchType, Tag: switchTag, Options: &switchOptions{}}},
		Route:     &option.RouteOptions{Final: switchTag},
	}
	if err := c.withInbound(&opts); err != nil {
		return option.Options{}, err
	}
	if opts.Log == nil {
		opts.Log = c.logOptions()
	}
	c.applyBind(&opts)
	for _, apply := range swapOpts {
		apply(&opts)
	}
	return opts, nil
}

// Start starts the instance (binds the inbound).
func (s *SwappableInstance) Start() error { return s.box.Start() }

// Close stops the instance and every outbound, including ones still in
// their grace period. It waits for a Swap or retirement in progress.
func (s *SwappableInstance) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for _, t := range s.timers {
		t.Stop()
	}
	s.timers = nil
	return s.box.Close()
}

// Swap routes new connections through hops. The previous outbound keeps
// serving connections it already carries and is removed after grace
// (DefaultSwapGrace when grace <= 0). On error the current outbound stays.
// Concurrent Swaps run one after the other.
func (s *SwappableInstance) Swap(_ context.Context, hops []protocol.Protocol, grace time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("instance is closed")
	}
	old := s.current
	if err := s.installLocked(hops); err != nil {
		return err
	}
	if grace <= 0 {
		grace = DefaultSwapGrace
	}
	s.retireLaterLocked(old, grace)
	return nil
}

// installLocked crafts hops under fresh tags, creates them in the running
// (or not yet started) instance and points the switch at the exit hop.
// The caller holds s.mu.
func (s *SwappableInstance) installLocked(hops []protocol.Protocol) error {
	if len(hops) == 0 {
		return errors.New("no outbound to install")
	}
	s.gen++
	outs, err := s.craftGeneration(hops, s.gen)
	if err != nil {
		return err
	}
	var added []created
	for i, out := range outs {
		c, err := s.create(out)
		if err != nil {
			s.removeLocked(added)
			return fmt.Errorf("hop %d: %w", i, err)
		}
		added = append(added, c)
	}
	exit := added[len(added)-1].tag
	s.sw.target.Store(&exit)
	s.current = added
	return nil
}

// craftGeneration crafts hops under generation gen's tags, each hop dialing
// through the one before it. The entry hop, the only one opening a socket
// itself, carries the socket mark.
func (s *SwappableInstance) craftGeneration(hops []protocol.Protocol, gen int) ([]option.Outbound, error) {
	outs := make([]option.Outbound, 0, len(hops))
	for i, hop := range hops {
		out, err := s.core.craftOutbound(hop, fmt.Sprintf("xk-g%d-%d", gen, i), i == 0)
		if err != nil {
			return nil, fmt.Errorf("hop %d: %w", i, err)
		}
		if i > 0 {
			if err := setDetour(&out, outs[i-1].Tag); err != nil {
				return nil, fmt.Errorf("hop %d: %w", i, err)
			}
		} else if s.mark != 0 {
			dialer, err := dialerOptions(&out)
			if err != nil {
				return nil, fmt.Errorf("hop %d: %w", i, err)
			}
			dialer.RoutingMark = option.FwMark(s.mark)
		}
		outs = append(outs, out)
	}
	return outs, nil
}

// create adds one crafted outbound to the instance: WireGuard is an
// endpoint in sing-box 1.14, everything else an outbound.
func (s *SwappableInstance) create(out option.Outbound) (created, error) {
	logger := s.box.LogFactory().NewLogger("outbound/" + out.Tag)
	if _, isEndpoint := out.Options.(*option.WireGuardEndpointOptions); isEndpoint {
		err := s.box.Endpoint().Create(s.ctx, s.box.Router(), logger, out.Tag, out.Type, out.Options)
		return created{tag: out.Tag, endpoint: true}, err
	}
	err := s.box.Outbound().Create(s.ctx, s.box.Router(), logger, out.Tag, out.Type, out.Options)
	return created{tag: out.Tag}, err
}

// retireLaterLocked removes the given generation after grace. The caller
// holds s.mu, so the timer cannot run before it is recorded.
func (s *SwappableInstance) retireLaterLocked(gen []created, grace time.Duration) {
	if len(gen) == 0 {
		return
	}
	var t *time.Timer
	t = time.AfterFunc(grace, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for i, x := range s.timers {
			if x == t {
				s.timers = append(s.timers[:i], s.timers[i+1:]...)
				break
			}
		}
		s.removeLocked(gen) // no-op once closed: Close tore everything down
	})
	s.timers = append(s.timers, t)
}

// removeLocked deletes (and closes) outbounds exit first, since sing-box
// refuses to remove an outbound another one still uses as its detour. The
// caller holds s.mu; after Close there is nothing left to remove (and
// sing-box would panic).
func (s *SwappableInstance) removeLocked(gen []created) {
	if s.closed {
		return
	}
	for i := len(gen) - 1; i >= 0; i-- {
		if gen[i].endpoint {
			_ = s.box.Endpoint().Remove(gen[i].tag)
		} else {
			_ = s.box.Outbound().Remove(gen[i].tag)
		}
	}
}
