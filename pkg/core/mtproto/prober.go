package mtproto

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/netbind"
)

const (
	// The one data center this probe asks for. Other DCs may differ.
	probeDC             = 2
	defaultProbeTimeout = 10 * time.Second
)

// Probe handshakes and runs req_pq_multi round trips on one connection. A valid
// resPQ proves reachability, not Telegram identity. Timings start at the dial.
func (m *MTProto) Probe(ctx context.Context, opts protocol.ProbeOptions) (protocol.ProbeResult, error) {
	return m.probe(ctx, opts, rand.Reader, time.Now)
}

func (m *MTProto) probe(ctx context.Context, opts protocol.ProbeOptions, rnd io.Reader, now func() time.Time) (protocol.ProbeResult, error) {
	var res protocol.ProbeResult
	samples := opts.Samples
	if samples == 0 {
		samples = 1
	}
	if samples < 1 || samples > protocol.MaxProbeSamples {
		return res, fmt.Errorf("mtproto: probe samples must be between 1 and %d, got %d", protocol.MaxProbeSamples, opts.Samples)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	binder, err := netbind.New(opts.BindInterface)
	if err != nil {
		return res, err
	}
	dialer := &net.Dialer{}
	binder.ApplyDialer(dialer)

	target := net.JoinHostPort(m.Address, m.Port)
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return res, fmt.Errorf("dial %s: %w", target, err)
	}
	defer conn.Close()
	res.ConnectTime = time.Since(start)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	tc := &timedConn{Conn: conn}
	var stream io.ReadWriter = tc
	if m.Secret.Type == SecretFakeTLS {
		ft := newFakeTLS(rnd, now, tc)
		if err := ft.handshake(m.Secret.CloakHost, m.Secret.Key[:]); err != nil {
			return res, stageErr(ctx, "faketls handshake", err)
		}
		stream = ft
	}

	obfs, err := newObfuscated2(rnd, stream, m.Secret.Key, paddedIntermediateTag, probeDC)
	if err != nil {
		return res, err
	}
	if err := obfs.handshake(); err != nil {
		return res, stageErr(ctx, "obfuscated2 handshake", err)
	}

	pc := &probeConn{stream: obfs, rnd: rnd, now: now}
	tc.arm(func() { res.TTFB = time.Since(start) })
	rtt, err := pc.roundTrip()
	if err != nil {
		var staged stagedError
		if errors.As(err, &staged) {
			return res, stageErr(ctx, staged.stage, staged.err)
		}
		return res, err
	}
	res.Delay = time.Since(start)
	res.RTTs = make([]time.Duration, 0, samples)
	res.RTTs = append(res.RTTs, rtt)

	// Extra samples are best effort. The probe already succeeded, so any later
	// failure just ends sampling.
	for len(res.RTTs) < samples && ctx.Err() == nil {
		rtt, err := pc.roundTrip()
		if err != nil {
			break
		}
		res.RTTs = append(res.RTTs, rtt)
	}

	res.Detail = fmt.Sprintf("%s, dc%d resPQ ok", m.Secret.Type, probeDC)
	if samples > 1 {
		res.Detail += fmt.Sprintf(", %d/%d samples", len(res.RTTs), samples)
	}
	return res, nil
}

// probeConn runs req_pq_multi exchanges over one established stream.
type probeConn struct {
	stream io.ReadWriter
	rnd    io.Reader
	now    func() time.Time
	ids    msgIDSeq
}

// roundTrip sends one request and validates the whole reply. Nonce and
// padding generation stay outside the measurement.
func (p *probeConn) roundTrip() (time.Duration, error) {
	var nonce [16]byte
	if _, err := io.ReadFull(p.rnd, nonce[:]); err != nil {
		return 0, err
	}
	msg := buildReqPQMultiWithID(nonce, p.ids.next(p.now()))
	frame, err := buildPaddedFrame(p.rnd, msg)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	if err := writeFrame(p.stream, frame); err != nil {
		return 0, stagedError{stage: "write req_pq_multi", err: err}
	}
	reply, err := readPaddedFrame(p.stream)
	if err != nil {
		return 0, stagedError{stage: "read resPQ", err: err}
	}
	rtt := time.Since(start)

	got, err := parseResPQ(reply)
	if err != nil {
		return 0, err
	}
	if got != nonce {
		return 0, errors.New("resPQ nonce mismatch")
	}
	return rtt, nil
}

// stagedError names the failed I/O step so the first exchange can render it
// through stageErr. Later samples discard it.
type stagedError struct {
	stage string
	err   error
}

func (e stagedError) Error() string { return e.stage + ": " + e.err.Error() }
func (e stagedError) Unwrap() error { return e.err }

// stageErr turns I/O failures into the reasons users see. Errors that already
// say something (digest mismatch, bad frame) pass through.
func stageErr(ctx context.Context, stage string, err error) error {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return fmt.Errorf("%s: %w", stage, context.Canceled)
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return fmt.Errorf("%s: timeout: %w", stage, context.DeadlineExceeded)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET):
		return fmt.Errorf("%s: EOF (proxy closed connection; wrong secret?)", stage)
	}
	return fmt.Errorf("%s: %w", stage, err)
}

// timedConn calls onFirst once, on the first byte read after arm.
type timedConn struct {
	net.Conn
	onFirst func()
}

func (c *timedConn) arm(f func()) { c.onFirst = f }

func (c *timedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.onFirst != nil {
		c.onFirst()
		c.onFirst = nil
	}
	return n, err
}
