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
	// The one data center this probe asks for; other DCs may differ.
	probeDC             = 2
	defaultProbeTimeout = 10 * time.Second
)

// Probe dials the proxy, runs the obfuscation handshake and one unencrypted
// req_pq_multi round trip. Success means a well-formed reply for DC 2, not a
// proven Telegram identity: a proxy can synthesize resPQ. Timings start at the dial.
func (m *MTProto) Probe(ctx context.Context, opts protocol.ProbeOptions) (protocol.ProbeResult, error) {
	return m.probe(ctx, opts, rand.Reader, time.Now)
}

func (m *MTProto) probe(ctx context.Context, opts protocol.ProbeOptions, rnd io.Reader, now func() time.Time) (protocol.ProbeResult, error) {
	var res protocol.ProbeResult
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

	var nonce [16]byte
	if _, err := io.ReadFull(rnd, nonce[:]); err != nil {
		return res, err
	}
	tc.arm(func() { res.TTFB = time.Since(start) })
	if err := writePaddedFrame(rnd, obfs, buildReqPQMulti(nonce, now())); err != nil {
		return res, stageErr(ctx, "write req_pq_multi", err)
	}
	frame, err := readPaddedFrame(obfs)
	if err != nil {
		return res, stageErr(ctx, "read resPQ", err)
	}
	got, err := parseResPQ(frame)
	if err != nil {
		return res, err
	}
	if got != nonce {
		return res, errors.New("resPQ nonce mismatch")
	}
	res.Delay = time.Since(start)
	res.Detail = fmt.Sprintf("%s, dc%d resPQ ok", m.Secret.Type, probeDC)
	return res, nil
}

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
