package mtproto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type serverMode int

const (
	modeOK             serverMode = iota // answer resPQ with the client's nonce
	modeHang                             // accept everything, never answer
	modeGarbage                          // answer with a wrong constructor
	modeTransportError                   // answer with a 4-byte -404 frame
	modeWrongNonce                       // answer a well-formed resPQ for another nonce
	modeStallHandshake                   // fake TLS only: read ClientHello, never reply
	// These answer request 1 normally, so only later samples differ.
	modeDropAfterFirst       // close without draining
	modeHangAfterFirst       // read request 2, never answer it
	modeWrongNonceAfterFirst // answer request 2 for another nonce
	modeSlowSecond           // answer request 2+ after slowSecondDelay
)

const (
	// Far longer than any client budget below, so a server timeout is never
	// mistaken for the client giving up.
	serverSafetyDeadline = 30 * time.Second
	// Long enough that a later RTT cannot be loopback jitter.
	slowSecondDelay = 300 * time.Millisecond
)

// recordedRequest is one parsed req_pq_multi and the connection it arrived on.
type recordedRequest struct {
	conn  int
	msgID uint64
	nonce [16]byte
}

// fakeProxy speaks the server side of obfuscated2 and fake TLS, answering
// req_pq_multi per mode. A different Secret simulates a wrong secret.
type fakeProxy struct {
	t      *testing.T
	ln     net.Listener
	secret Secret
	mode   serverMode
	wg     sync.WaitGroup
	// Signalled at the stall point so cancellation tests do not race the handshake.
	reached chan struct{}
	once    sync.Once

	mu       sync.Mutex
	conns    int
	active   []net.Conn
	requests []recordedRequest
}

func startFakeProxy(t *testing.T, secret Secret, mode serverMode) *fakeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProxy{t: t, ln: ln, secret: secret, mode: mode, reached: make(chan struct{})}
	p.wg.Add(1)
	go p.acceptLoop()
	t.Cleanup(func() {
		_ = ln.Close()
		p.closeActive()
		p.wg.Wait()
	})
	return p
}

func (p *fakeProxy) port() string {
	_, port, _ := net.SplitHostPort(p.ln.Addr().String())
	return port
}

func (p *fakeProxy) signalReached() { p.once.Do(func() { close(p.reached) }) }

func (p *fakeProxy) track(conn net.Conn) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns++
	p.active = append(p.active, conn)
	return p.conns
}

func (p *fakeProxy) closeActive() {
	p.mu.Lock()
	conns := append([]net.Conn(nil), p.active...)
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (p *fakeProxy) record(connIdx int, msgID uint64, nonce [16]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = append(p.requests, recordedRequest{conn: connIdx, msgID: msgID, nonce: nonce})
}

// connections is safe to read once the probe under test has returned.
func (p *fakeProxy) connections() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conns
}

// observed returns every parsed request, in arrival order.
func (p *fakeProxy) observed() []recordedRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]recordedRequest(nil), p.requests...)
}

func (p *fakeProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer conn.Close()
			p.serve(conn)
		}()
	}
}

// drainAndClose reads what the client already sent so the close is a clean EOF
// rather than a TCP reset, like a real proxy dropping the connection.
func drainAndClose(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = io.Copy(io.Discard, conn)
}

func (p *fakeProxy) serve(conn net.Conn) {
	connIdx := p.track(conn)
	_ = conn.SetDeadline(time.Now().Add(serverSafetyDeadline))
	var stream io.ReadWriter = conn

	if p.secret.Type == SecretFakeTLS {
		rec, err := readRecord(conn)
		if err != nil || rec.Type != recordHandshake {
			return
		}
		if p.mode == modeStallHandshake {
			p.signalReached()
			_, _ = io.Copy(io.Discard, conn) // never answer the ClientHello
			return
		}
		full := make([]byte, 0, tlsRecordHeaderLen+len(rec.Data))
		full = append(full, byte(rec.Type), rec.Version[0], rec.Version[1])
		full = binary.BigEndian.AppendUint16(full, uint16(len(rec.Data)))
		full = append(full, rec.Data...)
		var clientRandom [helloRandomLen]byte
		copy(clientRandom[:], full[helloRandomOffset:helloRandomOffset+helloRandomLen])

		// Validate the client digest as a proxy would, ignoring timestamp skew.
		zeroed := append([]byte(nil), full...)
		for i := helloRandomOffset; i < helloRandomOffset+helloRandomLen; i++ {
			zeroed[i] = 0
		}
		mac := hmac.New(sha256.New, p.secret.Key[:])
		mac.Write(zeroed)
		if !bytes.Equal(mac.Sum(nil)[:28], clientRandom[:28]) {
			// A real proxy forwards to the cloak host and the client gets a genuine
			// ServerHello that fails the HMAC check. Our own key fails the same way.
			_, _ = conn.Write(buildServerHelloFlight(rand.Reader, clientRandom, p.secret.Key[:]))
			drainAndClose(conn)
			return
		}
		if _, err := conn.Write(buildServerHelloFlight(rand.Reader, clientRandom, p.secret.Key[:])); err != nil {
			return
		}
		stream = &fakeTLS{conn: conn, sentCCS: true}
	}

	var init [obfsInitLen]byte
	if _, err := io.ReadFull(stream, init[:]); err != nil {
		return
	}
	encrypt, decrypt, err := serverStreams(init, p.secret.Key)
	if err != nil {
		return
	}
	var plain [obfsInitLen]byte
	decrypt.XORKeyStream(plain[:], init[:])
	if [4]byte(plain[56:60]) != paddedIntermediateTag {
		// Wrong secret: the tag is noise. Real proxies drop the connection.
		drainAndClose(conn)
		return
	}
	obfs := &obfuscated2{conn: stream, encrypt: encrypt, decrypt: decrypt}

	// A probe may sample several times on this one stream.
	for reqNum := 1; ; reqNum++ {
		frame, err := readPaddedFrame(obfs)
		if err != nil {
			return
		}
		msgID, nonce, ok := p.parseRequest(frame)
		if !ok {
			return
		}
		p.record(connIdx, msgID, nonce)
		if !p.respond(conn, obfs, reqNum, nonce) {
			return
		}
	}
}

// parseRequest validates a req_pq_multi frame and returns its message ID and nonce.
func (p *fakeProxy) parseRequest(frame []byte) (uint64, [16]byte, bool) {
	var nonce [16]byte
	if len(frame) < reqPQMultiLen || len(frame)-reqPQMultiLen > 15 ||
		binary.LittleEndian.Uint64(frame[:8]) != 0 ||
		binary.LittleEndian.Uint64(frame[8:16])&3 != 0 ||
		uint32(binary.LittleEndian.Uint64(frame[8:16])) == 0 ||
		binary.LittleEndian.Uint32(frame[16:20]) != 20 ||
		binary.LittleEndian.Uint32(frame[20:24]) != reqPQMultiConstructor {
		p.t.Errorf("fake proxy: expected req_pq_multi, got % x", frame)
		return 0, nonce, false
	}
	copy(nonce[:], frame[24:40])
	return binary.LittleEndian.Uint64(frame[8:16]), nonce, true
}

// respond answers request reqNum and reports whether to keep serving.
func (p *fakeProxy) respond(conn net.Conn, obfs *obfuscated2, reqNum int, nonce [16]byte) bool {
	switch p.mode {
	case modeHang:
		p.signalReached()
		_, _ = io.Copy(io.Discard, conn) // block until the client gives up
		return false
	case modeTransportError:
		_ = writePaddedFrame(rand.Reader, obfs, []byte{0x6c, 0xfe, 0xff, 0xff}) // int32 -404
		return false
	case modeGarbage:
		reply := buildResPQ(nonce)
		binary.LittleEndian.PutUint32(reply[20:24], 0xdeadbeef)
		_ = writePaddedFrame(rand.Reader, obfs, reply)
		return false
	case modeWrongNonce:
		_ = writePaddedFrame(rand.Reader, obfs, buildResPQ(flipNonce(nonce)))
		return false
	case modeDropAfterFirst:
		// No drain. It would hold the connection open long enough to turn this
		// into a timeout test.
		_ = writePaddedFrame(rand.Reader, obfs, buildResPQ(nonce))
		return false
	case modeHangAfterFirst:
		if reqNum == 1 {
			_ = writePaddedFrame(rand.Reader, obfs, buildResPQ(nonce))
			return true
		}
		// Getting here proves the client validated response 1 and asked again.
		p.signalReached()
		_, _ = io.Copy(io.Discard, conn)
		return false
	case modeWrongNonceAfterFirst:
		if reqNum == 1 {
			_ = writePaddedFrame(rand.Reader, obfs, buildResPQ(nonce))
			return true
		}
		_ = writePaddedFrame(rand.Reader, obfs, buildResPQ(flipNonce(nonce)))
		return false
	case modeSlowSecond:
		if reqNum > 1 {
			time.Sleep(slowSecondDelay)
		}
		_ = writePaddedFrame(rand.Reader, obfs, buildResPQ(nonce))
		return true
	default:
		_ = writePaddedFrame(rand.Reader, obfs, buildResPQ(nonce))
		return true
	}
}

func flipNonce(nonce [16]byte) [16]byte {
	other := nonce
	other[0] ^= 0xff
	return other
}
