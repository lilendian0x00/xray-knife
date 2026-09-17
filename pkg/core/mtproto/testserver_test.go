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
)

// fakeProxy speaks the server side of obfuscated2 and fake TLS, parses one
// req_pq_multi and answers according to its mode. Starting it with a different
// Secret than the client uses simulates a wrong secret.
type fakeProxy struct {
	t      *testing.T
	ln     net.Listener
	secret Secret
	mode   serverMode
	wg     sync.WaitGroup
	// Signalled at the stall point (modeHang: request read; modeStallHandshake:
	// ClientHello read) so cancellation tests do not race the handshake.
	reached chan struct{}
	once    sync.Once
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
		p.wg.Wait()
	})
	return p
}

func (p *fakeProxy) port() string {
	_, port, _ := net.SplitHostPort(p.ln.Addr().String())
	return port
}

func (p *fakeProxy) signalReached() { p.once.Do(func() { close(p.reached) }) }

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
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
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

	frame, err := readPaddedFrame(obfs)
	if err != nil {
		return
	}
	if len(frame) < reqPQMultiLen || len(frame)-reqPQMultiLen > 15 ||
		binary.LittleEndian.Uint64(frame[:8]) != 0 ||
		binary.LittleEndian.Uint64(frame[8:16])&3 != 0 ||
		uint32(binary.LittleEndian.Uint64(frame[8:16])) == 0 ||
		binary.LittleEndian.Uint32(frame[16:20]) != 20 ||
		binary.LittleEndian.Uint32(frame[20:24]) != reqPQMultiConstructor {
		p.t.Errorf("fake proxy: expected req_pq_multi, got % x", frame)
		return
	}
	var nonce [16]byte
	copy(nonce[:], frame[24:40])

	switch p.mode {
	case modeHang:
		p.signalReached()
		_, _ = io.Copy(io.Discard, conn) // block until the client gives up
	case modeTransportError:
		_ = writePaddedFrame(rand.Reader, obfs, []byte{0x6c, 0xfe, 0xff, 0xff}) // int32 -404
	case modeGarbage:
		reply := buildResPQ(nonce)
		binary.LittleEndian.PutUint32(reply[20:24], 0xdeadbeef)
		_ = writePaddedFrame(rand.Reader, obfs, reply)
	case modeWrongNonce:
		var other [16]byte
		copy(other[:], nonce[:])
		other[0] ^= 0xff
		_ = writePaddedFrame(rand.Reader, obfs, buildResPQ(other))
	default:
		_ = writePaddedFrame(rand.Reader, obfs, buildResPQ(nonce))
	}
}
