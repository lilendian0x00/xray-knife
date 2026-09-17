package mtproto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	utls "github.com/refraction-networking/utls"
)

type recordType byte

const (
	recordChangeCipherSpec recordType = 0x14
	recordAlert            recordType = 0x15
	recordHandshake        recordType = 0x16
	recordApplication      recordType = 0x17
)

var (
	tlsVersion10 = [2]byte{0x03, 0x01}
	tlsVersion12 = [2]byte{0x03, 0x03}
)

const (
	tlsRecordHeaderLen = 5
	// helloRandomOffset locates the 32-byte random inside a ClientHello or
	// ServerHello record: 5 record header + 1 handshake type + 3 length + 2 version.
	helloRandomOffset   = 11
	helloRandomLen      = 32
	maxHandshakeRecords = 16
	// serverHelloMinBody is the shortest ServerHello body this probe accepts:
	// 4 handshake header + 2 version + 32 random + 1 session id length +
	// 2 cipher suite + 1 compression method.
	serverHelloMinBody = 42
)

type tlsRecord struct {
	Type    recordType
	Version [2]byte
	Data    []byte
}

func readRecord(r io.Reader) (tlsRecord, error) {
	var hdr [tlsRecordHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return tlsRecord{}, err
	}
	rec := tlsRecord{Type: recordType(hdr[0])}
	copy(rec.Version[:], hdr[1:3])
	if rec.Version[0] != 0x03 || rec.Version[1] > 0x04 {
		return tlsRecord{}, fmt.Errorf("faketls: unknown record version % x", hdr[1:3])
	}
	rec.Data = make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
	if _, err := io.ReadFull(r, rec.Data); err != nil {
		return tlsRecord{}, err
	}
	return rec, nil
}

func writeRecord(w io.Writer, rec tlsRecord) error {
	if len(rec.Data) > 0xffff {
		return errors.New("faketls: record too large")
	}
	buf := make([]byte, tlsRecordHeaderLen+len(rec.Data))
	buf[0] = byte(rec.Type)
	copy(buf[1:3], rec.Version[:])
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(rec.Data)))
	copy(buf[tlsRecordHeaderLen:], rec.Data)
	n, err := w.Write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	return err
}

// buildClientHello returns a Chrome-fingerprint ClientHello for host whose
// random is HMAC-SHA256(key, record-with-zero-random), last 4 bytes XORed with
// the Unix time. The random comes back for checking the server's reply.
func buildClientHello(rnd io.Reader, now time.Time, host string, key []byte) ([]byte, [helloRandomLen]byte, error) {
	var random [helloRandomLen]byte
	// A nil net.Conn is fine: BuildHandshakeState only assembles bytes.
	conn := utls.UClient(nil, &utls.Config{ServerName: host, Rand: rnd}, utls.HelloChrome_Auto)
	if err := conn.BuildHandshakeState(); err != nil {
		return nil, random, fmt.Errorf("faketls: build ClientHello: %w", err)
	}
	hello := conn.HandshakeState.Hello.Raw

	record := make([]byte, 0, tlsRecordHeaderLen+len(hello))
	record = append(record, byte(recordHandshake), tlsVersion10[0], tlsVersion10[1])
	record = binary.BigEndian.AppendUint16(record, uint16(len(hello)))
	record = append(record, hello...)
	if len(record) < helloRandomOffset+helloRandomLen {
		return nil, random, errors.New("faketls: ClientHello too short")
	}

	field := record[helloRandomOffset : helloRandomOffset+helloRandomLen]
	for i := range field {
		field[i] = 0
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(record)
	copy(field, mac.Sum(nil))
	ts := binary.LittleEndian.Uint32(field[helloRandomLen-4:]) ^ uint32(now.Unix())
	binary.LittleEndian.PutUint32(field[helloRandomLen-4:], ts)
	copy(random[:], field)
	return record, random, nil
}

// verifyServerHello reads the reply flight (ServerHello, optional handshake
// records, ChangeCipherSpec, one application record) and checks the server
// random against HMAC-SHA256(key, clientRandom || flight with that random zeroed).
func verifyServerHello(r io.Reader, clientRandom [helloRandomLen]byte, key []byte) error {
	var flight bytes.Buffer
	tee := io.TeeReader(r, &flight)

	rec, err := readRecord(tee)
	if err != nil {
		return fmt.Errorf("faketls: read ServerHello: %w", err)
	}
	if rec.Type != recordHandshake {
		return fmt.Errorf("faketls: unexpected record type 0x%02x, want handshake", byte(rec.Type))
	}
	if len(rec.Data) < serverHelloMinBody {
		return errors.New("faketls: ServerHello too short")
	}
	handshakeLen := int(rec.Data[1])<<16 | int(rec.Data[2])<<8 | int(rec.Data[3])
	if rec.Data[0] != 2 || handshakeLen != len(rec.Data)-4 {
		return errors.New("faketls: invalid ServerHello type or length")
	}

	sawChangeCipherSpec := false
	for i := 0; i < maxHandshakeRecords && !sawChangeCipherSpec; i++ {
		rec, err = readRecord(tee)
		if err != nil {
			return fmt.Errorf("faketls: read handshake flight: %w", err)
		}
		switch rec.Type {
		case recordHandshake:
		case recordChangeCipherSpec:
			if !bytes.Equal(rec.Data, []byte{1}) {
				return errors.New("faketls: invalid ChangeCipherSpec")
			}
			sawChangeCipherSpec = true
		default:
			return fmt.Errorf("faketls: unexpected record type 0x%02x in handshake flight", byte(rec.Type))
		}
	}
	if !sawChangeCipherSpec {
		return errors.New("faketls: no ChangeCipherSpec in handshake flight")
	}
	rec, err = readRecord(tee)
	if err != nil {
		return fmt.Errorf("faketls: read application record: %w", err)
	}
	if rec.Type != recordApplication {
		return fmt.Errorf("faketls: unexpected record type 0x%02x, want application data", byte(rec.Type))
	}

	packet := flight.Bytes()
	var got [helloRandomLen]byte
	copy(got[:], packet[helloRandomOffset:helloRandomOffset+helloRandomLen])
	for i := helloRandomOffset; i < helloRandomOffset+helloRandomLen; i++ {
		packet[i] = 0
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(clientRandom[:])
	mac.Write(packet)
	if !hmac.Equal(mac.Sum(nil), got[:]) {
		return errors.New("faketls: server digest mismatch (wrong secret or cloak domain answered)")
	}
	return nil
}

// fakeTLS carries bytes inside TLS application records after the fake
// handshake, as the conn of an obfuscated2 stream.
type fakeTLS struct {
	rnd     io.Reader
	now     func() time.Time
	conn    io.ReadWriter
	sentCCS bool
	readBuf bytes.Buffer
}

func newFakeTLS(rnd io.Reader, now func() time.Time, conn io.ReadWriter) *fakeTLS {
	return &fakeTLS{rnd: rnd, now: now, conn: conn}
}

// handshake sends the ClientHello and verifies the proxy's reply.
func (f *fakeTLS) handshake(host string, key []byte) error {
	record, clientRandom, err := buildClientHello(f.rnd, f.now(), host, key)
	if err != nil {
		return err
	}
	n, err := f.conn.Write(record)
	if err == nil && n != len(record) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("faketls: write ClientHello: %w", err)
	}
	return verifyServerHello(f.conn, clientRandom, key)
}

// Write sends p as one application record. The first call also sends the
// ChangeCipherSpec record real clients send and some proxies expect.
func (f *fakeTLS) Write(p []byte) (int, error) {
	if !f.sentCCS {
		if err := writeRecord(f.conn, tlsRecord{Type: recordChangeCipherSpec, Version: tlsVersion12, Data: []byte{0x01}}); err != nil {
			return 0, err
		}
		f.sentCCS = true
	}
	if err := writeRecord(f.conn, tlsRecord{Type: recordApplication, Version: tlsVersion12, Data: p}); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read returns application-record payload and skips ChangeCipherSpec records.
// Errors from the underlying conn stay unwrapped so EOF is recognisable.
func (f *fakeTLS) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for f.readBuf.Len() == 0 {
		rec, err := readRecord(f.conn)
		if err != nil {
			return 0, err
		}
		switch rec.Type {
		case recordApplication:
			f.readBuf.Write(rec.Data)
		case recordChangeCipherSpec:
		default:
			return 0, fmt.Errorf("faketls: unexpected record type 0x%02x", byte(rec.Type))
		}
	}
	return f.readBuf.Read(p)
}
