package mtproto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"
)

// buildServerHelloFlight is what a proxy answers to a valid ClientHello:
// ServerHello, ChangeCipherSpec, one application record, server random set to
// HMAC-SHA256(key, clientRandom || flight-with-zero-random).
func buildServerHelloFlight(rnd io.Reader, clientRandom [helloRandomLen]byte, key []byte) []byte {
	hello := []byte{0x02, 0x00, 0x00, 38, 0x03, 0x03} // ServerHello, body length 38, TLS 1.2
	hello = append(hello, make([]byte, helloRandomLen)...)
	hello = append(hello, 0x00, 0x13, 0x01, 0x00) // no session id, TLS_AES_128_GCM_SHA256, no compression
	cert := make([]byte, 64)
	_, _ = io.ReadFull(rnd, cert)

	var flight bytes.Buffer
	_ = writeRecord(&flight, tlsRecord{Type: recordHandshake, Version: tlsVersion12, Data: hello})
	_ = writeRecord(&flight, tlsRecord{Type: recordChangeCipherSpec, Version: tlsVersion12, Data: []byte{0x01}})
	_ = writeRecord(&flight, tlsRecord{Type: recordApplication, Version: tlsVersion12, Data: cert})

	packet := flight.Bytes()
	mac := hmac.New(sha256.New, key)
	mac.Write(clientRandom[:])
	mac.Write(packet)
	copy(packet[helloRandomOffset:helloRandomOffset+helloRandomLen], mac.Sum(nil))
	return packet
}

func TestBuildClientHelloDigest(t *testing.T) {
	key := mustHex(t, testKeyHex)
	now := time.Unix(1_800_000_000, 0)
	record, clientRandom, err := buildClientHello(rand.Reader, now, "www.google.com", key)
	if err != nil {
		t.Fatal(err)
	}
	if record[0] != byte(recordHandshake) || record[1] != 0x03 || record[2] != 0x01 {
		t.Errorf("record header = % x, want 16 03 01", record[:3])
	}
	if int(binary.BigEndian.Uint16(record[3:5])) != len(record)-5 {
		t.Errorf("record length field %d != %d", binary.BigEndian.Uint16(record[3:5]), len(record)-5)
	}
	if !bytes.Contains(record, []byte("www.google.com")) {
		t.Errorf("SNI missing from ClientHello:\n% x", record)
	}
	if !bytes.Equal(record[helloRandomOffset:helloRandomOffset+helloRandomLen], clientRandom[:]) {
		t.Error("returned clientRandom does not match the record")
	}

	zeroed := append([]byte(nil), record...)
	for i := helloRandomOffset; i < helloRandomOffset+helloRandomLen; i++ {
		zeroed[i] = 0
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(zeroed)
	digest := mac.Sum(nil)
	if !bytes.Equal(clientRandom[:28], digest[:28]) {
		t.Error("first 28 bytes of the random must be the HMAC digest")
	}
	got := binary.LittleEndian.Uint32(clientRandom[28:]) ^ uint32(now.Unix())
	if got != binary.LittleEndian.Uint32(digest[28:]) {
		t.Error("last 4 bytes must be digest XOR unix time")
	}
}

func TestVerifyServerHello(t *testing.T) {
	key := mustHex(t, testKeyHex)
	var clientRandom [helloRandomLen]byte
	_, _ = rand.Read(clientRandom[:])

	good := buildServerHelloFlight(rand.Reader, clientRandom, key)
	if err := verifyServerHello(bytes.NewReader(good), clientRandom, key); err != nil {
		t.Fatalf("valid flight rejected: %v", err)
	}

	bad := append([]byte(nil), good...)
	bad[helloRandomOffset+3] ^= 0xff
	err := verifyServerHello(bytes.NewReader(bad), clientRandom, key)
	if err == nil || !strings.Contains(err.Error(), "server digest mismatch") {
		t.Errorf("tampered digest: err = %v", err)
	}

	otherKey := bytes.Repeat([]byte{7}, 16)
	err = verifyServerHello(bytes.NewReader(good), clientRandom, otherKey)
	if err == nil || !strings.Contains(err.Error(), "server digest mismatch") {
		t.Errorf("wrong key: err = %v", err)
	}

	var appFirst bytes.Buffer
	_ = writeRecord(&appFirst, tlsRecord{Type: recordApplication, Version: tlsVersion12, Data: []byte{1, 2, 3}})
	err = verifyServerHello(&appFirst, clientRandom, key)
	if err == nil || !strings.Contains(err.Error(), "unexpected record type") {
		t.Errorf("application record first: err = %v", err)
	}

	if err := verifyServerHello(bytes.NewReader(good[:20]), clientRandom, key); err == nil {
		t.Error("truncated flight accepted")
	}

	// A flight arriving one byte at a time must still verify.
	if err := verifyServerHello(iotest1(good), clientRandom, key); err != nil {
		t.Errorf("fragmented flight rejected: %v", err)
	}
}

// iotest1 yields at most one byte per Read.
func iotest1(b []byte) io.Reader { return &oneByteReader{src: bytes.NewReader(b)} }

type oneByteReader struct{ src *bytes.Reader }

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return r.src.Read(p[:1])
}

func TestVerifyServerHelloMalformed(t *testing.T) {
	key := mustHex(t, testKeyHex)
	var clientRandom [helloRandomLen]byte
	_, _ = rand.Read(clientRandom[:])

	shortHello := func() []byte {
		var buf bytes.Buffer
		_ = writeRecord(&buf, tlsRecord{Type: recordHandshake, Version: tlsVersion12, Data: make([]byte, 20)})
		return buf.Bytes()
	}()
	if err := verifyServerHello(bytes.NewReader(shortHello), clientRandom, key); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Errorf("short ServerHello: err = %v", err)
	}

	wrongType := append([]byte(nil), buildServerHelloFlight(rand.Reader, clientRandom, key)...)
	wrongType[5] = 0x01 // ClientHello handshake type
	if err := verifyServerHello(bytes.NewReader(wrongType), clientRandom, key); err == nil || !strings.Contains(err.Error(), "invalid ServerHello type or length") {
		t.Errorf("wrong handshake type: err = %v", err)
	}

	wrongLen := append([]byte(nil), buildServerHelloFlight(rand.Reader, clientRandom, key)...)
	wrongLen[8] = 0x05 // handshake length no longer matches the record body
	if err := verifyServerHello(bytes.NewReader(wrongLen), clientRandom, key); err == nil || !strings.Contains(err.Error(), "invalid ServerHello type or length") {
		t.Errorf("inconsistent handshake length: err = %v", err)
	}

	badVersion := append([]byte(nil), buildServerHelloFlight(rand.Reader, clientRandom, key)...)
	badVersion[1] = 0x02
	if err := verifyServerHello(bytes.NewReader(badVersion), clientRandom, key); err == nil || !strings.Contains(err.Error(), "unknown record version") {
		t.Errorf("bad record version: err = %v", err)
	}

	badCCS := func() []byte {
		hello := []byte{0x02, 0x00, 0x00, 38, 0x03, 0x03}
		hello = append(hello, make([]byte, helloRandomLen)...)
		hello = append(hello, 0x00, 0x13, 0x01, 0x00)
		var buf bytes.Buffer
		_ = writeRecord(&buf, tlsRecord{Type: recordHandshake, Version: tlsVersion12, Data: hello})
		_ = writeRecord(&buf, tlsRecord{Type: recordChangeCipherSpec, Version: tlsVersion12, Data: []byte{0x02}})
		return buf.Bytes()
	}()
	if err := verifyServerHello(bytes.NewReader(badCCS), clientRandom, key); err == nil || !strings.Contains(err.Error(), "invalid ChangeCipherSpec") {
		t.Errorf("bad ChangeCipherSpec payload: err = %v", err)
	}

	// Extra handshake records before ChangeCipherSpec are accepted...
	extra := func(n int) []byte {
		hello := []byte{0x02, 0x00, 0x00, 38, 0x03, 0x03}
		hello = append(hello, make([]byte, helloRandomLen)...)
		hello = append(hello, 0x00, 0x13, 0x01, 0x00)
		var buf bytes.Buffer
		_ = writeRecord(&buf, tlsRecord{Type: recordHandshake, Version: tlsVersion12, Data: hello})
		for i := 0; i < n; i++ {
			_ = writeRecord(&buf, tlsRecord{Type: recordHandshake, Version: tlsVersion12, Data: []byte{0x0b, 0, 0, 0}})
		}
		_ = writeRecord(&buf, tlsRecord{Type: recordChangeCipherSpec, Version: tlsVersion12, Data: []byte{0x01}})
		_ = writeRecord(&buf, tlsRecord{Type: recordApplication, Version: tlsVersion12, Data: make([]byte, 16)})
		packet := buf.Bytes()
		mac := hmac.New(sha256.New, key)
		mac.Write(clientRandom[:])
		mac.Write(packet)
		copy(packet[helloRandomOffset:helloRandomOffset+helloRandomLen], mac.Sum(nil))
		return packet
	}
	if err := verifyServerHello(bytes.NewReader(extra(3)), clientRandom, key); err != nil {
		t.Errorf("extra handshake records rejected: %v", err)
	}
	// ...but not past the sanity limit.
	if err := verifyServerHello(bytes.NewReader(extra(maxHandshakeRecords+1)), clientRandom, key); err == nil ||
		!strings.Contains(err.Error(), "no ChangeCipherSpec") {
		t.Errorf("handshake record limit: err = %v", err)
	}
}

func TestFakeTLSRecordsRoundTrip(t *testing.T) {
	var c2s, s2c bytes.Buffer
	client := newFakeTLS(rand.Reader, time.Now, rwPair{r: &s2c, w: &c2s})

	if n, err := client.Read(nil); n != 0 || err != nil {
		t.Errorf("zero-length Read = %d, %v; want 0, nil", n, err)
	}

	if _, err := client.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	first, err := readRecord(&c2s)
	if err != nil || first.Type != recordChangeCipherSpec {
		t.Fatalf("first record = %+v, %v; want ChangeCipherSpec", first, err)
	}
	second, err := readRecord(&c2s)
	if err != nil || second.Type != recordApplication || string(second.Data) != "abc" {
		t.Fatalf("second record = %+v, %v; want application 'abc'", second, err)
	}
	if _, err := client.Write([]byte("def")); err != nil {
		t.Fatal(err)
	}
	third, err := readRecord(&c2s)
	if err != nil || third.Type != recordApplication {
		t.Fatalf("ChangeCipherSpec must be sent only once; got %+v", third)
	}

	_ = writeRecord(&s2c, tlsRecord{Type: recordChangeCipherSpec, Version: tlsVersion12, Data: []byte{1}})
	_ = writeRecord(&s2c, tlsRecord{Type: recordApplication, Version: tlsVersion12, Data: []byte("xyz")})
	got := make([]byte, 3)
	if _, err := io.ReadFull(client, got); err != nil || string(got) != "xyz" {
		t.Fatalf("client read %q, %v", got, err)
	}

	_ = writeRecord(&s2c, tlsRecord{Type: recordAlert, Version: tlsVersion12, Data: []byte{2, 40}})
	if _, err := client.Read(got); err == nil || !strings.Contains(err.Error(), "unexpected record type") {
		t.Errorf("alert record: err = %v", err)
	}
}

func TestReadRecordTruncated(t *testing.T) {
	var full bytes.Buffer
	_ = writeRecord(&full, tlsRecord{Type: recordApplication, Version: tlsVersion12, Data: []byte("payload")})
	raw := full.Bytes()

	if _, err := readRecord(bytes.NewReader(raw[:3])); err == nil {
		t.Error("truncated record header accepted")
	}
	if _, err := readRecord(bytes.NewReader(raw[:len(raw)-2])); err == nil {
		t.Error("truncated record body accepted")
	}
	// Fragmented delivery of a complete record still succeeds.
	rec, err := readRecord(iotest1(raw))
	if err != nil || string(rec.Data) != "payload" {
		t.Errorf("fragmented record = %+v, %v", rec, err)
	}
}

func TestFakeTLSWriteShortWrite(t *testing.T) {
	w := &shortWriter{limit: 3}
	client := newFakeTLS(rand.Reader, time.Now, w)
	if _, err := client.Write([]byte("abc")); err == nil {
		t.Fatal("a short ChangeCipherSpec write must fail")
	}
}
