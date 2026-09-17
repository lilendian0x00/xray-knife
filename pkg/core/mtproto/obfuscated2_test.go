package mtproto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// rwPair wires a client to an in-process server: reads from r, writes to w.
type rwPair struct{ r, w *bytes.Buffer }

func (p rwPair) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p rwPair) Write(b []byte) (int, error) { return p.w.Write(b) }

// serverStreams is clientStreams with the two streams swapped.
func serverStreams(init [obfsInitLen]byte, key [16]byte) (encrypt, decrypt cipher.Stream, err error) {
	clientEnc, clientDec, err := clientStreams(init, key)
	return clientDec, clientEnc, err
}

func testKey(t *testing.T) [16]byte {
	t.Helper()
	var k [16]byte
	copy(k[:], mustHex(t, testKeyHex))
	return k
}

func TestGenerateInitSkipsForbiddenPrefixes(t *testing.T) {
	block := func(prefix ...byte) []byte {
		b := bytes.Repeat([]byte{0x01}, obfsInitLen)
		copy(b, prefix)
		return b
	}
	var feed []byte
	feed = append(feed, block(0xef)...)                               // abridged marker
	feed = append(feed, block('H', 'E', 'A', 'D')...)                 // HTTP verb
	feed = append(feed, block('P', 'O', 'S', 'T')...)                 // HTTP verb
	feed = append(feed, block('G', 'E', 'T', ' ')...)                 // HTTP verb
	feed = append(feed, block('O', 'P', 'T', 'I')...)                 // HTTP verb
	feed = append(feed, block(0x16, 0x03, 0x01, 0x02)...)             // TLS-looking prefix
	feed = append(feed, block(0xdd, 0xdd, 0xdd, 0xdd)...)             // padded intermediate tag
	feed = append(feed, block(0xee, 0xee, 0xee, 0xee)...)             // intermediate tag
	feed = append(feed, block(0x02, 0x02, 0x02, 0x02, 0, 0, 0, 0)...) // zero second word
	good := block(0x02, 0x02, 0x02, 0x02, 0x03)
	feed = append(feed, good...)

	init, err := generateInit(bytes.NewReader(feed))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(init[:], good) {
		t.Fatalf("generateInit returned a forbidden block:\n% x", init[:8])
	}
}

// Pins the wire bytes against a vector from an independent Python
// implementation of the transport obfuscation (hashlib sha256, AES-256-CTR from
// pyca/cryptography 46.0.3), so a key-derivation mistake cannot hide behind a
// client and server that agree with each other.
func TestObfuscated2HeaderVector(t *testing.T) {
	// (i*7+3) mod 256 passes every generateInit filter.
	var seed [obfsInitLen]byte
	for i := range seed {
		seed[i] = byte((i*7 + 3) & 0xff)
	}
	const (
		wantHeader     = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848246bbf8b3fc398f"
		wantEncPayload = "7634258a5e296cb128b8ddc9"
	)

	var wire bytes.Buffer
	client, err := newObfuscated2(bytes.NewReader(seed[:]), rwPair{r: new(bytes.Buffer), w: &wire}, testKey(t), paddedIntermediateTag, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("hello, proxy")); err != nil {
		t.Fatal(err)
	}
	got := wire.Bytes()
	if len(got) != obfsInitLen+12 {
		t.Fatalf("wire has %d bytes, want %d", len(got), obfsInitLen+12)
	}
	if !bytes.Equal(got[:56], seed[:56]) {
		t.Errorf("wire bytes 0..56 must be the clear seed:\ngot  % x\nwant % x", got[:56], seed[:56])
	}
	if h := hex.EncodeToString(got[:obfsInitLen]); h != wantHeader {
		t.Errorf("header = %s\nwant     %s", h, wantHeader)
	}
	if p := hex.EncodeToString(got[obfsInitLen:]); p != wantEncPayload {
		t.Errorf("encrypted payload = %s, want %s", p, wantEncPayload)
	}
}

func TestObfuscated2RoundTrip(t *testing.T) {
	key := testKey(t)
	var c2s, s2c bytes.Buffer
	client, err := newObfuscated2(rand.Reader, rwPair{r: &s2c, w: &c2s}, key, paddedIntermediateTag, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("hello, proxy")); err != nil {
		t.Fatal(err)
	}

	// Server side: the first 64 bytes are the header; bytes 0..56 are plaintext.
	var init [obfsInitLen]byte
	copy(init[:], c2s.Next(obfsInitLen))
	serverEnc, serverDec, err := serverStreams(init, key)
	if err != nil {
		t.Fatal(err)
	}
	var plain [obfsInitLen]byte
	serverDec.XORKeyStream(plain[:], init[:])
	// Only bytes 56..64 were encrypted; decrypting the clear prefix is junk,
	// done here only to advance CTR by 64 bytes.
	if [4]byte(plain[56:60]) != paddedIntermediateTag {
		t.Errorf("tag = % x, want dd dd dd dd", plain[56:60])
	}
	if dc := binary.LittleEndian.Uint16(plain[60:62]); dc != 2 {
		t.Errorf("dc = %d, want 2", dc)
	}
	payload := c2s.Bytes()
	serverDec.XORKeyStream(payload, payload)
	if string(payload) != "hello, proxy" {
		t.Errorf("server decrypted %q", payload)
	}

	// Server -> client.
	reply := []byte("hello, client")
	enc := make([]byte, len(reply))
	serverEnc.XORKeyStream(enc, reply)
	s2c.Write(enc)
	got := make([]byte, len(reply))
	if _, err := client.Read(got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello, client" {
		t.Errorf("client decrypted %q", got)
	}
}

func TestObfuscated2WrongKeyProducesWrongTag(t *testing.T) {
	var wire bytes.Buffer
	client, err := newObfuscated2(rand.Reader, rwPair{r: new(bytes.Buffer), w: &wire}, testKey(t), paddedIntermediateTag, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.handshake(); err != nil {
		t.Fatal(err)
	}
	var init [obfsInitLen]byte
	copy(init[:], wire.Bytes())
	_, serverDec, err := serverStreams(init, [16]byte{9, 9, 9})
	if err != nil {
		t.Fatal(err)
	}
	var plain [obfsInitLen]byte
	serverDec.XORKeyStream(plain[:], init[:])
	if [4]byte(plain[56:60]) == paddedIntermediateTag {
		t.Fatal("a wrong key must not reveal the transport tag")
	}
}

// shortWriter takes limit bytes, then short-writes with a nil error.
type shortWriter struct {
	limit int
	buf   bytes.Buffer
}

func (w *shortWriter) Read([]byte) (int, error) { return 0, nil }

func (w *shortWriter) Write(p []byte) (int, error) {
	n := len(p)
	if n > w.limit {
		n = w.limit
	}
	w.buf.Write(p[:n])
	w.limit -= n
	return n, nil
}

func TestObfuscated2ShortWrites(t *testing.T) {
	w := &shortWriter{limit: 10}
	client, err := newObfuscated2(rand.Reader, w, testKey(t), paddedIntermediateTag, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.handshake(); err == nil {
		t.Fatal("a short header write must fail")
	}

	w2 := &shortWriter{limit: obfsInitLen + 2}
	client2, err := newObfuscated2(rand.Reader, w2, testKey(t), paddedIntermediateTag, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := client2.handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := client2.Write([]byte("hello, proxy")); err == nil {
		t.Fatal("a short payload write must fail")
	}
}
