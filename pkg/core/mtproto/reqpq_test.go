package mtproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

// buildResPQ is an unencrypted resPQ: client nonce, server nonce, pq, one
// fingerprint.
func buildResPQ(nonce [16]byte) []byte {
	body := binary.LittleEndian.AppendUint32(nil, resPQConstructor)
	body = append(body, nonce[:]...)
	body = append(body, bytes.Repeat([]byte{0x5a}, 16)...)                          // server_nonce
	body = append(body, 8, 0x17, 0xed, 0x48, 0x94, 0x1a, 0x08, 0xf9, 0x81, 0, 0, 0) // pq: TL string, 8 bytes + 3 padding
	body = binary.LittleEndian.AppendUint32(body, vectorConstructor)                // Vector<long>
	body = binary.LittleEndian.AppendUint32(body, 1)
	body = binary.LittleEndian.AppendUint64(body, 0xc3b42b026ce86b21) // server_public_key_fingerprints[0]
	msg := make([]byte, 20, 20+len(body))
	binary.LittleEndian.PutUint64(msg[8:16], uint64(time.Now().Unix())<<32|1)
	binary.LittleEndian.PutUint32(msg[16:20], uint32(len(body)))
	return append(msg, body...)
}

func TestBuildReqPQMulti(t *testing.T) {
	var nonce [16]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	now := time.Unix(1_800_000_000, 0)
	msg := buildReqPQMulti(nonce, now)
	if len(msg) != 40 {
		t.Fatalf("len = %d, want 40", len(msg))
	}
	if binary.LittleEndian.Uint64(msg[0:8]) != 0 {
		t.Error("auth_key_id must be 0")
	}
	if got := binary.LittleEndian.Uint64(msg[8:16]); got != uint64(now.Unix())<<32|4 {
		t.Errorf("message_id = %x, want %x", got, uint64(now.Unix())<<32|4)
	}
	if binary.LittleEndian.Uint32(msg[16:20]) != 20 {
		t.Error("message_data_length must be 20")
	}
	if binary.LittleEndian.Uint32(msg[20:24]) != reqPQMultiConstructor {
		t.Errorf("constructor = %x", msg[20:24])
	}
	if !bytes.Equal(msg[24:40], nonce[:]) {
		t.Error("nonce mismatch")
	}
}

func TestBuildReqPQMultiFractionalMessageID(t *testing.T) {
	for _, nanos := range []int64{0, 1, 250_000_000, 999_999_999} {
		now := time.Unix(1_800_000_000, nanos)
		msg := buildReqPQMulti([16]byte{}, now)
		id := binary.LittleEndian.Uint64(msg[8:16])
		if id>>32 != uint64(now.Unix()) || id&3 != 0 || uint32(id) == 0 {
			t.Fatalf("invalid message ID %x for %v", id, now)
		}
		if nanos == 250_000_000 && uint32(id) != 1<<30 {
			t.Fatalf("fractional seconds lost: %x", id)
		}
	}
}

func TestParseResPQ(t *testing.T) {
	var nonce [16]byte
	nonce[0] = 0xab
	got, err := parseResPQ(buildResPQ(nonce))
	if err != nil || got != nonce {
		t.Fatalf("got %x, %v", got, err)
	}

	_, err = parseResPQ([]byte{0x6c, 0xfe, 0xff, 0xff})
	var te TransportError
	if !errors.As(err, &te) || te.Code != -404 || err.Error() != "transport error -404" {
		t.Errorf("transport error: %v", err)
	}

	garbage := buildResPQ(nonce)
	binary.LittleEndian.PutUint32(garbage[20:24], 0xdeadbeef)
	if _, err := parseResPQ(garbage); err == nil || !strings.Contains(err.Error(), "unexpected constructor 0xdeadbeef") {
		t.Errorf("garbage: %v", err)
	}

	if _, err := parseResPQ(make([]byte, 24)); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Errorf("short: %v", err)
	}

	encrypted := buildResPQ(nonce)
	encrypted[0] = 1
	if _, err := parseResPQ(encrypted); err == nil || !strings.Contains(err.Error(), "auth_key_id") {
		t.Errorf("non-zero auth_key_id: %v", err)
	}
}

func TestParseResPQBoundsAndPadding(t *testing.T) {
	var nonce [16]byte
	nonce[0] = 0xab
	valid := buildResPQ(nonce)
	// The spec mentions 0-15 padding bytes, but a live MTProxy sent 35, so
	// every length below must be accepted.
	paddings := []int{0, 1, 2, 3, 4, 8, 15, 16, 35, 71, 255}
	for _, pad := range paddings {
		frame := append(append([]byte(nil), valid...), bytes.Repeat([]byte{0x77}, pad)...)
		if got, err := parseResPQ(frame); err != nil || got != nonce {
			t.Fatalf("padding %d: nonce=%x err=%v", pad, got, err)
		}
	}
	for _, pad := range []int{0, 1, 15, 35, 55} { // a transport error stays under a resPQ's minimum size
		transport := append([]byte{0x6c, 0xfe, 0xff, 0xff}, make([]byte, pad)...)
		var te TransportError
		if _, err := parseResPQ(transport); !errors.As(err, &te) || te.Code != -404 {
			t.Fatalf("padded transport error %d: %v", pad, err)
		}
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"nonce-only":             func(b []byte) []byte { return b[:40] },
		"missing fingerprint":    func(b []byte) []byte { return b[:len(b)-8] },
		"oversized body":         func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:20], 0xffffffff); return b },
		"unaligned body":         func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:20], 63); return b },
		"undersized body":        func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:20], 40); return b },
		"wrong response ID":      func(b []byte) []byte { b[8] = 0; return b },
		"invalid pq":             func(b []byte) []byte { b[56] = 254; return b },
		"zero pq":                func(b []byte) []byte { b[56] = 0; return b },
		"invalid vector":         func(b []byte) []byte { b[68] = 0; return b },
		"oversized vector count": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[72:76], 0xffffffff); return b },
		"zero vector count":      func(b []byte) []byte { binary.LittleEndian.PutUint32(b[72:76], 0); return b },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseResPQ(mutate(append([]byte(nil), valid...))); err == nil {
				t.Fatal("malformed resPQ accepted")
			}
		})
	}
}

func TestParseResPQQuickAckIsNotATransportError(t *testing.T) {
	// -1 marks a quick ACK, not an error code.
	if _, err := parseResPQ([]byte{0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("quick ACK accepted as resPQ")
	} else {
		var te TransportError
		if errors.As(err, &te) {
			t.Fatalf("quick ACK reported as %v", te)
		}
	}
}
