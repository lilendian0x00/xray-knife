package mtproto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
)

func TestPaddedFrameRoundTrip(t *testing.T) {
	for _, size := range []int{4, 8, 40, 84, 1024} {
		payload := make([]byte, size)
		_, _ = rand.Read(payload)
		for padLen := 0; padLen < 16; padLen++ { // deterministic coverage of every legal length
			var wire bytes.Buffer
			if err := writePaddedFrame(bytes.NewReader(append([]byte{byte(padLen)}, make([]byte, padLen)...)), &wire, payload); err != nil {
				t.Fatal(err)
			}
			raw := wire.Bytes()
			declared := int(binary.LittleEndian.Uint32(raw[:4]))
			if declared != len(raw)-4 {
				t.Fatalf("declared length %d, wire has %d payload bytes", declared, len(raw)-4)
			}
			if pad := declared - size; pad != padLen {
				t.Fatalf("padding %d bytes, want %d", pad, padLen)
			}
			got, err := readPaddedFrame(&wire)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != size+padLen || !bytes.Equal(got[:size], payload) {
				t.Fatalf("size %d: payload/padding mismatch", size)
			}
		}
	}
}

func TestWritePaddedFrameRejectsUnaligned(t *testing.T) {
	err := writePaddedFrame(rand.Reader, new(bytes.Buffer), []byte{1, 2, 3})
	if err == nil || !strings.Contains(err.Error(), "multiple of 4") {
		t.Fatalf("err = %v", err)
	}
}

func TestWritePaddedFrameShortWrite(t *testing.T) {
	w := &shortWriter{limit: 2}
	if err := writePaddedFrame(rand.Reader, w, make([]byte, 8)); err == nil {
		t.Fatal("a short frame write must fail")
	}
}

func TestReadPaddedFrameKeepsFourByteFrames(t *testing.T) {
	wire := []byte{4, 0, 0, 0, 0x6c, 0xfe, 0xff, 0xff}
	got, err := readPaddedFrame(bytes.NewReader(wire))
	if err != nil || !bytes.Equal(got, wire[4:]) {
		t.Fatalf("got % x, %v", got, err)
	}
}

func TestReadPaddedFrameRejectsHugeLength(t *testing.T) {
	wire := []byte{0xff, 0xff, 0xff, 0x7f}
	if _, err := readPaddedFrame(bytes.NewReader(wire)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestReadPaddedFrameRejectsTinyLength(t *testing.T) {
	for _, n := range []byte{0, 1, 2, 3} {
		if _, err := readPaddedFrame(bytes.NewReader([]byte{n, 0, 0, 0})); err == nil || !strings.Contains(err.Error(), "too short") {
			t.Fatalf("length %d: err = %v", n, err)
		}
	}
}

func TestReadPaddedFrameFragmentedAndTruncated(t *testing.T) {
	var wire bytes.Buffer
	if err := writePaddedFrame(bytes.NewReader(make([]byte, 16)), &wire, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	raw := wire.Bytes()
	got, err := readPaddedFrame(iotest1(raw))
	if err != nil || len(got) != len(raw)-4 {
		t.Fatalf("fragmented read: got %d bytes, %v", len(got), err)
	}
	if _, err := readPaddedFrame(bytes.NewReader(raw[:2])); err == nil {
		t.Error("truncated frame header accepted")
	}
	if _, err := readPaddedFrame(bytes.NewReader(raw[:len(raw)-1])); err == nil {
		t.Error("truncated frame body accepted")
	}
}
