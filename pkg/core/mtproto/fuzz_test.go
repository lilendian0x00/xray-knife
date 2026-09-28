package mtproto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The parsers below read bytes chosen by the proxy (or whoever answers in
// its place); none of them may panic or over-allocate on hostile input.

func FuzzParseResPQ(f *testing.F) {
	var nonce [16]byte
	f.Add(buildResPQ(nonce))
	f.Add([]byte{0x6c, 0xfe, 0xff, 0xff})
	f.Add(make([]byte, unencryptedHeaderLen+resPQMinBody))
	f.Fuzz(func(t *testing.T, frame []byte) {
		_, _ = parseResPQ(frame)
	})
}

func FuzzReadPaddedFrame(f *testing.F) {
	f.Add([]byte{8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{3, 0, 0, 0})
	f.Fuzz(func(t *testing.T, wire []byte) {
		frame, err := readPaddedFrame(bytes.NewReader(wire))
		if err == nil {
			if n := binary.LittleEndian.Uint32(wire[:4]); int(n) != len(frame) || n > maxFrameLen {
				t.Fatalf("frame of %d bytes for header %d", len(frame), n)
			}
		}
	})
}

func FuzzVerifyServerHello(f *testing.F) {
	key := make([]byte, secretKeyLen)
	var clientRandom [helloRandomLen]byte
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00})
	f.Add([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01})
	f.Fuzz(func(t *testing.T, flight []byte) {
		_ = verifyServerHello(bytes.NewReader(flight), clientRandom, key)
	})
}

func FuzzParseSecret(f *testing.F) {
	f.Add(testKeyHex)
	f.Add("dd" + testKeyHex)
	f.Add("ee" + testKeyHex + "7777772e676f6f676c652e636f6d")
	f.Add("7uRg4tr0kPpfVR-C_bnFp1d3d3Lmdvb2dsZS5jb20")
	f.Fuzz(func(t *testing.T, raw string) {
		s, err := ParseSecret(raw)
		if err != nil {
			return
		}
		// A decoded secret must round-trip through its canonical hex form.
		again, err := ParseSecret(s.Hex())
		if err != nil || again != s {
			t.Fatalf("ParseSecret(%q) = %+v, re-parse of %s = %+v, %v", raw, s, s.Hex(), again, err)
		}
	})
}
