package mtproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// TL constructors used by the probe. See https://core.telegram.org/mtproto/auth_key
const (
	reqPQMultiConstructor uint32 = 0xbe7e8ef1
	resPQConstructor      uint32 = 0x05162463
	vectorConstructor     uint32 = 0x1cb5c415
)

// Layout of the unencrypted message: auth_key_id(8) message_id(8)
// message_data_length(4) constructor(4) nonce(16).
const (
	unencryptedHeaderLen = 8 + 8 + 4
	reqPQMultiLen        = unencryptedHeaderLen + 4 + 16
	// resPQMinBody is the shortest legal resPQ body: constructor(4), nonce(16),
	// server_nonce(16), padded pq(4) and a Vector<long>(8) with one fingerprint(8).
	resPQMinBody = 56
)

// TransportError is a 4-byte MTProto transport-level error frame such as -404.
type TransportError struct{ Code int32 }

func (e TransportError) Error() string {
	// https://core.telegram.org/mtproto/mtproto-transports#transport-errors
	switch e.Code {
	case -429:
		return "transport error -429 (too many connections: Telegram is rate-limiting this IP)"
	case -444:
		return "transport error -444 (invalid data center)"
	}
	return fmt.Sprintf("transport error %d", e.Code)
}

// timestampMsgID is Unix time * 2^32 plus fractional seconds. Client IDs are
// divisible by four and their low 32 bits must be nonzero.
func timestampMsgID(now time.Time) uint64 {
	fraction := (uint64(now.Nanosecond()) << 32) / uint64(time.Second)
	fraction &^= 3
	if fraction == 0 {
		fraction = 4
	}
	return uint64(now.Unix())<<32 | fraction
}

// msgIDSeq hands out one connection's message IDs. They must increase even when
// the clock does not. https://core.telegram.org/mtproto/description#message-identifier-msg-id
type msgIDSeq struct{ last uint64 }

func (s *msgIDSeq) next(now time.Time) uint64 {
	id := timestampMsgID(now)
	if id <= s.last {
		id = s.last + 4
		if uint32(id) == 0 { // rolled into the next second
			id += 4
		}
	}
	s.last = id
	return id
}

// buildReqPQMulti encodes an unencrypted req_pq_multi#be7e8ef1 nonce:int128.
func buildReqPQMulti(nonce [16]byte, now time.Time) []byte {
	return buildReqPQMultiWithID(nonce, timestampMsgID(now))
}

func buildReqPQMultiWithID(nonce [16]byte, msgID uint64) []byte {
	msg := make([]byte, reqPQMultiLen)
	binary.LittleEndian.PutUint64(msg[8:16], msgID)
	binary.LittleEndian.PutUint32(msg[16:20], reqPQMultiLen-unencryptedHeaderLen)
	binary.LittleEndian.PutUint32(msg[20:24], reqPQMultiConstructor)
	copy(msg[24:40], nonce[:])
	return msg
}

// parseResPQ validates the complete unencrypted resPQ TL object and returns
// its client nonce. Transport padding is outside message_data_length.
func parseResPQ(frame []byte) ([16]byte, error) {
	var nonce [16]byte
	// A transport error is a bare negative int32, maybe padded. Anything
	// shorter than the smallest resPQ cannot be a resPQ.
	if len(frame) >= 4 && len(frame) < unencryptedHeaderLen+resPQMinBody {
		code := int32(binary.LittleEndian.Uint32(frame[:4]))
		if code < -1 { // -1 denotes a quick ACK, which this probe never requests.
			return nonce, TransportError{Code: code}
		}
	}
	if len(frame) < unencryptedHeaderLen+resPQMinBody {
		return nonce, fmt.Errorf("resPQ frame too short: %d bytes", len(frame))
	}
	if binary.LittleEndian.Uint64(frame[0:8]) != 0 {
		return nonce, errors.New("resPQ has a non-zero auth_key_id (unexpected encrypted message)")
	}
	if binary.LittleEndian.Uint64(frame[8:16])&3 != 1 {
		return nonce, errors.New("resPQ has an invalid response message_id")
	}
	// message_data_length is authoritative, the rest is padding. Real proxies pad
	// past the documented 0-15 bytes, so the tail is capped by readPaddedFrame.
	n := uint64(binary.LittleEndian.Uint32(frame[16:20]))
	available := uint64(len(frame) - unencryptedHeaderLen)
	if n < resPQMinBody || n%4 != 0 || n > available {
		return nonce, errors.New("resPQ has an invalid message_data_length")
	}
	body := frame[unencryptedHeaderLen : unencryptedHeaderLen+int(n)]
	if c := binary.LittleEndian.Uint32(body[:4]); c != resPQConstructor {
		return nonce, fmt.Errorf("unexpected constructor 0x%08x, want resPQ 0x%08x", c, resPQConstructor)
	}
	// resPQ: constructor, nonce:int128, server_nonce:int128, pq:bytes,
	// server_public_key_fingerprints:Vector<long>. pq is at most 8 bytes.
	pqLen := int(body[36])
	if pqLen < 1 || pqLen > 8 {
		return nonce, errors.New("resPQ has an invalid pq length")
	}
	vectorOffset := 36 + (1+pqLen+3)&^3
	if vectorOffset+8 > len(body) || binary.LittleEndian.Uint32(body[vectorOffset:]) != vectorConstructor {
		return nonce, errors.New("resPQ has an invalid fingerprint vector")
	}
	count := uint64(binary.LittleEndian.Uint32(body[vectorOffset+4:]))
	if count == 0 || count*8 != uint64(len(body)-vectorOffset-8) {
		return nonce, errors.New("resPQ has an invalid fingerprint count")
	}
	copy(nonce[:], body[4:20])
	return nonce, nil
}
