// The padded-intermediate framing below follows github.com/gotd/td v0.161.0,
// proto/codec/padded_intermediate.go. MIT License, Copyright (c) 2020
// Aleksandr Razumov. See LICENSE.gotd in this directory.

package mtproto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// maxFrameLen caps what a hostile peer can make us allocate; a resPQ is under
// 100 bytes.
const maxFrameLen = 1 << 20

// writePaddedFrame writes one padded-intermediate frame: 4-byte little-endian
// length, payload, 0..15 random padding bytes covered by that length. Payload
// length must be a multiple of 4, as all TL objects are.
func writePaddedFrame(rnd io.Reader, w io.Writer, payload []byte) error {
	if len(payload)%4 != 0 {
		return fmt.Errorf("frame payload length %d is not a multiple of 4", len(payload))
	}
	var padByte [1]byte
	if _, err := io.ReadFull(rnd, padByte[:]); err != nil {
		return err
	}
	pad := int(padByte[0] % 16)
	frame := make([]byte, 4+len(payload)+pad)
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(payload)+pad))
	copy(frame[4:], payload)
	if _, err := io.ReadFull(rnd, frame[4+len(payload):]); err != nil {
		return err
	}
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	return err
}

// readPaddedFrame returns payload plus padding; the message decoder splits them
// using message_data_length. Read errors stay unwrapped so callers see io.EOF.
func readPaddedFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n < 4 {
		return nil, fmt.Errorf("frame length %d is too short", n)
	}
	if n > maxFrameLen {
		return nil, fmt.Errorf("frame length %d exceeds limit %d", n, maxFrameLen)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
