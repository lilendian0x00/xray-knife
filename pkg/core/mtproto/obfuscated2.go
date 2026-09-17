// Ported from github.com/gotd/td v0.161.0, mtproxy/obfuscated2 (keys.go,
// keys_util.go, obfuscated2.go). MIT License, Copyright (c) 2020 Aleksandr
// Razumov. See LICENSE.gotd in this directory.

package mtproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// paddedIntermediateTag goes into the obfuscated2 header to tell the proxy how
// the stream is framed.
var paddedIntermediateTag = [4]byte{0xdd, 0xdd, 0xdd, 0xdd}

const obfsInitLen = 64

// obfuscated2 is the AES-CTR obfuscated transport used between a Telegram
// client and an MTProto proxy. See
// https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation
type obfuscated2 struct {
	conn    io.ReadWriter
	header  []byte
	encrypt cipher.Stream
	decrypt cipher.Stream
}

// newObfuscated2 derives the client streams and the 64-byte header for a
// session to the given DC. Call handshake to send the header before Write.
func newObfuscated2(rnd io.Reader, conn io.ReadWriter, key [16]byte, tag [4]byte, dc int) (*obfuscated2, error) {
	init, err := generateInit(rnd)
	if err != nil {
		return nil, fmt.Errorf("obfuscated2: generate init: %w", err)
	}
	copy(init[56:60], tag[:])
	binary.LittleEndian.PutUint16(init[60:62], uint16(dc))

	// Key material is init[8:56], so the tag and DC above do not affect it.
	encrypt, decrypt, err := clientStreams(init, key)
	if err != nil {
		return nil, err
	}
	// Encrypt all 64 bytes, not just 56..64: the proxy decrypts the whole block
	// too, and both counters must advance equally.
	var encrypted [obfsInitLen]byte
	encrypt.XORKeyStream(encrypted[:], init[:])
	header := make([]byte, obfsInitLen)
	copy(header, init[:56])
	copy(header[56:], encrypted[56:])
	return &obfuscated2{conn: conn, header: header, encrypt: encrypt, decrypt: decrypt}, nil
}

// handshake sends the header. Nothing comes back: the proxy starts relaying.
func (o *obfuscated2) handshake() error {
	n, err := o.conn.Write(o.header)
	if err == nil && n != len(o.header) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("obfuscated2: write header: %w", err)
	}
	return nil
}

func (o *obfuscated2) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	o.encrypt.XORKeyStream(buf, p)
	n, err := o.conn.Write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (o *obfuscated2) Read(p []byte) (int, error) {
	n, err := o.conn.Read(p)
	if n > 0 {
		o.decrypt.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// clientStreams derives the client's encrypt and decrypt AES-CTR streams.
// Encrypt key material is init[8:40] (key) and init[40:56] (IV); decrypt
// material is the same 48 bytes reversed. With a proxy secret, both keys are
// SHA-256(material || secret).
func clientStreams(init [obfsInitLen]byte, key [16]byte) (encrypt, decrypt cipher.Stream, err error) {
	encKey := sha256.Sum256(append(append([]byte{}, init[8:40]...), key[:]...))
	encIV := init[40:56]

	var rev [48]byte
	for i := 0; i < 48; i++ {
		rev[i] = init[55-i]
	}
	decKey := sha256.Sum256(append(append([]byte{}, rev[:32]...), key[:]...))
	decIV := rev[32:48]

	if encrypt, err = newCTR(encKey[:], encIV); err != nil {
		return nil, nil, err
	}
	if decrypt, err = newCTR(decKey[:], decIV); err != nil {
		return nil, nil, err
	}
	return encrypt, decrypt, nil
}

func newCTR(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("obfuscated2: aes: %w", err)
	}
	return cipher.NewCTR(block, iv), nil
}

// generateInit draws 64 random bytes, redrawing while the prefix looks like
// another protocol or the second word is zero, as the official clients do.
func generateInit(rnd io.Reader) ([obfsInitLen]byte, error) {
	var init [obfsInitLen]byte
	for {
		if _, err := io.ReadFull(rnd, init[:]); err != nil {
			return init, err
		}
		if init[0] == 0xef {
			continue
		}
		switch binary.LittleEndian.Uint32(init[0:4]) {
		case 0x44414548, // HEAD
			0x54534f50, // POST
			0x20544547, // GET
			0x4954504f, // OPTI
			0x02010316, // TLS-looking prefix
			0xdddddddd, // padded intermediate
			0xeeeeeeee: // intermediate
			continue
		}
		if binary.LittleEndian.Uint32(init[4:8]) == 0 {
			continue
		}
		return init, nil
	}
}
