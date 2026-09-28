package singbox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"golang.org/x/crypto/ssh"
)

// encryptedSSHKey returns an OpenSSH private key encrypted with pass, its
// bcrypt rounds rewritten to rounds (0 keeps the default 16).
func encryptedSSHKey(t *testing.T, pass string, rounds uint32) (string, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	if rounds != 0 {
		// openssh-key-v1\0, string cipher, string kdf, string kdfopts{string salt, uint32 rounds}
		b := block.Bytes
		off := len("openssh-key-v1\x00")
		skip := func() { off += 4 + int(binary.BigEndian.Uint32(b[off:])) }
		skip()
		skip()
		opts := off + 4
		salt := int(binary.BigEndian.Uint32(b[opts:]))
		binary.BigEndian.PutUint32(b[opts+4+salt:], rounds)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block)), signer
}

// Reviewer repro: 2048 bcrypt rounds with a wrong passphrase used to cost
// ~15s of CPU inside Parse. Parse must neither decrypt nor accept it.
func TestSSHParseRejectsCostlyKDFFast(t *testing.T) {
	pemKey, _ := encryptedSSHKey(t, "pw", 2048)
	start := time.Now()
	err := NewSSH("ssh://root@1.2.3.4:22?pk=" + url.QueryEscape(pemKey) + "&pkp=wrong").Parse()
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Parse took %v", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "bcrypt rounds") {
		t.Fatalf("err = %v, want a bcrypt rounds error", err)
	}
}

func TestSSHEncryptedKeyDecryptsLazilyOnce(t *testing.T) {
	const pass = "p+ss word"
	pemKey, _ := encryptedSSHKey(t, pass, 0)
	c := NewSingboxService(false, false)
	for name, pkp := range map[string]string{
		"query escape": url.QueryEscape(pass), // space as '+', '+' as %2B
		"path escape":  url.PathEscape(pass),  // '+' literal, space as %20
	} {
		link := "ssh://root@1.2.3.4:22?pk=" + url.QueryEscape(pemKey) + "&pkp=" + pkp
		start := time.Now()
		s := parseLink(t, c, link).(*SSH)
		if time.Since(start) > 50*time.Millisecond {
			t.Errorf("%s: Parse took %v; it must not run the KDF", name, time.Since(start))
		}
		out, err := s.CraftOutboundOptions(false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		o := out.Options.(*option.SSHOutboundOptions)
		key := strings.Join(o.PrivateKey, "\n")
		if o.PrivateKeyPassphrase != "" || !bytes.Contains([]byte(key), []byte("OPENSSH PRIVATE KEY")) {
			t.Fatalf("%s: want an unencrypted key and no passphrase, got passphrase %q", name, o.PrivateKeyPassphrase)
		}
		if _, err := ssh.ParsePrivateKey([]byte(key)); err != nil {
			t.Fatalf("%s: crafted key is not unencrypted: %v", name, err)
		}
		// Crafting again reuses the decrypted key.
		start = time.Now()
		if _, err := s.CraftOutboundOptions(false); err != nil || time.Since(start) > 20*time.Millisecond {
			t.Errorf("%s: second craft err %v took %v", name, err, time.Since(start))
		}
	}

	s := parseLink(t, c, "ssh://root@1.2.3.4:22?pk="+url.QueryEscape(pemKey)+"&pkp=nope").(*SSH)
	if _, err := s.CraftOutboundOptions(false); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("wrong passphrase: err = %v", err)
	}
	s = parseLink(t, c, "ssh://root@1.2.3.4:22?pk="+url.QueryEscape(pemKey)).(*SSH)
	if _, err := s.CraftOutboundOptions(false); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("missing passphrase: err = %v", err)
	}
}

func TestEndToEndSSHEncryptedKey(t *testing.T) {
	skipUnderRace(t)
	target := startTarget(t)
	pemKey, signer := encryptedSSHKey(t, "p+ss word", 0)
	addr, _ := startSSHServer(t, "tunnel", "", signer.PublicKey())
	fetchThrough(t, NewSingboxService(false, false),
		"ssh://tunnel@"+addr+"?pk="+url.QueryEscape(pemKey)+"&pkp="+url.QueryEscape("p+ss word"), target)
}
