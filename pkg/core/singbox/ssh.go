package singbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sing_ssh "github.com/sagernet/sing-box/protocol/ssh"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"golang.org/x/crypto/ssh"
)

// SSH tunnel links, as NekoBox and Hiddify emit them:
//
//	ssh://USER:PASSWORD@host:22?pk=PRIVATE_KEY&pkp=PASSPHRASE&hk=HOST_KEY#remark
//
// Accepted parameters (aliases in parentheses):
//
//	pk (private_key)                 PEM private key, percent-encoded or base64
//	pkp (private_key_passphrase, passphrase)
//	hk (host_key)                    authorized_keys-format host keys, comma
//	                                 separated or repeated; none accepts any key
//
// Encoders disagree on whether '+' in a query value is a space, and both
// PEM and host keys contain '+' and spaces, so each key is decoded both ways
// and the variant golang.org/x/crypto/ssh accepts wins.

const defaultSSHUser = "root"

func NewSSH(link string) Protocol {
	return &SSH{OrigLink: link}
}

func (s *SSH) Name() string {
	return protocol.SSHIdentifier
}

func (s *SSH) Parse() error {
	uri, remark, err := parseShareLink(s.OrigLink)
	if err != nil {
		return fmt.Errorf("failed to parse SSH link: %w", err)
	}
	if uri.Scheme != protocol.SSHIdentifier {
		return fmt.Errorf("ssh unrecognized scheme: %s", uri.Scheme)
	}
	s.Address, s.Port = uri.Hostname(), uri.Port()
	if s.Address == "" {
		return errors.New("ssh link has no server address")
	}
	if s.Port == "" {
		s.Port = "22"
	}
	if _, err := parsePort(s.Port); err != nil {
		return fmt.Errorf("ssh: %w", err)
	}
	if uri.User != nil {
		s.User = uri.User.Username()
		s.Password, _ = uri.User.Password()
	}
	if s.User == "" {
		s.User = defaultSSHUser
	}

	// Passphrases are ambiguous like keys ('+' or space); keep both
	// decodings and let the (lazy) decryption pick the one that works.
	s.passphrases = queryVariants(uri.RawQuery, "pkp", "private_key_passphrase", "passphrase")
	if len(s.passphrases) > 0 {
		s.PrivateKeyPassphrase = s.passphrases[0]
	}
	if rawKey := queryVariants(uri.RawQuery, "pk", "private_key"); len(rawKey) > 0 {
		pemText, err := pickPrivateKey(rawKey)
		if err != nil {
			return fmt.Errorf("ssh link private key: %w", err)
		}
		s.PrivateKey = pemText
	}
	s.key = &sshKeyCache{}
	for _, name := range []string{"hk", "host_key"} {
		for _, variants := range queryVariantGroups(uri.RawQuery, name) {
			s.HostKeys = append(s.HostKeys, splitHostKeys(variants)...)
		}
	}
	if s.Password == "" && s.PrivateKey == "" {
		return errors.New("ssh link has neither a password nor a private key")
	}
	s.Remark = remark
	return nil
}

// queryVariantGroups returns, for every occurrence of name in rawQuery, the
// value decoded with '+' kept literal and with '+' as a space.
func queryVariantGroups(rawQuery, name string) [][]string {
	var groups [][]string
	for _, pair := range strings.Split(rawQuery, "&") {
		key, value, _ := strings.Cut(pair, "=")
		if k, err := url.QueryUnescape(key); err != nil || k != name {
			continue
		}
		var variants []string
		if v, err := url.PathUnescape(value); err == nil {
			variants = append(variants, v)
		}
		if v, err := url.QueryUnescape(value); err == nil && (len(variants) == 0 || v != variants[0]) {
			variants = append(variants, v)
		}
		if len(variants) > 0 {
			groups = append(groups, variants)
		}
	}
	return groups
}

// queryVariants returns the decodings of the first of names present.
func queryVariants(rawQuery string, names ...string) []string {
	for _, name := range names {
		if groups := queryVariantGroups(rawQuery, name); len(groups) > 0 {
			return groups[0]
		}
	}
	return nil
}

// maxSSHKDFRounds caps the bcrypt rounds an encrypted private key may ask
// for. OpenSSH uses 16; x/crypto accepts up to 2048, which with a wrong
// passphrase burns about 15s of CPU per attempt, uncancellable — a crafted
// link would stall a subscription import.
const maxSSHKDFRounds = 64

// checkPrivateKey validates a PEM private key's framing and type without
// running its KDF (ssh.ParsePrivateKey stops at PassphraseMissingError for
// encrypted keys) and bounds the KDF work an encrypted key would cost.
func checkPrivateKey(pemText string) (encrypted bool, err error) {
	_, err = ssh.ParsePrivateKey([]byte(pemText))
	if err == nil {
		return false, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return false, err
	}
	return true, checkKDFRounds(pemText)
}

// checkKDFRounds rejects OpenSSH keys whose bcrypt KDF asks for more than
// maxSSHKDFRounds rounds. Legacy PEM encryption uses a cheap MD5 KDF.
func checkKDFRounds(pemText string) error {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return nil
	}
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(block.Bytes, []byte(magic)) {
		return errors.New("ssh: invalid openssh private key format")
	}
	var header struct {
		CipherName string
		KdfName    string
		KdfOpts    string
		Rest       []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(block.Bytes[len(magic):], &header); err != nil {
		return err
	}
	if header.KdfName != "bcrypt" {
		return nil
	}
	var opts struct {
		Salt   string
		Rounds uint32
	}
	if err := ssh.Unmarshal([]byte(header.KdfOpts), &opts); err != nil {
		return err
	}
	if opts.Rounds > maxSSHKDFRounds {
		return fmt.Errorf("private key asks for %d bcrypt rounds (at most %d accepted)", opts.Rounds, maxSSHKDFRounds)
	}
	return nil
}

// pickPrivateKey returns the candidate (or its base64 decoding) that is a
// well-formed SSH private key. Nothing is decrypted here.
func pickPrivateKey(candidates []string) (string, error) {
	var firstErr error
	for _, c := range candidates {
		forms := []string{c}
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c)); err == nil {
			forms = append(forms, string(decoded))
		}
		for _, pemText := range forms {
			_, err := checkPrivateKey(pemText)
			if err == nil {
				return pemText, nil
			}
			if firstErr == nil || strings.Contains(err.Error(), "bcrypt rounds") {
				firstErr = err
			}
		}
	}
	if firstErr == nil || !strings.Contains(firstErr.Error(), "bcrypt rounds") {
		return "", errors.New("does not parse as a private key")
	}
	return "", firstErr
}

// sshKeyCache holds the decrypted private key so the KDF runs at most once
// per parsed link, however often it is crafted.
type sshKeyCache struct {
	mu   sync.Mutex
	done bool
	pem  string
	err  error
}

// usablePrivateKey returns the private key as unencrypted PEM, decrypting
// it on first use. Each passphrase decoding is tried until one works.
func (s *SSH) usablePrivateKey() (string, error) {
	if s.PrivateKey == "" {
		return "", nil
	}
	encrypted, err := checkPrivateKey(s.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("ssh private key: %w", err)
	}
	if !encrypted {
		return s.PrivateKey, nil
	}
	cache := s.key
	if cache == nil {
		cache = &sshKeyCache{} // built by hand, not by Parse: no caching
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !cache.done {
		cache.pem, cache.err = decryptPrivateKey(s.PrivateKey, s.passphraseCandidates())
		cache.done = true
	}
	return cache.pem, cache.err
}

func (s *SSH) passphraseCandidates() []string {
	if len(s.passphrases) > 0 {
		return s.passphrases
	}
	return []string{s.PrivateKeyPassphrase}
}

// decryptPrivateKey decrypts pemText with the first passphrase that works
// and re-encodes it unencrypted, so sing-box does not run the KDF again.
func decryptPrivateKey(pemText string, passphrases []string) (string, error) {
	for _, pass := range passphrases {
		if pass == "" {
			continue
		}
		raw, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(pemText), []byte(pass))
		if errors.Is(err, x509.IncorrectPasswordError) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("ssh private key: %w", err)
		}
		if k, ok := raw.(*ed25519.PrivateKey); ok {
			raw = *k
		}
		block, err := ssh.MarshalPrivateKey(raw, "")
		if err != nil {
			return "", fmt.Errorf("ssh private key: %w", err)
		}
		return string(pem.EncodeToMemory(block)), nil
	}
	return "", errors.New("ssh private key: wrong or missing passphrase (pkp)")
}

// splitHostKeys splits comma-separated host keys, preferring the decoding
// in which every key parses.
func splitHostKeys(variants []string) []string {
	for _, v := range variants {
		keys := splitList(v)
		valid := len(keys) > 0
		for _, k := range keys {
			if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k)); err != nil {
				valid = false
				break
			}
		}
		if valid {
			return keys
		}
	}
	return splitList(variants[0])
}

func (s *SSH) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), s.Name(),
		color.RedString("Remark"), s.Remark,
		color.RedString("Address"), s.Address,
		color.RedString("Port"), s.Port,
		color.RedString("User"), s.User,
	)
	if s.Password != "" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("Password"), s.Password)
	}
	if s.PrivateKey != "" {
		info += fmt.Sprintf("%s: yes\n", color.RedString("Private Key"))
	}
	if len(s.HostKeys) > 0 {
		info += fmt.Sprintf("%s: %d pinned\n", color.RedString("Host Keys"), len(s.HostKeys))
	}
	return info
}

func (s *SSH) GetLink() string {
	return s.OrigLink
}

func (s *SSH) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = s.Name()
	g.Address = s.Address
	g.Port = s.Port
	g.ID = s.User
	g.Remark = s.Remark
	g.TLS = "none"
	g.Network = "tcp"
	g.OrigLink = s.GetLink()
	return g
}

func (s *SSH) CraftInboundOptions() (*option.Inbound, error) {
	return nil, fmt.Errorf("%s: inbound not supported", s.Name())
}

func (s *SSH) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	port, err := parsePort(s.Port)
	if err != nil {
		return nil, err
	}
	privateKey, err := s.usablePrivateKey()
	if err != nil {
		return nil, err
	}
	opts := option.SSHOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     serverHost(s.Address),
			ServerPort: port,
		},
		User:     s.User,
		Password: s.Password,
	}
	if privateKey != "" {
		// Already decrypted: no passphrase, so sing-box runs no KDF.
		opts.PrivateKey = strings.Split(strings.TrimSpace(privateKey), "\n")
	}
	if len(s.HostKeys) > 0 {
		opts.HostKey = s.HostKeys
	}
	return &option.Outbound{
		Type:    s.Name(),
		Options: &opts,
	}, nil
}

func (s *SSH) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {
	options, err := s.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}
	sshOptions, ok := options.Options.(*option.SSHOutboundOptions)
	if !ok {
		return nil, fmt.Errorf("ssh: unexpected options type %T", options.Options)
	}
	return sing_ssh.NewOutbound(ctx, service.FromContext[adapter.Router](ctx), l, "out_ssh", *sshOptions)
}
