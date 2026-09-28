// Package subscription fetches and decodes share-link lists without CLI or database state.
// Callers control network access and validate the resulting configs.
//
// Besides plain and base64 link lists, Decode imports structured client
// configs, detected from the content (never from headers):
//
//   - Clash / mihomo YAML: the top-level proxies: list.
//   - sing-box JSON: outbounds and endpoints.
//   - xray JSON: outbounds of one config, or of an array of configs (the
//     v2rayN "custom config" form, whose "remarks" name each proxy).
//
// Each proxy entry becomes a share link (vmess, vless incl. REALITY/flow,
// trojan, ss incl. obfs-local/v2ray-plugin, hysteria2 incl. obfs and port
// hopping, hysteria, tuic, anytls, wireguard, socks5, http). Entries that
// cannot be expressed are skipped and counted by reason in
// DecodeResult.Skipped; non-proxy entries (direct, block, selector, ...)
// are ignored. A document with no usable proxy fails with
// ErrNoSupportedProxies (which is also an ErrInvalidFormat).
package subscription

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	DefaultMaxBytes int64 = 64 << 20
	// DefaultMaxStructuredBytes caps Clash YAML and sing-box/xray JSON
	// bodies: parsing takes many times their size in memory.
	DefaultMaxStructuredBytes int64 = 8 << 20
	DefaultMaxLinks                 = 100000
	DefaultTimeout                  = 30 * time.Second
)

var (
	ErrTooLarge      = errors.New("subscription exceeds size limit")
	ErrTooManyLinks  = errors.New("subscription exceeds link limit")
	ErrInvalidFormat = errors.New("subscription must contain a plain or base64-encoded share-link list, Clash YAML, or sing-box/xray JSON")
	// ErrNoSupportedProxies reports a structured config whose proxies were
	// all skipped. errors.Is(err, ErrInvalidFormat) holds for it too.
	ErrNoSupportedProxies = fmt.Errorf("%w: no proxy in it can be expressed as a supported share link", ErrInvalidFormat)
)

// DecodeResult is a decoded subscription.
type DecodeResult struct {
	Links  []string
	Format Format
	// Skipped counts structured entries that could not become share links,
	// by reason (e.g. "unsupported clash proxy type ssr": 3).
	Skipped map[string]int
}

type DecodeOptions struct {
	// Zero selects the default; negative limits are invalid.
	MaxBytes int64
	MaxLinks int
	// MaxStructuredBytes caps structured documents (Clash YAML, sing-box
	// or xray JSON), before or after base64 decoding; at most MaxBytes.
	MaxStructuredBytes int64
}

// Decode reads plain or base64 lists, preserving duplicates and malformed config options,
// and structured client configs (see the package documentation).
// Invalid documents and limit breaches return an error, never a partial list.
func Decode(body []byte, opts DecodeOptions) ([]string, error) {
	res, err := DecodeDetailed(body, opts)
	if err != nil {
		return nil, err
	}
	return res.Links, nil
}

// DecodeDetailed is Decode, also reporting the detected format and the
// structured entries that were skipped. On ErrNoSupportedProxies the
// result is still returned so callers can show why.
func DecodeDetailed(body []byte, opts DecodeOptions) (*DecodeResult, error) {
	maxBytes, maxLinks, err := limits(opts)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, ErrTooLarge
	}
	body = trimBody(body)
	if len(body) == 0 {
		return &DecodeResult{Links: []string{}, Format: FormatPlain}, nil
	}
	maxStructured := opts.MaxStructuredBytes
	if maxStructured == 0 {
		maxStructured = DefaultMaxStructuredBytes
	}
	if kind := structuredFormat(body); kind != "" {
		return decodeStructured(body, kind, maxLinks, maxStructured)
	}
	format := FormatPlain
	if !bytes.Contains(body, []byte("://")) {
		// Allow base64 wrapped across lines by subscription providers, and
		// "#" metadata lines around it. "//" is not a comment here: a wrapped
		// base64 line may legitimately start with it.
		var kept strings.Builder
		for _, line := range strings.FieldsFunc(string(body), func(r rune) bool { return r == '\n' || r == '\r' }) {
			if line = strings.TrimSpace(line); !strings.HasPrefix(line, "#") {
				kept.WriteString(line)
			}
		}
		encoded := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, kept.String())
		if encoded == "" {
			return &DecodeResult{Links: []string{}, Format: FormatPlain}, nil
		}
		decoded := false
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(encoded); err == nil {
				body = trimBody(b)
				decoded = true
				break
			}
		}
		if !decoded {
			return nil, ErrInvalidFormat
		}
		// Some providers base64-encode a whole Clash or JSON config.
		if kind := structuredFormat(body); kind != "" {
			return decodeStructured(body, kind, maxLinks, maxStructured)
		}
		format = FormatBase64
	}
	if !utf8.Valid(body) {
		return nil, ErrInvalidFormat
	}
	links := make([]string, 0)
	// Split on CR as well as LF: some providers emit classic-Mac line endings.
	lines := strings.FieldsFunc(string(body), func(r rune) bool { return r == '\n' || r == '\r' })
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Providers prepend metadata such as "#profile-title:" or
		// "#profile-update-interval:"; comments never make a source invalid.
		if line == "" || isComment(line) {
			continue
		}
		scheme, value, ok := strings.Cut(line, "://")
		if !ok || value == "" || !validScheme(scheme) {
			return nil, ErrInvalidFormat
		}
		if len(links) == maxLinks {
			return nil, ErrTooManyLinks
		}
		links = append(links, line)
	}
	return &DecodeResult{Links: links, Format: format}, nil
}

// isComment reports whether a subscription line is metadata or a comment
// rather than a share link.
func isComment(line string) bool {
	return strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//")
}

func trimBody(body []byte) []byte {
	return bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(body), []byte("\xef\xbb\xbf")))
}

func validScheme(s string) bool {
	if s == "" || !asciiLetter(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !asciiLetter(c) && !(c >= '0' && c <= '9') && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func asciiLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func limits(opts DecodeOptions) (int64, int, error) {
	if opts.MaxBytes < 0 || opts.MaxLinks < 0 || opts.MaxStructuredBytes < 0 {
		return 0, 0, errors.New("subscription limits must not be negative")
	}
	if opts.MaxBytes == 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.MaxLinks == 0 {
		opts.MaxLinks = DefaultMaxLinks
	}
	return opts.MaxBytes, opts.MaxLinks, nil
}

type FetchOptions struct {
	DecodeOptions
	Method  string // Default GET.
	Headers http.Header
	Timeout time.Duration // Overall request/body deadline; zero defaults to 30s.
}

type FetchResult struct {
	Links        []string
	Format       Format         // detected document format
	Skipped      map[string]int // structured entries skipped, by reason
	StatusCode   int
	NotModified  bool // HTTP 304: preserve the previous source snapshot.
	ETag         string
	LastModified string
}

// Fetch downloads a bounded list; a nil client uses http.DefaultClient.
// The caller's client controls redirects and network access. HTTP 304 preserves the snapshot.
// On ErrNoSupportedProxies the result, with Format and Skipped, is returned alongside the error.
func Fetch(ctx context.Context, client *http.Client, rawURL string, opts FetchOptions) (*FetchResult, error) {
	maxBytes, _, err := limits(opts.DecodeOptions)
	if err != nil {
		return nil, err
	}
	// The extra byte used to detect overflow must itself fit in int64.
	if maxBytes == math.MaxInt64 || opts.Timeout < 0 {
		return nil, errors.New("invalid subscription fetch limits")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("subscription URL must be HTTP or HTTPS with a host")
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	if opts.Method == "" {
		opts.Method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, opts.Method, u.String(), nil)
	if err != nil {
		return nil, errors.New("invalid subscription request")
	}
	if opts.Headers != nil {
		req.Header = opts.Headers.Clone()
	}
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &fetchError{err: err}
	}
	defer resp.Body.Close()
	result := &FetchResult{
		StatusCode:   resp.StatusCode,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}
	if resp.StatusCode == http.StatusNotModified {
		result.NotModified = true
		return result, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("subscription server returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return nil, ErrTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, &fetchError{err: err}
	}
	decoded, err := DecodeDetailed(body, opts.DecodeOptions)
	if decoded != nil {
		result.Links, result.Format, result.Skipped = decoded.Links, decoded.Format, decoded.Skipped
	}
	if err != nil {
		if errors.Is(err, ErrNoSupportedProxies) {
			// Like DecodeDetailed: report the skips with the error.
			return result, err
		}
		return nil, err
	}
	return result, nil
}

// Preserve errors.Is/As (e.g. cancellation) without printing a URL/token from
// net/http's *url.Error or a custom transport's error in ordinary logs.
type fetchError struct{ err error }

func (e *fetchError) Error() string {
	if cause := safeCause(e.err); cause != "" {
		return "subscription request failed: " + cause
	}
	return "subscription request failed"
}
func (e *fetchError) Unwrap() error { return e.err }

// safeCause names the network-level reason for a failed request using only
// error types whose text carries no request URL (a *url.Error, or a custom
// transport or redirect policy error, may embed the tokenized URL).
func safeCause(err error) string {
	var dnsErr *net.DNSError
	var opErr *net.OpError
	var certErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &dnsErr):
		if dnsErr.IsNotFound {
			return "DNS lookup failed: no such host"
		}
		return "DNS lookup failed"
	case errors.As(err, &certErr):
		return "TLS certificate verification failed"
	case errors.As(err, &recordErr):
		return "TLS handshake failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "connection closed by the server"
	case errors.As(err, &opErr):
		return opErr.Op + " failed"
	}
	return ""
}
