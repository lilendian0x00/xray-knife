package dpi

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

// Failure kinds. They separate "the network dropped us" (the signal DPI
// leaves) from "the server or config is wrong".
const (
	KindTimeout = "timeout" // no answer: silent drop, typical of blackholing DPI
	KindReset   = "reset"   // connection reset: typical of SNI-based RST injection
	KindRefused = "refused" // nothing listening / port blocked with RST on SYN
	KindEOF     = "eof"     // closed mid-handshake
	KindTLS     = "tls"     // handshake or certificate error
	KindDNS     = "dns"     // name resolution failed
	KindHTTP    = "http"    // proxied request answered with an unexpected status
	KindBuild   = "config"  // the link could not be parsed or built
	KindOther   = "other"
)

// Classify maps an error to one of the Kind* constants.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return KindTimeout
	case errors.Is(err, syscall.ECONNRESET):
		return KindReset
	case errors.Is(err, syscall.ECONNREFUSED):
		return KindRefused
	case errors.As(err, &dnsErr):
		return KindDNS
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return KindEOF
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return KindTimeout
	}

	// Cores wrap transport errors in their own types, so fall back to text.
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline exceeded"), strings.Contains(s, "timed out"):
		return KindTimeout
	case strings.Contains(s, "connection reset"), strings.Contains(s, "reset by peer"):
		return KindReset
	case strings.Contains(s, "connection refused"):
		return KindRefused
	case strings.Contains(s, "no such host"), strings.Contains(s, "lookup "):
		return KindDNS
	case strings.Contains(s, "eof"), strings.Contains(s, "closed pipe"), strings.Contains(s, "use of closed"):
		return KindEOF
	case strings.Contains(s, "tls"), strings.Contains(s, "x509"), strings.Contains(s, "certificate"), strings.Contains(s, "handshake"):
		return KindTLS
	}
	return KindOther
}
