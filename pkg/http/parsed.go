package http

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// ParsedLink is a share link parsed once and shared by semantic dedup, the
// TCP prescan and the test itself, instead of each stage parsing it again.
//
// A batch holds one per link until the link is tested; the test releases the
// parsed protocol (see release), so memory tracks the links still pending
// rather than the whole input.
type ParsedLink struct {
	// Link is the share link as given to ParseLink.
	Link string
	// Proto is the parsed protocol, nil when parsing failed (or once the
	// link has been tested and released).
	Proto protocol.Protocol
	// Err is the create/parse failure, worded as the test reports it.
	Err error

	parsed bool // false: parse lazily on first use (RunTests' string path)
}

// ParseLink creates and parses one link. A parser panic is confined to this
// link and reported as its parse error.
func ParseLink(c core.Core, link string) *ParsedLink {
	pl := &ParsedLink{Link: link}
	pl.parse(c)
	return pl
}

func (pl *ParsedLink) parse(c core.Core) {
	pl.parsed = true
	trimmed := strings.TrimSpace(pl.Link)
	if trimmed == "" {
		pl.Err = errors.New("config link is empty")
		return
	}
	defer func() {
		if p := recover(); p != nil {
			pl.Proto = nil
			pl.Err = fmt.Errorf("parse protocol: internal error: %v", p)
		}
	}()
	proto, err := c.CreateProtocol(trimmed)
	if err != nil {
		pl.Err = fmt.Errorf("create protocol: %v", err)
		return
	}
	if err := proto.Parse(); err != nil {
		pl.Err = fmt.Errorf("parse protocol: %v", err)
		return
	}
	pl.Proto = proto
}

// ensureParsed parses a lazily created link on first use.
func (pl *ParsedLink) ensureParsed(c core.Core) {
	if !pl.parsed {
		pl.parse(c)
	}
}

// release drops the parsed protocol once the link is done with. The result
// keeps its own reference if a caller needs it.
func (pl *ParsedLink) release() {
	pl.Proto = nil
}

// ParseLinks parses every non-empty link (trimmed) once, in order.
func ParseLinks(c core.Core, links []string) []*ParsedLink {
	out := make([]*ParsedLink, 0, len(links))
	for _, link := range links {
		trimmed := strings.TrimSpace(link)
		if trimmed == "" {
			continue
		}
		out = append(out, ParseLink(c, trimmed))
	}
	return out
}

// unparsedLinks wraps links for lazy parsing, so string-based callers keep
// their old memory profile (each link parsed by the worker that tests it).
func unparsedLinks(links []string) []*ParsedLink {
	out := make([]*ParsedLink, len(links))
	for i, link := range links {
		out[i] = &ParsedLink{Link: link}
	}
	return out
}

// LinksOf returns the links of parsed, in order.
func LinksOf(parsed []*ParsedLink) []string {
	out := make([]string, len(parsed))
	for i, pl := range parsed {
		out[i] = pl.Link
	}
	return out
}

// SemanticDeduplicateParsed keeps the first link for each connection
// fingerprint, reusing the parsed protocols. Links that failed to parse are
// kept (deduplicated by exact text) so the test can report them.
func SemanticDeduplicateParsed(parsed []*ParsedLink) ([]*ParsedLink, int) {
	seen := make(map[string]struct{}, len(parsed))
	unique := make([]*ParsedLink, 0, len(parsed))
	removed := 0
	for _, pl := range parsed {
		key := "raw:" + strings.TrimSpace(pl.Link) // fallback for unparseable links
		if pl.Proto != nil {
			if fingerprint, err := core.FingerprintProtocol(pl.Proto); err == nil {
				key = fingerprint
			}
		}
		if _, exists := seen[key]; exists {
			removed++
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, pl)
	}
	return unique, removed
}
