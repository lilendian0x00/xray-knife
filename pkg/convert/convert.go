// Package convert exports share links as subscriptions and client configs.
//
// It is the inverse of pkg/subscription's importers and is meant for
// commands and endpoints that publish tested configs (e.g. `subs export`
// or a served /sub/<token> URL). Every function takes the links as they
// are stored (one share link per element) and never contacts the network.
//
//	ToPlain(links)                  one link per line (the universal form)
//	ToBase64(links)                 the same, base64-encoded (v2rayN, Shadowrocket, ...)
//	ToClash(links, ClashOptions)    Clash / mihomo YAML: proxies, a url-test
//	                                group, a select group and a MATCH rule
//	ToSingbox(links, SingboxOptions) sing-box client JSON: one outbound (or
//	                                WireGuard endpoint) per link built with
//	                                xray-knife's sing-box builders, plus
//	                                urltest + selector groups and a mixed inbound
//	ToXray(links)                   xray JSON with one outbound per link,
//	                                built with xray-knife's xray builders
//
// Structured exports return a *Report: links that a target cannot express
// (an xhttp link for sing-box, TUIC for xray, MTProto for anything) are
// skipped with a reason instead of failing the export. When nothing at
// all can be exported the error is ErrNothingToExport and the report
// says why. Proxy names come from the link remarks, made unique by
// suffixing " 2", " 3", ...; empty remarks become "<protocol>-<n>".
//
// The output depends only on the links, so the same input always gives
// the same bytes.
package convert

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// ErrNothingToExport means no input link could be expressed in the
// requested format; the Report lists the reasons.
var ErrNothingToExport = errors.New("none of the links can be exported in this format")

// Skipped is one link left out of an export.
type Skipped struct {
	Index  int    // position in the input slice
	Name   string // the link's remark, when it parsed
	Reason string
}

// Report summarises a structured export.
type Report struct {
	Converted int
	Skipped   []Skipped
}

func (r *Report) skip(index int, name, format string, args ...interface{}) {
	r.Skipped = append(r.Skipped, Skipped{Index: index, Name: name, Reason: fmt.Sprintf(format, args...)})
}

// ToPlain renders links one per line, dropping blank entries.
func ToPlain(links []string) []byte {
	var b strings.Builder
	for _, l := range links {
		if l = strings.TrimSpace(l); l != "" {
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	return []byte(b.String())
}

// ToBase64 renders the plain list as standard padded base64, the
// subscription form most clients expect.
func ToBase64(links []string) []byte {
	plain := ToPlain(links)
	out := make([]byte, base64.StdEncoding.EncodedLen(len(plain)))
	base64.StdEncoding.Encode(out, plain)
	return out
}

// scheme returns a link's lower-cased scheme.
func scheme(link string) string {
	s, _, _ := strings.Cut(strings.TrimSpace(link), "://")
	return strings.ToLower(s)
}

// entry is a parsed input link.
type entry struct {
	index int
	link  string
	name  string
	proto protocol.Protocol
}

// parseAll parses every link with create, skipping blank, MTProto and
// unparsable links into the report.
func parseAll(links []string, r *Report, create func(link string) (protocol.Protocol, error)) []entry {
	var out []entry
	for i, link := range links {
		link = strings.TrimSpace(link)
		if link == "" {
			continue
		}
		p, err := create(link)
		if errors.Is(err, mtproto.ErrNotProxyable) || (err == nil && !protocol.Relays(p)) {
			r.skip(i, "", "MTProto proxies are Telegram-only and cannot be exported")
			continue
		}
		if err != nil {
			r.skip(i, "", "%s: %v", scheme(link), err)
			continue
		}
		if err := p.Parse(); err != nil {
			r.skip(i, "", "%s: %v", scheme(link), err)
			continue
		}
		out = append(out, entry{index: i, link: link, name: p.ConvertToGeneralConfig().Remark, proto: p})
	}
	return out
}

// names hands out unique, non-empty proxy names.
type names map[string]bool

func (n names) take(want, proto string, index int) string {
	want = strings.TrimSpace(want)
	if want == "" {
		want = proto + "-" + strconv.Itoa(index+1)
	}
	name := want
	for i := 2; n[name]; i++ {
		name = want + " " + strconv.Itoa(i)
	}
	n[name] = true
	return name
}

// splitList splits a comma-separated value, trimming blanks.
func splitList(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
