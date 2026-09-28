package dpi

import (
	"fmt"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
)

// Profile is one candidate setting the finder tries: a fragment (nil means
// "no fragmentation", the baseline) and optionally an SNI override.
type Profile struct {
	// Name is a short human label, e.g. "baseline" or "tlshello 100-200 / 10-20ms".
	Name string `json:"name"`
	// Spec is the --fragment value that reproduces this profile ("" for none).
	Spec string `json:"spec"`
	// Fragment is the parsed fragment (nil for none).
	Fragment *fragment.Options `json:"fragment,omitempty"`
	// SNI replaces the link's SNI when non-empty.
	SNI string `json:"sni,omitempty"`
	// Args is Flags() precomputed for JSON consumers (the web UI copies it).
	Args string `json:"args,omitempty"`
}

// Flags renders the command-line flags that reproduce the profile's
// fragment and noise settings, e.g. "--fragment tlshello,100-200,10-20" or
// "--noise rand:10-20:10-16" ("" for the baseline). The SNI override is not
// a flag: it has to be set in the link.
func (p Profile) Flags() string {
	if p.Fragment == nil {
		return ""
	}
	var parts []string
	if spec := p.Fragment.String(); spec != "" {
		parts = append(parts, "--fragment "+spec)
	}
	for _, n := range p.Fragment.Noises {
		parts = append(parts, "--noise "+n.String())
	}
	return strings.Join(parts, " ")
}

// Label renders the profile for tables: the fragment spec plus the SNI.
func (p Profile) Label() string {
	s := p.Name
	if p.SNI != "" {
		s += " [sni " + p.SNI + "]"
	}
	return s
}

// Mode picks how many fragment candidates to generate.
type Mode string

const (
	// ModeQuick tries a dozen settings that work on most SNI filters.
	ModeQuick Mode = "quick"
	// ModeFull tries the whole packets × length × interval grid.
	ModeFull Mode = "full"
)

// ParseMode accepts "quick"/"full" (case-insensitive, "" = quick).
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "quick":
		return ModeQuick, nil
	case "full":
		return ModeFull, nil
	default:
		return "", fmt.Errorf("unknown mode %q (want quick or full)", s)
	}
}

// quickSpecs are fragment settings commonly reported working against SNI
// filtering (v2rayN/Hiddify defaults and community-tested values), ordered
// from gentle (cheap) to aggressive (slow).
var quickSpecs = []string{
	"tlshello,100-200,10-20",
	"tlshello,200-400,5-10",
	"tlshello,50-100,1-5",
	"tlshello,10-20,10-20",
	"tlshello,5-10,1-2",
	"tlshello,1-5,1-3",
	"1-1,40-60,1-3",
	"1-2,10-20,10-20",
	"1-3,1-5,1-2",
	"1-3,3-5,5-10",
	"1-5,1-1,1-1",
}

var (
	fullPackets   = []string{"tlshello", "1-1", "1-3"}
	fullLengths   = []string{"1-3", "5-10", "10-20", "50-100", "100-200", "200-400"}
	fullIntervals = []string{"0", "1-3", "10-20", "30-50"}
)

// singboxSpecs covers what sing-box can express: it only has on/off switches
// for TCP-segment and TLS-record fragmentation, so length/interval grids
// collapse to these two.
var singboxSpecs = []string{"1-3,1-1", "tlshello,1-1"}

// Specs returns the fragment specs for a mode.
func Specs(mode Mode) []string {
	if mode != ModeFull {
		return append([]string(nil), quickSpecs...)
	}
	out := make([]string, 0, len(fullPackets)*len(fullLengths)*len(fullIntervals))
	for _, p := range fullPackets {
		for _, l := range fullLengths {
			for _, i := range fullIntervals {
				out = append(out, p+","+l+","+i)
			}
		}
	}
	return out
}

// BuildProfiles turns fragment specs and SNI overrides into the candidate
// list. The baseline (no fragment, original SNI) always comes first so the
// report can tell "DPI in the way" from "server down". Each SNI override
// is tried both without a fragment and with every spec.
func BuildProfiles(specs []string, snis []string) ([]Profile, error) {
	frags := []Profile{{Name: "baseline"}}
	seen := map[string]bool{"": true}
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		o, err := fragment.Parse(spec)
		if err != nil {
			return nil, err
		}
		if o == nil {
			// "none"/"off" is the baseline, which is already included.
			continue
		}
		key := o.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		frags = append(frags, Profile{Name: describe(o), Spec: key, Fragment: o})
	}

	out := append([]Profile(nil), frags...)
	for _, sni := range snis {
		sni = strings.TrimSpace(sni)
		if sni == "" {
			continue
		}
		for _, f := range frags {
			p := f
			p.Fragment = f.Fragment.Clone()
			p.SNI = sni
			out = append(out, p)
		}
	}
	return out, nil
}

func describe(o *fragment.Options) string {
	s := o.Packets + " " + o.Length.String()
	if !o.Interval.IsZero() {
		s += " / " + o.Interval.String() + "ms"
	}
	return s
}

// gentleness orders equally good profiles: fewer, larger fragments with
// shorter pauses cost less per handshake, so they are preferred.
func gentleness(p Profile) int {
	if p.Fragment == nil {
		return 1 << 30
	}
	score := p.Fragment.Length.Min*10 - p.Fragment.Interval.Max
	if p.Fragment.Packets == fragment.PacketsTLSHello {
		// Splitting only the hello leaves the rest of the stream intact.
		score += 5000
	}
	return score
}
