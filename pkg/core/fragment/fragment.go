// Package fragment describes the TLS/TCP fragmentation and UDP noise
// applied to the dial between the local core and the proxy server (the
// first hop). Splitting the TLS ClientHello across several TCP segments
// or TLS records hides the SNI from middleboxes that only inspect the
// first packet, which is how most SNI-based DPI in censored networks
// decides to reset a connection.
//
// The same Options value is understood by both cores:
//
//   - xray: a freedom outbound with "fragment"/"noises" settings, wired
//     in front of the proxy outbound through sockopt.dialerProxy (the
//     layout v2rayN and Hiddify use).
//   - sing-box: the TLS "fragment" (TCP segments) and "record_fragment"
//     (TLS records) switches. sing-box picks segment sizes itself, so
//     Length/Interval/MaxSplit/Noises are xray-only.
package fragment

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// PacketsTLSHello fragments only the TLS ClientHello record.
const PacketsTLSHello = "tlshello"

// Range is an inclusive integer range. Min == Max denotes a fixed value.
type Range struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// IsZero reports whether the range is unset.
func (r Range) IsZero() bool { return r.Min == 0 && r.Max == 0 }

// String renders the range in the "min-max" form xray accepts.
func (r Range) String() string {
	if r.Min == r.Max {
		return strconv.Itoa(r.Min)
	}
	return fmt.Sprintf("%d-%d", r.Min, r.Max)
}

// ParseRange parses "N" or "N-M" (inclusive, N <= M, both >= 0).
func ParseRange(s string) (Range, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Range{}, errors.New("empty range")
	}
	lo, hi, found := strings.Cut(s, "-")
	a, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return Range{}, fmt.Errorf("invalid range %q: %w", s, err)
	}
	b := a
	if found {
		b, err = strconv.Atoi(strings.TrimSpace(hi))
		if err != nil {
			return Range{}, fmt.Errorf("invalid range %q: %w", s, err)
		}
	}
	if a < 0 || b < 0 {
		return Range{}, fmt.Errorf("invalid range %q: negative value", s)
	}
	if a > b {
		return Range{}, fmt.Errorf("invalid range %q: min greater than max", s)
	}
	return Range{Min: a, Max: b}, nil
}

// Noise is one xray UDP noise packet sent before the real traffic.
// Type is "rand", "str", "base64" or "hex"; Packet is a length range for
// "rand" or the payload otherwise; Delay is in milliseconds.
type Noise struct {
	Type   string `json:"type"`
	Packet string `json:"packet"`
	Delay  Range  `json:"delay"`
}

// String renders the noise in the "type:packet:delay" form ParseNoise reads.
func (n Noise) String() string {
	return fmt.Sprintf("%s:%s:%s", n.Type, n.Packet, n.Delay)
}

// Options configures fragmentation for the first hop. The zero value (or
// a nil *Options) disables it.
type Options struct {
	// Packets selects what to split: "tlshello" (the ClientHello only)
	// or a TCP write range such as "1-3" (the first writes of the stream).
	Packets string `json:"packets"`
	// Length is the size of each fragment in bytes.
	Length Range `json:"length"`
	// Interval is the pause between fragments in milliseconds.
	Interval Range `json:"interval"`
	// MaxSplit caps how many fragments one write is cut into (xray only,
	// zero means unlimited).
	MaxSplit Range `json:"maxSplit,omitzero"`
	// Noises are UDP noise packets (xray only).
	Noises []Noise `json:"noises,omitempty"`
}

// Enabled reports whether any fragmentation or noise is configured.
func (o *Options) Enabled() bool {
	return o != nil && (o.Packets != "" || len(o.Noises) > 0)
}

// FragmentsTCP reports whether TCP/TLS fragmentation (not just noise) is set.
func (o *Options) FragmentsTCP() bool {
	return o != nil && o.Packets != ""
}

// Validate checks the options for values the cores would reject.
func (o *Options) Validate() error {
	if o == nil {
		return nil
	}
	if o.Packets != "" {
		if !strings.EqualFold(o.Packets, PacketsTLSHello) {
			r, err := ParseRange(o.Packets)
			if err != nil {
				return fmt.Errorf("fragment packets: %w", err)
			}
			if r.Min == 0 {
				return errors.New(`fragment packets: range must start at 1 (or use "tlshello")`)
			}
		}
		if o.Length.IsZero() {
			return errors.New("fragment length is required")
		}
		if o.Length.Min == 0 {
			return errors.New("fragment length must be at least 1 byte")
		}
		if o.Interval.Max > 10_000 {
			return errors.New("fragment interval above 10000ms would stall every handshake")
		}
	}
	for i, n := range o.Noises {
		switch n.Type {
		case "rand", "str", "base64", "hex":
		default:
			return fmt.Errorf("noise %d: unknown type %q (want rand, str, base64 or hex)", i+1, n.Type)
		}
		if n.Packet == "" {
			return fmt.Errorf("noise %d: empty packet", i+1)
		}
		if n.Type == "rand" {
			if _, err := ParseRange(n.Packet); err != nil {
				return fmt.Errorf("noise %d: %w", i+1, err)
			}
		}
	}
	return nil
}

// String renders the fragment part as "packets,length,interval" (the
// form Parse reads), or "" when fragmentation is off.
func (o *Options) String() string {
	if !o.FragmentsTCP() {
		return ""
	}
	return fmt.Sprintf("%s,%s,%s", o.Packets, o.Length, o.Interval)
}

// Parse reads the "packets,length,interval" spec used by v2rayN/Hiddify,
// e.g. "tlshello,100-200,10-20" or "1-3,1-5,1-2". The interval may be
// omitted (no pause). An empty spec or "off"/"none" returns nil.
func Parse(spec string) (*Options, error) {
	spec = strings.TrimSpace(spec)
	switch strings.ToLower(spec) {
	case "", "off", "none", "false", "0":
		return nil, nil
	}
	parts := strings.Split(spec, ",")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("invalid fragment %q: want packets,length[,interval] (e.g. tlshello,100-200,10-20)", spec)
	}
	o := &Options{Packets: strings.ToLower(strings.TrimSpace(parts[0]))}
	var err error
	if o.Length, err = ParseRange(parts[1]); err != nil {
		return nil, fmt.Errorf("invalid fragment length: %w", err)
	}
	if len(parts) == 3 {
		if o.Interval, err = ParseRange(parts[2]); err != nil {
			return nil, fmt.Errorf("invalid fragment interval: %w", err)
		}
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return o, nil
}

// ParseNoise reads "type:packet[:delay]", e.g. "rand:10-20:10-16" or
// "str:hello:5".
func ParseNoise(spec string) (Noise, error) {
	parts := strings.SplitN(strings.TrimSpace(spec), ":", 3)
	if len(parts) < 2 {
		return Noise{}, fmt.Errorf("invalid noise %q: want type:packet[:delay] (e.g. rand:10-20:10-16)", spec)
	}
	n := Noise{Type: strings.ToLower(strings.TrimSpace(parts[0])), Packet: strings.TrimSpace(parts[1])}
	if len(parts) == 3 {
		d, err := ParseRange(parts[2])
		if err != nil {
			return Noise{}, fmt.Errorf("invalid noise delay: %w", err)
		}
		n.Delay = d
	}
	o := Options{Noises: []Noise{n}}
	if err := o.Validate(); err != nil {
		return Noise{}, err
	}
	return n, nil
}

// Build combines a fragment spec and noise specs (as given on the command
// line) into Options. It returns nil when both are empty.
func Build(fragmentSpec string, noiseSpecs []string) (*Options, error) {
	o, err := Parse(fragmentSpec)
	if err != nil {
		return nil, err
	}
	for _, s := range noiseSpecs {
		if strings.TrimSpace(s) == "" {
			continue
		}
		n, err := ParseNoise(s)
		if err != nil {
			return nil, err
		}
		if o == nil {
			o = &Options{}
		}
		o.Noises = append(o.Noises, n)
	}
	return o, nil
}

// Clone returns a deep copy (nil-safe).
func (o *Options) Clone() *Options {
	if o == nil {
		return nil
	}
	c := *o
	c.Noises = append([]Noise(nil), o.Noises...)
	return &c
}
