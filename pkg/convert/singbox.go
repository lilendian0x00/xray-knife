package convert

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"net/netip"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// SingboxOptions shapes the sing-box document. Zero values pick the
// defaults noted on each field.
type SingboxOptions struct {
	ListenAddress string        // mixed inbound address, default 127.0.0.1
	ListenPort    uint16        // mixed inbound port, default 2080
	SelectTag     string        // selector tag, default "proxy"
	AutoTag       string        // urltest tag, default "auto"
	TestURL       string        // urltest probe, default https://www.gstatic.com/generate_204
	TestInterval  time.Duration // urltest interval, default 5m
	// InsecureTLS skips certificate verification on every exported TLS
	// outbound (as --insecure does when testing).
	InsecureTLS bool
}

func (o *SingboxOptions) defaults() {
	if o.ListenAddress == "" {
		o.ListenAddress = "127.0.0.1"
	}
	if o.ListenPort == 0 {
		o.ListenPort = 2080
	}
	if o.SelectTag == "" {
		o.SelectTag = "proxy"
	}
	if o.AutoTag == "" {
		o.AutoTag = "auto"
	}
	if o.TestURL == "" {
		o.TestURL = "https://www.gstatic.com/generate_204"
	}
	if o.TestInterval == 0 {
		o.TestInterval = 5 * time.Minute
	}
}

// ToSingbox renders links as a sing-box client config. Outbounds come
// from xray-knife's sing-box builders, so an exported config behaves like
// the one xray-knife tests with. The output does not depend on how this
// binary was built: REALITY and uTLS fingerprints are kept even without
// the with_utls tag (the config is for a full sing-box).
func ToSingbox(links []string, opts SingboxOptions) ([]byte, *Report, error) {
	opts.defaults()
	listen, err := netip.ParseAddr(opts.ListenAddress)
	if err != nil {
		return nil, nil, err
	}
	r := &Report{}
	sc := singbox.NewSingboxService(false, opts.InsecureTLS)
	entries := parseAll(links, r, sc.CreateProtocol)

	used := names{opts.SelectTag: true, opts.AutoTag: true, "direct": true}
	var outbounds []option.Outbound
	var endpoints []option.Endpoint
	var tags []string
	for _, e := range entries {
		sp, ok := e.proto.(singbox.Protocol)
		if !ok {
			r.skip(e.index, e.name, "not a sing-box protocol")
			continue
		}
		out, err := singbox.CraftOutboundOptionsFor(sp, opts.InsecureTLS, true)
		if err != nil {
			r.skip(e.index, e.name, "%v", err)
			continue
		}
		out.Tag = used.take(e.name, sp.Name(), e.index)
		if wg, isEndpoint := out.Options.(*option.WireGuardEndpointOptions); isEndpoint {
			endpoints = append(endpoints, option.Endpoint{Type: out.Type, Tag: out.Tag, Options: wg})
		} else {
			outbounds = append(outbounds, *out)
		}
		tags = append(tags, out.Tag)
	}
	r.Converted = len(tags)
	if len(tags) == 0 {
		return nil, r, ErrNothingToExport
	}

	groups := []option.Outbound{
		{Type: C.TypeSelector, Tag: opts.SelectTag, Options: &option.SelectorOutboundOptions{
			Outbounds: append([]string{opts.AutoTag}, tags...),
			Default:   opts.AutoTag,
		}},
		{Type: C.TypeURLTest, Tag: opts.AutoTag, Options: &option.URLTestOutboundOptions{
			Outbounds: tags,
			URL:       opts.TestURL,
			Interval:  badoption.Duration(opts.TestInterval),
		}},
	}
	outbounds = append(groups, outbounds...)
	outbounds = append(outbounds, option.Outbound{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}})

	addr := badoption.Addr(listen)
	doc := option.Options{
		Log: &option.LogOptions{Level: "warn"},
		Inbounds: []option.Inbound{{
			Type: C.TypeMixed,
			Tag:  "mixed-in",
			Options: &option.HTTPMixedInboundOptions{
				ListenOptions: option.ListenOptions{Listen: &addr, ListenPort: opts.ListenPort},
			},
		}},
		Outbounds: outbounds,
		Endpoints: endpoints,
		Route:     &option.RouteOptions{Final: opts.SelectTag},
	}
	raw, err := json.MarshalContext(context.Background(), &doc)
	if err != nil {
		return nil, r, err
	}
	var pretty bytes.Buffer
	if err := stdjson.Indent(&pretty, raw, "", "  "); err != nil {
		return nil, r, err
	}
	pretty.WriteByte('\n')
	return pretty.Bytes(), r, nil
}
