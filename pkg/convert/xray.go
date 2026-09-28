package convert

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"

	"github.com/xtls/xray-core/infra/conf"
)

// ToXray renders links as an xray config holding one outbound per link
// (tagged with the proxy name; the first is xray's default route), built
// with xray-knife's xray builders; HTTP(S) proxies become xray "http"
// outbounds. Protocols only sing-box implements (TUIC, AnyTLS, Hysteria
// v1, SSH) are skipped.
func ToXray(links []string) ([]byte, *Report, error) {
	r := &Report{}
	xc := xray.NewXrayService(false, false)
	sc := singbox.NewSingboxService(false, false)
	entries := parseAll(links, r, func(link string) (protocol.Protocol, error) {
		switch scheme(link) {
		case protocol.HTTPIdentifier, protocol.HTTPSIdentifier:
			return sc.CreateProtocol(link)
		}
		return xc.CreateProtocol(link)
	})

	used := names{}
	var outbounds []interface{}
	for _, e := range entries {
		var ob *conf.OutboundDetourConfig
		var err error
		switch p := e.proto.(type) {
		case xray.Protocol:
			ob, err = p.BuildOutboundDetourConfig(false)
		case *singbox.HTTPProxy:
			ob, err = xrayHTTPOutbound(p)
		default:
			r.skip(e.index, e.name, "not an xray protocol")
			continue
		}
		if err == nil {
			// The config must also build: that is where xray rejects
			// removed transports and bad settings.
			_, err = ob.Build()
		}
		if err != nil {
			r.skip(e.index, e.name, "%v", err)
			continue
		}
		ob.Tag = used.take(e.name, e.proto.ConvertToGeneralConfig().Protocol, e.index)
		raw, err := json.Marshal(ob)
		if err != nil {
			r.skip(e.index, e.name, "%v", err)
			continue
		}
		var generic interface{}
		if err := json.Unmarshal(raw, &generic); err != nil {
			r.skip(e.index, e.name, "%v", err)
			continue
		}
		outbounds = append(outbounds, prune(generic))
	}
	r.Converted = len(outbounds)
	if len(outbounds) == 0 {
		return nil, r, ErrNothingToExport
	}
	out, err := json.MarshalIndent(map[string]interface{}{"outbounds": outbounds}, "", "  ")
	if err != nil {
		return nil, r, err
	}
	return append(out, '\n'), r, nil
}

// xrayHTTPOutbound builds xray's HTTP proxy outbound (HTTPS: TLS stream).
func xrayHTTPOutbound(h *singbox.HTTPProxy) (*conf.OutboundDetourConfig, error) {
	port, err := strconv.ParseUint(h.Port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q", h.Port)
	}
	server := map[string]interface{}{"address": h.Address, "port": port}
	if h.Username != "" || h.Password != "" {
		server["users"] = []map[string]string{{"user": h.Username, "pass": h.Password}}
	}
	raw, err := json.Marshal(map[string]interface{}{"servers": []interface{}{server}})
	if err != nil {
		return nil, err
	}
	msg := json.RawMessage(raw)
	ob := &conf.OutboundDetourConfig{Protocol: "http", Settings: &msg}
	if h.TLS {
		fp := h.TlsFingerprint
		if fp == "" {
			fp = "chrome" // what xray-knife's own TLS builders default to
		}
		network := conf.TransportProtocol("tcp")
		ob.StreamSetting = &conf.StreamConfig{
			Network:  &network,
			Security: "tls",
			TLSSettings: &conf.TLSConfig{
				ServerName:  h.SNI,
				Fingerprint: fp,
			},
		}
		if alpn := splitList(h.ALPN); len(alpn) > 0 {
			l := conf.StringList(alpn)
			ob.StreamSetting.TLSSettings.ALPN = &l
		}
	}
	return ob, nil
}

// prune drops null, false, zero, empty-string and empty-container object
// members that marshalling xray's config structs leaves behind; xray
// treats every one of them as its default.
func prune(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			child = prune(child)
			if isEmpty(child) {
				delete(t, k)
			} else {
				t[k] = child
			}
		}
		return t
	case []interface{}:
		// Keep every element: a list's zeros can matter (WireGuard
		// "reserved": [1, 0, 3]).
		for i, child := range t {
			t[i] = prune(child)
		}
		return t
	}
	return v
}

func isEmpty(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return true
	case bool:
		return !t
	case float64:
		return t == 0
	case string:
		return t == ""
	case map[string]interface{}:
		return len(t) == 0
	case []interface{}:
		return len(t) == 0
	}
	return false
}
