package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/utils"

	"github.com/fatih/color"
	"github.com/xtls/xray-core/infra/conf"
)

func NewVmess(link string) Protocol {
	return &Vmess{OrigLink: link}
}

func (v *Vmess) Name() string {
	return "vmess"
}

// method1 parses the common form: base64 of a v2rayN JSON object.
func method1(v *Vmess, link string) error {
	base, remark := splitRemark(link)
	b64encoded := strings.TrimPrefix(base, protocol.VmessIdentifier+"://")
	if b64encoded == "" {
		return fmt.Errorf("vmess link too short: %s", link)
	}
	decoded, err := utils.Base64Decode(b64encoded)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(decoded, v); err != nil {
		return err
	}

	// SNI & HOST Validation
	if !validHostList(strings.TrimSpace(v.Host)) {
		return fmt.Errorf("invalid characters in 'host' parameter: %q", v.Host)
	}
	if !validSNI(strings.TrimSpace(v.SNI)) {
		return fmt.Errorf("invalid characters in 'sni' parameter: %q", v.SNI)
	}
	v.Host = strings.TrimSpace(v.Host)
	v.SNI = strings.TrimSpace(v.SNI)
	v.Address = unbracket(strings.TrimSpace(v.Address))
	if v.Remark == "" {
		v.Remark = remark
	}
	return nil
}

// Example:
// vmess://YXV0bzpjYmI0OTM1OC00NGQxLTQ4MmYtYWExNC02ODA3NzNlNWNjMzdAc25hcHBmb29kLmlyOjQ0Mw?remarks=sth&obfsParam=huhierg.com&path=/&obfs=websocket&tls=1&peer=gdfgreg.com&alterId=0
func method2(v *Vmess, link string) error {
	link, _ = splitRemark(link)
	uri, err := url.Parse(link)
	if err != nil {
		return err
	}
	decoded, err := utils.Base64Decode(uri.Host)
	if err != nil {
		return err
	}
	link = protocol.VmessIdentifier + "://" + string(decoded) + "?" + uri.RawQuery

	uri, err = url.Parse(link)
	if err != nil {
		return err
	}

	v.Security = uri.User.Username()
	v.ID, _ = uri.User.Password()

	v.Address, v.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	queryValues := uri.Query()
	if value := queryValues.Get("remarks"); value != "" {
		v.Remark = value
	}

	if value := queryValues.Get("path"); value != "" {
		v.Path = value
	}

	if value := queryValues.Get("tls"); value == "1" {
		v.TLS = "tls"
	}

	if value := queryValues.Get("obfs"); value != "" {
		switch value {
		case "websocket":
			v.Network = "ws"
			v.Type = "none"
		case "none":
			v.Network = "tcp"
			v.Type = "none"
		}
	}
	host := ""
	if value := queryValues.Get("obfsParam"); value != "" {
		host = value
	}
	sni := ""
	if value := queryValues.Get("peer"); value != "" {
		sni = value
	} else {
		if v.TLS == "tls" {
			sni = host
		}
	}

	// SNI & HOST Validation
	if !validHostList(host) {
		return fmt.Errorf("invalid characters in 'host' parameter: %q", host)
	}
	v.Host = host

	if !validSNI(sni) {
		return fmt.Errorf("invalid characters in 'sni' parameter: %q", sni)
	}
	v.SNI = sni

	return nil
}

//func method3(v *Vmess, link string) error {
//
//}

func (v *Vmess) Parse() error {
	if !strings.HasPrefix(v.OrigLink, protocol.VmessIdentifier) {
		return fmt.Errorf("vmess unreconized: %s", v.OrigLink)
	}

	if err1 := method1(v, v.OrigLink); err1 != nil {
		// Start from a clean struct: method1 may have partially filled it.
		*v = Vmess{OrigLink: v.OrigLink, CertFile: v.CertFile, KeyFile: v.KeyFile}
		if err2 := method2(v, v.OrigLink); err2 != nil {
			return fmt.Errorf("invalid vmess link: not base64 JSON (%v) nor legacy form (%v)", err1, err2)
		}
	}

	if v.Type == "xhttp" || v.Type == "http" || v.Network == "ws" || v.Network == "h2" {
		if v.Path == "" {
			v.Path = "/"
		}
	}

	// Default the transport network to "tcp" when unset, mirroring VLESS/Trojan.
	// An empty network makes conf.TransportProtocol.Build() hard-error.
	if v.Network == "" {
		v.Network = "tcp"
	}

	return nil
}

func (v *Vmess) DetailsStr() string {
	copyV := *v
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n",
		color.RedString("Protocol"), v.Name(),
		color.RedString("Remark"), copyV.Remark,
		color.RedString("Network"), copyV.Network,
		color.RedString("Address"), copyV.Address,
		color.RedString("Port"), copyV.Port,
		color.RedString("UUID"), copyV.ID)

	if copyV.Network == "" {

	} else if copyV.Type == "xhttp" || copyV.Type == "http" || copyV.Network == "httpupgrade" || copyV.Network == "ws" || copyV.Network == "h2" {
		if copyV.Type == "" {
			copyV.Type = "none"
		}
		if copyV.Host == "" {
			copyV.Host = "none"
		}
		if copyV.Path == "" {
			copyV.Path = "none"
		}

		info += fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n",
			color.RedString("Type"), copyV.Type,
			color.RedString("Host"), copyV.Host,
			color.RedString("Path"), copyV.Path)
	} else if copyV.Network == "kcp" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("KCP Seed"), copyV.Path)
	} else if copyV.Network == "grpc" {
		if copyV.Host == "" {
			copyV.Host = "none"
		}
		info += fmt.Sprintf("%s: %s\n%s: %s\n",
			color.RedString("ServiceName"), copyV.Path,
			color.RedString("Authority"), copyV.Host)
	}

	if len(copyV.TLS) != 0 && copyV.TLS != "none" {
		if len(copyV.SNI) == 0 {
			if copyV.Host != "" {
				copyV.SNI = copyV.Host
			} else {
				copyV.SNI = "none"
			}
		}
		if len(copyV.ALPN) == 0 {
			copyV.ALPN = "none"
		}
		if len(copyV.TlsFingerprint) == 0 {
			copyV.TlsFingerprint = "none"
		}
		info += fmt.Sprintf("%s: tls\n%s: %s\n%s: %s\n%s: %s\n",
			color.RedString("TLS"),
			color.RedString("SNI"), copyV.SNI,
			color.RedString("ALPN"), copyV.ALPN,
			color.RedString("Fingerprint"), copyV.TlsFingerprint)

		if truthy(v.AllowInsecure) {
			info += fmt.Sprintf("%s: true\n", color.RedString("Insecure"))
		}
		if v.PinnedPeerCertSha256 != "" {
			info += fmt.Sprintf("%s: %s\n",
				color.RedString("Pinned cert"), v.PinnedPeerCertSha256)
		}
	}
	return info
}

func (v *Vmess) GetLink() string {
	return v.OrigLink
}

func (v *Vmess) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = v.Name()
	g.Address = v.Address
	g.Aid = portString(v.Aid)
	g.Host = v.Host
	g.ID = v.ID
	g.Network = v.Network
	g.Path = v.Path
	g.Port = portString(v.Port)
	g.Remark = v.Remark
	if v.TLS == "" {
		g.TLS = "none"
	} else {
		g.TLS = v.TLS
	}
	g.SNI = v.SNI
	g.ALPN = v.ALPN
	g.TlsFingerprint = v.TlsFingerprint
	g.Type = v.Type
	g.OrigLink = v.GetLink()

	return g
}

// transport maps the VMess JSON fields onto the shared stream builders.
// VMess overloads "type": the TCP header type, the xhttp mode or the gRPC
// mode; for gRPC "path" is the service name and "host" the authority.
func (v *Vmess) transport() transportSpec {
	ts := transportSpec{
		Network:              v.Network,
		Host:                 v.Host,
		Path:                 v.Path,
		Security:             v.TLS,
		SNI:                  v.SNI,
		ALPN:                 v.ALPN,
		Fingerprint:          v.TlsFingerprint,
		PinnedPeerCertSha256: v.PinnedPeerCertSha256,
		VerifyPeerCertByName: v.VerifyPeerCertByName,
		ECHConfigList:        v.ECHConfigList,
	}
	switch ts.network() {
	case "tcp", "raw":
		ts.HeaderType = v.Type
	case "xhttp":
		ts.Mode = v.Type
	case "grpc":
		ts.Mode = v.Type
		ts.ServiceName = v.Path
		ts.Authority = v.Host
	}
	return ts
}

// wantsInsecure reports whether the link asks to skip certificate checks.
func (v *Vmess) wantsInsecure() bool { return truthy(v.AllowInsecure) }

// alterID returns the numeric alterId (0 when absent or malformed).
func (v *Vmess) alterID() uint64 {
	n, err := strconv.ParseUint(portString(v.Aid), 10, 32)
	if err != nil {
		return 0
	}
	return n
}

func (v *Vmess) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	ts := v.transport()
	if ts.security() == "reality" {
		return nil, fmt.Errorf("vmess does not support REALITY")
	}
	s, err := ts.outboundStream()
	if err != nil {
		return nil, err
	}

	// Build Settings via json.Marshal on a typed map so addresses/IDs
	// containing special chars cannot corrupt the JSON output.
	portNum, err := parsePort(portString(v.Port))
	if err != nil {
		return nil, err
	}
	security := v.Security
	if security == "" {
		security = "auto"
	}
	settingsBytes, err := json.Marshal(map[string]interface{}{
		"vnext": []map[string]interface{}{
			{
				"address": v.Address,
				"port":    portNum,
				"users": []map[string]interface{}{
					{
						"id":       v.ID,
						"alterId":  v.alterID(),
						"security": security,
					},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal vmess settings: %w", err)
	}
	oset := json.RawMessage(settingsBytes)
	return &conf.OutboundDetourConfig{
		Tag:           "proxy",
		Protocol:      v.Name(),
		Settings:      &oset,
		StreamSetting: s,
	}, nil
}

func (v *Vmess) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	ts := v.transport()
	stream, err := ts.inboundStream(v.CertFile, v.KeyFile)
	if err != nil {
		return nil, err
	}
	settings := map[string]interface{}{
		"clients": []map[string]interface{}{{
			"id":      v.ID,
			"alterId": v.alterID(),
		}},
	}
	return inboundDetour(v.Name(), v.Address, portString(v.Port), settings, stream)
}
