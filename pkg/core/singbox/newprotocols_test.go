package singbox

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"golang.org/x/crypto/ssh"
)

func TestTuicParse(t *testing.T) {
	c := NewSingboxService(false, false)
	cases := []struct {
		name, link string
		check      func(t *testing.T, p *Tuic)
		wantErr    string
	}{
		{name: "v2rayN", link: "tuic://" + testUUID + ":pw@example.com:443?sni=a.com&alpn=h3&congestion_control=bbr#name", check: func(t *testing.T, p *Tuic) {
			if p.UUID != testUUID || p.Password != "pw" || p.SNI != "a.com" || p.CongestionControl != "bbr" || p.Remark != "name" {
				t.Errorf("%+v", p)
			}
		}},
		{name: "nekobox", link: "tuic://" + testUUID + ":p%40ss@1.2.3.4:8443?congestion_control=cubic&udp_relay_mode=quic&allow_insecure=1&disable_sni=1&alpn=h3,spdy/3.1", check: func(t *testing.T, p *Tuic) {
			if p.Password != "p@ss" || p.UDPRelayMode != "quic" || !p.Insecure || !p.DisableSNI || p.ALPN != "h3,spdy/3.1" {
				t.Errorf("%+v", p)
			}
		}},
		{name: "hiddify aliases", link: "tuic://" + testUUID + ":pw@[2001:db8::1]:443?insecure=true&congestion-control=new-reno&peer=b.com&reduce_rtt=1", check: func(t *testing.T, p *Tuic) {
			if p.Address != "2001:db8::1" || !p.Insecure || p.CongestionControl != "new_reno" || p.SNI != "b.com" || !p.ZeroRTT {
				t.Errorf("%+v", p)
			}
		}},
		{name: "v4 token", link: "tuic://token@1.2.3.4:443", wantErr: "v4"},
		{name: "bad congestion control", link: "tuic://" + testUUID + ":pw@1.2.3.4:443?congestion_control=vegas", wantErr: "congestion"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := c.CreateProtocol(tc.link)
			if err != nil {
				t.Fatal(err)
			}
			err = p.Parse()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, p.(*Tuic))
		})
	}
	// ALPN defaults to h3; QUIC cannot negotiate without one.
	p := parseLink(t, c, "tuic://"+testUUID+":pw@1.2.3.4:443").(*Tuic)
	out, err := p.CraftOutboundOptions(false)
	if err != nil {
		t.Fatal(err)
	}
	if tls := out.Options.(*option.TUICOutboundOptions).TLS; strings.Join(tls.ALPN, ",") != "h3" || tls.UTLS != nil {
		t.Fatalf("TLS = %+v", tls)
	}
}

func TestHysteriaParse(t *testing.T) {
	c := NewSingboxService(false, false)
	h := parseLink(t, c, "hysteria://example.com:443?protocol=udp&auth=secret&peer=a.com&insecure=1&upmbps=100&downmbps=200&alpn=hysteria&obfs=xplus&obfsParam=ob#v1").(*Hysteria)
	if h.Auth != "secret" || h.SNI != "a.com" || !h.Insecure || h.UpMbps != 100 || h.DownMbps != 200 || h.ObfsPassword != "ob" || h.Remark != "v1" {
		t.Fatalf("%+v", h)
	}
	h = parseLink(t, c, "hysteria://pw@[2001:db8::1]:443,5000-5002?obfs=legacypw&sni=b.com").(*Hysteria)
	if h.Address != "2001:db8::1" || h.Auth != "pw" || h.ObfsPassword != "legacypw" || h.SNI != "b.com" ||
		h.UpMbps != defaultHysteriaUpMbps || h.DownMbps != defaultHysteriaDownMbps ||
		strings.Join(h.ServerPorts, ",") != "443:443,5000:5002" {
		t.Fatalf("%+v", h)
	}
	h = parseLink(t, c, "hysteria://1.2.3.4:443?auth_str=x&mport=6000-6010&up=30%20Mbps").(*Hysteria)
	if h.SNI != "1.2.3.4" || h.UpMbps != 30 || strings.Join(h.ServerPorts, ",") != "443:443,6000:6010" {
		t.Fatalf("%+v", h)
	}
	for _, bad := range []string{
		"hysteria://1.2.3.4:443?protocol=faketcp&auth=x",
		"hysteria://1.2.3.4:443?upmbps=-1",
		"hysteria://1.2.3.4?auth=x",
	} {
		p, err := c.CreateProtocol(bad)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Parse(); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestAnyTLSParse(t *testing.T) {
	c := NewSingboxService(false, false)
	a := parseLink(t, c, "anytls://p%40ss@example.com:443/?sni=a.com&insecure=1&fp=firefox&alpn=h2#any").(*AnyTLS)
	if a.Password != "p@ss" || a.SNI != "a.com" || !a.Insecure || a.TlsFingerprint != "firefox" || a.Security != "tls" || a.Remark != "any" {
		t.Fatalf("%+v", a)
	}
	a = parseLink(t, c, "anytls://pw@[::1]:443?security=reality&pbk=k&sid=ab&peer=b.com&allowInsecure=1").(*AnyTLS)
	if a.Address != "::1" || a.Security != "reality" || a.PublicKey != "k" || a.ShortID != "ab" || a.SNI != "b.com" || !a.Insecure {
		t.Fatalf("%+v", a)
	}
	for _, bad := range []string{"anytls://@1.2.3.4:443", "anytls://pw@1.2.3.4:443?security=none"} {
		p, _ := c.CreateProtocol(bad)
		if err := p.Parse(); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	// AnyTLS is TLS over TCP, so fragmentation applies to it.
	f, _ := fragment.Parse("tlshello,10-20,1")
	fc := NewSingboxService(false, false, WithFragment(f))
	out, err := fc.craftOutbound(parseLink(t, fc, "anytls://pw@1.2.3.4:443?sni=a.com"), "x", true)
	if err != nil {
		t.Fatal(err)
	}
	if tls := out.Options.(*option.AnyTLSOutboundOptions).TLS; !tls.Fragment || !tls.RecordFragment {
		t.Fatalf("anytls TLS not fragmented: %+v", tls)
	}
	// QUIC protocols are left alone.
	for _, link := range []string{"tuic://" + testUUID + ":pw@1.2.3.4:443", "hysteria://1.2.3.4:443?auth=x"} {
		out, err := fc.craftOutbound(parseLink(t, fc, link), "x", true)
		if err != nil {
			t.Fatal(err)
		}
		if tls := out.Options.(option.OutboundTLSOptionsWrapper).TakeOutboundTLSOptions(); tls.Fragment {
			t.Errorf("%s: QUIC TLS fragmented", link)
		}
	}
}

// testSSHKey returns an ed25519 key as OpenSSH PEM plus its signer.
func testSSHKey(t *testing.T) (string, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block)), signer
}

func TestSSHParseVariants(t *testing.T) {
	c := NewSingboxService(false, false)
	pemKey, signer := testSSHKey(t)
	hostKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	s := parseLink(t, c, "ssh://admin:p%40ss@example.com:2222#box").(*SSH)
	if s.User != "admin" || s.Password != "p@ss" || s.Port != "2222" || s.Remark != "box" {
		t.Fatalf("%+v", s)
	}
	s = parseLink(t, c, "ssh://:pw@1.2.3.4").(*SSH)
	if s.User != defaultSSHUser || s.Port != "22" {
		t.Fatalf("defaults: %+v", s)
	}

	// The same key encoded the way url.Values does ('+' for space) and the
	// way PathEscape does ('+' literal), plus base64-wrapped.
	for name, pk := range map[string]string{
		"query escape": url.QueryEscape(pemKey),
		"path escape":  url.PathEscape(pemKey),
		"base64":       url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(pemKey))),
	} {
		for hkName, hk := range map[string]string{"query": url.QueryEscape(hostKey), "path": url.PathEscape(hostKey)} {
			link := "ssh://root@1.2.3.4:22?pk=" + pk + "&hk=" + hk
			s := parseLink(t, c, link).(*SSH)
			if s.PrivateKey != pemKey {
				t.Errorf("%s/%s: private key not recovered", name, hkName)
			}
			if len(s.HostKeys) != 1 || s.HostKeys[0] != hostKey {
				t.Errorf("%s/%s: host keys = %q", name, hkName, s.HostKeys)
			}
		}
	}

	for _, bad := range []string{"ssh://root@1.2.3.4:22", "ssh://root@1.2.3.4:22?pk=garbage"} {
		p, _ := c.CreateProtocol(bad)
		if err := p.Parse(); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestNewProtocolsBuild(t *testing.T) {
	pemKey, _ := testSSHKey(t)
	for _, link := range []string{
		"tuic://" + testUUID + ":pw@127.0.0.1:443?sni=a.com&congestion_control=bbr&udp_relay_mode=native",
		"hysteria://127.0.0.1:443,20000-20010?auth=pw&peer=a.com&obfs=xplus&obfsParam=o",
		"ssh://root:pw@127.0.0.1:22",
		"ssh://root@127.0.0.1:22?pk=" + url.QueryEscape(pemKey),
	} {
		c := NewSingboxService(false, false)
		inst, err := c.MakeInstance(context.Background(), parseLink(t, c, link))
		if err != nil {
			t.Fatalf("%s: MakeInstance: %v", link, err)
		}
		if !raceEnabled {
			if err := inst.Start(); err != nil {
				t.Errorf("%s: Start: %v", link, err)
			}
		}
		inst.Close()
	}

	c := NewSingboxService(false, false)
	inst, err := c.MakeInstance(context.Background(), parseLink(t, c, "anytls://pw@127.0.0.1:443?sni=a.com"))
	if err != nil {
		t.Fatalf("anytls: %v", err)
	}
	inst.Close()
}

func freeUDPPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return strconv.Itoa(port)
}

func TestEndToEndNewProtocols(t *testing.T) {
	skipUnderRace(t)
	target := startTarget(t)
	cases := []struct {
		name   string
		udp    bool
		server func(port string) option.Inbound
		link   func(port string) string
	}{
		{
			name: "tuic",
			udp:  true,
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeTUIC, Options: &option.TUICInboundOptions{
					ListenOptions: loopbackListen(port), Users: []option.TUICUser{{Name: "u", UUID: testUUID, Password: "pw"}},
					CongestionControl: "bbr", InboundTLSOptionsContainer: serverTLS(t, "h3"),
				}}
			},
			link: func(port string) string {
				return "tuic://" + testUUID + ":pw@127.0.0.1:" + port + "?sni=example.com&congestion_control=bbr&allow_insecure=1"
			},
		},
		{
			name: "hysteria v1 xplus",
			udp:  true,
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeHysteria, Options: &option.HysteriaInboundOptions{
					ListenOptions: loopbackListen(port), UpMbps: 100, DownMbps: 100, Obfs: "ob",
					Users: []option.HysteriaUser{{Name: "u", AuthString: "secret"}}, InboundTLSOptionsContainer: serverTLS(t),
				}}
			},
			link: func(port string) string {
				return "hysteria://127.0.0.1:" + port + "?protocol=udp&auth=secret&peer=example.com&insecure=1&upmbps=100&downmbps=100&obfs=xplus&obfsParam=ob"
			},
		},
		{
			name: "anytls",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeAnyTLS, Options: &option.AnyTLSInboundOptions{
					ListenOptions: loopbackListen(port), Users: []option.AnyTLSUser{{Name: "u", Password: "pw"}},
					InboundTLSOptionsContainer: serverTLS(t),
				}}
			},
			link: func(port string) string {
				return "anytls://pw@127.0.0.1:" + port + "?sni=example.com&insecure=1"
			},
		},
		{
			name: "hysteria2",
			udp:  true,
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeHysteria2, Options: &option.Hysteria2InboundOptions{
					ListenOptions: loopbackListen(port), Users: []option.Hysteria2User{{Name: "u", Password: "p@ss"}},
					InboundTLSOptionsContainer: serverTLS(t),
				}}
			},
			link: func(port string) string {
				return "hysteria2://p%40ss@127.0.0.1:" + port + "/?sni=example.com&insecure=1"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := freePort(t)
			if tc.udp {
				port = freeUDPPort(t)
			}
			startServer(t, tc.server(port))
			fetchThrough(t, NewSingboxService(false, false), tc.link(port), target)
		})
	}
}

// startSSHServer runs a minimal SSH server that accepts one user and serves
// direct-tcpip channels (what an SSH tunnel client opens per connection).
func startSSHServer(t *testing.T, user, password string, authorized ssh.PublicKey) (addr string, hostKey ssh.PublicKey) {
	t.Helper()
	_, hostSigner := testSSHKey(t)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == user && password != "" && string(pass) == password {
				return nil, nil
			}
			return nil, io.EOF
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == user && authorized != nil && string(key.Marshal()) == string(authorized.Marshal()) {
				return nil, nil
			}
			return nil, io.EOF
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					conn.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() != "direct-tcpip" {
						nc.Reject(ssh.UnknownChannelType, "only direct-tcpip")
						continue
					}
					go serveDirectTCPIP(nc)
				}
			}()
		}
	}()
	return ln.Addr().String(), hostSigner.PublicKey()
}

func serveDirectTCPIP(nc ssh.NewChannel) {
	extra := nc.ExtraData()
	if len(extra) < 4 {
		nc.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}
	n := binary.BigEndian.Uint32(extra)
	if uint32(len(extra)) < 4+n+4 {
		nc.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}
	host := string(extra[4 : 4+n])
	port := binary.BigEndian.Uint32(extra[4+n:])
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 5*time.Second)
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		upstream.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		io.Copy(upstream, ch)
		upstream.Close()
	}()
	io.Copy(ch, upstream)
	ch.Close()
}

func TestEndToEndSSH(t *testing.T) {
	skipUnderRace(t)
	target := startTarget(t)
	pemKey, clientSigner := testSSHKey(t)

	addr, _ := startSSHServer(t, "tunnel", "p@ss", nil)
	fetchThrough(t, NewSingboxService(false, false), "ssh://tunnel:p%40ss@"+addr+"#pw", target)

	addr, hostKey := startSSHServer(t, "tunnel", "", clientSigner.PublicKey())
	pinned := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey)))
	fetchThrough(t, NewSingboxService(false, false),
		"ssh://tunnel@"+addr+"?pk="+url.QueryEscape(pemKey)+"&hk="+url.QueryEscape(pinned), target)

	// A pinned host key that does not match must fail.
	_, otherSigner := testSSHKey(t)
	wrong := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey())))
	c := NewSingboxService(false, false)
	p := parseLink(t, c, "ssh://tunnel@"+addr+"?pk="+url.QueryEscape(pemKey)+"&hk="+url.QueryEscape(wrong))
	client, instance, err := c.MakeHttpClient(context.Background(), p, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if resp, err := client.Get(target); err == nil {
		resp.Body.Close()
		t.Fatal("connected despite a mismatched pinned host key")
	}
}
