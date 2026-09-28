package singbox

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	sing_hysteria "github.com/sagernet/sing-box/protocol/hysteria"
	sing_hysteria2 "github.com/sagernet/sing-box/protocol/hysteria2"
	sing_tuic "github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
)

// These tests move real HTTP traffic through a crafted client outbound and
// a local sing-box server, so a mis-crafted transport, header or credential
// fails here instead of against a live proxy.

func startTarget(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func loopbackListen(port string) option.ListenOptions {
	p, _ := strconv.Atoi(port)
	addr := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	return option.ListenOptions{Listen: &addr, ListenPort: uint16(p)}
}

// serverContext is boxContext plus the server side of the protocols this
// core only dials (tuic, hysteria, hysteria2, anytls).
func serverContext(ctx context.Context) context.Context {
	r := newRegistries()
	sing_tuic.RegisterInbound(r.inbound)
	sing_hysteria.RegisterInbound(r.inbound)
	sing_hysteria2.RegisterInbound(r.inbound)
	registerAnyTLSServer(r.inbound)
	return r.context(ctx)
}

// startServer runs a sing-box server with one inbound; with no outbounds
// configured sing-box forwards to its built-in direct outbound.
func startServer(t *testing.T, in option.Inbound) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	instance, err := box.New(box.Options{
		Context: serverContext(ctx),
		Options: option.Options{
			Log:      &option.LogOptions{Disabled: true},
			Inbounds: []option.Inbound{in},
		},
	})
	if err != nil {
		cancel()
		t.Fatalf("server box.New: %v", err)
	}
	if err := instance.Start(); err != nil {
		cancel()
		t.Fatalf("server Start: %v", err)
	}
	t.Cleanup(func() {
		instance.Close()
		cancel()
	})
}

var (
	testCertOnce sync.Once
	testCertPEM  string
	testKeyPEM   string
)

func selfSignedCert(t *testing.T) (string, string) {
	t.Helper()
	testCertOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "example.com"},
			DNSNames:     []string{"example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			panic(err)
		}
		testCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		testKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	})
	return testCertPEM, testKeyPEM
}

func serverTLS(t *testing.T, alpn ...string) option.InboundTLSOptionsContainer {
	cert, key := selfSignedCert(t)
	return option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
		Enabled:     true,
		ServerName:  "example.com",
		ALPN:        alpn,
		Certificate: []string{cert},
		Key:         []string{key},
	}}
}

// fetchThrough crafts link with c, dials target through it and checks the body.
func fetchThrough(t *testing.T, c *Core, link, target string) {
	t.Helper()
	p := parseLink(t, c, link)
	client, instance, err := c.MakeHttpClient(context.Background(), p, 10*time.Second)
	if err != nil {
		t.Fatalf("MakeHttpClient: %v", err)
	}
	defer instance.Close()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET through %s: %v", link, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("GET through %s: %d %q", link, resp.StatusCode, body)
	}
}

func TestEndToEnd(t *testing.T) {
	skipUnderRace(t)
	target := startTarget(t)
	ss2022Key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	trojanPassword := "p@ss/wörd"

	cases := []struct {
		name   string
		server func(port string) option.Inbound
		link   func(port string) string
	}{
		{
			name: "vless tcp",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeVLESS, Options: &option.VLESSInboundOptions{
					ListenOptions: loopbackListen(port), Users: []option.VLESSUser{{Name: "u", UUID: testUUID}},
				}}
			},
			link: func(port string) string {
				return "vless://" + testUUID + "@127.0.0.1:" + port + "?type=tcp&security=none#vless"
			},
		},
		{
			name: "vless ws without host",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeVLESS, Options: &option.VLESSInboundOptions{
					ListenOptions: loopbackListen(port), Users: []option.VLESSUser{{Name: "u", UUID: testUUID}},
					Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket, WebsocketOptions: option.V2RayWebsocketOptions{Path: "/ws"}},
				}}
			},
			link: func(port string) string {
				return "vless://" + testUUID + "@127.0.0.1:" + port + "?type=ws&path=%2Fws"
			},
		},
		{
			name: "vless ws early data",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeVLESS, Options: &option.VLESSInboundOptions{
					ListenOptions: loopbackListen(port), Users: []option.VLESSUser{{Name: "u", UUID: testUUID}},
					Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket, WebsocketOptions: option.V2RayWebsocketOptions{
						Path: "/ws", MaxEarlyData: 2048, EarlyDataHeaderName: "Sec-WebSocket-Protocol",
					}},
				}}
			},
			link: func(port string) string {
				return "vless://" + testUUID + "@127.0.0.1:" + port + "?type=ws&host=example.com&path=%2Fws%3Fed%3D2048"
			},
		},
		{
			name: "vless grpc tls default alpn",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeVLESS, Options: &option.VLESSInboundOptions{
					ListenOptions: loopbackListen(port), Users: []option.VLESSUser{{Name: "u", UUID: testUUID}},
					InboundTLSOptionsContainer: serverTLS(t, "h2"),
					Transport:                  &option.V2RayTransportOptions{Type: C.V2RayTransportTypeGRPC, GRPCOptions: option.V2RayGRPCOptions{ServiceName: "svc"}},
				}}
			},
			link: func(port string) string {
				return "vless://" + testUUID + "@127.0.0.1:" + port + "?type=grpc&serviceName=%2Fsvc&security=tls&sni=example.com&allowInsecure=1"
			},
		},
		{
			name: "vless httpupgrade",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeVLESS, Options: &option.VLESSInboundOptions{
					ListenOptions: loopbackListen(port), Users: []option.VLESSUser{{Name: "u", UUID: testUUID}},
					Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTPUpgrade, HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{Path: "/up"}},
				}}
			},
			link: func(port string) string {
				return "vless://" + testUUID + "@127.0.0.1:" + port + "?type=httpupgrade&path=%2Fup"
			},
		},
		{
			name: "vmess tcp",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeVMess, Options: &option.VMessInboundOptions{
					ListenOptions: loopbackListen(port), Users: []option.VMessUser{{Name: "u", UUID: testUUID}},
				}}
			},
			link: func(port string) string {
				return vmessLink(t, map[string]any{"v": "2", "add": "127.0.0.1", "port": port, "id": testUUID, "aid": "0", "net": "tcp", "type": "none", "scy": "auto"})
			},
		},
		{
			name: "vmess ws tls",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeVMess, Options: &option.VMessInboundOptions{
					ListenOptions: loopbackListen(port), Users: []option.VMessUser{{Name: "u", UUID: testUUID}},
					InboundTLSOptionsContainer: serverTLS(t),
					Transport:                  &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket, WebsocketOptions: option.V2RayWebsocketOptions{Path: "/vm"}},
				}}
			},
			link: func(port string) string {
				return vmessLink(t, map[string]any{"add": "127.0.0.1", "port": port, "id": testUUID, "net": "ws", "path": "/vm", "tls": "tls", "sni": "example.com", "allowinsecure": true})
			},
		},
		{
			name: "trojan tls encoded password",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeTrojan, Options: &option.TrojanInboundOptions{
					ListenOptions: loopbackListen(port), Users: []option.TrojanUser{{Name: "u", Password: trojanPassword}},
					InboundTLSOptionsContainer: serverTLS(t),
				}}
			},
			link: func(port string) string {
				return "trojan://" + url.PathEscape(trojanPassword) + "@127.0.0.1:" + port + "?sni=example.com&allowInsecure=1#trojan"
			},
		},
		{
			name: "shadowsocks sip002",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeShadowsocks, Options: &option.ShadowsocksInboundOptions{
					ListenOptions: loopbackListen(port), Method: "aes-128-gcm", Password: "pw",
				}}
			},
			link: func(port string) string {
				return "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@127.0.0.1:" + port + "#ss"
			},
		},
		{
			name: "shadowsocks 2022 plain userinfo",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeShadowsocks, Options: &option.ShadowsocksInboundOptions{
					ListenOptions: loopbackListen(port), Method: "2022-blake3-aes-128-gcm", Password: ss2022Key,
				}}
			},
			link: func(port string) string {
				return "ss://2022-blake3-aes-128-gcm:" + url.PathEscape(ss2022Key) + "@127.0.0.1:" + port
			},
		},
		{
			name: "shadowsocks legacy",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeShadowsocks, Options: &option.ShadowsocksInboundOptions{
					ListenOptions: loopbackListen(port), Method: "aes-256-gcm", Password: "p@ss",
				}}
			},
			link: func(port string) string {
				return "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:p@ss@127.0.0.1:"+port)) + "#legacy"
			},
		},
		{
			name: "socks auth",
			server: func(port string) option.Inbound {
				return option.Inbound{Type: C.TypeSOCKS, Options: &option.SocksInboundOptions{
					ListenOptions: loopbackListen(port), Users: []auth.User{{Username: "user", Password: "p:ss"}},
				}}
			},
			link: func(port string) string {
				return "socks://user:p%3Ass@127.0.0.1:" + port
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := freePort(t)
			startServer(t, tc.server(port))
			fetchThrough(t, NewSingboxService(false, false), tc.link(port), target)
		})
	}
}

// TestEndToEndFragment checks a fragmented ClientHello still completes the
// handshake (sing-box splits it at the SNI).
func TestEndToEndFragment(t *testing.T) {
	skipUnderRace(t)
	target := startTarget(t)
	port := freePort(t)
	startServer(t, option.Inbound{Type: C.TypeTrojan, Options: &option.TrojanInboundOptions{
		ListenOptions: loopbackListen(port), Users: []option.TrojanUser{{Name: "u", Password: "pw"}},
		InboundTLSOptionsContainer: serverTLS(t),
	}})
	for _, spec := range []string{"tlshello,10-20,1-2", "1-3,1-5,1"} {
		f, err := fragment.Parse(spec)
		if err != nil {
			t.Fatal(err)
		}
		c := NewSingboxService(false, false, WithFragment(f))
		fetchThrough(t, c, "trojan://pw@127.0.0.1:"+port+"?sni=example.com&allowInsecure=1", target)
	}
}

// TestEndToEndProxyInbound is `proxy -z sing-box`: a local socks inbound in
// front of a crafted outbound. It failed with "outbound type not found: socks"
// before the inbound registry was populated.
func TestEndToEndProxyInbound(t *testing.T) {
	skipUnderRace(t)
	target := startTarget(t)
	serverPort := freePort(t)
	startServer(t, option.Inbound{Type: C.TypeVLESS, Options: &option.VLESSInboundOptions{
		ListenOptions: loopbackListen(serverPort), Users: []option.VLESSUser{{Name: "u", UUID: testUUID}},
	}})

	for _, in := range []struct {
		name  string
		proto func(port string) protocol.Protocol
		proxy func(port string) *url.URL
	}{
		{name: "socks", proto: func(port string) protocol.Protocol {
			return &Socks{Address: "127.0.0.1", Port: port, Username: "u", Password: "p"}
		}, proxy: func(port string) *url.URL {
			return &url.URL{Scheme: "socks5", User: url.UserPassword("u", "p"), Host: "127.0.0.1:" + port}
		}},
		{name: "mixed http", proto: func(port string) protocol.Protocol {
			return &Http{Address: "127.0.0.1", Port: port}
		}, proxy: func(port string) *url.URL {
			return &url.URL{Scheme: "http", Host: "127.0.0.1:" + port}
		}},
	} {
		t.Run(in.name, func(t *testing.T) {
			localPort := freePort(t)
			c := NewSingboxService(false, false, WithInbound(in.proto(localPort)))
			out := parseLink(t, c, "vless://"+testUUID+"@127.0.0.1:"+serverPort+"?type=tcp")
			inst, err := c.MakeInstance(context.Background(), out)
			if err != nil {
				t.Fatalf("MakeInstance: %v", err)
			}
			defer inst.Close()
			if err := inst.Start(); err != nil {
				t.Fatalf("Start: %v", err)
			}
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(in.proxy(localPort))}, Timeout: 10 * time.Second}
			resp, err := client.Get(target)
			if err != nil {
				t.Fatalf("GET via local %s inbound: %v", in.name, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "ok" {
				t.Fatalf("body %q", body)
			}
		})
	}
}

// recordingSocks is a minimal no-auth SOCKS5 server that remembers which
// destinations it was asked to CONNECT to.
type recordingSocks struct {
	addr    string
	mu      sync.Mutex
	targets []string
}

func startRecordingSocks(t *testing.T) *recordingSocks {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &recordingSocks{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	return s
}

func (s *recordingSocks) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.targets...)
}

func (s *recordingSocks) handle(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 262)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil || buf[0] != 5 {
		return
	}
	if _, err := io.ReadFull(conn, buf[:buf[1]]); err != nil {
		return
	}
	conn.Write([]byte{5, 0})
	if _, err := io.ReadFull(conn, buf[:4]); err != nil || buf[1] != 1 {
		return
	}
	var host string
	switch buf[3] {
	case 1:
		io.ReadFull(conn, buf[:4])
		host = net.IP(buf[:4]).String()
	case 3:
		io.ReadFull(conn, buf[:1])
		n := int(buf[0])
		io.ReadFull(conn, buf[:n])
		host = string(buf[:n])
	case 4:
		io.ReadFull(conn, buf[:16])
		host = net.IP(buf[:16]).String()
	default:
		return
	}
	io.ReadFull(conn, buf[:2])
	dest := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(buf[:2]))))
	s.mu.Lock()
	s.targets = append(s.targets, dest)
	s.mu.Unlock()

	upstream, err := net.DialTimeout("tcp", dest, 5*time.Second)
	if err != nil {
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go io.Copy(upstream, conn)
	io.Copy(conn, upstream)
}

// TestEndToEndChainOrder pins the chain direction: hop 0 is dialed first
// (entry) and the last hop reaches the destination (exit).
func TestEndToEndChainOrder(t *testing.T) {
	skipUnderRace(t)
	target := startTarget(t)
	targetHost := target[len("http://"):]
	entry, exit := startRecordingSocks(t), startRecordingSocks(t)

	c := NewSingboxService(false, false)
	hops := []protocol.Protocol{
		parseLink(t, c, "socks://"+entry.addr),
		parseLink(t, c, "socks://"+exit.addr),
	}
	client, instance, err := c.MakeChainedHttpClient(context.Background(), hops, 10*time.Second)
	if err != nil {
		t.Fatalf("MakeChainedHttpClient: %v", err)
	}
	defer instance.Close()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET through chain: %v", err)
	}
	resp.Body.Close()

	if got := entry.seen(); len(got) != 1 || got[0] != exit.addr {
		t.Errorf("entry hop was asked for %v, want the exit hop %s", got, exit.addr)
	}
	if got := exit.seen(); len(got) != 1 || got[0] != targetHost {
		t.Errorf("exit hop was asked for %v, want the target %s", got, targetHost)
	}
}

func ExampleWithFragment() {
	f, _ := fragment.Parse("tlshello,100-200,10-20")
	c := NewSingboxService(false, false, WithFragment(f))
	fmt.Println(c.Fragment.String())
	// Output: tlshello,100-200,10-20
}
