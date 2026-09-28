package http

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// endpointForLink is endpointForProto for a share link.
func endpointForLink(c core.Core, link string) string {
	return endpointForProto(ParseLink(c, link).Proto)
}

func TestIsUDPBased(t *testing.T) {
	cases := []struct {
		name string
		gc   protocol.GeneralConfig
		want bool
	}{
		{"hysteria2", protocol.GeneralConfig{Protocol: "hysteria2"}, true},
		{"hy2-alias", protocol.GeneralConfig{Protocol: "hy2"}, true},
		{"wireguard", protocol.GeneralConfig{Protocol: "wireguard"}, true},
		{"tun", protocol.GeneralConfig{Protocol: "tun"}, true},
		{"vmess-kcp-network", protocol.GeneralConfig{Protocol: "vmess", Network: "kcp"}, true},
		{"vless-kcp-type", protocol.GeneralConfig{Protocol: "vless", Type: "kcp"}, true},
		{"quic-type", protocol.GeneralConfig{Protocol: "vless", Type: "quic"}, true},
		{"vless-tcp", protocol.GeneralConfig{Protocol: "vless", Type: "tcp"}, false},
		{"vmess-ws", protocol.GeneralConfig{Protocol: "vmess", Network: "ws"}, false},
		{"trojan-grpc", protocol.GeneralConfig{Protocol: "trojan", Type: "grpc"}, false},
		{"shadowsocks", protocol.GeneralConfig{Protocol: "ss"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUDPBased(tc.gc); got != tc.want {
				t.Errorf("isUDPBased(%+v) = %v, want %v", tc.gc, got, tc.want)
			}
		})
	}
}

func TestEndpointForLink(t *testing.T) {
	c := core.CoreFactoryWith(core.XrayCoreType, core.FactoryOptions{})

	cases := []struct {
		name string
		link string
		want string
	}{
		{
			name: "vless-tcp",
			link: "vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@1.2.3.4:443?encryption=none&security=none&type=tcp#x",
			want: "1.2.3.4:443",
		},
		{
			name: "vless-kcp-bypass",
			link: "vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@1.2.3.4:443?encryption=none&security=none&type=kcp#x",
			want: "",
		},
		{
			name: "hysteria2-bypass",
			link: "hysteria2://s3cret@1.2.3.4:443?sni=example.com#x",
			want: "",
		},
		{
			name: "wireguard-bypass",
			link: "wireguard://cHJpdmF0ZQ@1.2.3.4:51820?publickey=cHVibGlj&address=10.0.0.2%2F32#x",
			want: "",
		},
		{
			name: "empty",
			link: "",
			want: "",
		},
		{
			name: "garbage",
			link: "not-a-link",
			want: "",
		},
		{
			name: "ipv6-brackets-not-doubled",
			link: "vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@[2001:db8::1]:443?encryption=none&security=none&type=tcp#x",
			want: "[2001:db8::1]:443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := endpointForLink(c, tc.link); got != tc.want {
				t.Errorf("endpointForLink(%q) = %q, want %q", tc.link, got, tc.want)
			}
		})
	}
}

// freeClosedPort returns a TCP port that was just bound and released, so a
// dial to it should fail (connection refused).
func freeClosedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	_ = l.Close()
	return port
}

func TestRunPrescan_GroupingBypassAndReachability(t *testing.T) {
	// A live listener that accepts and immediately closes connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, livePort, _ := net.SplitHostPort(ln.Addr().String())
	deadPort := freeClosedPort(t)

	uuid := "a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5"
	vless := func(port, remark string) string {
		return fmt.Sprintf("vless://%s@127.0.0.1:%s?encryption=none&security=none&type=tcp#%s", uuid, port, remark)
	}

	// Two live configs share one endpoint (tests grouping), one dead config,
	// plus UDP-based configs that must bypass the TCP probe and be kept.
	links := []string{
		vless(livePort, "live1"),
		vless(livePort, "live2"), // same endpoint as live1
		vless(deadPort, "dead"),
		fmt.Sprintf("hysteria2://s3cret@127.0.0.1:%s?sni=example.com#hy2", deadPort),
		fmt.Sprintf("wireguard://cHJpdmF0ZQ@127.0.0.1:%s?publickey=cHVibGlj&address=10.0.0.2%%2F32#wg", deadPort),
		fmt.Sprintf("vless://%s@127.0.0.1:%s?encryption=none&security=none&type=kcp#kcp", uuid, deadPort),
	}

	c := core.CoreFactoryWith(core.XrayCoreType, core.FactoryOptions{})

	var startCalls, progressCalls int32
	var reportedUnique int32
	res, err := RunPrescan(context.Background(), c, links,
		PrescanOptions{Workers: 16, Timeout: 1500 * time.Millisecond},
		func(u int) { atomic.AddInt32(&startCalls, 1); atomic.StoreInt32(&reportedUnique, int32(u)) },
		func() { atomic.AddInt32(&progressCalls, 1) },
	)
	if err != nil {
		t.Fatalf("RunPrescan: %v", err)
	}

	// Endpoints: {live, dead} = 2 (UDP-based links add none).
	if res.UniqueEndpoints != 2 {
		t.Errorf("UniqueEndpoints = %d, want 2", res.UniqueEndpoints)
	}
	if res.TCPReachable != 2 {
		t.Errorf("TCPReachable = %d, want 2 (both live configs)", res.TCPReachable)
	}
	// hy2 + wireguard + kcp-vless bypass the probe.
	if res.Bypassed != 3 {
		t.Errorf("Bypassed = %d, want 3", res.Bypassed)
	}
	if res.FilteredOut != 1 {
		t.Errorf("FilteredOut = %d, want 1 (the dead tcp config)", res.FilteredOut)
	}
	if len(res.Reachable) != 5 {
		t.Fatalf("len(Reachable) = %d, want 5", len(res.Reachable))
	}

	// The dead TCP config must be dropped; order preserved for survivors.
	wantOrder := []string{links[0], links[1], links[3], links[4], links[5]}
	for i, w := range wantOrder {
		if res.Reachable[i] != w {
			t.Errorf("Reachable[%d] = %q, want %q", i, res.Reachable[i], w)
		}
	}

	if atomic.LoadInt32(&startCalls) != 1 {
		t.Errorf("onStart called %d times, want 1", startCalls)
	}
	if reportedUnique != 2 {
		t.Errorf("onStart reported %d unique endpoints, want 2", reportedUnique)
	}
	if got := atomic.LoadInt32(&progressCalls); got != 2 {
		t.Errorf("onProgress called %d times, want 2 (one per unique endpoint)", got)
	}
}

func TestRunPrescan_AllBypassNoEndpoints(t *testing.T) {
	c := core.CoreFactoryWith(core.XrayCoreType, core.FactoryOptions{})
	links := []string{
		"hysteria2://s3cret@1.2.3.4:443?sni=example.com#hy2",
		"wireguard://cHJpdmF0ZQ@1.2.3.4:51820?publickey=cHVibGlj&address=10.0.0.2%2F32#wg",
	}
	res, err := RunPrescan(context.Background(), c, links, PrescanOptions{}, nil, nil)
	if err != nil {
		t.Fatalf("RunPrescan: %v", err)
	}
	if res.UniqueEndpoints != 0 {
		t.Errorf("UniqueEndpoints = %d, want 0", res.UniqueEndpoints)
	}
	if res.Bypassed != 2 || len(res.Reachable) != 2 {
		t.Errorf("Bypassed=%d Reachable=%d, want 2/2", res.Bypassed, len(res.Reachable))
	}
}
