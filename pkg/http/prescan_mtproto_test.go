package http

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

const prescanSecret = "dd00112233445566778899aabbccddeeff"

// MTProto is plain TCP, so the pre-scan must dial it rather than bypass it.
func TestEndpointForLinkMTProto(t *testing.T) {
	c := core.NewAutomaticCore(false, false)

	cases := []struct {
		name string
		link string
		want string
	}{
		{"tg", "tg://proxy?server=1.2.3.4&port=443&secret=" + prescanSecret, "1.2.3.4:443"},
		{"t.me", "https://t.me/proxy?server=1.2.3.4&port=443&secret=" + prescanSecret, "1.2.3.4:443"},
		{"port normalization", "tg://proxy?server=1.2.3.4&port=00443&secret=" + prescanSecret, "1.2.3.4:443"},
		{"ipv6", "tg://proxy?server=2001:db8::1&port=443&secret=" + prescanSecret, "[2001:db8::1]:443"},
		{"bad secret bypassed", "tg://proxy?server=1.2.3.4&port=443&secret=zz", ""},
		{"missing port bypassed", "tg://proxy?server=1.2.3.4&secret=" + prescanSecret, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := endpointForLink(c, tc.link); got != tc.want {
				t.Errorf("endpointForLink(%q) = %q, want %q", tc.link, got, tc.want)
			}
		})
	}

	if isUDPBased(protocol.GeneralConfig{Protocol: protocol.MTProtoIdentifier, Network: "tcp", Type: "tcp"}) {
		t.Error("mtproto must not be treated as UDP-based")
	}
}

// Both spellings of one proxy share a dialed endpoint; an unreachable one is
// filtered out rather than bypassed.
func TestRunPrescanMTProto(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

	links := []string{
		"tg://proxy?server=127.0.0.1&port=" + livePort + "&secret=" + prescanSecret,
		"https://t.me/proxy?server=127.0.0.1&port=" + livePort + "&secret=" + prescanSecret,
		"tg://proxy?server=127.0.0.1&port=" + deadPort + "&secret=" + prescanSecret,
		"tg://proxy?server=127.0.0.1&port=443&secret=zz", // unparseable: bypassed
	}
	res, err := RunPrescan(context.Background(), core.NewAutomaticCore(false, false), links,
		PrescanOptions{Timeout: 2 * time.Second}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.UniqueEndpoints != 2 {
		t.Errorf("UniqueEndpoints = %d, want 2 (the two live spellings share one)", res.UniqueEndpoints)
	}
	if res.TCPReachable != 2 || res.Bypassed != 1 || res.FilteredOut != 1 {
		t.Errorf("reachable=%d bypassed=%d filtered=%d", res.TCPReachable, res.Bypassed, res.FilteredOut)
	}
	if len(res.Reachable) != 3 {
		t.Fatalf("Reachable = %v", res.Reachable)
	}
	for _, kept := range res.Reachable {
		if kept == links[2] {
			t.Error("an unreachable mtproto proxy survived the pre-scan")
		}
	}
}
