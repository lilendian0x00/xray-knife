package net

import (
	"net"
	"strings"
	"testing"
)

const tcpTestSecret = "00112233445566778899aabbccddeeff"

// runTcp runs the tcp subcommand the way a user would.
func runTcp(t *testing.T, link string) error {
	t.Helper()
	cmd := newTcpCommand()
	cmd.SetArgs([]string{"--config", link})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd.Execute()
}

func TestTcpCommandMTProtoLink(t *testing.T) {
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
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	if err := runTcp(t, "tg://proxy?server=127.0.0.1&port="+port+"&secret="+tcpTestSecret); err != nil {
		t.Fatalf("tg:// link: %v", err)
	}
	if err := runTcp(t, "https://t.me/proxy?server=127.0.0.1&port="+port+"&secret="+tcpTestSecret); err != nil {
		t.Fatalf("t.me link: %v", err)
	}
}

func TestTcpCommandIPv6Loopback(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
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
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	if err := runTcp(t, "tg://proxy?server=::1&port="+port+"&secret="+tcpTestSecret); err != nil {
		t.Fatalf("ipv6 link: %v", err)
	}
}

func TestTcpCommandRejectsBadConfig(t *testing.T) {
	// A bad secret fails in Parse, before any dial.
	err := runTcp(t, "tg://proxy?server=127.0.0.1&port=1&secret=zz")
	if err == nil || !strings.Contains(err.Error(), "couldn't parse the config") {
		t.Fatalf("bad secret: err = %v", err)
	}
	if err := runTcp(t, ""); err == nil {
		t.Fatal("missing config link accepted")
	}
	if err := runTcp(t, "not-a-link"); err == nil {
		t.Fatal("unsupported link accepted")
	}
}
