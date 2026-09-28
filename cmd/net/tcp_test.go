package net

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
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

func TestTcpCommandPositionalLinkAndCount(t *testing.T) {
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

	cmd := newTcpCommand()
	cmd.SetArgs([]string{"tg://proxy?server=127.0.0.1&port=" + port + "&secret=" + tcpTestSecret, "-n", "3", "--interval", "1ms", "--json"})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.Execute(); err != nil {
		t.Fatalf("positional link with -n 3: %v", err)
	}
}

func TestProbeReportsLoss(t *testing.T) {
	saved := dialFunc
	t.Cleanup(func() { dialFunc = saved })
	calls := 0
	dialFunc = func(ctx context.Context, timeout time.Duration, addr string) (net.Conn, error) {
		calls++
		if calls%2 == 0 {
			return nil, errors.New("connection refused")
		}
		c1, c2 := net.Pipe()
		c2.Close()
		return c1, nil
	}
	cfg := &tcpCmdConfig{count: 4, timeout: time.Second}
	sum := probe(context.Background(), cfg, "x:1", func(int, time.Duration, error) {})
	if sum.Sent != 4 || sum.Received != 2 || sum.LossPct != 50 || len(sum.Errors) != 2 {
		t.Fatalf("summary = %+v", sum)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sum := probe(ctx, cfg, "x:1", func(int, time.Duration, error) {}); sum.Sent != 0 {
		t.Fatalf("cancelled probe sent %d", sum.Sent)
	}
}

func TestTcpCommandTimesOutUnreachable(t *testing.T) {
	saved := dialFunc
	t.Cleanup(func() { dialFunc = saved })
	var gotTimeout time.Duration
	dialFunc = func(ctx context.Context, timeout time.Duration, addr string) (net.Conn, error) {
		gotTimeout = timeout
		return nil, errors.New("i/o timeout")
	}
	cmd := newTcpCommand()
	cmd.SetArgs([]string{"-c", "tg://proxy?server=192.0.2.1&port=443&secret=" + tcpTestSecret, "--timeout", "250ms"})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.Execute(); err == nil {
		t.Fatal("unreachable server reported success")
	}
	if gotTimeout != 250*time.Millisecond {
		t.Fatalf("dial timeout = %v, want 250ms", gotTimeout)
	}
}
