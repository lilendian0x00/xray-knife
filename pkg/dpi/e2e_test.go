package dpi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
)

// These tests run the finder against real cores: a local trojan server sits
// behind a middlebox that behaves like naive SNI-based DPI (it inspects the
// first packet of each connection and resets it when the blocked name is
// visible), so the baseline must fail and a fragmented hello must pass.

const blockedSNI = "blocked.example"

func selfSigned(t *testing.T, name string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:])
}

// startTrojan serves a minimal trojan server (CONNECT only) over TLS.
func startTrojan(t *testing.T, password string, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	sum := sha256.Sum224([]byte(password))
	want := []byte(hex.EncodeToString(sum[:]))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTrojan(c, want)
		}
	}()
	return ln.Addr().String()
}

func serveTrojan(c net.Conn, want []byte) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	head := make([]byte, len(want)+2+2)
	if _, err := io.ReadFull(br, head); err != nil || !bytes.Equal(head[:len(want)], want) || head[len(want)+2] != 1 {
		return
	}
	var host string
	switch head[len(head)-1] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		n, err := br.ReadByte()
		if err != nil {
			return
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 4)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb[:2])
	up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return
	}
	defer up.Close()
	_ = c.SetDeadline(time.Time{})
	go func() {
		_, _ = io.Copy(up, br)
		_ = up.(*net.TCPConn).CloseWrite()
	}()
	_, _ = io.Copy(c, up)
}

// startSNIFilter forwards to upstream unless the first read of a connection
// contains the blocked name, in which case it resets the connection.
func startSNIFilter(t *testing.T, upstream, blocked string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 16<<10)
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if bytes.Contains(buf[:n], []byte(blocked)) {
					_ = c.(*net.TCPConn).SetLinger(0) // RST, like injected resets
					return
				}
				_ = c.SetReadDeadline(time.Time{})
				up, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer up.Close()
				if _, err := up.Write(buf[:n]); err != nil {
					return
				}
				go func() {
					_, _ = io.Copy(up, c)
					_ = up.(*net.TCPConn).CloseWrite()
				}()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestEndToEndFindsFragmentPastSNIFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real cores")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	cert, pin := selfSigned(t, blockedSNI)
	server := startTrojan(t, "pw", cert)
	filtered := startSNIFilter(t, server, blockedSNI)
	link := "trojan://pw@" + filtered + "?security=tls&type=tcp&sni=" + blockedSNI + "&pcs=" + pin + "#e2e"

	rep, err := Run(context.Background(), Options{
		Link:     link,
		CoreType: core.AutoCoreType,
		TestURL:  target.URL + "/generate_204",
		Timeout:  6 * time.Second,
		Attempts: 2,
		Threads:  3,
		Specs:    []string{"tlshello,5-10,5-10", "1-1,3-5,5-10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		t.Logf("%-28s %-7s %d/%d median=%dms failures=%v err=%s", r.Profile.Label(), r.Status, r.Successes, r.Attempts, r.MedianDelay, r.Failures, r.LastError)
	}
	t.Logf("direct: %+v", rep.Direct)
	if rep.Core != "xray" {
		t.Fatalf("core = %q, want xray (fragment grid)", rep.Core)
	}
	if rep.Verdict != VerdictFragmentHelps {
		t.Fatalf("verdict = %q (%s)", rep.Verdict, rep.Advice)
	}
	if rep.Best == nil || rep.Best.Profile.Fragment == nil || rep.Best.Status != StatusPass {
		t.Fatalf("best = %+v", rep.Best)
	}
	base := rep.Results[0]
	if base.Profile.Name != "baseline" || base.Successes != 0 {
		t.Fatalf("baseline got through the filter: %+v", base)
	}
	if !rep.Direct.TCPOK || !rep.Direct.TLSChecked || rep.Direct.TLSOK {
		t.Fatalf("direct check should see TCP ok and TLS cut: %+v", rep.Direct)
	}
}

func TestEndToEndNoInterference(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real cores")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	cert, pin := selfSigned(t, "open.example")
	server := startTrojan(t, "pw", cert)
	link := "trojan://pw@" + server + "?security=tls&type=tcp&sni=open.example&pcs=" + pin

	rep, err := Run(context.Background(), Options{
		Link: link, TestURL: target.URL + "/generate_204", Timeout: 6 * time.Second,
		Attempts: 1, Specs: []string{"tlshello,100-200,10-20"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != VerdictNoInterference || !rep.Direct.TLSOK {
		t.Fatalf("verdict = %q direct = %+v results = %+v", rep.Verdict, rep.Direct, rep.Results)
	}
}

func TestSingboxRealityRejected(t *testing.T) {
	link := "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:443?security=reality&sni=www.example.com&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&type=tcp&fp=chrome"
	_, err := Run(context.Background(), Options{Link: link, CoreType: core.SingboxCoreType, Timeout: time.Second, Attempts: 1})
	if err == nil || !strings.Contains(err.Error(), "--core xray") {
		t.Fatalf("REALITY on sing-box: err = %v, want a --core xray hint", err)
	}
}
