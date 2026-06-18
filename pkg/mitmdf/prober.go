package mitmdf

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type ProbeResult struct {
	FrontDomain string `json:"frontDomain"`
	Success     bool   `json:"success"`
	StatusCode  int    `json:"statusCode"`
	LatencyMs   int64  `json:"latencyMs"`
	Error       string `json:"error,omitempty"`
}

func ProbeDomain(targetDomain string, frontDomains []string) []ProbeResult {
	results := make([]ProbeResult, len(frontDomains))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i, fd := range frontDomains {
		wg.Add(1)
		go func(idx int, frontDomain string) {
			defer wg.Done()
			r := ProbeResult{FrontDomain: frontDomain}
			start := time.Now()

			addrs, err := net.LookupHost(frontDomain)
			if err != nil {
				r.Error = fmt.Sprintf("DNS lookup failed: %v", err)
				mu.Lock()
				results[idx] = r
				mu.Unlock()
				return
			}
			if len(addrs) == 0 {
				r.Error = "no addresses resolved"
				mu.Lock()
				results[idx] = r
				mu.Unlock()
				return
			}

			addr := net.JoinHostPort(addrs[0], "443")
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			conn, err := dialer.Dial("tcp", addr)
			if err != nil {
				r.Error = fmt.Sprintf("TCP dial failed: %v", err)
				mu.Lock()
				results[idx] = r
				mu.Unlock()
				return
			}

			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         frontDomain,
				InsecureSkipVerify: true,
			})
			if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				_ = conn.Close()
				r.Error = fmt.Sprintf("set deadline: %v", err)
				mu.Lock()
				results[idx] = r
				mu.Unlock()
				return
			}
			if err := tlsConn.Handshake(); err != nil {
				_ = conn.Close()
				r.Error = fmt.Sprintf("TLS handshake failed: %v", err)
				mu.Lock()
				results[idx] = r
				mu.Unlock()
				return
			}

			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				_ = tlsConn.Close()
				r.Error = fmt.Sprintf("create request: %v", err)
				mu.Lock()
				results[idx] = r
				mu.Unlock()
				return
			}
			req.Host = targetDomain
			if err := req.Write(tlsConn); err != nil {
				_ = tlsConn.Close()
				r.Error = fmt.Sprintf("write request: %v", err)
				mu.Lock()
				results[idx] = r
				mu.Unlock()
				return
			}

			resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
			_ = tlsConn.Close()
			if err != nil {
				r.Error = fmt.Sprintf("read response: %v", err)
				mu.Lock()
				results[idx] = r
				mu.Unlock()
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			r.Success = true
			r.StatusCode = resp.StatusCode
			r.LatencyMs = time.Since(start).Milliseconds()
			mu.Lock()
			results[idx] = r
			mu.Unlock()
		}(i, fd)
	}

	wg.Wait()
	return results
}
