package utils

import (
	"bufio"
	"errors"
	"fmt"
	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

func makeUTlsConn(hostname string, addr string) (*tls.UConn, string, error) {
	config := tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: false,
	}
	dialConn, err := net.DialTimeout("tcp", addr, time.Duration(15)*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, &config, tls.HelloChrome_62)
	//defer uTlsConn.Close()

	if err != nil {
		return nil, "", fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	err = uTlsConn.Handshake()
	if err != nil {
		return nil, "", fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}
	return uTlsConn, uTlsConn.HandshakeState.ServerHello.AlpnProtocol, nil
}

func SendHTTPRequest(fullURL *url.URL, useragent string, method string) (*http.Response, error) {
	p := fullURL.Port()
	if p == "" {
		if fullURL.Scheme == "https" {
			p = "443"
		} else {
			p = "80"
		}
	}
	var conn *tls.UConn
	var alpn string
	var utlsErr error

	// TODO: For ARM it gives error (https://github.com/coyove/goflyway/issues/126)
	addrs, err := net.LookupIP(fullURL.Host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not resolve dns: %v\n", err)
		os.Exit(1)
	}

	addr := addrs[0].String() + ":" + p

	if fullURL.Scheme == "https" {
		conn, alpn, utlsErr = makeUTlsConn(fullURL.Host, addr)
		if utlsErr != nil {
			return nil, utlsErr
		}
	}

	req := &http.Request{
		Method: method,
		URL:    fullURL,
		Header: make(http.Header),
		Host:   fullURL.Host,
	}
	req.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	if alpn == "http/1.1" || alpn == "" {
		req.Header.Set("accept-encoding", "gzip, deflate, br")
	}

	req.Header.Set("accept-language", "en-US,en;q=0.9")
	req.Header.Set("dnt", "1")
	req.Header.Set("pragma", "no-cache")
	req.Header.Set("sec-ch-ua", "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"")
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Set("sec-fetch-dest", "document")
	req.Header.Set("sec-fetch-mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("sec-fetch-user", "?1")
	req.Header.Set("Sec-Gpc", "1")
	req.Header.Set("upgrade-insecure-requests", "1")
	//req.Header.Set("connection", "keep-alive")
	if useragent != "" {
		req.Header.Set("user-agent", useragent)
	} else {
		req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
	}

	if fullURL.Scheme == "https" {
		switch alpn {
		case "h2":
			req.Proto = "HTTP/2.0"
			req.ProtoMajor = 2
			req.ProtoMinor = 0

			tr := http2.Transport{
				ReadIdleTimeout: time.Duration(20) * time.Second,
			}
			cConn, err := tr.NewClientConn(conn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Could not make http client conn: %v", err)
				os.Exit(1)
			}
			trip, err2 := cConn.RoundTrip(req)
			if err2 != nil {
				return nil, err2
			}

			return trip, nil
		case "http/1.1", "":
			req.Proto = "HTTP/1.1"
			req.ProtoMajor = 1
			req.ProtoMinor = 1
			err = req.Write(conn)
			if err != nil {
				return nil, err
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), req)
			if err != nil {
				return nil, err
			}
			return response, nil
		}
	} else {
		// HTTP
		dialConn, err := net.DialTimeout("tcp", addr, time.Duration(15)*time.Second)
		if err != nil {
			return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
		}
		err = req.Write(dialConn)
		if err != nil {
			return nil, err
		}
		response, err := http.ReadResponse(bufio.NewReader(dialConn), req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}

	return nil, errors.New("Bad alpn! ")
}
