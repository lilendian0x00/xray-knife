package cloudflare

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type SpeedTester struct {
	SNI              string
	DownloadEndpoint string
	UploadEndpoint   string
}

func (c *SpeedTester) MakeDownloadHTTPRequest(noTLS bool, amount uint32) *http.Request {
	scheme := "https"
	if noTLS {
		scheme = "http"
	}
	return &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path:     c.DownloadEndpoint,
			RawQuery: fmt.Sprintf("bytes=%d", amount),
			Scheme:   scheme,
			Host:     c.SNI,
		},
		Header: make(http.Header),
		Host:   c.SNI,
	}
}

func (c *SpeedTester) MakeUploadHTTPRequest(noTLS bool, amount uint32) *http.Request {
	scheme := "https"
	if noTLS {
		scheme = "http"
	}
	lk := strings.NewReader(strings.Repeat("0", int(amount)))
	rc := io.NopCloser(lk)
	return &http.Request{
		Method: "POST",
		URL: &url.URL{
			Path:   c.UploadEndpoint,
			Scheme: scheme,
			Host:   c.SNI,
		},
		Header: make(http.Header),
		Host:   c.SNI,
		Body:   rc,
	}
}

var Speedtest = &SpeedTester{
	SNI:              "speed.cloudflare.com",
	DownloadEndpoint: "/__down",
	UploadEndpoint:   "/__up",
}
