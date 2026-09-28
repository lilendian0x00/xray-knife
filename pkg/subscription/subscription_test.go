package subscription

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDecodeFormats(t *testing.T) {
	const input = "vless://uuid@host:443#one\r\n\n future-protocol://value \nvless://uuid@host:443#one\n"
	want := []string{"vless://uuid@host:443#one", "future-protocol://value", "vless://uuid@host:443#one"}
	forms := []string{input, "\xef\xbb\xbf" + input}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		encoded := enc.EncodeToString([]byte(input))
		forms = append(forms, encoded, encoded[:20]+"\r\n "+encoded[20:])
	}
	for _, body := range forms {
		got, err := Decode([]byte(body), DecodeOptions{})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("decoded %v, error %v", got, err)
		}
	}
	for _, body := range []string{"", " \r\n", "\xef\xbb\xbf"} {
		got, err := Decode([]byte(body), DecodeOptions{})
		if err != nil || got == nil || len(got) != 0 {
			t.Fatalf("empty list: got %v, error %v", got, err)
		}
	}
}

func TestDecodeLargeSource(t *testing.T) {
	// Public sources can contain 38K+ entries; both their raw and encoded
	// forms must fit the defaults without truncating or deduplicating input.
	const count = 40000
	body := strings.Repeat("vless://uuid@example.com:443?type=ws#source\n", count)
	for _, data := range []string{body, base64.StdEncoding.EncodeToString([]byte(body))} {
		links, err := Decode([]byte(data), DecodeOptions{})
		if err != nil || len(links) != count {
			t.Fatalf("large source: %d links, %v", len(links), err)
		}
	}
}

func TestDecodeRejectsInvalidSnapshots(t *testing.T) {
	for _, body := range []string{
		"<html>login at https://provider.test</html>",
		`{"outbounds":[]}`, "proxies:\n  - name: example", "not a subscription",
		"vless://uuid@host:443\ninvalid line", "vless://", "://foo",
		"\x00", "vless://uuid@host:443\xff",
		base64.StdEncoding.EncodeToString([]byte("<html>login</html>")),
	} {
		got, err := Decode([]byte(body), DecodeOptions{})
		if !errors.Is(err, ErrInvalidFormat) || got != nil {
			t.Fatalf("invalid snapshot returned %v, error %v", got, err)
		}
	}
	for _, tc := range []struct {
		opts DecodeOptions
		want error
	}{
		{DecodeOptions{MaxBytes: 5}, ErrTooLarge},
		{DecodeOptions{MaxLinks: 1}, ErrTooManyLinks},
	} {
		got, err := Decode([]byte("socks://host:1080\nsocks://other:1080"), tc.opts)
		if !errors.Is(err, tc.want) || got != nil {
			t.Fatalf("limit returned %v, error %v", got, err)
		}
	}
	if _, err := Decode(nil, DecodeOptions{MaxBytes: -1}); err == nil {
		t.Fatal("negative limit accepted")
	}
}

func TestFetchHeadersAndConditionalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("User-Agent") != "pool-test" {
			t.Error("request headers missing")
		}
		w.Header().Set("ETag", `"revision-1"`)
		w.Header().Set("Last-Modified", "Mon, 07 Sep 2026 12:00:00 GMT")
		if r.Header.Get("If-None-Match") == `"revision-1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		io.WriteString(w, "socks://host:1080\n")
	}))
	defer server.Close()
	headers := http.Header{"Authorization": {"Bearer token"}, "User-Agent": {"pool-test"}}
	before := headers.Clone()
	client := server.Client()
	result, err := Fetch(context.Background(), client, server.URL, FetchOptions{Headers: headers})
	if err != nil || result.NotModified || len(result.Links) != 1 || result.ETag == "" || result.LastModified == "" {
		t.Fatalf("fetch: %+v, error %v", result, err)
	}
	if !reflect.DeepEqual(headers, before) || client.Timeout != 0 {
		t.Fatal("fetch mutated caller configuration")
	}
	headers.Set("If-None-Match", result.ETag)
	result, err = Fetch(context.Background(), client, server.URL, FetchOptions{Headers: headers})
	if err != nil || !result.NotModified || result.Links != nil {
		t.Fatalf("304 must preserve previous snapshot: %+v, error %v", result, err)
	}
}

func TestFetchBodyLimitsAndFailures(t *testing.T) {
	for _, mode := range []string{"length", "chunked", "gzip", "invalid", "status", "empty"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "status":
					w.WriteHeader(http.StatusUnauthorized)
				case "invalid":
					io.WriteString(w, "<html>login</html>")
				case "empty":
					w.WriteHeader(http.StatusNoContent)
				case "gzip":
					w.Header().Set("Content-Encoding", "gzip")
					gz := gzip.NewWriter(w)
					io.WriteString(gz, strings.Repeat("socks://host:1080\n", 100))
					gz.Close()
				default:
					if mode == "chunked" {
						w.(http.Flusher).Flush()
					}
					io.WriteString(w, strings.Repeat("socks://host:1080\n", 100))
				}
			}))
			defer server.Close()
			result, err := Fetch(context.Background(), server.Client(), server.URL+"?secret=token", FetchOptions{DecodeOptions: DecodeOptions{MaxBytes: 64}})
			switch mode {
			case "empty":
				if err != nil || result.Links == nil || len(result.Links) != 0 {
					t.Fatalf("empty: %+v, %v", result, err)
				}
			case "status", "invalid":
				if err == nil || result != nil || strings.Contains(err.Error(), "token") {
					t.Fatalf("failure: %+v, %v", result, err)
				}
			default:
				if !errors.Is(err, ErrTooLarge) || result != nil {
					t.Fatalf("oversized body: %+v, %v", result, err)
				}
			}
		})
	}
}

func TestFetchCancellationAndTimeout(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout", "body-timeout"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "body-timeout" {
					w.(http.Flusher).Flush()
				}
				close(started)
				<-r.Context().Done()
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				go func() { <-started; cancel() }()
			}
			_, err := Fetch(ctx, server.Client(), server.URL+"?token=super-secret", FetchOptions{Timeout: 100 * time.Millisecond})
			want := context.DeadlineExceeded
			if mode == "cancel" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || strings.Contains(err.Error(), "super-secret") {
				t.Fatalf("wanted redacted %v, got %v", want, err)
			}
		})
	}
}

func TestFetchClientPolicyAndURLValidation(t *testing.T) {
	policyErr := errors.New("blocked destination with secret=token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return policyErr }
	_, err := Fetch(context.Background(), client, server.URL, FetchOptions{})
	if !errors.Is(err, policyErr) || strings.Contains(err.Error(), "token") {
		t.Fatalf("redirect policy not preserved/redacted: %v", err)
	}
	for _, address := range []string{"file:///etc/passwd", "ftp://host/source", "://token", "https:///source"} {
		if _, err := Fetch(context.Background(), client, address, FetchOptions{}); err == nil {
			t.Fatal("invalid URL accepted")
		}
	}
}

func TestDecodePreservesMalformedCandidates(t *testing.T) {
	// Public lists can contain a handful of bad credentials among thousands
	// of valid links. Report those candidates later; do not lose the source.
	body := "ss://bad\x00credential@host:443#broken\nsocks://host:1080\n"
	links, err := Decode([]byte(body), DecodeOptions{})
	if err != nil || len(links) != 2 || links[0] != "ss://bad\x00credential@host:443#broken" {
		t.Fatalf("malformed candidate lost: %d links, %v", len(links), err)
	}
}

// MTProto links travel in subscriptions like any other, plain or base64.
func TestDecodePreservesMTProtoLinks(t *testing.T) {
	const secret = "dd00112233445566778899aabbccddeeff"
	want := []string{
		"tg://proxy?server=1.2.3.4&port=443&secret=" + secret + "#mine",
		"https://t.me/proxy?server=1.2.3.4&port=443&secret=" + secret,
		"http://telegram.dog/proxy?server=5.6.7.8&port=8443&secret=" + secret,
		"vless://uuid@host:443#one",
	}
	input := strings.Join(want, "\n") + "\n"
	for _, body := range []string{input, base64.StdEncoding.EncodeToString([]byte(input))} {
		got, err := Decode([]byte(body), DecodeOptions{})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("decoded %v, error %v", got, err)
		}
	}
}

// Providers prepend metadata lines; they must not invalidate the source.
func TestDecodeSkipsCommentLines(t *testing.T) {
	const input = "#profile-title: base64:TXkgUHJvdmlkZXI=\n#profile-update-interval: 12\n" +
		"// Updated 2026-09-20\nvless://uuid@host:443#one\n  # indented note\nsocks://host:1080\n"
	want := []string{"vless://uuid@host:443#one", "socks://host:1080"}
	for _, body := range []string{input, base64.StdEncoding.EncodeToString([]byte(input))} {
		got, err := Decode([]byte(body), DecodeOptions{})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("decoded %v, error %v", got, err)
		}
	}
	got, err := Decode([]byte("# nothing but a comment\n"), DecodeOptions{})
	if err != nil || len(got) != 0 {
		t.Fatalf("comment-only source: %v, %v", got, err)
	}
}

func TestDecodeSplitsCarriageReturns(t *testing.T) {
	got, err := Decode([]byte("vless://a@h:1\rvmess://b\r\rtrojan://c@h:2"), DecodeOptions{})
	want := []string{"vless://a@h:1", "vmess://b", "trojan://c@h:2"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded %v, error %v", got, err)
	}
}

// The cause is named without leaking the tokenized URL.
func TestFetchErrorNamesCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := server.URL
	server.Close() // nothing listens any more: connection refused
	_, err := Fetch(context.Background(), http.DefaultClient, addr+"/sub?token=super-secret", FetchOptions{})
	if err == nil || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") && !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("cause missing from %q", err)
	}
}

// A wrapped base64 line may start with "//"; only "#" lines are metadata there.
func TestDecodeBase64LineStartingWithSlashes(t *testing.T) {
	encoded := "dm1lc3M6Ly9h" + "\n" + "//8=" // "vmess://a" + bytes 0xff 0xff
	_, err := Decode([]byte(encoded), DecodeOptions{})
	// The payload is not valid UTF-8 once "//8=" is kept, so the decoder must
	// reject it rather than silently decode a truncated body.
	if !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("err = %v, want ErrInvalidFormat (line kept, not dropped as a comment)", err)
	}
}
