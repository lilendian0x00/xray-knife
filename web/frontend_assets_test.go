package web

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
)

func frontendRequest(h http.Handler, method, target, encoding, byteRange string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	if encoding != "" {
		r.Header.Set("Accept-Encoding", encoding)
	}
	if byteRange != "" {
		r.Header.Set("Range", byteRange)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestFrontendAssetsMatchDist(t *testing.T) {
	h, err := newFrontendHandler()
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	err = fs.WalkDir(os.DirFS("dist"), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		files++
		original, err := os.ReadFile(path.Join("dist", name))
		if err != nil {
			return err
		}
		target := "/" + name
		if name == "index.html" {
			target = "/"
		}
		for _, encoding := range []string{"identity", "gzip"} {
			t.Run(name+"/"+encoding, func(t *testing.T) {
				w := frontendRequest(h, "GET", target, encoding, "")
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d: %s", w.Code, w.Body)
				}
				if w.Header().Get("Vary") != "Accept-Encoding" {
					t.Fatal("missing Vary: Accept-Encoding")
				}
				if w.Header().Get("Content-Length") != strconv.Itoa(w.Body.Len()) {
					t.Fatal("incorrect representation length")
				}
				body := w.Body.Bytes()
				if encoding == "gzip" {
					if w.Header().Get("Content-Encoding") != "gzip" {
						t.Fatal("missing gzip encoding")
					}
					zr, err := gzip.NewReader(bytes.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					defer zr.Close()
					body, err = io.ReadAll(zr)
					if err != nil {
						t.Fatal(err)
					}
				} else if w.Header().Get("Content-Encoding") != "" {
					t.Fatal("identity response labeled as compressed")
				}
				if !bytes.Equal(body, original) {
					t.Fatal("response differs from dist; run go generate ./web")
				}
				wantType := map[string]string{".html": "text/html", ".js": "javascript", ".css": "text/css", ".svg": "image/svg+xml"}[path.Ext(name)]
				if wantType != "" && !strings.Contains(w.Header().Get("Content-Type"), wantType) {
					t.Fatalf("incorrect content type: %s", w.Header().Get("Content-Type"))
				}
				head := frontendRequest(h, "HEAD", target, encoding, "")
				if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != w.Header().Get("Content-Length") {
					t.Fatal("HEAD does not match GET headers with an empty body")
				}
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	embeddedCount := 0
	fs.WalkDir(embeddedFiles, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !entry.IsDir() {
			embeddedCount++
			if !strings.HasPrefix(name, "dist-gzip/") || !strings.HasSuffix(name, ".gz") {
				t.Errorf("uncompressed asset embedded: %s", name)
			}
		}
		return nil
	})
	if files != embeddedCount {
		t.Fatalf("dist has %d files, embed has %d; stale generated assets", files, embeddedCount)
	}
}

func TestFrontendNegotiationAndRanges(t *testing.T) {
	h, err := newFrontendHandler()
	if err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		encoding, byteRange string
		status              int
		gzip                bool
	}{
		{"", "", 200, false},
		{"br", "", 200, false},
		{"gzip, deflate, br", "", 200, true},
		{"GZIP", "", 200, true},
		{"gzip;q=0", "", 200, false},
		{"gzip;q=0, *;q=1", "", 200, false},
		{"gzip;q=0.5, identity;q=0.1", "", 200, true},
		{"gzip;q=0.1, identity;q=0.5", "", 200, false},
		{"gzip;q=NaN", "", 200, false},
		{"gzip;q=invalid", "", 200, false},
		{"*", "", 200, true},
		{"*;q=0", "", 406, false},
		{"gzip;q=0, identity;q=0", "", 406, false},
		{"*;q=0, gzip;q=1", "", 200, true},
		{"identity", "bytes=0-9", 206, false},
		{"gzip", "bytes=0-9", 206, false},
		{"gzip", "bytes=0-9,20-29", 206, false},
		{"gzip", "bytes=999999-", 416, false},
		{"gzip, identity;q=0", "bytes=0-9,20-29", 200, true},
	} {
		t.Run(tc.encoding+"/"+tc.byteRange, func(t *testing.T) {
			w := frontendRequest(h, "GET", "/dashboard/deep?tab=proxy", tc.encoding, tc.byteRange)
			if w.Code != tc.status || (w.Header().Get("Content-Encoding") == "gzip") != tc.gzip {
				t.Fatalf("status=%d encoding=%q", w.Code, w.Header().Get("Content-Encoding"))
			}
			if tc.status == 200 && !tc.gzip && !bytes.Equal(w.Body.Bytes(), index) {
				t.Fatal("SPA fallback differs from index.html")
			}
			if tc.status == 206 && tc.byteRange == "bytes=0-9" && !bytes.Equal(w.Body.Bytes(), index[:10]) {
				t.Fatal("incorrect identity byte range")
			}
		})
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Accept-Encoding", "identity;q=0")
	r.Header.Add("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("multiple Accept-Encoding fields not respected")
	}
}

func TestFrontendRouteBoundaries(t *testing.T) {
	s := &Server{router: http.NewServeMux(), authDetails: &AuthDetails{Username: "test"}}
	s.setupRoutes()
	for _, tc := range []struct {
		method, target, contentType string
		status                      int
	}{
		{"GET", "/api/v1/auth/check", "application/json", 200},
		{"GET", "/api/v1/proxy/status", "application/json", 401},
		{"GET", "/missing/client/route", "text/html", 200},
		{"POST", "/missing/client/route", "text/plain", 405},
	} {
		w := frontendRequest(s.router, tc.method, tc.target, "gzip", "")
		if w.Code != tc.status || !strings.Contains(w.Header().Get("Content-Type"), tc.contentType) {
			t.Errorf("%s: status=%d type=%q", tc.target, w.Code, w.Header().Get("Content-Type"))
		}
		if strings.HasPrefix(tc.target, "/api/") && w.Header().Get("Content-Encoding") != "" {
			t.Error("frontend handler intercepted API response")
		}
	}
	w := frontendRequest(s.router, "GET", "/index.html?tab=proxy", "gzip", "")
	if w.Code != 301 || w.Header().Get("Location") != "/?tab=proxy" {
		t.Fatalf("index redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
}
