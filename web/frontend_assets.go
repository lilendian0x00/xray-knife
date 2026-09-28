package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:generate go run ./internal/compress
//go:embed all:dist-gzip
var embeddedFiles embed.FS

type frontendAsset struct {
	compressed []byte
	decoded    func() ([]byte, error)
	// etag identifies the content; the gzip representation appends "-gz"
	// so the two encodings never share a validator.
	etag string
}

// cacheControlFor picks the caching policy: Vite's content-hashed files
// under assets/ never change, index.html must be revalidated so a new
// build is picked up, and the few unhashed root files get an hour.
func cacheControlFor(name string) string {
	switch {
	case strings.HasPrefix(name, "assets/"):
		return "public, max-age=31536000, immutable"
	case name == "index.html":
		return "no-cache"
	default:
		return "public, max-age=3600"
	}
}

func newFrontendHandler() (http.Handler, error) {
	assets := make(map[string]frontendAsset)
	err := fs.WalkDir(embeddedFiles, "dist-gzip", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		// all: embeds dotfiles too; skip OS litter such as .DS_Store.
		if strings.HasPrefix(path.Base(name), ".") {
			return nil
		}
		if !strings.HasSuffix(name, ".gz") {
			return fmt.Errorf("frontend asset is not gzip compressed: %s", name)
		}
		compressed, err := embeddedFiles.ReadFile(name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(compressed)
		assets[strings.TrimSuffix(strings.TrimPrefix(name, "dist-gzip/"), ".gz")] = frontendAsset{
			compressed: compressed,
			etag:       hex.EncodeToString(sum[:8]),
			// Only for identity responses, then reused. Browsers normally get the
			// precompressed bytes.
			decoded: sync.OnceValues(func() ([]byte, error) {
				zr, err := gzip.NewReader(bytes.NewReader(compressed))
				if err != nil {
					return nil, err
				}
				defer zr.Close()
				return io.ReadAll(zr)
			}),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, ok := assets["index.html"]; !ok {
		return nil, fmt.Errorf("embedded frontend index missing")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "index.html" {
			target := "./"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		asset, ok := assets[name]
		if !ok {
			// A missing file (e.g. a chunk from an older build referenced by a
			// cached page) must 404: answering with index.html would hand the
			// browser HTML where it expects JavaScript.
			if path.Ext(name) != "" {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			// Client-side routes, including /, are served by the SPA entry point.
			name, asset = "index.html", assets["index.html"]
		}
		w.Header().Set("Cache-Control", cacheControlFor(name))
		w.Header().Add("Vary", "Accept-Encoding")
		gzipQ, identityQ := frontendEncodingQuality(r.Header.Values("Accept-Encoding"))
		if gzipQ == 0 && identityQ == 0 {
			http.Error(w, "No acceptable content encoding", http.StatusNotAcceptable)
			return
		}
		useGzip := gzipQ > 0 && gzipQ >= identityQ
		// Byte ranges come from the identity representation. If the client forbids
		// identity, drop Range and send a whole gzip body: a multipart range
		// envelope must not be labeled Content-Encoding: gzip.
		if r.Header.Get("Range") != "" {
			if identityQ > 0 {
				useGzip = false
			} else {
				r = r.Clone(r.Context())
				r.Header.Del("Range")
			}
		}
		body := asset.compressed
		if !useGzip {
			var err error
			body, err = asset.decoded()
			if err != nil {
				http.Error(w, "Could not decode frontend asset", http.StatusInternalServerError)
				return
			}
		}
		contentType := mime.TypeByExtension(path.Ext(name))
		if contentType == "" {
			decoded, err := asset.decoded()
			if err != nil {
				http.Error(w, "Could not decode frontend asset", http.StatusInternalServerError)
				return
			}
			contentType = http.DetectContentType(decoded)
		}
		w.Header().Set("Content-Type", contentType)
		if useGzip {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("ETag", `"`+asset.etag+`-gz"`)
		} else {
			w.Header().Set("ETag", `"`+asset.etag+`"`)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
	}), nil
}

// An explicit coding overrides '*'. Identity is acceptable by default unless
// identity;q=0 or an otherwise-unqualified *;q=0 excludes it.
func frontendEncodingQuality(headers []string) (gzipQ, identityQ float64) {
	gzipQ, identityQ = -1, -1
	wildcard := -1.0
	for _, item := range strings.Split(strings.Join(headers, ","), ",") {
		parts := strings.Split(item, ";")
		quality := 1.0
		for _, parameter := range parts[1:] {
			key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if ok && strings.EqualFold(strings.TrimSpace(key), "q") {
				q, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
				if err != nil || !(q >= 0 && q <= 1) {
					quality = 0
				} else {
					quality = q
				}
			}
		}
		switch strings.ToLower(strings.TrimSpace(parts[0])) {
		case "gzip":
			gzipQ = quality
		case "identity":
			identityQ = quality
		case "*":
			wildcard = quality
		}
	}
	if gzipQ < 0 {
		gzipQ = max(0, wildcard)
	}
	if identityQ < 0 {
		identityQ = 1
		if wildcard == 0 {
			identityQ = 0
		}
	}
	return
}
