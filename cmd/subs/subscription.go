package subs

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/lilendian0x00/xray-knife/v11/pkg/subscription"
)

type Subscription struct {
	Remark      string
	Url         string
	UserAgent   string
	Method      string
	ConfigLinks []string
	Proxy       string
	MaxBytes    int64
	MaxLinks    int
	Timeout     time.Duration
	// Format and Skipped describe the last fetched document: what kind it
	// was (plain, base64, clash, singbox, xray) and, for structured
	// documents, how many entries could not become share links, by reason.
	Format  subscription.Format
	Skipped map[string]int
}

// FetchAll retains the CLI API. Library callers should use subscription.Fetch
// to inject their own context, HTTP client, limits, and request policy.
func (s *Subscription) FetchAll() ([]string, error) {
	return s.FetchAllContext(context.Background())
}

func (s *Subscription) FetchAllContext(ctx context.Context) ([]string, error) {
	if s.Method == "" {
		s.Method = http.MethodGet
	}
	// req.C() gives its http.Client a 2-minute Timeout, which silently capped
	// --fetch-timeout. subscription.Fetch bounds the whole fetch with its own
	// context deadline, so drop the client-level one.
	client := req.C().ImpersonateChrome().DisableAutoReadResponse().SetTimeout(0)
	defer client.GetClient().CloseIdleConnections()
	if s.Proxy != "" {
		client.SetProxyURL(s.Proxy)
	}
	headers := client.Headers.Clone()
	if s.UserAgent != "" {
		headers.Set("User-Agent", s.UserAgent)
	}
	result, err := subscription.Fetch(ctx, client.GetClient(), s.Url, subscription.FetchOptions{
		DecodeOptions: subscription.DecodeOptions{MaxBytes: s.MaxBytes, MaxLinks: s.MaxLinks},
		Method:        s.Method,
		Headers:       headers,
		Timeout:       s.Timeout,
	})
	if err != nil {
		return nil, err
	}
	if !result.NotModified {
		s.ConfigLinks = result.Links
		s.Format = result.Format
		s.Skipped = result.Skipped
	}
	return s.ConfigLinks, nil
}

// formatSummary describes a fetched document, e.g. "clash: 120 links,
// skipped 4 (2 unsupported clash proxy type snell, 2 missing server)". It is
// empty for plain and base64 lists that skipped nothing, which is the
// common case and needs no comment.
func formatSummary(format subscription.Format, links int, skipped map[string]int) string {
	total := 0
	for _, n := range skipped {
		total += n
	}
	if total == 0 && (format == "" || format == subscription.FormatPlain || format == subscription.FormatBase64) {
		return ""
	}
	if format == "" {
		format = subscription.FormatPlain
	}
	out := fmt.Sprintf("%s: %d links", format, links)
	if total == 0 {
		return out
	}
	reasons := make([]string, 0, len(skipped))
	for reason := range skipped {
		reasons = append(reasons, reason)
	}
	sort.Slice(reasons, func(i, j int) bool {
		if skipped[reasons[i]] != skipped[reasons[j]] {
			return skipped[reasons[i]] > skipped[reasons[j]]
		}
		return reasons[i] < reasons[j]
	})
	parts := make([]string, len(reasons))
	for i, r := range reasons {
		parts[i] = fmt.Sprintf("%d %s", skipped[r], r)
	}
	return fmt.Sprintf("%s, skipped %d (%s)", out, total, strings.Join(parts, ", "))
}

func (s *Subscription) RemoveDuplicate(verbose bool) {
	// Remove duplicates using hashmap (hashed keys)
	allKeys := make(map[string]bool)
	var list []string
	for _, item := range s.ConfigLinks {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	if verbose {
		log.Printf("Removed %d duplicate configs!\n", len(s.ConfigLinks)-len(list))
	}
	s.ConfigLinks = list
}
