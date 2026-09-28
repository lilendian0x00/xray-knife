package web

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/subscription"
)

// subscriptionView is the JSON form of a database.Subscription.
type subscriptionView struct {
	ID            int64      `json:"id"`
	URL           string     `json:"url"`
	Remark        string     `json:"remark"`
	UserAgent     string     `json:"userAgent"`
	Enabled       bool       `json:"enabled"`
	LastFetchedAt *time.Time `json:"lastFetchedAt"`
	CreatedAt     time.Time  `json:"createdAt"`
	ConfigCount   int        `json:"configCount"`
}

func toSubscriptionView(s database.Subscription) subscriptionView {
	v := subscriptionView{
		ID:        s.ID,
		URL:       s.URL,
		Remark:    s.Remark.String,
		UserAgent: s.UserAgent.String,
		Enabled:   s.Enabled,
		CreatedAt: s.CreatedAt,
	}
	if s.LastFetchedAt.Valid {
		t := s.LastFetchedAt.Time
		v.LastFetchedAt = &t
	}
	if n, err := database.CountSubscriptionConfigs(s.ID); err == nil {
		v.ConfigCount = n
	}
	return v
}

// configView is the JSON form of a database.SubscriptionConfig.
type configView struct {
	ID             int64      `json:"id"`
	SubscriptionID *int64     `json:"subscriptionId"`
	Link           string     `json:"link"`
	Protocol       string     `json:"protocol"`
	Remark         string     `json:"remark"`
	AddedAt        time.Time  `json:"addedAt"`
	LastSeenAt     *time.Time `json:"lastSeenAt"`
}

func toConfigView(c database.SubscriptionConfig) configView {
	v := configView{
		ID:       c.ID,
		Link:     c.ConfigLink,
		Protocol: c.Protocol.String,
		Remark:   c.Remark.String,
		AddedAt:  c.AddedAt,
	}
	if c.SubscriptionID.Valid {
		id := c.SubscriptionID.Int64
		v.SubscriptionID = &id
	}
	if c.LastSeenAt.Valid {
		t := c.LastSeenAt.Time
		v.LastSeenAt = &t
	}
	return v
}

func (h *APIHandler) registerSubscriptionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/subscriptions", h.handleListSubscriptions)
	mux.HandleFunc("POST /api/v1/subscriptions", h.handleAddSubscription)
	mux.HandleFunc("POST /api/v1/subscriptions/fetch-all", h.handleFetchAllSubscriptions)
	mux.HandleFunc("GET /api/v1/subscriptions/{id}", h.handleGetSubscription)
	mux.HandleFunc("PATCH /api/v1/subscriptions/{id}", h.handleUpdateSubscription)
	mux.HandleFunc("DELETE /api/v1/subscriptions/{id}", h.handleDeleteSubscription)
	mux.HandleFunc("POST /api/v1/subscriptions/{id}/fetch", h.handleFetchSubscription)
	mux.HandleFunc("POST /api/v1/subscriptions/{id}/test", h.handleTestSubscription)
	mux.HandleFunc("GET /api/v1/subscriptions/{id}/configs", h.handleSubscriptionConfigs)
	mux.HandleFunc("GET /api/v1/configs", h.handleAllConfigs)
}

// pathID reads the {id} path value as a positive integer.
func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, badRequest("invalid id %q", r.PathValue("id"))
	}
	return id, nil
}

// lookupSubscription loads a subscription or returns a 404 error.
func lookupSubscription(id int64) (*database.Subscription, error) {
	sub, err := database.GetSubscriptionByID(id)
	if err != nil {
		if strings.Contains(err.Error(), "no subscription found") {
			return nil, notFound("no subscription with id %d", id)
		}
		return nil, err
	}
	return sub, nil
}

// validSubscriptionURL accepts only http(s) URLs with a host.
func validSubscriptionURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return badRequest("subscription URL must be an http:// or https:// URL with a host")
	}
	return nil
}

func (h *APIHandler) handleListSubscriptions(w http.ResponseWriter, r *http.Request) {
	if err := dbReady(); err != nil {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}
	subs, err := database.ListSubscriptions()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	out := make([]subscriptionView, 0, len(subs))
	for _, s := range subs {
		out = append(out, toSubscriptionView(s))
	}
	writeJSONResponse(w, http.StatusOK, out)
}

func (h *APIHandler) handleAddSubscription(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL       string `json:"url"`
		Remark    string `json:"remark"`
		UserAgent string `json:"userAgent"`
	}
	if err := decodeJSONBody(w, r, &body); err != nil {
		writeDecodeError(w, err)
		return
	}
	body.URL = strings.TrimSpace(body.URL)
	if err := validSubscriptionURL(body.URL); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if err := dbReady(); err != nil {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}
	if err := database.AddSubscription(body.URL, strings.TrimSpace(body.Remark), strings.TrimSpace(body.UserAgent)); err != nil {
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, conflict(codeExists, "a subscription with this URL already exists"), http.StatusConflict)
			return
		}
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	subs, err := database.ListSubscriptions()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	for _, s := range subs {
		if s.URL == body.URL {
			writeJSONResponse(w, http.StatusCreated, toSubscriptionView(s))
			return
		}
	}
	writeJSONResponse(w, http.StatusCreated, map[string]string{"status": "created"})
}

func (h *APIHandler) handleGetSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if err := dbReady(); err != nil {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}
	sub, err := lookupSubscription(id)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, toSubscriptionView(*sub))
}

func (h *APIHandler) handleUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	var body struct {
		URL       *string `json:"url"`
		Remark    *string `json:"remark"`
		UserAgent *string `json:"userAgent"`
		Enabled   *bool   `json:"enabled"`
	}
	if err := decodeJSONBody(w, r, &body); err != nil {
		writeDecodeError(w, err)
		return
	}
	if body.URL != nil {
		trimmed := strings.TrimSpace(*body.URL)
		if err := validSubscriptionURL(trimmed); err != nil {
			writeError(w, err, http.StatusBadRequest)
			return
		}
		body.URL = &trimmed
	}
	if body.URL == nil && body.Remark == nil && body.UserAgent == nil && body.Enabled == nil {
		writeError(w, badRequest("nothing to update"), http.StatusBadRequest)
		return
	}
	if err := dbReady(); err != nil {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}
	if _, err := lookupSubscription(id); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	if err := database.UpdateSubscription(id, body.URL, body.Remark, body.UserAgent, body.Enabled); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "already exists") {
			writeError(w, conflict(codeExists, "a subscription with this URL already exists"), http.StatusConflict)
			return
		}
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	sub, err := lookupSubscription(id)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, toSubscriptionView(*sub))
}

func (h *APIHandler) handleDeleteSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if err := dbReady(); err != nil {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}
	if _, err := lookupSubscription(id); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	deleted, err := database.DeleteSubscriptionCounted(id)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"status": "deleted", "configsDeleted": deleted})
}

// fetchOptions is the optional body of the fetch endpoints.
type fetchOptions struct {
	MaxBytes   int64  `json:"maxBytes"`
	MaxLinks   int    `json:"maxLinks"`
	TimeoutSec int    `json:"timeoutSec"`
	Proxy      string `json:"proxy"`
	UserAgent  string `json:"userAgent"`
}

func (o *fetchOptions) validate() error {
	if o.MaxBytes < 0 || o.MaxLinks < 0 || o.TimeoutSec < 0 {
		return badRequest("maxBytes, maxLinks and timeoutSec must not be negative")
	}
	if o.TimeoutSec > 600 {
		return badRequest("timeoutSec must be at most 600")
	}
	if o.Proxy != "" {
		u, err := url.Parse(o.Proxy)
		if err != nil || u.Host == "" {
			return badRequest("proxy must be a URL such as socks5://127.0.0.1:1080")
		}
	}
	return nil
}

// fetchOutcome is the result of fetching one subscription.
type fetchOutcome struct {
	ID          int64 `json:"id"`
	Fetched     int   `json:"fetched"`
	Saved       int   `json:"saved"`
	Unparsable  int   `json:"unparsable"`
	NotModified bool  `json:"notModified"`
	// Format is the detected document format (plain, base64, clash,
	// singbox, xray); Skipped counts structured entries that could not be
	// turned into share links, by reason.
	Format      string         `json:"format,omitempty"`
	Skipped     map[string]int `json:"skipped,omitempty"`
	SkipSummary []string       `json:"skipSummary,omitempty"`
	Error       string         `json:"error,omitempty"`
}

// skipSummary renders skip counts as sorted "reason (count)" entries.
func skipSummary(skipped map[string]int) []string {
	out := make([]string, 0, len(skipped))
	for reason, n := range skipped {
		out = append(out, fmt.Sprintf("%s (%d)", reason, n))
	}
	sort.Strings(out)
	return out
}

// fetchSubscription downloads one subscription and stores its configs. It
// mirrors `xray-knife subs fetch`: Chrome impersonation, the subscription's
// own User-Agent unless overridden, bounded size, parse errors kept as
// unknown-protocol rows.
func fetchSubscription(ctx context.Context, sub *database.Subscription, opts fetchOptions) (fetchOutcome, error) {
	out := fetchOutcome{ID: sub.ID}
	client := req.C().ImpersonateChrome().DisableAutoReadResponse()
	defer client.GetClient().CloseIdleConnections()
	// Fetch below enforces its own deadline; req's default 2-minute client
	// timeout would silently cap a longer one.
	client.SetTimeout(0)
	if opts.Proxy != "" {
		client.SetProxyURL(opts.Proxy)
	}
	headers := client.Headers.Clone()
	ua := sub.UserAgent.String
	if opts.UserAgent != "" {
		ua = opts.UserAgent
	}
	if ua != "" {
		headers.Set("User-Agent", ua)
	}
	res, err := subscription.Fetch(ctx, client.GetClient(), sub.URL, subscription.FetchOptions{
		DecodeOptions: subscription.DecodeOptions{MaxBytes: opts.MaxBytes, MaxLinks: opts.MaxLinks},
		Headers:       headers,
		Timeout:       time.Duration(opts.TimeoutSec) * time.Second,
	})
	if err != nil {
		// The document arrived but is unusable (wrong format, too big, no
		// supported proxies): that is not a gateway failure.
		if errors.Is(err, subscription.ErrInvalidFormat) || errors.Is(err, subscription.ErrTooLarge) || errors.Is(err, subscription.ErrTooManyLinks) {
			return out, &apiError{status: http.StatusUnprocessableEntity, code: codeInvalidFormat, msg: err.Error()}
		}
		// fetchError hides URLs/tokens; surface the underlying cause kind.
		msg := err.Error()
		var inner interface{ Unwrap() error }
		if errors.As(err, &inner) {
			if cause := inner.Unwrap(); cause != nil {
				var ue *url.Error
				if errors.As(cause, &ue) {
					msg += ": " + ue.Err.Error()
				} else if errors.Is(cause, context.DeadlineExceeded) {
					msg += ": timeout"
				}
			}
		}
		return out, &apiError{status: http.StatusBadGateway, code: codeFetchFailed, msg: msg}
	}
	if res.NotModified {
		out.NotModified = true
		return out, nil
	}
	out.Fetched = len(res.Links)
	out.Format = string(res.Format)
	if len(res.Skipped) > 0 {
		out.Skipped = res.Skipped
		out.SkipSummary = skipSummary(res.Skipped)
	}
	configs, unparsable := parseSubscriptionLinks(res.Links, sub.ID)
	out.Unparsable = unparsable
	if len(configs) > 0 {
		if err := database.UpsertSubscriptionConfigs(configs); err != nil {
			return out, err
		}
	}
	out.Saved = len(configs)
	if err := database.UpdateSubscriptionFetched(sub.ID, time.Now()); err != nil {
		return out, err
	}
	return out, nil
}

// linkParser parses links for their protocol and remark.
var linkParser = sync.OnceValue(func() core.Core { return core.NewAutomaticCore(false, false) })

// parseSubscriptionLinks builds the rows for a subscription's links, as
// `subs fetch` does (core.DescribeLink), counting the unparsable ones.
func parseSubscriptionLinks(links []string, subID int64) ([]database.SubscriptionConfig, int) {
	now := time.Now().UTC()
	parser := linkParser()
	configs := make([]database.SubscriptionConfig, 0, len(links))
	unparsable := 0
	seen := make(map[string]bool, len(links))
	for _, link := range links {
		link = strings.TrimSpace(link)
		if link == "" || seen[link] {
			continue
		}
		seen[link] = true
		c := database.SubscriptionConfig{
			SubscriptionID: sql.NullInt64{Int64: subID, Valid: true},
			ConfigLink:     link,
			LastSeenAt:     database.NullTime{Time: now, Valid: true},
		}
		proto, remark, ok := core.DescribeLink(parser, link)
		c.Protocol = sql.NullString{String: proto, Valid: proto != ""}
		c.Remark = sql.NullString{String: remark, Valid: remark != ""}
		if !ok {
			unparsable++
		}
		configs = append(configs, c)
	}
	return configs, unparsable
}

func (h *APIHandler) handleFetchSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	var opts fetchOptions
	if err := decodeOptionalJSONBody(w, r, &opts, maxSmallBody); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := opts.validate(); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if err := dbReady(); err != nil {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}
	sub, err := lookupSubscription(id)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	out, err := fetchSubscription(r.Context(), sub, opts)
	if err != nil {
		writeError(w, err, http.StatusBadGateway)
		return
	}
	if fresh, err := lookupSubscription(id); err == nil {
		sub = fresh
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"fetched":      out.Fetched,
		"saved":        out.Saved,
		"unparsable":   out.Unparsable,
		"notModified":  out.NotModified,
		"format":       out.Format,
		"skipped":      out.Skipped,
		"skipSummary":  out.SkipSummary,
		"subscription": toSubscriptionView(*sub),
	})
}

func (h *APIHandler) handleFetchAllSubscriptions(w http.ResponseWriter, r *http.Request) {
	var opts fetchOptions
	if err := decodeOptionalJSONBody(w, r, &opts, maxSmallBody); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := opts.validate(); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if err := dbReady(); err != nil {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}
	subs, err := database.ListSubscriptions()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	results := make([]fetchOutcome, 0, len(subs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)
	for _, s := range subs {
		if !s.Enabled {
			continue
		}
		wg.Add(1)
		go func(s database.Subscription) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out, err := fetchSubscription(r.Context(), &s, opts)
			if err != nil {
				out.Error = err.Error()
			}
			mu.Lock()
			results = append(results, out)
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	writeJSONResponse(w, http.StatusOK, map[string]any{"results": results})
}

func (h *APIHandler) handleTestSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	var body httpTestRequestBody
	if err := decodeOptionalJSONBody(w, r, &body, maxLargeBody); err != nil {
		writeDecodeError(w, err)
		return
	}
	body.SubscriptionID = id
	h.startHttpTest(w, &body)
}

// listConfigs serves a filtered, paginated config list.
func listConfigs(w http.ResponseWriter, r *http.Request, subID int64) {
	if err := dbReady(); err != nil {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}
	protocol := strings.TrimSpace(r.URL.Query().Get("protocol"))
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	configs, err := database.ListSubscriptionConfigs(subID, protocol, 0)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	views := make([]configView, 0, len(configs))
	for _, c := range configs {
		if q != "" && !strings.Contains(strings.ToLower(c.ConfigLink), q) && !strings.Contains(strings.ToLower(c.Remark.String), q) {
			continue
		}
		views = append(views, toConfigView(c))
	}
	page, perPage, _ := pageParams(r)
	start := min((page-1)*perPage, len(views))
	end := min(start+perPage, len(views))
	writeJSONResponse(w, http.StatusOK, paginated[configView]{Items: views[start:end], Total: len(views), Page: page, PerPage: perPage})
}

func (h *APIHandler) handleSubscriptionConfigs(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if err := dbReady(); err != nil {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}
	if _, err := lookupSubscription(id); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	listConfigs(w, r, id)
}

func (h *APIHandler) handleAllConfigs(w http.ResponseWriter, r *http.Request) {
	var subID int64
	if s := r.URL.Query().Get("subscriptionId"); s != "" {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil || id < 0 {
			writeError(w, badRequest("invalid subscriptionId"), http.StatusBadRequest)
			return
		}
		subID = id
	}
	listConfigs(w, r, subID)
}
