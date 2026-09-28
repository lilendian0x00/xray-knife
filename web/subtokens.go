package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/utils/xkhome"
)

// Public subscription tokens let phone clients (v2rayNG, Hiddify, Clash,
// sing-box) subscribe to the configs that recently passed a test, at
// /sub/<token>, without a login. Only a SHA-256 of each token is stored:
// tokens are 192 random bits, so a fast hash is enough, and a leaked file
// does not leak working URLs.

const (
	subTokenPrefix       = "xks_"
	subTokenFileName     = "webui-sub-tokens.json"
	maxSubTokens         = 64
	subTokenRatePerMin   = 30
	defaultSubMax        = 200
	defaultSubUpdateHrs  = 6
	subLastUsedSaveEvery = time.Minute
)

// subTokenDefaults are the filters a token applies unless the request
// overrides them with query parameters.
type subTokenDefaults struct {
	Format              string  `json:"format"`
	Status              string  `json:"status"`
	Max                 int     `json:"max"`
	SubscriptionIDs     []int64 `json:"subscriptionIds,omitempty"`
	Protocol            string  `json:"protocol,omitempty"`
	MaxAgeHours         int     `json:"maxAgeHours,omitempty"`
	UpdateIntervalHours int     `json:"updateIntervalHours,omitempty"`
}

type subToken struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Hash       string           `json:"hash"`   // hex SHA-256 of the token
	Prefix     string           `json:"prefix"` // first characters, to recognise it in lists
	CreatedAt  time.Time        `json:"createdAt"`
	LastUsedAt *time.Time       `json:"lastUsedAt,omitempty"`
	UseCount   int64            `json:"useCount"`
	Defaults   subTokenDefaults `json:"defaults"`

	// Per-token request budget (not persisted).
	windowStart time.Time
	windowCount int
}

// subTokenView is what the API lists (never the hash).
type subTokenView struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Prefix     string           `json:"prefix"`
	CreatedAt  time.Time        `json:"createdAt"`
	LastUsedAt *time.Time       `json:"lastUsedAt"`
	UseCount   int64            `json:"useCount"`
	Defaults   subTokenDefaults `json:"defaults"`
}

func (t *subToken) view() subTokenView {
	return subTokenView{ID: t.ID, Name: t.Name, Prefix: t.Prefix, CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt, UseCount: t.UseCount, Defaults: t.Defaults}
}

// subTokenStore keeps tokens in a 0600 JSON file in the xray-knife
// directory (or only in memory when path is empty).
type subTokenStore struct {
	mu        sync.Mutex
	path      string
	tokens    []*subToken
	lastSaved time.Time
	now       func() time.Time
	// broken is set when the file exists but cannot be read; token
	// features then stay off rather than overwriting it with an empty list.
	broken error
}

// unavailable reports why token features are off (nil when they work).
func (st *subTokenStore) unavailable() error {
	if st == nil {
		return errors.New("subscription tokens are not configured")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.broken != nil {
		return &apiError{status: http.StatusServiceUnavailable, code: "tokens_unavailable", msg: st.broken.Error()}
	}
	return nil
}

func hashSubToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

const revocationFileName = "webui-revoked.json"

// defaultStatePath is name in the xray-knife directory ("" if unavailable).
func defaultStatePath(name string) string {
	dir, err := xkhome.Dir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, name)
}

// defaultSubTokenPath is webui-sub-tokens.json in the xray-knife directory.
func defaultSubTokenPath() string { return defaultStatePath(subTokenFileName) }

func loadSubTokenStore(path string) (*subTokenStore, error) {
	st := &subTokenStore{path: path, now: time.Now}
	if path == "" {
		return st, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		st.broken = fmt.Errorf("subscription tokens are disabled: cannot read %s: %v", path, err)
		return st, st.broken
	}
	if err := json.Unmarshal(data, &st.tokens); err != nil {
		st.tokens = nil
		// Keep a copy and never write over the original: fixing or removing
		// it (then restarting) is the user's call.
		backup := path + ".bak"
		_ = os.WriteFile(backup, data, 0o600)
		st.broken = fmt.Errorf("subscription tokens are disabled: %s is corrupt (%v); a copy is at %s — fix or delete it and restart", path, err, backup)
		return st, st.broken
	}
	return st, nil
}

// saveLocked writes the store atomically. The caller holds mu.
func (st *subTokenStore) saveLocked() error {
	st.lastSaved = st.now()
	if st.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(st.tokens, "", "  ")
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}

// create makes a token; the plaintext is returned once and never stored.
func (st *subTokenStore) create(name string, d subTokenDefaults) (string, subTokenView, error) {
	var raw [24]byte
	var id [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", subTokenView{}, err
	}
	if _, err := rand.Read(id[:]); err != nil {
		return "", subTokenView{}, err
	}
	plain := subTokenPrefix + base64.RawURLEncoding.EncodeToString(raw[:])
	if err := st.unavailable(); err != nil {
		return "", subTokenView{}, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.tokens) >= maxSubTokens {
		return "", subTokenView{}, conflict(codeBusy, "at most %d subscription tokens; revoke one first", maxSubTokens)
	}
	t := &subToken{
		ID:        hex.EncodeToString(id[:]),
		Name:      name,
		Hash:      hashSubToken(plain),
		Prefix:    plain[:len(subTokenPrefix)+4],
		CreatedAt: st.now().UTC(),
		Defaults:  d,
	}
	st.tokens = append(st.tokens, t)
	if err := st.saveLocked(); err != nil {
		st.tokens = st.tokens[:len(st.tokens)-1]
		return "", subTokenView{}, err
	}
	return plain, t.view(), nil
}

func (st *subTokenStore) list() []subTokenView {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]subTokenView, 0, len(st.tokens))
	for _, t := range st.tokens {
		out = append(out, t.view())
	}
	return out
}

func (st *subTokenStore) update(id string, name *string, d *subTokenDefaults) (subTokenView, error) {
	if err := st.unavailable(); err != nil {
		return subTokenView{}, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, t := range st.tokens {
		if t.ID == id {
			if name != nil {
				t.Name = *name
			}
			if d != nil {
				t.Defaults = *d
			}
			if err := st.saveLocked(); err != nil {
				return subTokenView{}, err
			}
			return t.view(), nil
		}
	}
	return subTokenView{}, notFound("no subscription token %q", id)
}

func (st *subTokenStore) revoke(id string) error {
	if err := st.unavailable(); err != nil {
		return err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for i, t := range st.tokens {
		if t.ID == id {
			st.tokens = append(st.tokens[:i], st.tokens[i+1:]...)
			return st.saveLocked()
		}
	}
	return notFound("no subscription token %q", id)
}

// lookup finds the token for plain, comparing every stored hash in
// constant time so timing does not reveal how close a guess was. It also
// applies the per-token request budget.
// The returned view is a copy, safe to use after a concurrent update.
func (st *subTokenStore) lookup(plain string) (found *subTokenView, limited bool) {
	want := []byte(hashSubToken(plain))
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.broken != nil {
		return nil, false
	}
	var tok *subToken
	for _, t := range st.tokens {
		if subtle.ConstantTimeCompare(want, []byte(t.Hash)) == 1 {
			tok = t
		}
	}
	if tok == nil {
		return nil, false
	}
	v := tok.view()
	v.Defaults.SubscriptionIDs = append([]int64(nil), tok.Defaults.SubscriptionIDs...)
	now := st.now()
	if now.Sub(tok.windowStart) >= time.Minute {
		tok.windowStart, tok.windowCount = now, 0
	}
	tok.windowCount++
	if tok.windowCount > subTokenRatePerMin {
		return &v, true
	}
	used := now.UTC()
	tok.LastUsedAt = &used
	tok.UseCount++
	// Usage stats are persisted at most once a minute.
	if now.Sub(st.lastSaved) >= subLastUsedSaveEvery {
		_ = st.saveLocked()
	}
	return &v, false
}

// validateSubDefaults checks token defaults and fills in the standard ones.
func validateSubDefaults(d *subTokenDefaults) error {
	d.Format = strings.ToLower(strings.TrimSpace(d.Format))
	if d.Format == "" {
		d.Format = "base64"
	}
	if _, ok := exportFormats[d.Format]; !ok {
		return badRequest("unknown format %q (want plain, base64, clash, singbox or xray)", d.Format)
	}
	d.Status = strings.ToLower(strings.TrimSpace(d.Status))
	switch d.Status {
	case "":
		d.Status = "passed"
	case "any", "all":
		d.Status = "any"
	case "passed", "semi-passed":
	default:
		return badRequest("status must be passed, semi-passed or any")
	}
	if d.Max < 0 || d.Max > maxExportLinks {
		return badRequest("max must be between 0 (default %d) and %d", defaultSubMax, maxExportLinks)
	}
	if d.Max == 0 {
		d.Max = defaultSubMax
	}
	for _, id := range d.SubscriptionIDs {
		if id <= 0 {
			return badRequest("invalid subscription id %d", id)
		}
	}
	d.Protocol = strings.ToLower(strings.TrimSpace(d.Protocol))
	if d.MaxAgeHours < 0 || d.UpdateIntervalHours < 0 || d.UpdateIntervalHours > 24*30 {
		return badRequest("maxAgeHours and updateIntervalHours must be non-negative (update interval at most 720)")
	}
	if d.UpdateIntervalHours == 0 {
		d.UpdateIntervalHours = defaultSubUpdateHrs
	}
	return nil
}

var subTokenNameRe = regexp.MustCompile(`^[\p{L}\p{N} _.\-]{1,64}$`)

// --- authenticated token management ---

func (h *APIHandler) registerSubTokenRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/sub-tokens", h.handleListSubTokens)
	mux.HandleFunc("POST /api/v1/sub-tokens", h.handleCreateSubToken)
	mux.HandleFunc("PATCH /api/v1/sub-tokens/{id}", h.handleUpdateSubToken)
	mux.HandleFunc("DELETE /api/v1/sub-tokens/{id}", h.handleRevokeSubToken)
}

type subTokenRequest struct {
	Name *string `json:"name"`
	subTokenDefaults
}

func (h *APIHandler) handleListSubTokens(w http.ResponseWriter, r *http.Request) {
	if err := h.subTokens.unavailable(); err != nil {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}
	writeJSONResponse(w, http.StatusOK, h.subTokens.list())
}

func (h *APIHandler) handleCreateSubToken(w http.ResponseWriter, r *http.Request) {
	var req subTokenRequest
	if err := decodeOptionalJSONBody(w, r, &req, maxSmallBody); err != nil {
		writeDecodeError(w, err)
		return
	}
	name := "xray-knife"
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if !subTokenNameRe.MatchString(name) {
		writeError(w, badRequest("name must be 1-64 letters, digits, spaces, '.', '_' or '-'"), http.StatusBadRequest)
		return
	}
	d := req.subTokenDefaults
	if err := validateSubDefaults(&d); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	plain, view, err := h.subTokens.create(name, d)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusCreated, map[string]any{
		"token":        plain,
		"path":         "/sub/" + plain,
		"subscription": view,
		"note":         "The token is shown only now; store the URL. Revoke it to disable the URL.",
	})
}

func (h *APIHandler) handleUpdateSubToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     *string           `json:"name"`
		Defaults *subTokenDefaults `json:"defaults"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if req.Name != nil {
		n := strings.TrimSpace(*req.Name)
		if !subTokenNameRe.MatchString(n) {
			writeError(w, badRequest("name must be 1-64 letters, digits, spaces, '.', '_' or '-'"), http.StatusBadRequest)
			return
		}
		req.Name = &n
	}
	if req.Defaults != nil {
		if err := validateSubDefaults(req.Defaults); err != nil {
			writeError(w, err, http.StatusBadRequest)
			return
		}
	}
	view, err := h.subTokens.update(r.PathValue("id"), req.Name, req.Defaults)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	if h.subCache != nil {
		h.subCache.forget(view.ID)
	}
	writeJSONResponse(w, http.StatusOK, view)
}

func (h *APIHandler) handleRevokeSubToken(w http.ResponseWriter, r *http.Request) {
	if err := h.subTokens.revoke(r.PathValue("id")); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// --- public /sub/<token> ---

// handlePublicSub serves the configs selected by a token. The token is
// looked up first: a valid token only draws on its own budget, so other
// clients guessing from the same address (or a shared reverse proxy) cannot
// lock it out. Unknown tokens are terse (no hint whether one exists) and
// rate-limited per client address. An empty selection is a 404 so clients
// keep their last good profile instead of replacing it with nothing.
func (s *Server) handlePublicSub(w http.ResponseWriter, r *http.Request) {
	ip := limiterKey(s.clientIP(r))
	if s.subTokens.unavailable() != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	tok, limited := s.subTokens.lookup(r.PathValue("token"))
	if tok == nil {
		if ok, wait := s.subLimiter.allow(ip); !ok {
			writeRateLimited(w, wait)
			return
		}
		s.subLimiter.fail(ip)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if limited {
		writeRateLimited(w, time.Minute)
		return
	}

	if err := dbReady(); err != nil {
		s.logger.Printf("[SUB] %q: %v", tok.Name, err)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	q, empty, err := publicSubQuery(tok.Defaults, r.URL.Query(), enabledSubscriptionIDs)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.status == http.StatusBadRequest {
			http.Error(w, ae.msg, http.StatusBadRequest)
			return
		}
		s.logger.Printf("[SUB] %q: %v", tok.Name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var links []string
	if !empty {
		links, err = s.subCache.get(tok.ID, q, func() ([]string, error) { return selectExportLinks(q) })
		if err != nil {
			s.logger.Printf("[SUB] %q: %v", tok.Name, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	if len(links) == 0 {
		http.Error(w, "no configs match", http.StatusNotFound)
		return
	}
	hdr := w.Header()
	hdr.Set("Cache-Control", "no-store")
	// Clients (Clash Verge, v2rayN, Hiddify, sing-box) read these to name the
	// profile and schedule refreshes.
	hdr.Set("Profile-Update-Interval", strconv.Itoa(max(tok.Defaults.UpdateIntervalHours, 1)))
	hdr.Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(tok.Name)))
	hdr.Set("X-Config-Count", strconv.Itoa(len(links)))
	s.logger.Printf("[SUB] %q served %d config(s) as %s to %s", tok.Name, len(links), q.Format, ip)
	writeExport(w, q, links, safeFilename(tok.Name), false, "inline")
}

// statusRank orders export statuses from widest to strictest.
var statusRank = map[string]int{"": 0, "semi-passed": 1, "passed": 2}

// publicSubQuery builds the export query for a public request. The token's
// settings are upper bounds: query parameters may narrow them (a stricter
// status, a lower max or age, one of the token's subscriptions, a single
// protocol) but never widen them. empty reports a request that cannot match
// anything within the token's scope.
func publicSubQuery(d subTokenDefaults, v url.Values, enabledIDs func() (map[int64]bool, error)) (q exportQuery, empty bool, err error) {
	q = exportQuery{
		Format:          d.Format,
		Status:          d.Status,
		Protocol:        d.Protocol,
		Limit:           d.Max,
		SubscriptionIDs: append([]int64(nil), d.SubscriptionIDs...),
		MaxAge:          time.Duration(d.MaxAgeHours) * time.Hour,
	}
	if q.Status == "any" {
		q.Status = ""
	}
	if q.Limit <= 0 || q.Limit > maxExportLinks {
		q.Limit = maxExportLinks
	}
	if _, ok := exportFormats[q.Format]; !ok {
		q.Format = "base64"
	}

	if f := strings.ToLower(strings.TrimSpace(v.Get("format"))); f != "" {
		if _, ok := exportFormats[f]; !ok {
			return q, false, badRequest("unknown format %q", f)
		}
		q.Format = f
	}
	if st, ok := v["status"]; ok {
		want := strings.ToLower(strings.TrimSpace(st[0]))
		if want == "any" || want == "all" {
			want = ""
		}
		if !database.ValidExportStatus(want) {
			return q, false, badRequest("status must be passed, semi-passed or any")
		}
		if statusRank[want] > statusRank[q.Status] {
			q.Status = want
		}
	}
	if p := strings.ToLower(strings.TrimSpace(v.Get("protocol"))); p != "" {
		if q.Protocol != "" && q.Protocol != p {
			empty = true
		}
		q.Protocol = p
	}
	if m := v.Get("max"); m != "" {
		n, err := strconv.Atoi(m)
		if err != nil || n < 0 {
			return q, false, badRequest("max must be a non-negative number")
		}
		if n > 0 && n < q.Limit {
			q.Limit = n
		}
	}
	if h := v.Get("maxAgeHours"); h != "" {
		n, err := strconv.Atoi(h)
		if err != nil || n < 0 {
			return q, false, badRequest("maxAgeHours must be a non-negative number")
		}
		if age := time.Duration(n) * time.Hour; n > 0 && (q.MaxAge == 0 || age < q.MaxAge) {
			q.MaxAge = age
		}
	}
	if ins := v.Get("insecure"); ins == "1" || ins == "true" {
		q.Insecure = true
	}
	if sub := v.Get("sub"); sub != "" {
		want, err := parseIDList(sub)
		if err != nil {
			return q, false, err
		}
		allowed := map[int64]bool{}
		if len(d.SubscriptionIDs) > 0 {
			for _, id := range d.SubscriptionIDs {
				allowed[id] = true
			}
		} else {
			// A token without its own list covers enabled subscriptions
			// only; naming a disabled one must not reach it.
			if allowed, err = enabledIDs(); err != nil {
				return q, false, err
			}
		}
		var ids []int64
		for _, id := range want {
			if allowed[id] {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			empty = true
		}
		q.SubscriptionIDs = ids
	}
	return q, empty, nil
}

// enabledSubscriptionIDs lists the enabled subscriptions.
func enabledSubscriptionIDs() (map[int64]bool, error) {
	subs, err := database.ListSubscriptions()
	if err != nil {
		return nil, err
	}
	out := make(map[int64]bool, len(subs))
	for _, sub := range subs {
		if sub.Enabled {
			out[sub.ID] = true
		}
	}
	return out, nil
}

// subSelectionTTL is how long a public subscription's selection is reused:
// phones refresh in bursts and the selection query scans every result.
const subSelectionTTL = 30 * time.Second

// selectionCache memoises selectExportLinks per token and query.
type selectionCache struct {
	mu      sync.Mutex
	entries map[string]selectionEntry
	now     func() time.Time
}

type selectionEntry struct {
	links   []string
	expires time.Time
}

func newSelectionCache() *selectionCache {
	return &selectionCache{entries: make(map[string]selectionEntry), now: time.Now}
}

func (c *selectionCache) get(tokenID string, q exportQuery, load func() ([]string, error)) ([]string, error) {
	key := fmt.Sprintf("%s|%s|%s|%d|%v|%d", tokenID, q.Status, q.Protocol, q.Limit, q.SubscriptionIDs, q.MaxAge)
	now := c.now()
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.links, nil
	}
	c.mu.Unlock()
	links, err := load()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= 256 {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= 256 {
			c.entries = make(map[string]selectionEntry)
		}
	}
	c.entries[key] = selectionEntry{links: links, expires: now.Add(subSelectionTTL)}
	return links, nil
}

// forget drops a token's cached selections (after its settings change).
func (c *selectionCache) forget(tokenID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if strings.HasPrefix(k, tokenID+"|") {
			delete(c.entries, k)
		}
	}
}

// safeFilename keeps a token name usable inside Content-Disposition.
func safeFilename(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "xray-knife"
	}
	return b.String()
}
