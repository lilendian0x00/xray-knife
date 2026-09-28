package subscription

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Format names the kind of document a subscription body was decoded from.
type Format string

const (
	FormatPlain   Format = "plain"   // one share link per line
	FormatBase64  Format = "base64"  // base64 of a plain list
	FormatClash   Format = "clash"   // Clash / mihomo YAML with a proxies: list
	FormatSingbox Format = "singbox" // sing-box JSON with outbounds/endpoints
	FormatXray    Format = "xray"    // xray JSON config, or an array of configs
)

// clashProxiesKey finds a top-level "proxies:" key; plain lists never
// have one at the start of a line.
var clashProxiesKey = regexp.MustCompile(`(?m)^proxies\s*:`)

// structuredFormat reports which structured format body is, if any.
func structuredFormat(body []byte) Format {
	switch {
	case len(body) > 0 && (body[0] == '{' || body[0] == '['):
		return "json"
	case clashProxiesKey.Match(body):
		return FormatClash
	}
	return ""
}

// entryConverter turns one structured entry into a share link. It returns
// ok=false (and no error) for entries that are not proxies at all, such
// as sing-box "direct" or xray "freedom" outbounds.
type entryConverter func(entry map[string]interface{}) (link string, ok bool, err error)

// decodeStructured converts a Clash YAML or sing-box/xray JSON document.
func decodeStructured(body []byte, kind Format, maxLinks int, maxBytes int64) (*DecodeResult, error) {
	// Parsed documents take many times their size in memory (a yaml.v3
	// node tree ~35x), so structured input has its own, smaller cap.
	if int64(len(body)) > maxBytes {
		return nil, ErrTooLarge
	}
	res := &DecodeResult{Links: []string{}, Skipped: map[string]int{}}
	var entries []map[string]interface{}
	var convert entryConverter
	switch kind {
	case FormatClash:
		var err error
		if entries, err = clashProxies(body); err != nil {
			return nil, err
		}
		res.Format, convert = FormatClash, clashToLink
	default:
		var err error
		res.Format, entries, err = jsonEntries(body)
		if err != nil {
			return nil, err
		}
		if res.Format == FormatXray {
			convert = xrayToLink
		} else {
			convert = singboxToLink
		}
	}

	proxies := 0
	for _, entry := range entries {
		link, ok, err := convert(entry)
		if !ok {
			continue
		}
		proxies++
		if err != nil {
			res.Skipped[sanitizeReason(err.Error())]++
			continue
		}
		if len(res.Links) == maxLinks {
			return nil, ErrTooManyLinks
		}
		res.Links = append(res.Links, link)
	}
	if proxies == 0 {
		return nil, ErrInvalidFormat
	}
	if len(res.Links) == 0 {
		return res, ErrNoSupportedProxies
	}
	return res, nil
}

// sanitizeReason makes a skip reason safe to print: entries come from
// the provider, and a proxy "type" can carry terminal escape sequences.
func sanitizeReason(reason string) string {
	var b strings.Builder
	n := 0
	for _, r := range reason {
		if unicode.IsControl(r) || r == utf8.RuneError {
			r = '?'
		}
		if n == maxReasonRunes {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

const maxReasonRunes = 120

// yamlNodeBudget bounds how many YAML nodes the proxies list may expand
// to, aliases included, so an alias bomb can't multiply entries.
const yamlNodeBudget = 2_000_000

var errYAMLTooComplex = fmt.Errorf("%w: clash document expands to too many nodes", ErrTooLarge)

// clashProxies returns the top-level proxies list as plain values. It
// walks the YAML node tree rather than decoding into Go values so every
// scalar keeps its source text: yaml.v3 would read "password: 0123" as
// the number 123 and "short-id: 00000000" as 0.
func clashProxies(body []byte) ([]map[string]interface{}, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, ErrInvalidFormat
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil, ErrInvalidFormat
	}
	budget := yamlNodeBudget
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "proxies" {
			continue
		}
		v, err := yamlValue(root.Content[i+1], &budget)
		if err != nil {
			return nil, err
		}
		items, ok := v.([]interface{})
		if !ok {
			return nil, ErrInvalidFormat
		}
		out := make([]map[string]interface{}, 0, len(items))
		for _, item := range items {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out, nil
	}
	return nil, ErrInvalidFormat
}

// yamlValue converts a YAML node into maps, slices and scalar strings,
// following aliases and "<<" merge keys within budget.
func yamlValue(n *yaml.Node, budget *int) (interface{}, error) {
	if *budget--; *budget < 0 {
		return nil, errYAMLTooComplex
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return yamlValue(n.Content[0], budget)
	case yaml.AliasNode:
		return yamlValue(n.Alias, budget)
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			return nil, nil
		}
		return n.Value, nil
	case yaml.SequenceNode:
		out := make([]interface{}, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := yamlValue(c, budget)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		out := map[string]interface{}{}
		var merges []*yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode {
				continue
			}
			if k.Tag == "!!merge" || k.Value == "<<" {
				merges = append(merges, v)
				continue
			}
			val, err := yamlValue(v, budget)
			if err != nil {
				return nil, err
			}
			out[k.Value] = val
		}
		// Merged keys never override the mapping's own keys.
		for _, m := range merges {
			mv, err := yamlValue(m, budget)
			if err != nil {
				return nil, err
			}
			sources := []interface{}{mv}
			if list, ok := mv.([]interface{}); ok {
				sources = list
			}
			for _, src := range sources {
				if sm, ok := src.(map[string]interface{}); ok {
					for k, v := range sm {
						if _, exists := out[k]; !exists {
							out[k] = v
						}
					}
				}
			}
		}
		return out, nil
	}
	return nil, nil
}

// jsonEntries extracts proxy entries from sing-box or xray JSON: an object
// with "outbounds" (and, for sing-box, "endpoints"), or an array of xray
// configs (v2rayN "custom config" subscriptions) whose "remarks" name
// their proxies.
func jsonEntries(body []byte) (Format, []map[string]interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc interface{}
	if err := dec.Decode(&doc); err != nil {
		return "", nil, ErrInvalidFormat
	}
	var configs []map[string]interface{}
	switch d := doc.(type) {
	case map[string]interface{}:
		configs = []map[string]interface{}{d}
	case []interface{}:
		for _, c := range d {
			if m, ok := c.(map[string]interface{}); ok {
				configs = append(configs, m)
			}
		}
	default:
		return "", nil, ErrInvalidFormat
	}

	var entries []map[string]interface{}
	format := Format("")
	for _, cfg := range configs {
		remarks := str(cfg, "remarks")
		for _, key := range []string{"outbounds", "endpoints"} {
			for _, o := range list(cfg, key) {
				ob, ok := o.(map[string]interface{})
				if !ok {
					continue
				}
				switch {
				case str(ob, "protocol") != "":
					format = FormatXray
					if remarks != "" {
						ob = withKey(ob, xrayRemarksKey, remarks)
					}
				case str(ob, "type") != "":
					if format == "" {
						format = FormatSingbox
					}
				default:
					continue
				}
				entries = append(entries, ob)
			}
		}
	}
	if format == "" {
		return "", nil, ErrInvalidFormat
	}
	return format, entries, nil
}

// xrayRemarksKey carries a config-level "remarks" into its outbounds.
const xrayRemarksKey = "\x00remarks"

func withKey(m map[string]interface{}, key string, value interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	out[key] = value
	return out
}

func compactJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// --- generic accessors for decoded YAML/JSON maps ---

func sub(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func list(m map[string]interface{}, key string) []interface{} {
	switch v := m[key].(type) {
	case []interface{}:
		return v
	case nil:
		return nil
	default:
		return []interface{}{v}
	}
}

// str returns a scalar as a string ("" when absent or not a scalar).
func str(m map[string]interface{}, key string) string {
	return scalar(m[key])
}

func scalar(v interface{}) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// strs returns a string or a list of scalars as strings.
func strs(m map[string]interface{}, key string) []string {
	var out []string
	for _, v := range list(m, key) {
		if s := scalar(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func boolean(m map[string]interface{}, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		b, _ := strconv.ParseBool(strings.TrimSpace(v))
		return b || strings.TrimSpace(v) == "1"
	case json.Number:
		return v.String() != "0"
	case int:
		return v != 0
	}
	return false
}

// integer reads a number (or numeric string); leading digits of strings
// such as "100 Mbps" count.
func integer(m map[string]interface{}, key string) int {
	s := str(m, key)
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9') {
		end++
	}
	n, _ := strconv.Atoi(s[:end])
	return n
}

// endpoint validates and returns server and port.
func endpoint(server string, port int) (string, int, error) {
	server = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(server), "["), "]")
	if server == "" {
		return "", 0, skipf("missing server")
	}
	if port <= 0 || port > 65535 {
		return "", 0, skipf("invalid port")
	}
	return server, port, nil
}

// headerValue reads a header that may be a string or a list.
func headerValue(headers map[string]interface{}, name string) string {
	for k := range headers {
		if strings.EqualFold(k, name) {
			return strings.Join(strs(headers, k), ",")
		}
	}
	return ""
}

// SkipSummary renders the skip counts deterministically, one
// "reason (count)" entry per reason, for logs and CLI output.
func (r *DecodeResult) SkipSummary() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.Skipped))
	for reason, n := range r.Skipped {
		out = append(out, fmt.Sprintf("%s (%d)", reason, n))
	}
	sort.Strings(out)
	return out
}
