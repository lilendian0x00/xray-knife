package mitmdf

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xtls/xray-core/infra/conf"
	core "github.com/xtls/xray-core/core"
)

func GenerateXrayConfig(cfg *Config) (*core.Config, error) {
	jsonBytes, err := buildConfigJSON(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build config JSON: %w", err)
	}

	var confCfg conf.Config
	if err := json.Unmarshal(jsonBytes, &confCfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	coreCfg, err := confCfg.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build xray config: %w", err)
	}
	return coreCfg, nil
}

func classifyDomain(d string) string {
	if strings.HasPrefix(d, "geoip:") || strings.HasPrefix(d, "geosite:") || strings.HasPrefix(d, "domain:") || strings.HasPrefix(d, "regexp:") || strings.HasPrefix(d, "full:") {
		return d
	}
	if strings.HasPrefix(d, "ip:") {
		return "ip:" + strings.TrimPrefix(d, "ip:")
	}
	return "domain:" + d
}

func buildConfigJSON(cfg *Config) ([]byte, error) {
	groups := cfg.Groups
	if groups == nil {
		groups = DefaultConfig().Groups
	}

	var irDomains []string
	for _, d := range cfg.ExtraIRDomains {
		if d = strings.TrimSpace(d); d != "" {
			irDomains = append(irDomains, classifyDomain(d))
		}
	}

	// Collect domains that need h11 (HTTP/1.1) ALPN
	globalH11Domains := []string{}
	allRedirectDomains := []string{}

	for _, g := range groups {
		if !g.Enabled {
			continue
		}
		for _, d := range g.ExtraDomains {
			if d = strings.TrimSpace(d); d == "" {
				continue
			}
			allRedirectDomains = append(allRedirectDomains, classifyDomain(d))
			// googlevideo.com requires HTTP/1.1
			if strings.Contains(d, "googlevideo.com") {
				globalH11Domains = append(globalH11Domains, classifyDomain(d))
			}
		}
	}

	dnsHosts := map[string]string{
		"geosite:category-ads-all": "#3",
		"fastly.redirect":          "github.githubassets.com",
		"dns.redirect":             "1.1.1.1",
	}

	inbounds := []map[string]interface{}{
		{
			"tag": "mixed-in",
			"port": cfg.SOCKS5Port,
			"protocol": "mixed",
			"sniffing": map[string]interface{}{
				"enabled":      true,
				"destOverride": []string{"fakedns", "tls"},
				"routeOnly":    false,
			},
			"settings": map[string]interface{}{
				"udp": true,
				"ip":  "127.0.0.1",
			},
			"streamSettings": map[string]interface{}{
				"sockopt": map[string]interface{}{
					"tcpKeepAliveInterval": 1,
					"tcpKeepAliveIdle":     11,
				},
			},
		},
		{
			"port":     11666,
			"tag":      "tls-decrypt-h11",
			"protocol": "tunnel",
			"settings": map[string]interface{}{
				"network":        "tcp",
				"port":           443,
				"followRedirect": true,
			},
			"streamSettings": map[string]interface{}{
				"security": "tls",
				"tlsSettings": map[string]interface{}{
					"alpn": []string{"http/1.1"},
					"certificates": []map[string]interface{}{
						{
							"usage":           "issue",
							"certificateFile": cfg.CertPath,
							"keyFile":         cfg.KeyPath,
						},
					},
				},
			},
		},
		{
			"port":     11777,
			"tag":      "tls-decrypt-h211",
			"protocol": "tunnel",
			"settings": map[string]interface{}{
				"network":        "tcp",
				"port":           443,
				"followRedirect": true,
			},
			"streamSettings": map[string]interface{}{
				"security": "tls",
				"tlsSettings": map[string]interface{}{
					"alpn": []string{"h2", "http/1.1"},
					"certificates": []map[string]interface{}{
						{
							"usage":           "issue",
							"certificateFile": cfg.CertPath,
							"keyFile":         cfg.KeyPath,
						},
					},
				},
			},
		},
	}

	dnsFakeDomains := []string{
		"domain:ir", "geosite:private", "geosite:category-ir",
		"full:github.githubassets.com",
	}
	dnsFakeDomains = append(dnsFakeDomains, irDomains...)

	dns := map[string]interface{}{
		"hosts": dnsHosts,
		"servers": []map[string]interface{}{
			{
				"address": "fakedns",
				"domains": dnsFakeDomains,
			},
			{
				"tag":       "no-filter-dns",
				"address":   "h2c://1.1.1.1/dns-query",
				"timeoutMs": 15000,
			},
			{
				"address": "localhost",
				"domains": dnsFakeDomains,
			},
		},
		"queryStrategy":  "UseSystem",
		"useSystemHosts": true,
		"serveStale":     true,
	}

	happyOpts := map[string]interface{}{
		"tryDelayMs":       300,
		"prioritizeIPv6":   false,
		"interleave":       2,
		"maxConcurrentTry": 20,
	}

	sockOpts := map[string]interface{}{
		"domainStrategy": "ForceIP",
		"happyEyeballs":  happyOpts,
	}

	tlsSettings := func(serverName, verifyNames string) map[string]interface{} {
		return map[string]interface{}{
			"serverName":           serverName,
			"verifyPeerCertByName": verifyNames,
			"alpn":                []string{"fromMitM"},
			"fingerprint":         "chrome",
		}
	}

	// Base outbounds
	outbounds := []map[string]interface{}{
		{"tag": "block", "protocol": "blackhole"},
		{
			"tag":      "direct",
			"protocol": "freedom",
			"streamSettings": map[string]interface{}{
				"sockopt": sockOpts,
			},
		},
		{"tag": "dns-out", "protocol": "dns"},
		{
			"tag":      "redirect-out-h11",
			"protocol": "freedom",
			"settings": map[string]interface{}{
				"redirect": "127.0.0.1:11666",
			},
		},
		{
			"tag":      "redirect-out-h211",
			"protocol": "freedom",
			"settings": map[string]interface{}{
				"redirect": "127.0.0.1:11777",
			},
		},
		{
			"tag": "tls-repack-frommitm",
			"protocol": "freedom",
			"streamSettings": map[string]interface{}{
				"security":     "tls",
				"tlsSettings": tlsSettings("fromMitM", "fromMitM"),
				"sockopt":     sockOpts,
			},
		},
	}

	rules := []map[string]interface{}{}

	// Block ads
	rules = append(rules, map[string]interface{}{
		"outboundTag": "block",
		"domain":      []string{"geosite:category-ads-all"},
	})

	// Generate outbounds and routing rules for each group
	for _, g := range groups {
		if !g.Enabled {
			continue
		}

		var verifyNames []string
		var groupDomains []string

		for _, d := range g.ExtraDomains {
			if d = strings.TrimSpace(d); d == "" {
				continue
			}
			if strings.HasPrefix(d, "geoip:") || strings.HasPrefix(d, "geosite:") || strings.HasPrefix(d, "domain:") || strings.HasPrefix(d, "regexp:") || strings.HasPrefix(d, "full:") {
				groupDomains = append(groupDomains, d)
				verifyNames = append(verifyNames, strings.TrimPrefix(d, "domain:"))
			} else if strings.HasPrefix(d, "ip:") {
				// IP-based rules handled separately
			} else {
				groupDomains = append(groupDomains, "domain:"+d)
				verifyNames = append(verifyNames, d)
			}
		}

		allVerify := strings.Join(append([]string{"fromMitM", g.FrontDomain}, verifyNames...), ",")

		ob := map[string]interface{}{
			"tag":      "tls-repack-" + g.Name,
			"protocol": "freedom",
			"streamSettings": map[string]interface{}{
				"security":     "tls",
				"tlsSettings": tlsSettings(g.FrontDomain, allVerify),
				"sockopt":     sockOpts,
			},
		}

		// DNS group gets special redirect
		if g.Name == "dns" {
			ob["settings"] = map[string]interface{}{
				"redirect": "dns.redirect:443",
			}
		}

		// Fastly group gets CDN redirect
		if g.Name == "fastly" {
			ob["settings"] = map[string]interface{}{
				"redirect": "fastly.redirect:443",
			}
		}

		outbounds = append(outbounds, ob)

		// Routing rules for this group
		if g.Name == "dns" {
			rules = append(rules, map[string]interface{}{
				"outboundTag": "tls-repack-dns",
				"inboundTag":  []string{"no-filter-dns"},
			})
			continue
		}

		// Split domains into h11 (googlevideo) and h211 (everything else)
		var gH11, gH211 []string
		for _, d := range groupDomains {
			if strings.Contains(d, "googlevideo") {
				gH11 = append(gH11, d)
			} else {
				gH211 = append(gH211, d)
			}
		}

		if len(gH11) > 0 {
			rules = append(rules, map[string]interface{}{
				"outboundTag": "tls-repack-" + g.Name,
				"domain":     gH11,
				"inboundTag": []string{"tls-decrypt-h11"},
			})
		}
		if len(gH211) > 0 {
			rules = append(rules, map[string]interface{}{
				"outboundTag": "tls-repack-" + g.Name,
				"domain":     gH211,
				"inboundTag": []string{"tls-decrypt-h211"},
			})
		}
	}

	// Block unmatched decrypt traffic
	if len(rules) > 1 {
		rules = append(rules, map[string]interface{}{
			"outboundTag": "block",
			"inboundTag":  []string{"tls-decrypt-h11"},
		})
		rules = append(rules, map[string]interface{}{
			"outboundTag": "block",
			"inboundTag":  []string{"tls-decrypt-h211"},
		})
	}

	// Redirect rules for port 443 traffic
	var h11Redirects, h211Redirects []string
	for _, d := range allRedirectDomains {
		isH11 := false
		for _, hd := range globalH11Domains {
			if d == hd {
				isH11 = true
				break
			}
		}
		if isH11 {
			h11Redirects = append(h11Redirects, d)
		} else {
			h211Redirects = append(h211Redirects, d)
		}
	}

	// Filter duplicates
	h11Redirects = uniqueStrings(h11Redirects)
	h211Redirects = uniqueStrings(h211Redirects)

	for _, d := range h11Redirects {
		rules = append(rules, map[string]interface{}{
			"outboundTag": "redirect-out-h11",
			"network":     "tcp",
			"port":        443,
			"domain":      []string{d},
		})
	}
	for _, d := range h211Redirects {
		rules = append(rules, map[string]interface{}{
			"outboundTag": "redirect-out-h211",
			"network":     "tcp",
			"port":        443,
			"domain":      []string{d},
		})
	}

	// Block suspicious IPs
	rules = append(rules, map[string]interface{}{
		"outboundTag": "block",
		"ip":          []string{"10.10.34.0/24", "2001:4188:2:600::/64"},
	})

	// Route IR/private traffic directly
	rules = append(rules, map[string]interface{}{
		"outboundTag": "direct",
		"ip":          append([]string{"geoip:private", "geoip:ir"}, irDomains...),
	})

	// Catch-all: direct for remaining traffic
	rules = append(rules, map[string]interface{}{
		"outboundTag": "direct",
		"ip":          []string{"0.0.0.0/0", "::/0"},
	})
	rules = append(rules, map[string]interface{}{
		"outboundTag": "block",
		"port":        "0-65535",
	})

	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
			"dnsLog":   false,
			"access":   "none",
		},
		"policy": map[string]interface{}{
			"levels": map[string]interface{}{
				"0": map[string]interface{}{
					"uplinkOnly":   0,
					"downlinkOnly": 0,
				},
			},
		},
		"dns": dns,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing": map[string]interface{}{
			"domainStrategy": "IPOnDemand",
			"rules":          rules,
		},
	}

	return json.MarshalIndent(config, "", "  ")
}

func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	var r []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			r = append(r, v)
		}
	}
	return r
}
