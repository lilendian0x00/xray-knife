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

// stripPrefix removes known routing prefix for verifyPeerCertByName
func stripPrefix(d string) string {
	for _, p := range []string{"domain:", "full:", "geosite:", "geoip:", "regexp:"} {
		if strings.HasPrefix(d, p) {
			return strings.TrimPrefix(d, p)
		}
	}
	return d
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

	// Pre-classify each group's domains into routing tags (domain, geosite, geoip)
	type groupRoute struct {
		name        string
		frontDomain string
		domains     []string  // domain:... entries
		geosites    []string  // geosite:... entries
		geoips      []string  // geoip:... entries
		hasDNS      bool
		h11Domains  []string // googlevideo-like -> h11 inbound
	}

	var grps []groupRoute
	for _, g := range groups {
		if !g.Enabled {
			continue
		}
		gr := groupRoute{
			name:        g.Name,
			frontDomain: g.FrontDomain,
		}
		for _, d := range g.ExtraDomains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			cd := classifyDomain(d)
			if strings.HasPrefix(cd, "geoip:") {
				gr.geoips = append(gr.geoips, cd)
				continue
			}
			if strings.HasPrefix(cd, "geosite:") {
				gr.geosites = append(gr.geosites, cd)
				continue
			}
			gr.domains = append(gr.domains, cd)
			if strings.Contains(d, "googlevideo") {
				gr.h11Domains = append(gr.h11Domains, cd)
			}
		}
		if g.Name == "dns" {
			gr.hasDNS = true
		}
		grps = append(grps, gr)
	}

	dnsHosts := map[string]interface{}{
		"geosite:category-ads-all": "#3",
		"fastly.redirect":          "github.githubassets.com",
		"dns.redirect":             []string{"1.1.1.1", "1.0.0.1"},
	}

	// DNS fake domains
	dnsFakeDomains := []string{
		"domain:ir", "geosite:private", "geosite:category-ir", "geosite:khanacademy",
		"full:github.githubassets.com",
	}
	dnsFakeDomains = append(dnsFakeDomains, irDomains...)

	dnsServers := []map[string]interface{}{
		{
			"address": "fakedns",
			"domains": dnsFakeDomains,
		},
		{
			"tag":         "no-filter-dns",
			"address":     "h2c://1.1.1.1/dns-query",
			"timeoutMs":   15000,
			"finalQuery":  true,
		},
		{
			"address":    "localhost",
			"domains":    dnsFakeDomains,
			"finalQuery": true,
		},
	}

	dns := map[string]interface{}{
		"hosts":         dnsHosts,
		"servers":       dnsServers,
		"queryStrategy": "UseSystem",
		"useSystemHosts": true,
		"serveStale":     true,
	}

	inbounds := []map[string]interface{}{
		{
			"tag":      "mixed-in",
			"port":     cfg.SOCKS5Port,
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

	sockOpts := map[string]interface{}{
		"domainStrategy": "ForceIP",
		"happyEyeballs": map[string]interface{}{
			"tryDelayMs":       300,
			"prioritizeIPv6":   false,
			"interleave":       2,
			"maxConcurrentTry": 20,
		},
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
		{"tag": "block", "protocol": "block"},
		{
			"tag":      "direct",
			"protocol": "direct",
			"streamSettings": map[string]interface{}{
				"sockopt": sockOpts,
			},
		},
		{"tag": "dns-out", "protocol": "dns"},
		{
			"tag":      "redirect-out-h11",
			"protocol": "direct",
			"settings": map[string]interface{}{
				"redirect": "127.0.0.1:11666",
			},
		},
		{
			"tag":      "redirect-out-h211",
			"protocol": "direct",
			"settings": map[string]interface{}{
				"redirect": "127.0.0.1:11777",
			},
		},
		{
			"tag":      "tls-repack-frommitm",
			"protocol": "direct",
			"streamSettings": map[string]interface{}{
				"security":     "tls",
				"tlsSettings": tlsSettings("fromMitM", "fromMitM"),
				"sockopt":     sockOpts,
			},
		},
	}

	// Build per-group repack outbounds
	for _, gr := range grps {
		allVerifyNames := []string{"fromMitM", gr.frontDomain}
		for _, d := range gr.domains {
			allVerifyNames = append(allVerifyNames, stripPrefix(d))
		}
		for _, d := range gr.geosites {
			allVerifyNames = append(allVerifyNames, stripPrefix(d))
		}
		if gr.hasDNS {
			// DNS group needs extra DNS provider names
			allVerifyNames = append(allVerifyNames,
				"www.google.com", "dns.google", "cloudflare-dns.com", "one.one.one.one")
		}

		ob := map[string]interface{}{
			"tag":      "tls-repack-" + gr.name,
			"protocol": "direct",
			"streamSettings": map[string]interface{}{
				"security":     "tls",
				"tlsSettings": tlsSettings(gr.frontDomain, strings.Join(allVerifyNames, ",")),
				"sockopt":     sockOpts,
			},
		}

		if gr.hasDNS {
			ob["settings"] = map[string]interface{}{
				"redirect": "dns.redirect:443",
			}
		}
		if gr.name == "fastly" {
			ob["settings"] = map[string]interface{}{
				"redirect": "fastly.redirect:443",
			}
		}

		outbounds = append(outbounds, ob)
	}

	// Build routing rules (order matches patterniha)
	rules := []map[string]interface{}{}

	// 1. Block ads
	rules = append(rules, map[string]interface{}{
		"outboundTag": "block",
		"domain":      []string{"geosite:category-ads-all"},
	})

	// 2. DNS repack from no-filter-dns inbound
	for _, gr := range grps {
		if gr.hasDNS {
			rules = append(rules, map[string]interface{}{
				"outboundTag": "tls-repack-dns",
				"inboundTag":  []string{"no-filter-dns"},
			})
		}
	}

	// 3. DNS out for port 53
	rules = append(rules, map[string]interface{}{
		"outboundTag": "dns-out",
		"port":        53,
	})

	// 4. Direct for IR/private domains
	directDomains := []string{"domain:ir", "geosite:private", "geosite:category-ir", "geosite:khanacademy"}
	directDomains = append(directDomains, irDomains...)
	rules = append(rules, map[string]interface{}{
		"outboundTag": "direct",
		"domain":      directDomains,
	})

	// 5-7. Per-group routing: h11 domains go through tls-decrypt-h11, rest through h211
	for _, gr := range grps {
		if gr.hasDNS {
			continue
		}

		// h11 domains (googlevideo)
		if len(gr.h11Domains) > 0 {
			rules = append(rules, map[string]interface{}{
				"outboundTag": "tls-repack-" + gr.name,
				"domain":      gr.h11Domains,
				"inboundTag":  []string{"tls-decrypt-h11"},
			})
		}

		// geosite + domain entries through h211
		routeDomains := append(gr.geosites, gr.domains...)
		if len(routeDomains) > 0 {
			rules = append(rules, map[string]interface{}{
				"outboundTag": "tls-repack-" + gr.name,
				"domain":      routeDomains,
				"inboundTag":  []string{"tls-decrypt-h211"},
			})
		}

		// geoip entries through h211
		if len(gr.geoips) > 0 {
			rules = append(rules, map[string]interface{}{
				"outboundTag": "tls-repack-" + gr.name,
				"ip":          gr.geoips,
				"inboundTag":  []string{"tls-decrypt-h211"},
			})
		}
	}

	// Block unmatched decrypt traffic
	rules = append(rules, map[string]interface{}{
		"outboundTag": "block",
		"inboundTag":  []string{"tls-decrypt-h11"},
	})
	rules = append(rules, map[string]interface{}{
		"outboundTag": "block",
		"inboundTag":  []string{"tls-decrypt-h211"},
	})

	// Redirect rules: h11 port 443
	for _, gr := range grps {
		for _, d := range gr.h11Domains {
			rules = append(rules, map[string]interface{}{
				"outboundTag": "redirect-out-h11",
				"network":     "tcp",
				"port":        443,
				"domain":      []string{d},
			})
		}
	}

	// Redirect rules: h211 port 443 (geosite + domain)
	for _, gr := range grps {
		allHDomains := append(gr.geosites, gr.domains...)
		if len(allHDomains) > 0 {
			rules = append(rules, map[string]interface{}{
				"outboundTag": "redirect-out-h211",
				"network":     "tcp",
				"port":        443,
				"domain":      allHDomains,
			})
		}
	}

	// Block suspicious IPs
	rules = append(rules, map[string]interface{}{
		"outboundTag": "block",
		"ip":          []string{"10.10.34.0/24", "2001:4188:2:600::/64"},
	})

	// Direct for IR/private IPs
	directIPs := []string{"geoip:private", "geoip:ir"}
	rules = append(rules, map[string]interface{}{
		"outboundTag": "direct",
		"ip":          directIPs,
	})

	// geoip:fastly redirect (for groups that reference fastly)
	for _, gr := range grps {
		for _, ip := range gr.geoips {
			if strings.Contains(ip, "fastly") {
				rules = append(rules, map[string]interface{}{
					"outboundTag": "redirect-out-h211",
					"network":     "tcp",
					"port":        443,
					"ip":          []string{ip},
				})
			}
		}
	}

	// Catch-all direct
	rules = append(rules, map[string]interface{}{
		"outboundTag": "direct",
		"ip":          []string{"0.0.0.0/0", "::/0"},
	})

	// Catch-all block
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
		"dns":       dns,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing": map[string]interface{}{
			"domainStrategy": "IPOnDemand",
			"rules":          rules,
		},
	}

	return json.MarshalIndent(config, "", "  ")
}
