package mitmdf

type GroupConfig struct {
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	FrontDomain  string   `json:"frontDomain"`
	ExtraDomains []string `json:"extraDomains,omitempty"`
}

type Config struct {
	CertPath       string        `json:"certPath"`
	KeyPath        string        `json:"keyPath"`
	ListenPort     int           `json:"listenPort"`
	SOCKS5Port     int           `json:"socks5Port"`
	Groups         []GroupConfig `json:"groups"`
	ExtraIRDomains []string      `json:"extraIRDomains,omitempty"`
}

var defaultGroups = []GroupConfig{
	{
		Name:        "google",
		Enabled:     true,
		FrontDomain: "www.google.com",
		ExtraDomains: []string{
			"googlevideo.com", "youtube.com", "dns.google",
		},
	},
	{
		Name:        "meta",
		Enabled:     true,
		FrontDomain: "www.microsoft.com",
		ExtraDomains: []string{
			"instagram.com", "facebook.com", "whatsapp.com",
			"fb.com", "meta.com",
		},
	},
	{
		Name:        "fastly",
		Enabled:     true,
		FrontDomain: "github.githubassets.com",
		ExtraDomains: []string{
			"reddit.com", "fastly.com", "github.com",
			"cnn.com", "buzzfeed.com",
		},
	},
	{
		Name:        "dns",
		Enabled:     true,
		FrontDomain: "www.microsoft.com",
	},
}

func DefaultConfig() *Config {
	groups := make([]GroupConfig, len(defaultGroups))
	for i, g := range defaultGroups {
		domains := make([]string, len(g.ExtraDomains))
		copy(domains, g.ExtraDomains)
		groups[i] = GroupConfig{
			Name:         g.Name,
			Enabled:      g.Enabled,
			FrontDomain:  g.FrontDomain,
			ExtraDomains: domains,
		}
	}
	return &Config{
		CertPath:   "mycert.crt",
		KeyPath:    "mycert.key",
		ListenPort: 10808,
		SOCKS5Port: 10808,
		Groups:     groups,
	}
}
