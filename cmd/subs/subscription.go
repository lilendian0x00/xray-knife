package subs

import (
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"

	"github.com/lilendian0x00/xray-knife/v10/utils"
	"github.com/lilendian0x00/xray-knife/v10/utils/customlog"

	"github.com/imroc/req/v3"
)

// TODO: Make a database to store subscriptions
type Subscription struct {
	Remark      string
	Url         string
	UserAgent   string
	Method      string
	ConfigLinks []string
	Proxy       string
}

func (s *Subscription) FetchAll() ([]string, error) {
	u, err := url.Parse(s.Url)
	if err != nil {
		return nil, fmt.Errorf("invalid subscription URL %q: %w", s.Url, err)
	}
	if s.Method == "" {
		s.Method = "GET"
	}

	client := req.C().ImpersonateChrome()

	r := client.R()
	if s.UserAgent != "" {
		r.SetHeader("User-Agent", s.UserAgent)
	}

	if s.Proxy != "" {
		client.SetProxyURL(s.Proxy)
	}

	response, err := r.Send(s.Method, u.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch subscription: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned HTTP %d for %s", response.StatusCode, s.Url)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var links []string
	decoded, err := utils.Base64Decode(string(body))
	if err != nil {
		// Probably It's not base64 encoded!, let's try parsing without decoding
		customlog.Printf(customlog.Processing, "Couldn't decode the body! let's try parsing without decoding...\n")
		links = strings.Split(string(body), "\n")
	} else {
		// Configs are separated by newline char
		links = strings.Split(string(decoded), "\n")
	}

	// Filter out empty and whitespace-only lines
	var filtered []string
	for _, l := range links {
		if trimmed := strings.TrimSpace(l); trimmed != "" {
			filtered = append(filtered, trimmed)
		}
	}

	s.ConfigLinks = filtered
	return filtered, nil
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
