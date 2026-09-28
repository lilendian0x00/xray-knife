package sysproxy

import (
	"errors"
	"fmt"
	"strings"
)

type darwinManager struct {
	// services is the list Get() saw; Set configures exactly these so
	// what Restore puts back matches what Set changed.
	services []string
}

// New returns a macOS proxy manager.
func New() (Manager, error) {
	return &darwinManager{}, nil
}

// proxyKinds is the set of macOS proxy preferences we manage.
// Each entry maps the kind tag (used in Settings.Data keys) to the
// networksetup get/set/state flags used to read or write that preference.
//
// We cover three preferences so the OS routes traffic correctly regardless
// of which inbound the service is running:
//   - "web":    HTTP traffic from browsers / NSURLSession consumers
//   - "https":  HTTPS traffic (browsers honour this independently from "web")
//   - "socks":  SOCKS-aware apps (Telegram, dev tools, etc.)
//
// The system-mode listener speaks both HTTP (with CONNECT for HTTPS) and
// SOCKS on one port for both cores (an xray socks inbound also accepts
// HTTP proxy requests; sing-box uses a "mixed" inbound), so pointing all
// three preferences at the same addr:port works.
var proxyKinds = []struct {
	tag       string
	getFlag   string
	setFlag   string
	stateFlag string
}{
	{"web", "-getwebproxy", "-setwebproxy", "-setwebproxystate"},
	{"https", "-getsecurewebproxy", "-setsecurewebproxy", "-setsecurewebproxystate"},
	{"socks", "-getsocksfirewallproxy", "-setsocksfirewallproxy", "-setsocksfirewallproxystate"},
}

func (m *darwinManager) Get() (*Settings, error) {
	services, err := activeNetworkServices()
	if err != nil {
		return nil, err
	}
	m.services = services

	s := &Settings{
		Platform: "darwin",
		Data:     make(map[string]string),
	}
	s.Data["services"] = strings.Join(services, "|")

	for _, svc := range services {
		for _, k := range proxyKinds {
			out, err := execOutput("networksetup", k.getFlag, svc)
			if err != nil {
				continue
			}
			parseProxyInfo(s.Data, "svc:"+svc+":"+k.tag+":", string(out))
		}
	}

	return s, nil
}

// parseProxyInfo reads `networksetup -get*proxy` output ("Enabled: Yes",
// "Server: host", "Port: 8080") into data under prefix.
func parseProxyInfo(data map[string]string, prefix, out string) {
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "Enabled":
			data[prefix+"enabled"] = val
		case "Server":
			data[prefix+"server"] = val
		case "Port":
			data[prefix+"port"] = val
		}
	}
}

func (m *darwinManager) Set(addr string, port string) error {
	services := m.services
	if len(services) == 0 {
		var err error
		if services, err = activeNetworkServices(); err != nil {
			return err
		}
	}

	for _, svc := range services {
		for _, k := range proxyKinds {
			if out, err := execCombined("networksetup", k.setFlag, svc, addr, port); err != nil {
				return fmt.Errorf("failed to set %s proxy for %s: %s: %w", k.tag, svc, strings.TrimSpace(string(out)), err)
			}
			if out, err := execCombined("networksetup", k.stateFlag, svc, "on"); err != nil {
				return fmt.Errorf("failed to enable %s proxy for %s: %s: %w", k.tag, svc, strings.TrimSpace(string(out)), err)
			}
		}
	}

	return nil
}

// Restore puts every managed preference back: the previous server/port
// (so a configured-but-disabled proxy keeps its values) and then the
// previous on/off state. It keeps going past failures and reports them
// all, so one broken service cannot leave the others pointing at us.
func (m *darwinManager) Restore(prev *Settings) error {
	if prev == nil {
		return nil
	}

	svcList := prev.Data["services"]
	if svcList == "" {
		return nil
	}

	var errs []error
	run := func(args ...string) {
		if out, err := execCombined("networksetup", args...); err != nil {
			errs = append(errs, fmt.Errorf("networksetup %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err))
		}
	}
	for _, svc := range strings.Split(svcList, "|") {
		for _, k := range proxyKinds {
			prefix := "svc:" + svc + ":" + k.tag + ":"
			wasEnabled := prev.Data[prefix+"enabled"] == "Yes"
			prevServer := prev.Data[prefix+"server"]
			prevPort := prev.Data[prefix+"port"]

			if prevServer != "" && prevPort != "" && prevPort != "0" {
				run(k.setFlag, svc, prevServer, prevPort)
			}
			if wasEnabled && prevServer != "" {
				run(k.stateFlag, svc, "on")
			} else {
				run(k.stateFlag, svc, "off")
			}
		}
	}

	return errors.Join(errs...)
}

// activeNetworkServices lists network services that have an active IP address.
func activeNetworkServices() ([]string, error) {
	out, err := execOutput("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("failed to list network services: %w", err)
	}

	var active []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		// Skip the header line and disabled services (prefixed with *)
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		info, err := execOutput("networksetup", "-getinfo", line)
		if err != nil {
			continue
		}
		if serviceHasIP(string(info)) {
			active = append(active, line)
		}
	}

	if len(active) == 0 {
		return nil, fmt.Errorf("no active network services found")
	}

	return active, nil
}

// serviceHasIP reports whether `networksetup -getinfo` output shows an
// assigned IPv4 or IPv6 address.
func serviceHasIP(info string) bool {
	for _, line := range strings.Split(info, "\n") {
		for _, key := range []string{"IP address: ", "IPv6 IP address: "} {
			if strings.HasPrefix(line, key) {
				ip := strings.TrimSpace(strings.TrimPrefix(line, key))
				if ip != "" && ip != "none" {
					return true
				}
			}
		}
	}
	return false
}
