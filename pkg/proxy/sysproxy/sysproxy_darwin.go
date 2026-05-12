package sysproxy

import (
	"fmt"
	"os/exec"
	"strings"
)

type darwinManager struct{}

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
// The xray "system" inbound speaks HTTP (with CONNECT for HTTPS), and the
// sing-box one is a "mixed" HTTP+SOCKS listener, so pointing all three
// preferences at the same addr:port works for both cores.
var proxyKinds = []struct {
	tag     string
	getFlag string
	setFlag string
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

	s := &Settings{
		Platform: "darwin",
		Data:     make(map[string]string),
	}
	s.Data["services"] = strings.Join(services, "|")

	for _, svc := range services {
		for _, k := range proxyKinds {
			prefix := "svc:" + svc + ":" + k.tag + ":"
			out, err := exec.Command("networksetup", k.getFlag, svc).Output()
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(out), "\n") {
				parts := strings.SplitN(line, ": ", 2)
				if len(parts) != 2 {
					continue
				}
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				switch key {
				case "Enabled":
					s.Data[prefix+"enabled"] = val
				case "Server":
					s.Data[prefix+"server"] = val
				case "Port":
					s.Data[prefix+"port"] = val
				}
			}
		}
	}

	return s, nil
}

func (m *darwinManager) Set(addr string, port string) error {
	services, err := activeNetworkServices()
	if err != nil {
		return err
	}

	for _, svc := range services {
		for _, k := range proxyKinds {
			if out, err := exec.Command("networksetup", k.setFlag, svc, addr, port).CombinedOutput(); err != nil {
				return fmt.Errorf("failed to set %s proxy for %s: %s: %w", k.tag, svc, string(out), err)
			}
			if out, err := exec.Command("networksetup", k.stateFlag, svc, "on").CombinedOutput(); err != nil {
				return fmt.Errorf("failed to enable %s proxy for %s: %s: %w", k.tag, svc, string(out), err)
			}
		}
	}

	return nil
}

func (m *darwinManager) Restore(prev *Settings) error {
	if prev == nil {
		return nil
	}

	svcList := prev.Data["services"]
	if svcList == "" {
		return nil
	}
	services := strings.Split(svcList, "|")

	for _, svc := range services {
		for _, k := range proxyKinds {
			prefix := "svc:" + svc + ":" + k.tag + ":"
			wasEnabled := prev.Data[prefix+"enabled"]
			prevServer := prev.Data[prefix+"server"]
			prevPort := prev.Data[prefix+"port"]

			if wasEnabled == "Yes" && prevServer != "" && prevPort != "" {
				exec.Command("networksetup", k.setFlag, svc, prevServer, prevPort).Run()
				exec.Command("networksetup", k.stateFlag, svc, "on").Run()
			} else {
				exec.Command("networksetup", k.stateFlag, svc, "off").Run()
			}
		}
	}

	return nil
}

// activeNetworkServices lists network services that have an active IP address.
func activeNetworkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
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
		// Check if the service has an active IP
		info, err := exec.Command("networksetup", "-getinfo", line).Output()
		if err != nil {
			continue
		}
		infoStr := string(info)
		// A service is active if it has a non-empty IP address
		if strings.Contains(infoStr, "IP address: ") {
			for _, infoLine := range strings.Split(infoStr, "\n") {
				if strings.HasPrefix(infoLine, "IP address: ") {
					ip := strings.TrimPrefix(infoLine, "IP address: ")
					ip = strings.TrimSpace(ip)
					if ip != "" && ip != "none" {
						active = append(active, line)
						break
					}
				}
			}
		}
	}

	if len(active) == 0 {
		return nil, fmt.Errorf("no active network services found")
	}

	return active, nil
}
