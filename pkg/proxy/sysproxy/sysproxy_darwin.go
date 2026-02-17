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
		prefix := "svc:" + svc + ":"
		out, err := exec.Command("networksetup", "-getsocksfirewallproxy", svc).Output()
		if err != nil {
			continue
		}
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
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

	return s, nil
}

func (m *darwinManager) Set(addr string, port string) error {
	services, err := activeNetworkServices()
	if err != nil {
		return err
	}

	for _, svc := range services {
		if out, err := exec.Command("networksetup", "-setsocksfirewallproxy", svc, addr, port).CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set SOCKS proxy for %s: %s: %w", svc, string(out), err)
		}
		if out, err := exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "on").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to enable SOCKS proxy for %s: %s: %w", svc, string(out), err)
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
		prefix := "svc:" + svc + ":"
		wasEnabled := prev.Data[prefix+"enabled"]
		prevServer := prev.Data[prefix+"server"]
		prevPort := prev.Data[prefix+"port"]

		if wasEnabled == "Yes" && prevServer != "" && prevPort != "" {
			// Restore to previous SOCKS proxy settings
			exec.Command("networksetup", "-setsocksfirewallproxy", svc, prevServer, prevPort).Run()
			exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "on").Run()
		} else {
			// Was disabled or empty, just turn it off
			exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "off").Run()
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
