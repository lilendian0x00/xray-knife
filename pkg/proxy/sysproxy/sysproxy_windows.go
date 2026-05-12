package sysproxy

import (
	"fmt"
	"strconv"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const (
	regPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

var (
	wininet                = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

type windowsManager struct{}

// New returns a Windows proxy manager.
func New() (Manager, error) {
	return &windowsManager{}, nil
}

func (m *windowsManager) Get() (*Settings, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("failed to open registry key: %w", err)
	}
	defer k.Close()

	s := &Settings{
		Platform: "windows",
		Data:     make(map[string]string),
	}

	proxyEnable, _, err := k.GetIntegerValue("ProxyEnable")
	if err == nil {
		s.Data["ProxyEnable"] = strconv.FormatUint(proxyEnable, 10)
	} else {
		s.Data["ProxyEnable"] = "0"
	}

	proxyServer, _, err := k.GetStringValue("ProxyServer")
	if err == nil {
		s.Data["ProxyServer"] = proxyServer
	}

	proxyOverride, _, err := k.GetStringValue("ProxyOverride")
	if err == nil {
		s.Data["ProxyOverride"] = proxyOverride
	}

	return s, nil
}

func (m *windowsManager) Set(addr string, port string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key for writing: %w", err)
	}
	defer k.Close()

	// Use the WinINet per-protocol format ("http=host:port;https=...;socks=...")
	// so HTTP, HTTPS and SOCKS traffic all hit our listener. The xray "system"
	// inbound speaks HTTP (with CONNECT for HTTPS) and the sing-box one is a
	// mixed HTTP+SOCKS listener, so pointing all three slots at the same
	// addr:port works for both cores. The old code wrote just "socks=..." which
	// made browsers speak SOCKS5 to an HTTP-only listener and silently fail.
	proxyServer := fmt.Sprintf("http=%s:%s;https=%s:%s;socks=%s:%s",
		addr, port, addr, port, addr, port)

	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return fmt.Errorf("failed to set ProxyEnable: %w", err)
	}
	if err := k.SetStringValue("ProxyServer", proxyServer); err != nil {
		return fmt.Errorf("failed to set ProxyServer: %w", err)
	}

	notifySystemSettingsChange()
	return nil
}

func (m *windowsManager) Restore(prev *Settings) error {
	if prev == nil {
		return nil
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key for writing: %w", err)
	}
	defer k.Close()

	enableStr := prev.Data["ProxyEnable"]
	enable, _ := strconv.ParseUint(enableStr, 10, 32)
	if err := k.SetDWordValue("ProxyEnable", uint32(enable)); err != nil {
		return fmt.Errorf("failed to restore ProxyEnable: %w", err)
	}

	if server, ok := prev.Data["ProxyServer"]; ok && server != "" {
		if err := k.SetStringValue("ProxyServer", server); err != nil {
			return fmt.Errorf("failed to restore ProxyServer: %w", err)
		}
	}

	if override, ok := prev.Data["ProxyOverride"]; ok {
		if err := k.SetStringValue("ProxyOverride", override); err != nil {
			return fmt.Errorf("failed to restore ProxyOverride: %w", err)
		}
	}

	notifySystemSettingsChange()
	return nil
}

// notifySystemSettingsChange signals running applications that internet settings have changed.
func notifySystemSettingsChange() {
	procInternetSetOptionW.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOptionW.Call(0, internetOptionRefresh, 0, 0)
}
