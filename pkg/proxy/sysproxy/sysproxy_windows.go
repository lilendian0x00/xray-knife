package sysproxy

import (
	"errors"
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
		Data:     map[string]string{"format": "2"},
	}

	proxyEnable, _, err := k.GetIntegerValue("ProxyEnable")
	if err == nil {
		s.Data["ProxyEnable"] = strconv.FormatUint(proxyEnable, 10)
	} else {
		s.Data["ProxyEnable"] = "0"
	}

	// Record presence separately from value so Restore can delete a
	// value that did not exist before instead of leaving ours behind.
	for _, name := range []string{"ProxyServer", "ProxyOverride", "AutoConfigURL"} {
		if v, _, err := k.GetStringValue(name); err == nil {
			s.Data[name] = v
			s.Data[name+".present"] = "1"
		}
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
	// A PAC script (AutoConfigURL) takes precedence over ProxyServer in
	// WinINet, so leaving it in place would silently bypass us. Get()
	// saved it; Restore puts it back.
	if err := k.DeleteValue("AutoConfigURL"); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("failed to clear AutoConfigURL: %w", err)
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

	// Snapshots written before "format" 2 carry no presence markers: for
	// them keep the old behaviour (restore what was recorded, never
	// delete).
	legacy := prev.Data["format"] != "2"
	var errs []error
	for _, name := range []string{"ProxyServer", "ProxyOverride", "AutoConfigURL"} {
		val, hadValue := prev.Data[name]
		_, present := prev.Data[name+".present"]
		switch {
		case present || (legacy && hadValue && val != ""):
			if err := k.SetStringValue(name, val); err != nil {
				errs = append(errs, fmt.Errorf("failed to restore %s: %w", name, err))
			}
		case !legacy:
			if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
				errs = append(errs, fmt.Errorf("failed to remove %s: %w", name, err))
			}
		}
	}

	notifySystemSettingsChange()
	return errors.Join(errs...)
}

// notifySystemSettingsChange signals running applications that internet settings have changed.
func notifySystemSettingsChange() {
	procInternetSetOptionW.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOptionW.Call(0, internetOptionRefresh, 0, 0)
}
