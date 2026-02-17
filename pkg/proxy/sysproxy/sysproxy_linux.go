package sysproxy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type desktopEnv int

const (
	deGNOME desktopEnv = iota
	deKDE
	deUnknown
)

type linuxManager struct {
	de           desktopEnv
	kwriteConfig string // "kwriteconfig5" or "kwriteconfig6"
	kreadConfig  string // "kreadconfig5" or "kreadconfig6"
}

// New detects the Linux desktop environment and returns the right Manager.
func New() (Manager, error) {
	m := &linuxManager{}
	m.de = detectDE()

	if m.de == deKDE {
		if path, err := exec.LookPath("kwriteconfig6"); err == nil {
			m.kwriteConfig = path
			m.kreadConfig, _ = exec.LookPath("kreadconfig6")
		} else if path, err := exec.LookPath("kwriteconfig5"); err == nil {
			m.kwriteConfig = path
			m.kreadConfig, _ = exec.LookPath("kreadconfig5")
		} else {
			m.de = deUnknown
		}
	}

	return m, nil
}

func detectDE() desktopEnv {
	desktop := strings.ToLower(os.Getenv("XDG_CURRENT_DESKTOP"))
	session := strings.ToLower(os.Getenv("DESKTOP_SESSION"))

	// GNOME and GNOME-compatible DEs (Unity, Cinnamon, MATE, XFCE, DDE, UKUI)
	if strings.Contains(desktop, "gnome") || strings.Contains(desktop, "unity") ||
		strings.Contains(desktop, "cinnamon") || strings.Contains(desktop, "mate") ||
		strings.Contains(desktop, "xfce") || strings.Contains(desktop, "x-cinnamon") ||
		strings.Contains(desktop, "dde") || strings.Contains(desktop, "ukui") ||
		strings.Contains(session, "gnome") || os.Getenv("GNOME_DESKTOP_SESSION_ID") != "" {
		if _, err := exec.LookPath("dconf"); err == nil {
			return deGNOME
		}
	}

	// KDE
	if strings.Contains(desktop, "kde") || strings.Contains(session, "plasma") ||
		strings.Contains(session, "kde") {
		return deKDE
	}

	// Fallback: if dconf is available, use it (window managers that borrow from GNOME)
	if _, err := exec.LookPath("dconf"); err == nil {
		return deGNOME
	}

	return deUnknown
}

func (m *linuxManager) Get() (*Settings, error) {
	s := &Settings{
		Platform: "linux",
		Data:     make(map[string]string),
	}

	switch m.de {
	case deGNOME:
		s.Data["de"] = "gnome"
		s.Data["mode"] = dconfRead("/system/proxy/mode")
		for _, proto := range []string{"http", "https", "ftp", "socks"} {
			s.Data[proto+"-host"] = dconfRead("/system/proxy/" + proto + "/host")
			s.Data[proto+"-port"] = dconfRead("/system/proxy/" + proto + "/port")
		}
		s.Data["ignore-hosts"] = dconfRead("/system/proxy/ignore-hosts")
	case deKDE:
		s.Data["de"] = "kde"
		s.Data["ProxyType"] = kdeRead(m.kreadConfig, "ProxyType")
		for _, key := range []string{"httpProxy", "httpsProxy", "ftpProxy", "socksProxy", "NoProxyFor"} {
			s.Data[key] = kdeRead(m.kreadConfig, key)
		}
	default:
		s.Data["de"] = "unknown"
	}

	return s, nil
}

func (m *linuxManager) Set(addr string, port string) error {
	switch m.de {
	case deGNOME:
		return m.gnomeSet(addr, port)
	case deKDE:
		return m.kdeSet(addr, port)
	default:
		return m.writeEnvFile(addr, port)
	}
}

// gnomeSet sets all protocol proxies (http, https, ftp, socks) to the same
// address using 'manual' mode. This is the same technique used by v2rayN.
// Uses dconf directly to avoid issues where a non-system gsettings binary
// (e.g. from conda/anaconda) writes to a different backend than what the
// GNOME desktop actually reads.
func (m *linuxManager) gnomeSet(addr, port string) error {
	writes := [][2]string{
		{"/system/proxy/mode", "'manual'"},
	}
	for _, proto := range []string{"http", "https", "ftp", "socks"} {
		writes = append(writes,
			[2]string{"/system/proxy/" + proto + "/host", "'" + addr + "'"},
			[2]string{"/system/proxy/" + proto + "/port", port},
		)
	}
	writes = append(writes,
		[2]string{"/system/proxy/ignore-hosts", "['localhost', '127.0.0.0/8', '::1']"},
	)
	for _, w := range writes {
		if out, err := exec.Command("dconf", "write", w[0], w[1]).CombinedOutput(); err != nil {
			return fmt.Errorf("dconf write %s failed: %s: %w", w[0], string(out), err)
		}
	}
	return nil
}

func (m *linuxManager) kdeSet(addr, port string) error {
	proxyURL := fmt.Sprintf("http://%s:%s", addr, port)
	cmds := [][]string{
		{m.kwriteConfig, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1"},
		{m.kwriteConfig, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", proxyURL},
		{m.kwriteConfig, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", proxyURL},
		{m.kwriteConfig, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ftpProxy", proxyURL},
		{m.kwriteConfig, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", proxyURL},
		{m.kwriteConfig, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "NoProxyFor", "localhost,127.0.0.0/8,::1"},
	}
	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("kwriteconfig failed: %s: %w", string(out), err)
		}
	}
	_ = exec.Command("dbus-send", "--type=signal", "/KIO/Scheduler",
		"org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:").Run()
	return nil
}

func (m *linuxManager) Restore(prev *Settings) error {
	if prev == nil {
		return nil
	}

	de := prev.Data["de"]
	switch de {
	case "gnome":
		mode := prev.Data["mode"]
		if mode == "" {
			mode = "none"
		}
		writes := [][2]string{
			{"/system/proxy/mode", "'" + mode + "'"},
		}
		for _, proto := range []string{"http", "https", "ftp", "socks"} {
			host := prev.Data[proto+"-host"]
			port := prev.Data[proto+"-port"]
			if port == "" {
				port = "0"
			}
			writes = append(writes,
				[2]string{"/system/proxy/" + proto + "/host", "'" + host + "'"},
				[2]string{"/system/proxy/" + proto + "/port", port},
			)
		}
		if ignoreHosts := prev.Data["ignore-hosts"]; ignoreHosts != "" {
			writes = append(writes, [2]string{"/system/proxy/ignore-hosts", ignoreHosts})
		}
		for _, w := range writes {
			if out, err := exec.Command("dconf", "write", w[0], w[1]).CombinedOutput(); err != nil {
				return fmt.Errorf("dconf restore %s failed: %s: %w", w[0], string(out), err)
			}
		}
		return nil

	case "kde":
		proxyType := prev.Data["ProxyType"]
		if proxyType == "" {
			proxyType = "0"
		}
		cmds := [][]string{
			{m.kwriteConfig, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", proxyType},
		}
		for _, key := range []string{"httpProxy", "httpsProxy", "ftpProxy", "socksProxy"} {
			if val := prev.Data[key]; val != "" {
				cmds = append(cmds, []string{m.kwriteConfig, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key, val})
			}
		}
		if noProxy := prev.Data["NoProxyFor"]; noProxy != "" {
			cmds = append(cmds, []string{m.kwriteConfig, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "NoProxyFor", noProxy})
		}

		kwrite := m.kwriteConfig
		if kwrite == "" {
			kwrite = "kwriteconfig5"
			if p, err := exec.LookPath("kwriteconfig6"); err == nil {
				kwrite = p
			}
		}
		for i := range cmds {
			if cmds[i][0] == "" {
				cmds[i][0] = kwrite
			}
		}

		for _, args := range cmds {
			if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
				return fmt.Errorf("kwriteconfig restore failed: %s: %w", string(out), err)
			}
		}
		_ = exec.Command("dbus-send", "--type=signal", "/KIO/Scheduler",
			"org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:").Run()
		return nil

	default:
		return m.writeUnsetEnvFile()
	}
}

func dconfRead(path string) string {
	out, err := exec.Command("dconf", "read", path).Output()
	if err != nil {
		return ""
	}
	return strings.Trim(strings.TrimSpace(string(out)), "'")
}

func kdeRead(kreadConfig, key string) string {
	if kreadConfig == "" {
		return ""
	}
	out, err := exec.Command(kreadConfig, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func envFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".xray-knife")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "proxy.env"), nil
}

func (m *linuxManager) writeEnvFile(addr, port string) error {
	path, err := envFilePath()
	if err != nil {
		return err
	}
	proxyURL := fmt.Sprintf("http://%s:%s", addr, port)
	content := fmt.Sprintf(`export http_proxy=%s
export https_proxy=%s
export all_proxy=%s
export no_proxy=localhost,127.0.0.1
`, proxyURL, proxyURL, proxyURL)

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	fmt.Printf("No supported desktop environment detected. Source %s in your shell to apply.\n", path)
	return nil
}

func (m *linuxManager) writeUnsetEnvFile() error {
	path, err := envFilePath()
	if err != nil {
		return err
	}
	content := `unset http_proxy https_proxy all_proxy no_proxy
`
	return os.WriteFile(path, []byte(content), 0o644)
}
