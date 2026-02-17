package sysproxy

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Settings holds the previous OS proxy configuration so it can be restored.
type Settings struct {
	Platform string            `json:"platform"`
	Data     map[string]string `json:"data"`
}

// Manager is the interface for platform-specific system proxy management.
type Manager interface {
	// Get reads the current OS proxy configuration.
	Get() (*Settings, error)
	// Set configures the OS to use a SOCKS proxy at addr:port.
	Set(addr string, port string) error
	// Restore reverts the OS proxy configuration to the previous settings.
	Restore(prev *Settings) error
}

// stateFilePath returns the path to the crash-recovery state file.
func stateFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".xray-knife")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, ".sysproxy-state.json"), nil
}

// SaveState persists the previous OS proxy settings to disk for crash recovery.
func SaveState(s *Settings) error {
	path, err := stateFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadState reads the persisted state file. Returns nil, nil if the file does not exist.
func LoadState() (*Settings, error) {
	path, err := stateFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ClearState removes the state file after a successful restore.
func ClearState() error {
	path, err := stateFilePath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
