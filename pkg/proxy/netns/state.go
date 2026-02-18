package netns

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// State is persisted to disk so a subsequent launch can clean up
// an orphaned namespace left behind by a crash (SIGKILL, power loss, etc.).
type State struct {
	Name     string `json:"name"`
	VethHost string `json:"vethHost"`
	VethNS   string `json:"vethNS"`
}

func stateFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".xray-knife")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, ".netns-state.json"), nil
}

// SaveState persists the namespace state to disk for crash recovery.
func SaveState(s *State) error {
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

// LoadState reads the persisted state file. Returns nil, nil if no file exists.
func LoadState() (*State, error) {
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
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ClearState removes the state file after a successful cleanup or shutdown.
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
