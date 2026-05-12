package netns

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// State is persisted to disk so a subsequent launch can clean up
// an orphaned namespace left behind by a crash (SIGKILL, power loss, etc.).
// Pid and BootID together identify the owning process; if the PID is alive
// AND the boot_id matches, the resources still belong to a live process and
// must NOT be reclaimed.
type State struct {
	Name     string `json:"name"`
	VethHost string `json:"vethHost"`
	VethNS   string `json:"vethNS"`
	Pid      int    `json:"pid"`
	BootID   string `json:"bootId"`
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

// readBootID returns the kernel boot_id, used to invalidate stale state
// across reboots (PIDs can recycle after a reboot).
func readBootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// SaveState persists the namespace state to disk for crash recovery.
// Pid and BootID are stamped automatically.
func SaveState(s *State) error {
	path, err := stateFilePath()
	if err != nil {
		return err
	}
	if s.Pid == 0 {
		s.Pid = os.Getpid()
	}
	if s.BootID == "" {
		s.BootID = readBootID()
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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

// stateOwnerAlive reports whether the recorded owner is still running.
// Returns true if the PID is alive AND the boot_id matches what was recorded
// (or no boot_id was recorded — fallback for legacy state files).
// A signal-0 send is the canonical liveness probe on Linux.
func stateOwnerAlive(s *State) bool {
	if s == nil || s.Pid <= 0 {
		return false
	}
	if s.BootID != "" && s.BootID != readBootID() {
		// Boot changed: PIDs from before reboot are meaningless.
		return false
	}
	proc, err := os.FindProcess(s.Pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	return !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH)
}
