package netns

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/statefile"
)

// State is persisted so a later launch can clean up a namespace left
// behind by a crash (SIGKILL, power loss, etc.). Pid and BootID identify
// the owner; while it is alive (same boot) its resources are left alone.
//
// Each instance writes its own file (keyed by PID) so parallel app-mode
// runs cannot overwrite or clear each other's state.
type State struct {
	Name string `json:"name"`
	// VethHost/VethNS are only set by state files written before the
	// veth pair was dropped; recovery still deletes them.
	VethHost string `json:"vethHost,omitempty"`
	VethNS   string `json:"vethNS,omitempty"`
	// ResolvDir is the /etc/netns/<name> directory we created, if any.
	ResolvDir string `json:"resolvDir,omitempty"`
	Pid       int    `json:"pid"`
	BootID    string `json:"bootId"`
}

const (
	legacyStateFile = ".netns-state.json"
	stateFilePrefix = ".netns-state-"
)

var legacyVethRE = regexp.MustCompile(`^xk[hn]-[0-9]{1,11}$`)

// Validate rejects state this package could not have written, so a forged
// file cannot make recovery (running as root) delete arbitrary
// namespaces, links or directories.
func (s *State) Validate() error {
	if s.Pid <= 0 {
		return errors.New("bad pid")
	}
	if err := ValidateName(s.Name); err != nil {
		return err
	}
	for _, v := range []string{s.VethHost, s.VethNS} {
		if v != "" && !legacyVethRE.MatchString(v) {
			return fmt.Errorf("bad veth name %q", v)
		}
	}
	if s.ResolvDir != "" && s.ResolvDir != filepath.Join(netnsEtcDir, s.Name) {
		return fmt.Errorf("bad resolver directory %q", s.ResolvDir)
	}
	return nil
}

func stateFileName(pid int) string { return fmt.Sprintf("%s%d.json", stateFilePrefix, pid) }

// readBootID returns the kernel boot_id, used to invalidate stale state
// across reboots (PIDs can recycle after a reboot).
func readBootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// SaveState persists the namespace state for crash recovery. Pid and
// BootID are stamped automatically.
func SaveState(s *State) error {
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
	return statefile.Write(stateFileName(s.Pid), data)
}

// LoadStates reads every persisted state file: per-instance and legacy,
// in the state directory and (read as untrusted) where older versions
// kept it. Files that do not validate are reported in bad.
func LoadStates() (states []*State, files []string, bad []string, err error) {
	dir, err := statefile.Dir()
	if err != nil {
		return nil, nil, nil, err
	}
	dirs := []string{dir}
	if legacy, ok := statefile.LegacyDir(); ok {
		dirs = append(dirs, legacy)
	}
	for _, d := range dirs {
		paths, _ := filepath.Glob(filepath.Join(d, stateFilePrefix+"*.json"))
		paths = append(paths, filepath.Join(d, legacyStateFile))
		for _, p := range paths {
			data, err := statefile.Read(p)
			if err != nil {
				continue
			}
			var s State
			if err := json.Unmarshal(data, &s); err != nil {
				bad = append(bad, p+": "+err.Error())
				continue
			}
			if err := s.Validate(); err != nil {
				bad = append(bad, p+": "+err.Error())
				continue
			}
			states = append(states, &s)
			files = append(files, p)
		}
	}
	return states, files, bad, nil
}

// ClearState removes this process's state file after a successful
// cleanup or shutdown.
func ClearState() error {
	return statefile.Remove(stateFileName(os.Getpid()))
}

// stateOwnerAlive reports whether the recorded owner is still running.
// Returns true if the PID is alive AND the boot_id matches what was recorded
// (or no boot_id was recorded — fallback for legacy state files).
// A signal-0 send is the canonical liveness probe on Linux.
func stateOwnerAlive(s *State) bool {
	if s == nil || s.Pid <= 0 {
		return false
	}
	if s.Pid == os.Getpid() {
		return true
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
