package sysproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/statefile"
)

// Settings holds the previous OS proxy configuration so it can be restored.
type Settings struct {
	Platform string            `json:"platform"`
	Data     map[string]string `json:"data"`
	// Owner identifies the process that changed the OS settings. Crash
	// recovery only restores state whose owner is gone, so a second
	// xray-knife instance never switches off a proxy a live one set.
	Owner *Owner `json:"owner,omitempty"`
}

// Owner identifies the process that saved a Settings snapshot.
type Owner struct {
	Pid int `json:"pid"`
	// Boot is a per-boot marker (Linux boot_id, or the boot time) so a
	// recycled PID after a reboot is not mistaken for the owner.
	Boot string `json:"boot,omitempty"`
}

// Manager is the interface for platform-specific system proxy management.
type Manager interface {
	// Get reads the current OS proxy configuration.
	Get() (*Settings, error)
	// Set configures the OS to use the HTTP+SOCKS proxy at addr:port.
	// It returns a *ManualConfigError when the OS cannot be configured
	// automatically and the user has to apply the settings themselves.
	Set(addr string, port string) error
	// Restore reverts the OS proxy configuration to the previous settings.
	Restore(prev *Settings) error
}

// ManualConfigError reports that no supported proxy settings backend was
// found; the settings were written to Path for the user to apply.
type ManualConfigError struct {
	Path string
}

func (e *ManualConfigError) Error() string {
	return fmt.Sprintf("no supported desktop environment detected; the OS proxy was NOT changed. Run 'source %s' in the shells that should use the proxy", e.Path)
}

// execOutput and execCombined run external commands. Tests replace them
// to feed canned tool output.
var (
	execOutput = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).Output()
	}
	execCombined = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}
)

const stateFileName = ".sysproxy-state.json"

// stateFilePath returns the path where we save proxy state for crash recovery.
func stateFilePath() (string, error) {
	return statefile.Path(stateFileName)
}

// SaveState persists the previous OS proxy settings to disk for crash
// recovery, stamped with this process as the owner. The write is atomic
// (and never follows a planted symlink), so a crash mid-write cannot
// leave a truncated file that would make the next start lose the user's
// original settings.
func SaveState(s *Settings) error {
	if s.Owner == nil {
		s.Owner = &Owner{Pid: os.Getpid(), Boot: bootMarker()}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return statefile.Write(stateFileName, data)
}

// LoadState reads the persisted state file. Returns nil, nil if the file does not exist.
func LoadState() (*Settings, error) {
	path, err := stateFilePath()
	if err != nil {
		return nil, err
	}
	data, err := statefile.Read(path)
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
	return statefile.Remove(stateFileName)
}

// OwnerAlive reports whether the process that saved s is still running.
// State without an owner (written by older versions) counts as orphaned.
func OwnerAlive(s *Settings) bool {
	if s == nil || s.Owner == nil || s.Owner.Pid <= 0 {
		return false
	}
	if s.Owner.Pid == os.Getpid() {
		return true
	}
	if s.Owner.Boot != "" && !sameBoot(s.Owner.Boot, bootMarker()) {
		return false
	}
	return processAlive(s.Owner.Pid)
}
