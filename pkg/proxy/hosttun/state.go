package hosttun

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

// State records what a running host-tun installed, so `proxy restore`
// can remove it after a crash: sing-tun's rules and the bypass rules
// outlive the process (the TUN device and its routes do not).
type State struct {
	Pid            int    `json:"pid"`
	BootID         string `json:"bootId"`
	TunName        string `json:"tunName"`
	TableIndex     int    `json:"tableIndex"`
	RuleIndex      int    `json:"ruleIndex"`
	BypassPriority int    `json:"bypassPriority"`
}

const stateFilePrefix = ".hosttun-state-"

// Table indices Start picks from (see pickRouteIndices).
const (
	tableIndexMin = 20000
	tableIndexMax = 60000
)

var ifNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// Validate rejects state whose values Start could not have produced, so a
// forged or corrupt file cannot make recovery delete arbitrary rules.
func (s *State) Validate() error {
	switch {
	case s.Pid <= 0:
		return errors.New("bad pid")
	case !ifNameRE.MatchString(s.TunName):
		return fmt.Errorf("bad TUN name %q", s.TunName)
	case s.RuleIndex < ruleSearchStart+1 || s.RuleIndex+ruleBlock > ruleSearchEnd:
		return fmt.Errorf("rule index %d out of range", s.RuleIndex)
	case s.BypassPriority != 0 && s.BypassPriority != s.RuleIndex-1:
		return fmt.Errorf("bypass priority %d does not match rule index %d", s.BypassPriority, s.RuleIndex)
	case s.TableIndex < tableIndexMin || s.TableIndex >= tableIndexMax:
		return fmt.Errorf("table index %d out of range", s.TableIndex)
	}
	return nil
}

func stateFileName(pid int) string { return fmt.Sprintf("%s%d.json", stateFilePrefix, pid) }

func readBootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// SaveState records s for this process.
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

// ClearState removes this process's state file.
func ClearState() error {
	return statefile.Remove(stateFileName(os.Getpid()))
}

// LoadStates returns every valid recorded host-tun state and its file,
// including state older versions left in the xray-knife home (validated
// like the rest). Invalid files are reported in bad and left alone.
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

// ownerAlive reports whether the process that wrote s still runs.
func ownerAlive(s *State) bool {
	if s.Pid <= 0 {
		return false
	}
	if s.Pid == os.Getpid() {
		return true
	}
	if s.BootID != "" && s.BootID != readBootID() {
		return false
	}
	proc, err := os.FindProcess(s.Pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
