package hosttun

import (
	"errors"
	"os"
)

// Recovered describes the leftovers of one crashed host-tun run.
type Recovered struct {
	Pid     int
	Removed []string
	Err     error // cleanup failed; the state file was kept for a retry
}

// RecoverFromCrash removes what host-tun runs whose owner is gone left
// behind (their state file too, unless cleanup failed). Live owners are
// reported in kept, unusable state files in bad.
func RecoverFromCrash() (recovered []Recovered, kept []int, bad []string) {
	states, files, bad, err := LoadStates()
	if err != nil {
		return nil, nil, []string{err.Error()}
	}
	for i, s := range states {
		if ownerAlive(s) {
			kept = append(kept, s.Pid)
			continue
		}
		removed, cerr := cleanupState(s)
		rec := Recovered{Pid: s.Pid, Removed: removed, Err: cerr}
		if cerr == nil {
			if err := os.Remove(files[i]); err != nil && !errors.Is(err, os.ErrNotExist) {
				rec.Err = err
			}
		}
		recovered = append(recovered, rec)
	}
	return recovered, kept, bad
}
