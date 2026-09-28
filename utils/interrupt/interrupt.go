// Package interrupt decides what a repeated Ctrl+C does.
//
// The root command cancels its context on the first SIGINT/SIGTERM and
// exits at once on the next one, so a hung cleanup cannot trap the user.
// A command whose shutdown must not be skipped (the proxy lifts a kill
// switch and restores the OS proxy settings) calls Own for as long as it
// runs and handles repeated signals itself with Watch.
package interrupt

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
)

var owners atomic.Int32

// Own makes the root signal handler leave repeated signals to the caller
// until release is called.
func Own() (release func()) {
	owners.Add(1)
	return sync.OnceFunc(func() { owners.Add(-1) })
}

// Owned reports whether a running command handles repeated signals itself.
func Owned() bool { return owners.Load() > 0 }

// ForceWindow is how soon a second Ctrl+C must follow the first to force
// an exit.
const ForceWindow = 5 * time.Second

// Watch calls cancel on the first signal. Only a second SIGINT within
// ForceWindow forces an exit: an SSH disconnect delivers several SIGHUPs
// (sudo relays them) and a service manager may repeat SIGTERM, and neither
// must skip the cleanup that lifts the kill switch. Before a forced exit,
// cleanup (the best-effort emergency teardown) still runs. Watch returns
// once done is closed, which the caller does after its own cleanup.
func Watch(done <-chan struct{}, sigs <-chan os.Signal, cancel func(), cleanup func(), now func() time.Time, exit func()) {
	var lastInt time.Time
	stopping := false
	for {
		var sig os.Signal
		select {
		case sig = <-sigs:
		case <-done:
			return
		}
		t := now()
		if !stopping {
			stopping = true
			customlog.Printf(customlog.Processing, "Received signal: %v. Shutting down... (press Ctrl+C twice to force quit)\n", sig)
			if sig == os.Interrupt {
				lastInt = t
			}
			cancel()
			continue
		}
		if sig != os.Interrupt {
			continue
		}
		if lastInt.IsZero() || t.Sub(lastInt) > ForceWindow {
			lastInt = t
			customlog.Printf(customlog.Warning, "Still shutting down; press Ctrl+C again within %v to force quit.\n", ForceWindow)
			continue
		}
		customlog.Printf(customlog.Failure, "Forcing exit: lifting the kill switch and restoring OS proxy settings first...\n")
		cleanup()
		customlog.Printf(customlog.Failure, "Forced exit. If anything is left behind, run 'xray-knife proxy restore'.\n")
		exit()
		return
	}
}
