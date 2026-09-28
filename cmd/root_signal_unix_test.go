//go:build unix

package cmd

import (
	"syscall"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/utils/interrupt"
)

// While a command owns repeated signals (the proxy lifting its kill
// switch), a second Ctrl+C must not make the root handler exit: the test
// process would die here if it did.
func TestSignalContextLeavesOwnedRepeatsToCommand(t *testing.T) {
	ctx, stop, interrupted := signalContext()
	defer stop()
	release := interrupt.Own()
	defer release()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("first SIGINT did not cancel the context")
	}
	if !interrupted() {
		t.Fatal("interrupt not recorded")
	}
	for i := 0; i < 2; i++ {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond) // the handler would have exited by now
}
