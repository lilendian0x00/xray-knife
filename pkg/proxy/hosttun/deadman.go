package hosttun

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/term"
)

// StdinIsTTY reports whether stdin is an interactive terminal. False under
// systemd, nohup, setsid, or shell redirection — in which case the deadman
// ENTER prompt can never be answered.
func StdinIsTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// DeadmanResult is what the caller learns when the deadman timer expires.
type DeadmanResult int

const (
	// DeadmanConfirmed: user sent the confirm token in time.
	DeadmanConfirmed DeadmanResult = iota
	// DeadmanExpired: timer fired without confirmation; caller should
	// tear down the tunnel.
	DeadmanExpired
	// DeadmanCanceled: ctx was canceled before either of the above.
	DeadmanCanceled
)

// RunDeadman waits for `timeout` for `confirm` to fire. If it does,
// returns DeadmanConfirmed. If the timer expires first, returns
// DeadmanExpired and the caller should tear down. If ctx is canceled,
// returns DeadmanCanceled.
//
// timeout <= 0 means "no deadman" — returns DeadmanConfirmed immediately.
func RunDeadman(ctx context.Context, timeout time.Duration, confirm <-chan struct{}) DeadmanResult {
	if timeout <= 0 {
		return DeadmanConfirmed
	}
	t := time.NewTimer(timeout)
	defer t.Stop()

	select {
	case <-confirm:
		return DeadmanConfirmed
	case <-t.C:
		return DeadmanExpired
	case <-ctx.Done():
		return DeadmanCanceled
	}
}

// DeadmanInstructions returns the user-facing prompt printed when
// host-tun comes up with a deadman timer.
func DeadmanInstructions(timeout time.Duration) string {
	return fmt.Sprintf(
		"host-tun is live. SSH access is at risk.\n"+
			"  → If you can still read this, the tunnel is preserving your SSH.\n"+
			"  → Press ENTER within %v to confirm — otherwise auto-teardown.\n"+
			"  → If SSH disconnects (SIGHUP), the tunnel is torn down on exit.\n"+
			"  → For unattended use: run under tmux/screen/systemd and pass --host-tun-deadman 0.\n",
		timeout,
	)
}
