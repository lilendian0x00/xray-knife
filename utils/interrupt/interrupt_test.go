package interrupt

import (
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// runWatch feeds sigs (with the fake clock advanced by gap[i] before each)
// and reports whether a forced exit happened and how often cleanup ran.
func runWatch(t *testing.T, sigs []os.Signal, gaps []time.Duration) (exited bool, cleaned int32) {
	t.Helper()
	ch := make(chan os.Signal, len(sigs))
	clock := time.Unix(1000, 0)
	var mu sync.Mutex
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	var calls atomic.Int32
	exit := make(chan struct{}, 1)
	done := make(chan struct{})
	defer close(done)
	go Watch(done, ch, func() {}, func() { calls.Add(1) }, now, func() { exit <- struct{}{} })
	for i, s := range sigs {
		mu.Lock()
		clock = clock.Add(gaps[i])
		mu.Unlock()
		ch <- s
		time.Sleep(20 * time.Millisecond) // let the watcher consume it
	}
	select {
	case <-exit:
		return true, calls.Load()
	case <-time.After(100 * time.Millisecond):
		return false, calls.Load()
	}
}

// An SSH disconnect delivers several SIGHUPs; they must never skip the
// cleanup that lifts the kill switch.
func TestRepeatedHangupsDoNotForceExit(t *testing.T) {
	if exited, _ := runWatch(t, []os.Signal{syscall.SIGHUP, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGHUP}, []time.Duration{0, 0, 0, 0}); exited {
		t.Fatal("SIGHUP/SIGTERM repeats forced an exit")
	}
}

func TestDoubleCtrlCForcesExitAfterEmergencyCleanup(t *testing.T) {
	exited, cleaned := runWatch(t, []os.Signal{os.Interrupt, os.Interrupt}, []time.Duration{0, time.Second})
	if !exited || cleaned != 1 {
		t.Fatalf("exited=%v cleaned=%d", exited, cleaned)
	}
	// A second Ctrl+C long after the first only re-arms.
	if exited, _ := runWatch(t, []os.Signal{os.Interrupt, os.Interrupt}, []time.Duration{0, 10 * time.Second}); exited {
		t.Fatal("slow second Ctrl+C forced an exit")
	}
	exited, _ = runWatch(t, []os.Signal{syscall.SIGHUP, os.Interrupt, os.Interrupt}, []time.Duration{0, time.Second, time.Second})
	if !exited {
		t.Fatal("double Ctrl+C after SIGHUP did not force an exit")
	}
}

// The first signal cancels the run, but Watch keeps handling signals until
// done is closed: the caller's cleanup runs after the cancel.
func TestWatchOutlivesCancel(t *testing.T) {
	ch := make(chan os.Signal, 2)
	done := make(chan struct{})
	canceled := make(chan struct{})
	exited := make(chan struct{})
	returned := make(chan struct{})
	go func() {
		Watch(done, ch, func() { close(canceled) }, func() {}, time.Now, func() { close(exited) })
		close(returned)
	}()
	ch <- os.Interrupt
	<-canceled
	ch <- os.Interrupt
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("second Ctrl+C after cancel was not handled")
	}
	<-returned

	// Closing done ends a watcher that saw no signal.
	done2 := make(chan struct{})
	returned2 := make(chan struct{})
	go func() {
		Watch(done2, make(chan os.Signal), func() {}, func() {}, time.Now, func() {})
		close(returned2)
	}()
	close(done2)
	select {
	case <-returned2:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after done closed")
	}
	close(done)
}

func TestOwn(t *testing.T) {
	if Owned() {
		t.Fatal("owned before Own")
	}
	a, b := Own(), Own()
	a()
	a() // release is idempotent
	if !Owned() {
		t.Fatal("released while another owner remains")
	}
	b()
	if Owned() {
		t.Fatal("still owned after every release")
	}
}
