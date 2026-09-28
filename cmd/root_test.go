package cmd

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
)

func TestExitCodeFor(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		interrupted bool
		want        int
	}{
		{"ok", nil, false, exitcode.OK},
		{"interrupted clean", nil, true, exitcode.Interrupted},
		{"runtime error", errors.New("boom"), false, exitcode.Error},
		{"nothing passed", exitcode.New(exitcode.NothingPassed, errors.New("0 of 5 passed")), false, exitcode.NothingPassed},
		{"canceled", fmt.Errorf("run: %w", context.Canceled), false, exitcode.Interrupted},
		{"error after signal", errors.New("partial"), true, exitcode.Interrupted},
		{"flag error", flagErrorFunc(rootCmd, errors.New("unknown flag: --nope")), false, exitcode.Usage},
		{"unknown command", errors.New(`unknown command "x" for "xray-knife"`), false, exitcode.Usage},
		{"required flag", errors.New(`required flag(s) "url" not set`), false, exitcode.Usage},
		{"arg count", errors.New("accepts 1 arg(s), received 0"), false, exitcode.Usage},
	}
	for _, tc := range cases {
		if got := exitCodeFor(rootCmd, tc.err, tc.interrupted); got != tc.want {
			t.Errorf("%s: exitCodeFor = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestExitCodeForPropagatesChildStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	// What `exec` returns: the child's status, passed through silently.
	err := exitcode.Child(exec.Command("sh", "-c", "exit 7").Run())
	if got := exitCodeFor(rootCmd, err, false); got != 7 {
		t.Fatalf("child exit status = %d, want 7", got)
	}
	// A child killed by SIGINT exits 130 (128+2), never os.Exit(-1).
	err = exitcode.Child(exec.Command("sh", "-c", "kill -INT $$").Run())
	if got := exitCodeFor(rootCmd, err, true); got != 130 {
		t.Fatalf("signalled child = %d, want 130", got)
	}
	if exitcode.Child(nil) != nil {
		t.Fatal("Child(nil) is not nil")
	}
}

// A helper process failing inside some other command is an ordinary error:
// printed, exit 1, not the helper's own status.
func TestWrappedHelperExitErrorIsAnError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	helper := exec.Command("sh", "-c", "exit 4").Run()
	err := fmt.Errorf("failed to set system proxy: %w", helper)
	if got := exitCodeFor(rootCmd, err, false); got != exitcode.Error {
		t.Fatalf("wrapped helper failure = %d, want %d", got, exitcode.Error)
	}
}

func TestParseDoesNotOpenDatabase(t *testing.T) {
	// The root command must not open or migrate the database up front: only
	// commands that query it do, lazily.
	for _, c := range rootCmd.Commands() {
		if c.Name() == "parse" && c.PersistentPreRunE != nil {
			t.Fatal("parse gained a pre-run hook")
		}
	}
	if rootCmd.PersistentPreRun != nil || rootCmd.PersistentPreRunE != nil {
		t.Fatal("root must not initialise anything eagerly")
	}
}

func TestQuietFlag(t *testing.T) {
	t.Cleanup(func() { customlog.SetQuiet(false) })
	f := rootCmd.PersistentFlags().Lookup("quiet")
	if f == nil {
		t.Fatal("--quiet not registered")
	}
	if err := rootCmd.PersistentFlags().Set("quiet", "true"); err != nil {
		t.Fatal(err)
	}
	if !customlog.Quiet() || customlog.ProgressEnabled() {
		t.Fatal("--quiet did not silence info logs and progress")
	}
	if err := rootCmd.PersistentFlags().Set("quiet", "nope"); err == nil {
		t.Fatal("non-boolean --quiet accepted")
	}
}
