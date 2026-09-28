package customlog

import (
	"os"

	"golang.org/x/term"
)

// IsTerminal reports whether f is attached to a terminal.
func IsTerminal(f *os.File) bool {
	return f != nil && term.IsTerminal(int(f.Fd()))
}

// noColorRequested honours the NO_COLOR convention (https://no-color.org)
// and TERM=dumb.
func noColorRequested() bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return true
	}
	return os.Getenv("TERM") == "dumb"
}

// ColorEnabled reports whether ANSI colour should be written to f: only to a
// terminal, and never when NO_COLOR is set or TERM=dumb.
func ColorEnabled(f *os.File) bool {
	return !noColorRequested() && IsTerminal(f)
}

// ProgressEnabled reports whether live progress output (bars, spinners,
// carriage-return redraws) should be drawn. Redraws are only readable on a
// terminal, so they are skipped when stderr is redirected to a file or pipe,
// with --quiet, and when XRAY_KNIFE_NO_PROGRESS is set.
func ProgressEnabled() bool {
	if _, set := os.LookupEnv("XRAY_KNIFE_NO_PROGRESS"); set || Quiet() {
		return false
	}
	return os.Getenv("TERM") != "dumb" && IsTerminal(os.Stderr)
}
