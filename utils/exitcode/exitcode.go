// Package exitcode defines xray-knife's process exit-code contract and an
// error type commands return to pick a specific code.
//
//	0   success
//	1   runtime error
//	2   usage error (bad flag, argument or flag combination)
//	3   the command ran but nothing passed (e.g. no config passed a test)
//	130 interrupted (Ctrl-C / SIGTERM)
package exitcode

import (
	"errors"
	"fmt"
)

const (
	OK            = 0
	Error         = 1
	Usage         = 2
	NothingPassed = 3
	Interrupted   = 130
)

// ExitError carries the exit code a command wants. When Silent is set the
// command has already told the user what happened, so main prints nothing.
type ExitError struct {
	Code   int
	Err    error
	Silent bool
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit status %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// ExitCode reports the code.
func (e *ExitError) ExitCode() int { return e.Code }

// New wraps err so the process exits with code.
func New(code int, err error) error {
	return &ExitError{Code: code, Err: err}
}

// Newf is New with a formatted message.
func Newf(code int, format string, args ...any) error {
	return &ExitError{Code: code, Err: fmt.Errorf(format, args...)}
}

// Silent exits with code without printing anything.
func Silent(code int) error {
	return &ExitError{Code: code, Silent: true}
}

// Of returns the code an error asks for, and whether it asked. Only an
// *ExitError in the chain counts: *os/exec.ExitError also has an ExitCode
// method, but a helper process failing deep inside a command is not the
// command choosing its exit status.
func Of(err error) (int, bool) {
	var e *ExitError
	if errors.As(err, &e) {
		return e.Code, true
	}
	return 0, false
}

// Child is how a command that runs a program on the user's behalf (`exec`)
// hands that program's exit status back: silently, with the same code, or
// 128+N when it was killed by signal N (130 when the signal is unknown).
// Errors that are not a child exit status are returned unchanged.
func Child(err error) error {
	var ee interface {
		ExitCode() int
	}
	if !errors.As(err, &ee) {
		return err
	}
	code := ee.ExitCode()
	if code < 0 {
		code = signalCode(err)
	}
	return &ExitError{Code: code, Err: err, Silent: true}
}

// IsSilent reports whether err asks main not to print it.
func IsSilent(err error) bool {
	var e *ExitError
	return errors.As(err, &e) && e.Silent
}
