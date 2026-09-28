//go:build !linux

package killswitch

import "errors"

var errNotLinux = errors.New("the kill switch is only supported on Linux")

func pickBackend(string) (backend, error) { return nil, errNotLinux }

func processAlive(int) bool { return false }

// Leftovers reports nothing: no kill switch can exist on this platform.
func Leftovers() ([]Leftover, error) { return nil, nil }

// RemoveStale is a no-op on this platform.
func RemoveStale(bool) (removed, kept []Leftover, err error) { return nil, nil, nil }
