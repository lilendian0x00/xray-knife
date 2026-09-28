//go:build !linux

package hosttun

func cleanupState(*State) ([]string, error) { return nil, nil }
