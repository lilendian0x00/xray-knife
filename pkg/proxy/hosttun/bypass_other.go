//go:build !linux

package hosttun

import "net/netip"

// Bypass is a no-op outside Linux (host-tun is Linux-only).
type Bypass struct{}

func NewBypass(int) *Bypass                { return &Bypass{} }
func (b *Bypass) SetMark(uint32) error     { return nil }
func (b *Bypass) Set([]netip.Prefix) error { return nil }
func (b *Bypass) Close() error             { return nil }
