package hosttun

import "os"

// markBase tags the socket marks xray-knife uses ("xk" in the top bits);
// the low bits come from the PID so parallel instances do not share one.
const markBase = 0x786b0000

// DefaultMark is the SO_MARK this process puts on its upstream sockets.
func DefaultMark() uint32 { return markBase | uint32(os.Getpid()&0xffff) }
