//go:build with_quic

package singbox

// The V2Ray QUIC transport registers itself from this package's init; the
// boxContext registries do not cover transports, so without the import every
// "type=quic" link failed with "create client transport: quic: invalid
// argument" even in with_quic builds.
import _ "github.com/sagernet/sing-box/transport/v2rayquic"
