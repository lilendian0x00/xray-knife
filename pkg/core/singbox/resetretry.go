package singbox

import (
	"net/http"
	"strings"
)

// resetRetry retries a request once when sing-box tore the outbound's
// connections down with "network changed".
//
// sing-box's NetworkManager reports the default interface once while
// starting, from a goroutine that races Box.Start (route/network.go,
// updateInterface). When that goroutine runs after Start has finished it
// calls ResetNetwork, and every outbound listening for interface updates
// (hysteria, hysteria2, tuic, ssh, wireguard and the mux-capable ones)
// closes its connections. A test request made right after Start then fails
// with "network changed" although the proxy works; a genuine network change
// mid-request deserves the same second chance.
type resetRetry struct {
	base http.RoundTripper
}

func (t *resetRetry) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "network changed") || req.Context().Err() != nil {
		return resp, err
	}
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return resp, err
		}
		body, bodyErr := req.GetBody()
		if bodyErr != nil {
			return resp, err
		}
		req = req.Clone(req.Context())
		req.Body = body
	}
	return t.base.RoundTrip(req)
}
