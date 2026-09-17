// Package mtproto parses tg://proxy and t.me/proxy share links and verifies a
// proxy with its obfuscation handshake plus one unencrypted MTProto round trip.
// These proxies only relay Telegram traffic, so they are never an outbound.
package mtproto

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// ErrNotProxyable is returned when an MTProto proxy is asked to be a general
// outbound (proxy, tun, chain, scanner).
var ErrNotProxyable = errors.New("mtproto proxies only relay Telegram traffic and cannot be used as a general outbound")

// Core satisfies core.Core. Only CreateProtocol does real work; reachability
// testing lives on MTProto.Probe.
type Core struct{}

func NewCore() *Core { return &Core{} }

func (c *Core) Name() string { return protocol.MTProtoIdentifier }

// CreateProtocol accepts tg://proxy?… and http(s)://t.me/proxy?… links.
func (c *Core) CreateProtocol(link string) (protocol.Protocol, error) {
	link = strings.TrimSpace(link)
	if !IsProxyLink(link) {
		return nil, fmt.Errorf("not an mtproto proxy link: %s", link)
	}
	return NewMTProto(link), nil
}

func (c *Core) MakeHttpClient(context.Context, protocol.Protocol, time.Duration) (*http.Client, protocol.Instance, error) {
	return nil, nil, ErrNotProxyable
}

func (c *Core) MakeInstance(context.Context, protocol.Protocol) (protocol.Instance, error) {
	return nil, ErrNotProxyable
}

func (c *Core) SetInbound(protocol.Protocol) error { return ErrNotProxyable }
