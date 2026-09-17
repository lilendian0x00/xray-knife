package proxy

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
)

const (
	chainVless      = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?encryption=none&security=tls&type=tcp#a"
	chainTrojan     = "trojan://password@5.6.7.8:443?security=tls&type=tcp#b"
	chainTrojan2    = "trojan://password@7.7.7.7:443?security=tls&type=tcp#c"
	chainMTProto    = "tg://proxy?server=9.9.9.9&port=443&secret=dd00112233445566778899aabbccddeeff"
	chainMTProtoTMe = "https://t.me/proxy?server=9.9.9.9&port=443&secret=dd00112233445566778899aabbccddeeff"
)

// The engines a chain can be built with: automatic plus the explicit cores the
// proxy service constructs.
func chainCores() map[string]core.Core {
	return map[string]core.Core{
		"automatic": core.NewAutomaticCore(false, false),
		"xray":      core.CoreFactory(core.XrayCoreType, false, false),
		"singbox":   core.CoreFactory(core.SingboxCoreType, false, false),
	}
}

func TestResolveFixedChainRejectsMTProto(t *testing.T) {
	for name, c := range chainCores() {
		t.Run(name, func(t *testing.T) {
			for _, mt := range []string{chainMTProto, chainMTProtoTMe} {
				_, err := resolveFixedChain(c, chainVless+"|"+mt, "")
				if err == nil || !strings.Contains(err.Error(), "chain hop 1: mtproto cannot be a chain hop: it only relays Telegram traffic") {
					t.Fatalf("%s: err = %v", mt, err)
				}
			}
			hops, err := resolveFixedChain(c, chainVless+"|"+chainTrojan, "")
			if err != nil || len(hops) != 2 {
				t.Fatalf("valid chain: err = %v, hops = %d", err, len(hops))
			}
		})
	}
}

func TestSelectChainFromPoolSkipsMTProto(t *testing.T) {
	for name, c := range chainCores() {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < 20; i++ { // the pool is shuffled; run enough times to hit every order
				hops, err := selectChainFromPool(c, []string{chainMTProto, chainVless, chainMTProtoTMe, chainTrojan}, 2)
				if err != nil {
					t.Fatal(err)
				}
				for _, h := range hops {
					if h.ConvertToGeneralConfig().Protocol == "mtproto" {
						t.Fatal("mtproto hop selected from pool")
					}
				}
			}
			if _, err := selectChainFromPool(c, []string{chainMTProto, chainMTProtoTMe, chainVless}, 2); err == nil {
				t.Fatal("a pool with one usable hop must not produce a 2-hop chain")
			}
			if _, err := selectChainFromPool(c, []string{chainMTProto, chainMTProtoTMe}, 2); err == nil {
				t.Fatal("a pool of only mtproto links must not produce a chain")
			}
		})
	}
}

func TestSelectExitHopFromPoolSkipsMTProto(t *testing.T) {
	for name, c := range chainCores() {
		t.Run(name, func(t *testing.T) {
			fixed, err := resolveFixedChain(c, chainVless+"|"+chainTrojan, "")
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 20; i++ {
				chain, err := selectExitHopFromPool(c, []string{chainMTProto, chainTrojan2}, fixed[:1], "")
				if err != nil {
					t.Fatal(err)
				}
				if exit := chain[len(chain)-1].ConvertToGeneralConfig(); exit.Protocol != "trojan" || exit.Address != "7.7.7.7" {
					t.Fatalf("exit hop = %+v", exit)
				}
			}
			if _, err := selectExitHopFromPool(c, []string{chainMTProto, chainMTProtoTMe}, fixed[:1], ""); err == nil {
				t.Fatal("a pool of only mtproto links must not yield an exit hop")
			}
		})
	}
}

// The service builds explicit xray/sing-box cores, so the guard has to fire in
// CreateProtocol, before any instance starts, and keep its reason intact.
func TestSingleModeRejectsMTProto(t *testing.T) {
	for _, coreType := range []string{"xray", "sing-box"} {
		t.Run(coreType, func(t *testing.T) {
			// Built directly around the core; New() would open the database.
			var engine core.Core
			if coreType == "xray" {
				engine = core.CoreFactory(core.XrayCoreType, false, false)
			} else {
				engine = core.CoreFactory(core.SingboxCoreType, false, false)
			}
			s := &Service{core: engine, logger: log.New(io.Discard, "", 0)}
			err := s.runSingleMode(context.Background(), chainMTProto)
			if err == nil {
				t.Fatal("single mode accepted an mtproto link")
			}
			if !errors.Is(err, mtproto.ErrNotProxyable) {
				t.Errorf("err = %v, want ErrNotProxyable", err)
			}
		})
	}
}
