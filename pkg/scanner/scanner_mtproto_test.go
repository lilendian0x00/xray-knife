package scanner

import (
	"io"
	"log"
	"strings"
	"testing"
	"time"
)

// The scanner swaps the config's address for each scanned IP, so an MTProto
// proxy can never be its outbound. Both link forms must be refused before any dial.
func TestScannerRejectsMTProtoConfig(t *testing.T) {
	for _, link := range []string{
		"tg://proxy?server=1.2.3.4&port=443&secret=00112233445566778899aabbccddeeff",
		"https://t.me/proxy?server=1.2.3.4&port=443&secret=00112233445566778899aabbccddeeff",
	} {
		s, err := NewScannerService(ScannerConfig{ConfigLink: link}, log.New(io.Discard, "", 0))
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		_, _, err = s.createClientFromConfig("1.1.1.1", time.Second)
		if err == nil {
			t.Fatalf("%s: scanner accepted an mtproto config", link)
		}
		if !strings.Contains(err.Error(), "unsupported protocol scheme") &&
			!strings.Contains(err.Error(), "only relay Telegram traffic") {
			t.Errorf("%s: err = %v, want a clear rejection", link, err)
		}
	}
}
