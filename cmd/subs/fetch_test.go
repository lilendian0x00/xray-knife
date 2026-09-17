package subs

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/subscription"
)

func newTestFetchCommand() *FetchCommand {
	return &FetchCommand{
		config: &FetchConfig{},
		core:   core.NewAutomaticCore(false, false),
	}
}

func TestFetchSourceAppliesConfiguredLimits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("socks://one:1080\nsocks://two:1080"))
	}))
	defer server.Close()
	fc := newTestFetchCommand()
	fc.config.MaxLinks = 1
	if _, err := fc.fetchSource(context.Background(), &Subscription{Url: server.URL}); !errors.Is(err, subscription.ErrTooManyLinks) {
		t.Fatalf("CLI did not pass the link limit: %v", err)
	}
	fc.config.MaxLinks = 2
	if links, err := fc.fetchSource(context.Background(), &Subscription{Url: server.URL}); err != nil || len(links) != 2 {
		t.Fatalf("raised CLI limit not honored: %d links, %v", len(links), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fc.fetchSource(ctx, &Subscription{Url: server.URL}); !errors.Is(err, context.Canceled) {
		t.Fatalf("CLI did not propagate cancellation: %v", err)
	}
}

func TestFetchLimitFlags(t *testing.T) {
	fc := newTestFetchCommand()
	cmd := fc.createCommand()
	if err := cmd.ParseFlags([]string{"--url", "https://example.com/sub", "--max-links", "200000", "--max-bytes", "134217728", "--fetch-timeout", "2m"}); err != nil {
		t.Fatal(err)
	}
	if err := fc.validateFlags(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if fc.config.MaxLinks != 200000 || fc.config.MaxBytes != 134217728 || fc.config.Timeout != 2*time.Minute {
		t.Fatal("fetch limits were not configured")
	}
	fc.config.MaxLinks = 0
	if err := fc.validateFlags(cmd, nil); err == nil {
		t.Fatal("zero CLI link limit accepted")
	}
}

func TestParseLinksCountsUnparsable(t *testing.T) {
	fc := newTestFetchCommand()

	links := []string{
		"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=tcp#ok",
		"this-is-not-a-config-link",
		"",
		"also://nonsense-protocol",
	}

	configs, unparsable := fc.parseLinks(links, sql.NullInt64{})

	if len(configs) != 3 {
		t.Fatalf("len(configs) = %d, want 3 (blank line skipped)", len(configs))
	}
	if unparsable != 2 {
		t.Fatalf("unparsable = %d, want 2", unparsable)
	}
}

func TestParseLinksAllGoodReportsZero(t *testing.T) {
	fc := newTestFetchCommand()

	links := []string{
		"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=tcp#ok",
	}

	configs, unparsable := fc.parseLinks(links, sql.NullInt64{})

	if len(configs) != 1 {
		t.Fatalf("len(configs) = %d, want 1", len(configs))
	}
	if unparsable != 0 {
		t.Fatalf("unparsable = %d, want 0", unparsable)
	}
}

const (
	mtprotoSecret = "dd00112233445566778899aabbccddeeff"
	mtprotoTg     = "tg://proxy?server=1.2.3.4&port=443&secret=" + mtprotoSecret + "#my proxy"
	mtprotoTMe    = "https://t.me/proxy?server=5.6.7.8&port=8443&secret=" + mtprotoSecret
)

func TestParseLinksClassifiesMTProto(t *testing.T) {
	fc := newTestFetchCommand()

	links := []string{
		mtprotoTg,
		mtprotoTMe,
		"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=tcp#ok",
		"tg://proxy?server=1.2.3.4&port=443&secret=zz", // bad secret: counted unparsable
	}
	configs, unparsable := fc.parseLinks(links, sql.NullInt64{})
	if len(configs) != 4 {
		t.Fatalf("len(configs) = %d, want 4", len(configs))
	}
	if unparsable != 1 {
		t.Fatalf("unparsable = %d, want 1", unparsable)
	}
	for i, want := range []string{"mtproto", "mtproto", "vless"} {
		if configs[i].Protocol.String != want {
			t.Errorf("configs[%d].Protocol = %q, want %q", i, configs[i].Protocol.String, want)
		}
	}
	if configs[0].Remark.String != "my proxy" {
		t.Errorf("remark = %q, want %q", configs[0].Remark.String, "my proxy")
	}
	if configs[0].ConfigLink != mtprotoTg || configs[1].ConfigLink != mtprotoTMe {
		t.Error("stored config links must keep their original spelling")
	}
	if configs[3].Protocol.Valid {
		t.Errorf("unparsable link got protocol %q", configs[3].Protocol.String)
	}
}

// The fetch -> DB -> filter path, against a throwaway database.
func TestMTProtoRowsSelectableByProtocol(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "subs-mtproto.db")); err != nil {
		t.Fatalf("temporary database: %v", err)
	}
	defer func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	}()
	if err := database.AddSubscription("https://example.test/sub", "test", ""); err != nil {
		t.Fatal(err)
	}
	subs, err := database.ListSubscriptions()
	if err != nil || len(subs) != 1 {
		t.Fatalf("subscriptions = %v, %v", subs, err)
	}

	fc := newTestFetchCommand()
	configs, unparsable := fc.parseLinks([]string{
		mtprotoTg,
		mtprotoTMe,
		"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=tcp#ok",
	}, sql.NullInt64{Int64: subs[0].ID, Valid: true})
	if unparsable != 0 {
		t.Fatalf("unparsable = %d", unparsable)
	}
	if err := database.UpsertSubscriptionConfigs(configs); err != nil {
		t.Fatal(err)
	}

	links, err := database.GetConfigsFromDB(0, "mtproto", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 {
		t.Fatalf("--protocol mtproto returned %d links: %v", len(links), links)
	}
	got := map[string]bool{links[0]: true, links[1]: true}
	if !got[mtprotoTg] || !got[mtprotoTMe] {
		t.Errorf("both spellings must survive the round trip: %v", links)
	}

	listed, err := database.ListSubscriptionConfigs(0, "mtproto", 0)
	if err != nil || len(listed) != 2 {
		t.Fatalf("list-configs --protocol mtproto: %d rows, %v", len(listed), err)
	}

	// Both spellings are one connection; semantic dedup must collapse them.
	c := core.NewAutomaticCore(false, false)
	one, err := core.ConnectionFingerprint(c, mtprotoTg)
	if err != nil {
		t.Fatal(err)
	}
	two, err := core.ConnectionFingerprint(c, "https://t.me/proxy?server=1.2.3.4&port=443&secret="+mtprotoSecret)
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Error("tg:// and t.me spellings of one proxy must share a fingerprint")
	}
}
