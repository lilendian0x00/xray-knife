package db

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/spf13/cobra"
)

func TestParseAge(t *testing.T) {
	cases := map[string]time.Duration{
		"":     0,
		"0":    0,
		"30d":  30 * 24 * time.Hour,
		"1.5d": 36 * time.Hour,
		"12h":  12 * time.Hour,
	}
	for in, want := range cases {
		got, err := parseAge(in)
		if err != nil || got != want {
			t.Errorf("parseAge(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"-1d", "abc", "d", "-5h"} {
		if _, err := parseAge(bad); err == nil {
			t.Errorf("parseAge(%q) accepted", bad)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	for in, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 5 << 20: "5.0 MiB"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestParseForceVersion(t *testing.T) {
	latest, _ := database.LatestVersion()
	if v, err := parseForceVersion("none"); err != nil || v != -1 {
		t.Fatalf("none = %d, %v", v, err)
	}
	if v, err := parseForceVersion("2"); err != nil || v != 2 {
		t.Fatalf("2 = %d, %v", v, err)
	}
	for _, bad := range []string{"0", "-3", "x", strconv.Itoa(int(latest) + 1)} {
		if _, err := parseForceVersion(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := parseForceVersion("0"); err == nil || !strings.Contains(err.Error(), "none") {
		t.Errorf("0 should point at \"none\": %v", err)
	}
}

// With no flags, prune only touches old test runs, never the config library.
func TestPruneDefaultKeepsConfigs(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "prune.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	old := database.NullTime{Time: time.Now().Add(-365 * 24 * time.Hour), Valid: true}
	if err := database.UpsertSubscriptionConfigs([]database.SubscriptionConfig{{ConfigLink: "vless://old", LastSeenAt: old}}); err != nil {
		t.Fatal(err)
	}
	cmd := newPruneCmd()
	cmd.SetArgs(nil)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if n, _ := database.CountSubscriptionConfigs(0); n != 1 {
		t.Fatalf("default prune deleted configs (%d left)", n)
	}
}

func TestMaintenanceCommandsNeedExistingDB(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none.db")
	database.SetPathResolver(func() (string, error) { return missing, nil })
	t.Cleanup(func() { database.SetPathResolver(nil) })
	for _, c := range []*cobra.Command{newStatsCmd(), newVacuumCmd()} {
		c.SetArgs(nil)
		c.SilenceUsage, c.SilenceErrors = true, true
		if err := c.Execute(); err == nil {
			t.Errorf("%s on a missing database succeeded", c.Name())
		}
	}
	m := newMigrateCmd()
	m.SetArgs([]string{"status"})
	m.SilenceUsage, m.SilenceErrors = true, true
	if err := m.Execute(); err == nil {
		t.Error("migrate status on a missing database succeeded")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("a maintenance command created the database")
	}
}
