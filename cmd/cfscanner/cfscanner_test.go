package cfscanner

import (
	"os"
	"strings"
	"testing"
)

func TestValidateConfigLink(t *testing.T) {
	cases := []struct {
		name    string
		link    string
		wantErr bool
	}{
		{"empty is fine", "", false},
		{"vless link", "vless://uuid@host:443?security=tls", false},
		{"v10 speedtest-top value", "10", true},
		{"bare host", "example.com", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfigLink(tc.link)
			if tc.wantErr && err == nil {
				t.Fatalf("validateConfigLink(%q) = nil, want error", tc.link)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateConfigLink(%q) = %v, want nil", tc.link, err)
			}
		})
	}
}

func TestValidateConfigLinkMentionsSpeedtestTop(t *testing.T) {
	err := validateConfigLink("10")
	if err == nil {
		t.Fatal("expected an error for a bare integer")
	}
	if !strings.Contains(err.Error(), "--speedtest-top") {
		t.Fatalf("error %q should point users at --speedtest-top", err)
	}
}

func TestCollectSubnets(t *testing.T) {
	dir := t.TempDir()
	file := dir + "/subnets.txt"
	if err := os.WriteFile(file, []byte("# cloudflare\n104.16.0.0/13\n\n1.1.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := collectSubnets([]string{file, "2606:4700::/32"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"104.16.0.0/13", "1.1.1.1/32", "2606:4700::/32"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, bad := range [][]string{{"1.2.3.0/40"}, {"not-a-subnet"}, {}, {dir + "/missing.txt"}} {
		if _, err := collectSubnets(bad); err == nil {
			t.Errorf("collectSubnets(%v) accepted", bad)
		}
	}
	empty := dir + "/empty.txt"
	_ = os.WriteFile(empty, []byte("# nothing\n"), 0o600)
	if _, err := collectSubnets([]string{empty}); err == nil {
		t.Error("empty subnet file accepted")
	}
}

func TestOutputPath(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"results.csv", "json"}: "results.json",
		{"results.csv", "csv"}:  "results.csv",
		{"out/scan", "jsonl"}:   "out/scan.jsonl",
		{"-", "json"}:           "-",
	} {
		got, err := outputPath(in[0], in[1])
		if err != nil || got != want {
			t.Errorf("outputPath(%q, %q) = %q, %v; want %q", in[0], in[1], got, err, want)
		}
	}
	if _, err := outputPath("results.csv", "xml"); err == nil {
		t.Error("unknown type accepted")
	}
}
