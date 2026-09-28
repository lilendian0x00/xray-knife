package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRegenerationIsDeterministicAndRemovesStaleAssets(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("dist/assets", 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"index.html", "assets/old.js"} {
		if err := os.WriteFile(filepath.Join("dist", name), []byte("test frontend payload"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := compress(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile("dist-gzip/index.html.gz")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove("dist/assets/old.js"); err != nil {
		t.Fatal(err)
	}
	if err := compress(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile("dist-gzip/index.html.gz")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("gzip output is not reproducible")
	}
	if _, err := os.Stat("dist-gzip/assets/old.js.gz"); !os.IsNotExist(err) {
		t.Fatalf("stale asset remains: %v", err)
	}
}
