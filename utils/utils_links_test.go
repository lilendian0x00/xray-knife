package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBase64DecodeVariants(t *testing.T) {
	want := "aes-128-gcm:p?>~ss"
	for name, in := range map[string]string{
		"std padded":   "YWVzLTEyOC1nY206cD8+fnNz",
		"std unpadded": "YWVzLTEyOC1nY206cD8+fnNz",
		"url padded":   "YWVzLTEyOC1nY206cD8-fnNz",
		"url raw":      "YWVzLTEyOC1nY206cD8-fnNz",
	} {
		got, err := Base64Decode(in)
		if err != nil || string(got) != want {
			t.Errorf("%s: Base64Decode(%q) = %q, %v", name, in, got, err)
		}
	}
	// Unpadded URL-safe input whose length is not a multiple of 4.
	got, err := Base64Decode("8J-YgA")
	if err != nil || string(got) != "\U0001F600" {
		t.Errorf("unpadded url-safe emoji: %q, %v", got, err)
	}
	if _, err := Base64Decode("not base64!"); err == nil {
		t.Error("invalid input accepted")
	}
}

func TestReadLinksFrom(t *testing.T) {
	in := "\ufeffvless://a\r\n\n  # comment\n// note\n  trojan://b  \n\t\n"
	got, err := ReadLinksFrom(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != "vless://a|trojan://b" {
		t.Fatalf("got %q", got)
	}
}

func TestReadLinksErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadLinks(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("missing file accepted")
	}
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, []byte("# only a comment\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLinks(empty); err == nil {
		t.Error("file without entries accepted")
	}
}
