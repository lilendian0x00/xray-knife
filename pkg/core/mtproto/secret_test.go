package mtproto

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

const testKeyHex = "00112233445566778899aabbccddeeff"

func TestParseSecretTypes(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantType  SecretType
		wantHost  string
		wantHex   string
		wantError string
	}{
		{name: "simple hex", raw: testKeyHex, wantType: SecretSimple, wantHex: testKeyHex},
		{name: "simple uppercase hex", raw: strings.ToUpper(testKeyHex), wantType: SecretSimple, wantHex: testKeyHex},
		{name: "secured hex", raw: "dd" + testKeyHex, wantType: SecretSecured, wantHex: "dd" + testKeyHex},
		{name: "faketls hex", raw: "ee" + testKeyHex + hex.EncodeToString([]byte("www.google.com")), wantType: SecretFakeTLS, wantHost: "www.google.com", wantHex: "ee" + testKeyHex + hex.EncodeToString([]byte("www.google.com"))},
		{name: "faketls base64url", raw: base64.RawURLEncoding.EncodeToString(mustHex(t, "ee"+testKeyHex+hex.EncodeToString([]byte("example.org")))), wantType: SecretFakeTLS, wantHost: "example.org", wantHex: "ee" + testKeyHex + hex.EncodeToString([]byte("example.org"))},
		{name: "secured base64 std padded", raw: base64.StdEncoding.EncodeToString(mustHex(t, "dd"+testKeyHex)), wantType: SecretSecured, wantHex: "dd" + testKeyHex},
		{name: "empty", raw: "", wantError: "empty"},
		{name: "not hex not base64", raw: "zz!!", wantError: "neither hex nor base64"},
		{name: "wrong length", raw: "0011", wantError: "length"},
		{name: "unknown prefix 17 bytes", raw: "aa" + testKeyHex, wantError: "prefix"},
		{name: "faketls empty host", raw: "ee" + testKeyHex, wantError: "prefix"},
		{name: "faketls bad host", raw: "ee" + testKeyHex + hex.EncodeToString([]byte("bad host!")), wantError: "cloak host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSecret(tc.raw)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Type != tc.wantType {
				t.Errorf("type = %v, want %v", got.Type, tc.wantType)
			}
			if got.CloakHost != tc.wantHost {
				t.Errorf("host = %q, want %q", got.CloakHost, tc.wantHost)
			}
			if hex.EncodeToString(got.Key[:]) != testKeyHex {
				t.Errorf("key = %x, want %s", got.Key, testKeyHex)
			}
			if got.Hex() != tc.wantHex {
				t.Errorf("Hex() = %q, want %q", got.Hex(), tc.wantHex)
			}
		})
	}
}

func TestSecretTypeString(t *testing.T) {
	for typ, want := range map[SecretType]string{SecretSimple: "simple", SecretSecured: "secured", SecretFakeTLS: "faketls", SecretType(0): "unknown"} {
		if got := typ.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", typ, got, want)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
