package webui

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func fakeHash(p string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
	return string(h), err
}

func gen(v string) func() (string, error) { return func() (string, error) { return v, nil } }

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func mustHash(t *testing.T, p string) string {
	t.Helper()
	h, err := fakeHash(p)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestResolveCredentials(t *testing.T) {
	storedHash := mustHash(t, "stored-pass")
	// session_check matches the stored hash: the last run used this password.
	file := map[string]string{"username": "fileuser", "password_hash": storedHash, "secret": "file-secret",
		"session_epoch": "3", "session_check": storedHash}

	cases := []struct {
		name                     string
		in                       credentialInputs
		wantUser, wantPass       string
		wantHash                 string
		wantSecret               string
		wantPassSrc, wantUserSrc string
		wantSave                 bool
		wantReset                bool
	}{
		{
			name:     "fresh install generates password and secret",
			in:       credentialInputs{},
			wantUser: "root", wantPass: "gen-pass", wantSecret: "gen-secret",
			wantPassSrc: "generated", wantUserSrc: "default", wantSave: true,
		},
		{
			// The old code regenerated the password here and ignored the flag.
			name:     "password flag without secret keeps the flag password",
			in:       credentialInputs{FlagPass: "flagpass", FlagPassSet: true},
			wantUser: "root", wantPass: "flagpass", wantSecret: "gen-secret",
			wantPassSrc: "flag", wantUserSrc: "default", wantSave: true,
		},
		{
			// The old code let the file's username win over the flag.
			name:     "user flag beats the file",
			in:       credentialInputs{FlagUser: "admin", FlagUserSet: true, File: file},
			wantUser: "admin", wantHash: storedHash, wantSecret: "file-secret",
			wantPassSrc: "file", wantUserSrc: "flag", wantSave: false,
		},
		{
			// A different password than last run: sessions are reset.
			name:     "env beats the file per field",
			in:       credentialInputs{Env: envOf(map[string]string{"XRAY_KNIFE_WEBUI_USER": "envuser", "XRAY_KNIFE_WEBUI_PASS": "envpass"}), File: file},
			wantUser: "envuser", wantPass: "envpass", wantSecret: "file-secret",
			wantPassSrc: "env", wantUserSrc: "env", wantSave: true, wantReset: true,
		},
		{
			name:     "flag beats env",
			in:       credentialInputs{FlagSecret: "flag-secret", FlagSecretSet: true, Env: envOf(map[string]string{"XRAY_KNIFE_WEBUI_SECRET": "env-secret"}), File: file},
			wantUser: "fileuser", wantHash: storedHash, wantSecret: "flag-secret",
			wantPassSrc: "file", wantUserSrc: "file", wantSave: false,
		},
		{
			name:     "empty flag value falls through",
			in:       credentialInputs{FlagUser: "", FlagUserSet: true, File: file},
			wantUser: "fileuser", wantHash: storedHash, wantSecret: "file-secret",
			wantPassSrc: "file", wantUserSrc: "file", wantSave: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc, err := resolveCredentials(tc.in, gen("gen-pass"), gen("gen-secret"), fakeHash)
			if err != nil {
				t.Fatal(err)
			}
			if rc.User != tc.wantUser || rc.Password != tc.wantPass || rc.Secret != tc.wantSecret {
				t.Fatalf("got user=%q pass=%q secret=%q", rc.User, rc.Password, rc.Secret)
			}
			if tc.wantHash != "" && rc.PasswordHash != tc.wantHash {
				t.Fatalf("hash = %q", rc.PasswordHash)
			}
			if rc.PasswordSource != tc.wantPassSrc || rc.UserSource != tc.wantUserSrc {
				t.Fatalf("sources: user=%s pass=%s", rc.UserSource, rc.PasswordSource)
			}
			if (rc.Save != nil) != tc.wantSave {
				t.Fatalf("save = %v, want save=%v", rc.Save, tc.wantSave)
			}
			if rc.SessionsReset != tc.wantReset {
				t.Fatalf("sessions reset = %v, want %v", rc.SessionsReset, tc.wantReset)
			}
			if rc.Save != nil {
				if _, ok := rc.Save["password"]; ok {
					t.Fatal("plaintext password persisted")
				}
				// A flag/env password must never reach the file.
				if tc.wantPassSrc == "flag" || tc.wantPassSrc == "env" {
					if bcrypt.CompareHashAndPassword([]byte(rc.Save["password_hash"]), []byte(rc.Password)) == nil {
						t.Fatal("flag/env password was written to webui.conf")
					}
				}
				if tc.wantPassSrc == "generated" && bcrypt.CompareHashAndPassword([]byte(rc.Save["password_hash"]), []byte("gen-pass")) != nil {
					t.Fatal("generated password hash not saved")
				}
			}
		})
	}
}

// Sessions survive restarts with the same password and end when it changes.
func TestSessionEpochFollowsPasswordChanges(t *testing.T) {
	run := func(file map[string]string, pass string) *resolvedCredentials {
		t.Helper()
		rc, err := resolveCredentials(credentialInputs{FlagPass: pass, FlagPassSet: pass != "", File: file}, gen("gen-pass"), gen("gen-secret"), fakeHash)
		if err != nil {
			t.Fatal(err)
		}
		return rc
	}
	merge := func(file, save map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range file {
			out[k] = v
		}
		for k, v := range save {
			out[k] = v
		}
		return out
	}
	first := run(map[string]string{}, "p1")
	if first.SessionEpoch != 0 || first.Save == nil || first.Save["session_check"] == "" {
		t.Fatalf("first run: %+v", first)
	}
	file := merge(map[string]string{}, first.Save)
	again := run(file, "p1")
	if again.SessionEpoch != 0 || again.Save != nil || again.SessionsReset {
		t.Fatalf("same password restarted: epoch=%d save=%v", again.SessionEpoch, again.Save)
	}
	changed := run(file, "p2")
	if changed.SessionEpoch != 1 || !changed.SessionsReset || changed.Save == nil {
		t.Fatalf("password change: epoch=%d reset=%v", changed.SessionEpoch, changed.SessionsReset)
	}
	if bcrypt.CompareHashAndPassword([]byte(changed.Save["session_check"]), []byte("p2")) != nil {
		t.Fatal("session check not updated")
	}
	// Generated password, then reused from the file: same session.
	gen1 := run(map[string]string{}, "")
	fromFile := run(merge(map[string]string{}, gen1.Save), "")
	if fromFile.SessionEpoch != gen1.SessionEpoch || fromFile.Save != nil {
		t.Fatalf("generated then file: %d vs %d save=%v", gen1.SessionEpoch, fromFile.SessionEpoch, fromFile.Save)
	}
}

// A legacy plaintext password is moved out even when this run's password
// comes from a flag.
func TestPlaintextMigratedEvenWithFlagPassword(t *testing.T) {
	rc, err := resolveCredentials(credentialInputs{FlagPass: "flagpw", FlagPassSet: true,
		File: map[string]string{"username": "u", "password": "legacy", "secret": "s"}}, gen("x"), gen("y"), fakeHash)
	if err != nil {
		t.Fatal(err)
	}
	if !rc.MigratedPlaintext || rc.Save == nil || rc.Password != "flagpw" {
		t.Fatalf("rc = %+v", rc)
	}
	if _, ok := rc.Save["password"]; ok {
		t.Fatal("plaintext password kept")
	}
	if bcrypt.CompareHashAndPassword([]byte(rc.Save["password_hash"]), []byte("legacy")) != nil {
		t.Fatal("legacy password not preserved as a hash")
	}
}

func TestResolveCredentialsMigratesPlaintext(t *testing.T) {
	rc, err := resolveCredentials(credentialInputs{File: map[string]string{"username": "u", "password": "legacy", "secret": "s"}},
		gen("x"), gen("y"), fakeHash)
	if err != nil {
		t.Fatal(err)
	}
	if !rc.MigratedPlaintext || rc.Save == nil || rc.Password != "" {
		t.Fatalf("rc = %+v", rc)
	}
	if bcrypt.CompareHashAndPassword([]byte(rc.PasswordHash), []byte("legacy")) != nil {
		t.Fatal("legacy password no longer verifies")
	}
	if rc.Save["username"] != "u" || rc.Save["secret"] != "s" {
		t.Fatalf("save = %v", rc.Save)
	}
}

func TestSaveAndLoadWebUIConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "webui.conf")
	h := mustHash(t, "p")
	if err := saveWebUIConfig(path, map[string]string{"username": "u", "password_hash": h, "secret": "s"}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", st.Mode().Perm())
	}
	got, err := loadWebUIConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["username"] != "u" || got["password_hash"] != h || got["secret"] != "s" || got["password"] != "" {
		t.Fatalf("round trip = %v", got)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1": true, "::1": true, "[::1]": true, "localhost": true, "0.0.0.0": false, "192.168.1.2": false} {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
}
