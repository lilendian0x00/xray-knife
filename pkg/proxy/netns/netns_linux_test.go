package netns

import (
	"slices"
	"strings"
	"testing"
)

func TestPasswdEntry(t *testing.T) {
	passwd := []byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/usr/bin/zsh\n")
	home, shell := passwdEntry(passwd, 1000)
	if home != "/home/alice" || shell != "/usr/bin/zsh" {
		t.Fatalf("home=%q shell=%q", home, shell)
	}
	if home, _ := passwdEntry(passwd, 4242); home != "" {
		t.Fatalf("unknown uid: %q", home)
	}
}

func TestUserEnv(t *testing.T) {
	env := userEnv([]string{"PATH=/bin", "HOME=/root", "USER=root", "LOGNAME=root"}, &Credential{Username: "alice", Home: "/home/alice"})
	want := []string{"PATH=/bin", "HOME=/home/alice", "USER=alice", "LOGNAME=alice"}
	if !slices.Equal(env, want) {
		t.Fatalf("env = %v", env)
	}
}

func TestNamespaceNSSwitch(t *testing.T) {
	host := "passwd:         files systemd\ngroup:          files systemd\nhosts:          files mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns myhostname\nnetworks:       files\n"
	got := namespaceNSSwitch(host)
	if !strings.Contains(got, "hosts: files dns\n") || strings.Contains(got, "resolve") || !strings.Contains(got, "passwd:         files systemd") {
		t.Fatalf("nsswitch:\n%s", got)
	}
	if got := namespaceNSSwitch(""); !strings.Contains(got, "hosts: files dns") {
		t.Fatalf("empty host file: %q", got)
	}
}
