//go:build linux

package netns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// Namespace represents a configured network namespace holding only
// loopback (the TUN is added later by StartTunnel).
type Namespace struct {
	config Config
	name   string
	// resolvDir is the /etc/netns/<name> directory we created (empty
	// when it pre-existed); files are the overlay files we wrote there.
	resolvDir string
	files     []string
}

// onFreshThread runs fn on a dedicated goroutine locked to its OS thread.
// The goroutine exits without unlocking, so the Go runtime terminates the
// thread instead of returning one whose network namespace fn changed to
// the scheduler's pool.
func onFreshThread[T any](fn func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		v, err := fn()
		ch <- result{v, err}
	}()
	r := <-ch
	return r.v, r.err
}

// Setup creates a named network namespace, brings up its loopback and
// writes /etc/netns/<name>/resolv.conf so programs started with
// `ip netns exec` (and Run/Shell) resolve through the tunnel instead of
// the host's 127.0.0.53 stub, which does not exist inside the namespace.
func Setup(cfg Config) (*Namespace, error) {
	if err := ValidateName(cfg.Name); err != nil {
		return nil, err
	}
	resolver, err := cfg.resolverAddr()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(netnsRunDir, cfg.Name)); err == nil {
		return nil, fmt.Errorf("namespace %q already exists; pick another --namespace or remove it with 'ip netns del %s'", cfg.Name, cfg.Name)
	}

	created := false
	_, err = onFreshThread(func() (struct{}, error) {
		// NewNamed also moves this thread into the new namespace.
		nsHandle, err := netns.NewNamed(cfg.Name)
		if err != nil {
			return struct{}{}, fmt.Errorf("failed to create namespace %q: %w", cfg.Name, err)
		}
		created = true
		defer nsHandle.Close()

		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return struct{}{}, fmt.Errorf("failed to find lo in namespace: %w", err)
		}
		if err := netlink.LinkSetUp(lo); err != nil {
			return struct{}{}, fmt.Errorf("failed to bring up lo: %w", err)
		}
		return struct{}{}, nil
	})
	if err != nil {
		if created {
			_ = CleanupNamespace(cfg.Name)
		}
		return nil, err
	}

	n := &Namespace{config: cfg, name: cfg.Name}
	if err := n.writeResolvConf(resolver); err != nil {
		n.Close()
		return nil, err
	}
	return n, nil
}

// overlayFiles are written to /etc/netns/<name>/, which `ip netns exec`
// bind-mounts over /etc inside the namespace:
//
//   - resolv.conf points at the tunnel's DNS instead of the host stub
//     (127.0.0.53 does not exist inside the namespace);
//   - nsswitch.conf resolves hosts with plain DNS, so nss-resolve (which
//     talks to the host's systemd-resolved over D-Bus) cannot answer from
//     outside the tunnel. A running nscd is still consulted by glibc
//     before NSS; stop it or disable its hosts cache for full coverage.
func (n *Namespace) writeResolvConf(resolver string) error {
	dir := filepath.Join(netnsEtcDir, n.name)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir, err)
		}
		n.resolvDir = dir
	}
	hostNSS, _ := os.ReadFile("/etc/nsswitch.conf")
	for _, f := range []struct{ name, content string }{
		{"resolv.conf", "# Written by xray-knife: queries are hijacked by the tunnel's DNS.\nnameserver " + resolver + "\n"},
		{"nsswitch.conf", namespaceNSSwitch(string(hostNSS))},
	} {
		file := filepath.Join(dir, f.name)
		if _, err := os.Lstat(file); err == nil {
			// The user already configured this namespace; respect it.
			continue
		}
		if err := os.WriteFile(file, []byte(f.content), 0o644); err != nil {
			return fmt.Errorf("failed to write %s: %w", file, err)
		}
		n.files = append(n.files, file)
	}
	return nil
}

// namespaceNSSwitch is the host's nsswitch.conf with the hosts line
// replaced by "files dns" (other databases unchanged, so user and group
// lookups keep working in the namespace shell).
func namespaceNSSwitch(host string) string {
	var b strings.Builder
	b.WriteString("# Written by xray-knife: host lookups use the namespace's DNS only.\n")
	replaced := false
	for _, line := range strings.Split(host, "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == "hosts:" {
			if !replaced {
				b.WriteString("hosts: files dns\n")
				replaced = true
			}
			continue
		}
		if line != "" {
			b.WriteString(line + "\n")
		}
	}
	if !replaced {
		b.WriteString("hosts: files dns\n")
	}
	return b.String()
}

// Name returns the namespace name.
func (n *Namespace) Name() string { return n.name }

// ResolvDir returns the /etc/netns/<name> directory Setup created, or ""
// when it already existed.
func (n *Namespace) ResolvDir() string { return n.resolvDir }

// Close deletes the namespace and the overlay files Setup created.
func (n *Namespace) Close() error {
	err := CleanupNamespace(n.name)
	for _, f := range n.files {
		_ = os.Remove(f)
	}
	if n.resolvDir != "" {
		_ = os.Remove(n.resolvDir) // only succeeds when empty
	}
	return err
}

// Credential is the user a command inside the namespace runs as.
type Credential struct {
	Uid, Gid              uint32
	Username, Home, Shell string
}

// SudoCredential returns the invoking user's identity when this process
// runs as root through sudo, or nil otherwise.
func SudoCredential() *Credential {
	if os.Geteuid() != 0 {
		return nil
	}
	uid, err1 := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	gid, err2 := strconv.ParseUint(os.Getenv("SUDO_GID"), 10, 32)
	if err1 != nil || err2 != nil || uid == 0 {
		return nil
	}
	c := &Credential{Uid: uint32(uid), Gid: uint32(gid), Username: os.Getenv("SUDO_USER")}
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		c.Home, c.Shell = passwdEntry(data, uint32(uid))
	}
	return c
}

// passwdEntry returns the home directory and login shell of uid.
func passwdEntry(passwd []byte, uid uint32) (home, shell string) {
	want := strconv.FormatUint(uint64(uid), 10)
	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 7 && f[2] == want {
			return f[5], f[6]
		}
	}
	return "", ""
}

// Command builds the command that runs args inside the named namespace.
// It prefers `ip netns exec`, which also bind-mounts /etc/netns/<name>/*
// (our resolv.conf) in a private mount namespace; nsenter is the
// fallback. When cred is non-nil the command drops to that user with
// setpriv(1). The returned warning is non-empty when a requested
// privilege drop or the resolv.conf overlay could not be applied.
func Command(ctx context.Context, name string, args []string, cred *Credential) (*exec.Cmd, string, error) {
	if err := ValidateName(name); err != nil {
		return nil, "", err
	}
	if len(args) == 0 {
		return nil, "", errors.New("no command specified")
	}
	var argv []string
	var warn string
	if ip, err := exec.LookPath("ip"); err == nil {
		argv = []string{ip, "netns", "exec", name}
	} else if nsenter, err := exec.LookPath("nsenter"); err == nil {
		argv = []string{nsenter, "--net=" + filepath.Join(netnsRunDir, name), "--"}
		warn = "iproute2 'ip' not found: running via nsenter, so /etc/netns/" + name + "/resolv.conf is not applied and DNS may not resolve"
	} else {
		return nil, "", errors.New("neither 'ip' (iproute2) nor 'nsenter' (util-linux) found in PATH")
	}

	env := os.Environ()
	if cred != nil {
		if setpriv, err := exec.LookPath("setpriv"); err == nil {
			argv = append(argv, setpriv,
				"--reuid="+strconv.FormatUint(uint64(cred.Uid), 10),
				"--regid="+strconv.FormatUint(uint64(cred.Gid), 10),
				"--init-groups", "--")
			env = userEnv(env, cred)
		} else {
			warn = joinWarn(warn, "setpriv (util-linux) not found: the command runs as root")
		}
	}
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, warn, nil
}

func joinWarn(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// userEnv rewrites the identity variables sudo leaves pointing at root.
func userEnv(env []string, cred *Credential) []string {
	out := make([]string, 0, len(env)+3)
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "HOME", "USER", "LOGNAME", "MAIL":
			continue
		}
		out = append(out, kv)
	}
	if cred.Home != "" {
		out = append(out, "HOME="+cred.Home)
	}
	if cred.Username != "" {
		out = append(out, "USER="+cred.Username, "LOGNAME="+cred.Username)
	}
	return out
}

// Shell launches an interactive shell inside the namespace, as cred when
// non-nil. It blocks until the shell exits. warn reports a privilege drop
// or DNS overlay that could not be applied.
func (n *Namespace) Shell(ctx context.Context, cred *Credential, warn func(string)) error {
	shell := os.Getenv("SHELL")
	if cred != nil && cred.Shell != "" {
		shell = cred.Shell
	}
	if shell == "" {
		shell = "/bin/sh"
	}
	return n.Run(ctx, []string{shell}, cred, warn)
}

// Run executes a command inside the namespace, as cred when non-nil.
func (n *Namespace) Run(ctx context.Context, args []string, cred *Credential, warn func(string)) error {
	cmd, w, err := Command(ctx, n.name, args, cred)
	if err != nil {
		return err
	}
	if w != "" && warn != nil {
		warn(w)
	}
	return cmd.Run()
}

// WaitForLinkGone blocks (up to timeout) until the given interface name is
// no longer present inside the namespace. Used to make sure the TUN device
// has been fully torn down before deleting the namespace, avoiding
// "device busy" / leftover-link warnings from the kernel.
func (n *Namespace) WaitForLinkGone(ifname string, timeout time.Duration) {
	if ifname == "" {
		return
	}
	_, _ = onFreshThread(func() (struct{}, error) {
		targetNS, err := netns.GetFromPath(filepath.Join(netnsRunDir, n.name))
		if err != nil {
			return struct{}{}, err
		}
		defer targetNS.Close()
		if err := netns.Set(targetNS); err != nil {
			return struct{}{}, err
		}
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if _, err := netlink.LinkByName(ifname); err != nil {
				return struct{}{}, nil // gone
			}
			time.Sleep(50 * time.Millisecond)
		}
		return struct{}{}, nil
	})
}

// CleanupNamespace deletes a named network namespace. A namespace that
// is already gone is not an error.
func CleanupNamespace(name string) error {
	if name == "" || ValidateName(name) != nil {
		return nil
	}
	if _, err := os.Stat(filepath.Join(netnsRunDir, name)); os.IsNotExist(err) {
		return nil
	}
	return netns.DeleteNamed(name)
}

// CleanupVeth deletes a veth pair by the host-side name.
// Deleting one end automatically removes the peer.
func CleanupVeth(name string) {
	if name == "" {
		return
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return
	}
	// Never delete something that isn't a veth, whatever the state file
	// says.
	if link.Type() != "veth" {
		return
	}
	netlink.LinkDel(link)
}

// RecoverFromCrash cleans up namespaces left by previous unclean exits —
// but only those whose recorded owner is no longer running, so a second
// xray-knife process never tears down resources owned by a live one.
// It returns the names of the namespaces it reclaimed. A state file is
// kept when its cleanup failed, so a later run can retry.
func RecoverFromCrash() []string {
	states, files, _, err := LoadStates()
	if err != nil {
		return nil
	}
	var reclaimed []string
	for i, state := range states {
		if stateOwnerAlive(state) {
			continue
		}
		CleanupVeth(state.VethHost)
		if err := CleanupNamespace(state.Name); err != nil {
			continue
		}
		if state.ResolvDir != "" {
			for _, f := range []string{"resolv.conf", "nsswitch.conf"} {
				_ = os.Remove(filepath.Join(state.ResolvDir, f))
			}
			_ = os.Remove(state.ResolvDir)
		}
		_ = os.Remove(files[i])
		reclaimed = append(reclaimed, state.Name)
	}
	return reclaimed
}
