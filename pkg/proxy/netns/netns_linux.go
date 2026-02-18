//go:build linux

package netns

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// Namespace represents a configured network namespace with a veth pair
// connecting it to the host.
type Namespace struct {
	config Config
	name   string
}

// Setup creates a named network namespace, a veth pair between host and
// namespace, assigns IPs, brings up interfaces, and sets the default
// route inside the namespace to point at the host veth end.
func Setup(cfg Config) (*Namespace, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the host namespace so we can return to it.
	hostNS, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get host namespace: %w", err)
	}
	defer hostNS.Close()

	// Create a new named namespace. This also switches the current
	// OS thread into the new namespace.
	nsHandle, err := netns.NewNamed(cfg.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to create namespace %q: %w", cfg.Name, err)
	}
	defer nsHandle.Close()

	// Bring up loopback inside the new namespace.
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		netns.Set(hostNS)
		netns.DeleteNamed(cfg.Name)
		return nil, fmt.Errorf("failed to find lo in namespace: %w", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		netns.Set(hostNS)
		netns.DeleteNamed(cfg.Name)
		return nil, fmt.Errorf("failed to bring up lo: %w", err)
	}

	// Switch back to host to create the veth pair.
	if err := netns.Set(hostNS); err != nil {
		netns.DeleteNamed(cfg.Name)
		return nil, fmt.Errorf("failed to return to host namespace: %w", err)
	}

	// Create veth pair on the host.
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: cfg.VethHost},
		PeerName:  cfg.VethNS,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		netns.DeleteNamed(cfg.Name)
		return nil, fmt.Errorf("failed to create veth pair: %w", err)
	}

	// Helper to tear down on error.
	cleanup := func() {
		netlink.LinkDel(veth)
		netns.DeleteNamed(cfg.Name)
	}

	// Configure the host side of the veth.
	hostLink, err := netlink.LinkByName(cfg.VethHost)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to find host veth %q: %w", cfg.VethHost, err)
	}
	hostAddr, err := netlink.ParseAddr(cfg.HostIP + cfg.Subnet)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to parse host address: %w", err)
	}
	if err := netlink.AddrAdd(hostLink, hostAddr); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to add address to host veth: %w", err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to bring up host veth: %w", err)
	}

	// Move the peer end into the namespace.
	peerLink, err := netlink.LinkByName(cfg.VethNS)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to find peer veth %q: %w", cfg.VethNS, err)
	}
	if err := netlink.LinkSetNsFd(peerLink, int(nsHandle)); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to move veth to namespace: %w", err)
	}

	// Enter the namespace to configure the peer side.
	if err := netns.Set(nsHandle); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to enter namespace for veth config: %w", err)
	}

	nsLink, err := netlink.LinkByName(cfg.VethNS)
	if err != nil {
		netns.Set(hostNS)
		cleanup()
		return nil, fmt.Errorf("failed to find veth inside namespace: %w", err)
	}
	nsAddr, err := netlink.ParseAddr(cfg.NSIP + cfg.Subnet)
	if err != nil {
		netns.Set(hostNS)
		cleanup()
		return nil, fmt.Errorf("failed to parse namespace address: %w", err)
	}
	if err := netlink.AddrAdd(nsLink, nsAddr); err != nil {
		netns.Set(hostNS)
		cleanup()
		return nil, fmt.Errorf("failed to add address to namespace veth: %w", err)
	}
	if err := netlink.LinkSetUp(nsLink); err != nil {
		netns.Set(hostNS)
		cleanup()
		return nil, fmt.Errorf("failed to bring up namespace veth: %w", err)
	}

	// Default route inside the namespace via the host veth IP.
	gw := net.ParseIP(cfg.HostIP)
	if gw == nil {
		netns.Set(hostNS)
		cleanup()
		return nil, fmt.Errorf("failed to parse gateway IP %q", cfg.HostIP)
	}
	if err := netlink.RouteAdd(&netlink.Route{Gw: gw}); err != nil {
		netns.Set(hostNS)
		cleanup()
		return nil, fmt.Errorf("failed to add default route in namespace: %w", err)
	}

	// Return to host namespace.
	if err := netns.Set(hostNS); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to return to host namespace after setup: %w", err)
	}

	return &Namespace{config: cfg, name: cfg.Name}, nil
}

// Close tears down the veth pair and deletes the namespace.
func (n *Namespace) Close() error {
	CleanupVeth(n.config.VethHost)
	CleanupNamespace(n.name)
	return nil
}

// Shell launches the user's default shell inside the namespace.
// It blocks until the shell exits.
func (n *Namespace) Shell(ctx context.Context) error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	return n.Run(ctx, []string{shell})
}

// Run executes a command inside the namespace using nsenter.
func (n *Namespace) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}
	nsPath := fmt.Sprintf("/var/run/netns/%s", n.name)
	nsenterArgs := append([]string{"--net=" + nsPath, "--"}, args...)
	cmd := exec.CommandContext(ctx, "nsenter", nsenterArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// CleanupNamespace deletes a named network namespace.
func CleanupNamespace(name string) {
	if name == "" {
		return
	}
	netns.DeleteNamed(name)
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
	netlink.LinkDel(link)
}

// RecoverFromCrash checks for a stale state file left by a previous
// unclean exit and cleans up the orphaned namespace and veth.
func RecoverFromCrash() {
	state, err := LoadState()
	if err != nil || state == nil {
		return
	}
	CleanupVeth(state.VethHost)
	CleanupNamespace(state.Name)
	ClearState()
}
