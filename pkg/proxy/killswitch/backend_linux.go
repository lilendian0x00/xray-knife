package killswitch

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func pickBackend(id string) (backend, error) {
	if _, err := exec.LookPath("nft"); err == nil {
		if _, err := run("", "nft", "list", "tables"); err == nil {
			return &nftBackend{table: nftTable(id)}, nil
		}
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		if _, err := exec.LookPath("ip6tables"); err != nil {
			return nil, errors.New("kill switch: iptables found but ip6tables missing; refusing to leave IPv6 unfiltered")
		}
		return &iptablesBackend{chain: iptablesChain(id)}, nil
	}
	return nil, errors.New("kill switch needs nftables (nft) or iptables/ip6tables")
}

func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

// Leftovers lists the kill switches currently installed on the system.
func Leftovers() ([]Leftover, error) {
	var found []Leftover
	var errs []string
	if _, err := exec.LookPath("nft"); err == nil {
		out, err := run("", "nft", "list", "tables")
		if err != nil {
			errs = append(errs, "nft list tables: "+strings.TrimSpace(string(out)))
		}
		found = append(found, parseNftTables(string(out))...)
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		for _, tool := range []string{"iptables", "ip6tables"} {
			out, err := run("", tool, "-w", "-S")
			if err != nil {
				errs = append(errs, tool+" -S: "+strings.TrimSpace(string(out)))
				continue
			}
			found = append(found, parseIptablesChains(string(out))...)
		}
	}
	found = dedupLeftovers(found)
	if len(errs) > 0 {
		return found, errors.New(strings.Join(errs, "; "))
	}
	return found, nil
}

// RemoveStale removes kill switches whose owning process is gone (all of
// them with force). It returns what it removed and what it left because
// the owner is still running.
func RemoveStale(force bool) (removed, kept []Leftover, err error) {
	left, lerr := Leftovers()
	var errs []string
	if lerr != nil {
		errs = append(errs, lerr.Error())
	}
	for _, l := range left {
		if !force && ownerAlive(l.ID) {
			kept = append(kept, l)
			continue
		}
		var b backend
		if l.Backend == "nftables" {
			b = &nftBackend{table: nftPrefix + l.ID}
		} else {
			b = &iptablesBackend{chain: iptablesPrefix + l.ID}
		}
		if rerr := b.remove(); rerr != nil {
			errs = append(errs, rerr.Error())
			continue
		}
		removed = append(removed, l)
	}
	if len(errs) > 0 {
		err = errors.New(strings.Join(errs, "; "))
	}
	return removed, kept, err
}
