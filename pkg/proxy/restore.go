package proxy

import (
	"fmt"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/hosttun"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/killswitch"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/netns"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/sysproxy"
)

// RestoreReport lists what Restore removed, what it left alone because
// its owner is still running, and what failed.
type RestoreReport struct {
	Removed []string
	Kept    []string
	Errors  []string
}

// Empty reports whether nothing was found.
func (r RestoreReport) Empty() bool {
	return len(r.Removed) == 0 && len(r.Kept) == 0 && len(r.Errors) == 0
}

// Restore removes what crashed proxy runs left behind: kill-switch rules,
// host-tun rules/routes, network namespaces and changed OS proxy
// settings. Resources whose owning process is still running are kept
// unless force is set (kill switch and system proxy only; a live
// namespace or TUN is never torn down from outside). Running it again
// finds nothing more to do.
func Restore(force bool) RestoreReport {
	var r RestoreReport

	// Kill switch first: it is what blocks the network.
	removed, kept, err := killswitch.RemoveStale(force)
	for _, l := range removed {
		r.Removed = append(r.Removed, "kill switch "+l.String())
	}
	for _, l := range kept {
		r.Kept = append(r.Kept, fmt.Sprintf("kill switch %s (pid %s still running; use --force)", l.String(), l.ID))
	}
	if err != nil {
		r.Errors = append(r.Errors, "kill switch: "+err.Error())
	}

	recovered, alive, bad := hosttun.RecoverFromCrash()
	for _, rec := range recovered {
		what := "state only"
		if len(rec.Removed) > 0 {
			what = strings.Join(rec.Removed, ", ")
		}
		if rec.Err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("tun leftovers of pid %d (state kept for a retry): %v", rec.Pid, rec.Err))
			continue
		}
		r.Removed = append(r.Removed, fmt.Sprintf("tun leftovers of pid %d: %s", rec.Pid, what))
	}
	for _, pid := range alive {
		r.Kept = append(r.Kept, fmt.Sprintf("tun of pid %d (still running)", pid))
	}
	for _, b := range bad {
		r.Kept = append(r.Kept, "ignored invalid state file "+b)
	}

	for _, name := range netns.RecoverFromCrash() {
		r.Removed = append(r.Removed, "network namespace "+name)
	}

	stale, err := sysproxy.LoadState()
	switch {
	case err != nil:
		r.Errors = append(r.Errors, "system proxy state: "+err.Error())
	case stale == nil:
	case sysproxy.OwnerAlive(stale) && !force:
		r.Kept = append(r.Kept, fmt.Sprintf("system proxy settings (pid %d still running; use --force)", stale.Owner.Pid))
	default:
		mgr, err := sysproxy.New()
		if err == nil {
			err = mgr.Restore(stale)
		}
		if err != nil {
			r.Errors = append(r.Errors, "system proxy: "+err.Error())
			break
		}
		if err := sysproxy.ClearState(); err != nil {
			r.Errors = append(r.Errors, "system proxy state: "+err.Error())
		}
		r.Removed = append(r.Removed, "system proxy settings (restored the previous configuration)")
	}
	return r
}
