package hosttun

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
)

// cleanupState removes the ip rules and routes a crashed host-tun left
// behind and describes what it removed. The TUN device itself is not
// touched: a non-persistent TUN disappears with the process that opened
// it, and one that exists under the recorded name belongs to someone
// else now.
func cleanupState(s *State) ([]string, error) {
	var removed []string
	var errs []error
	lo := s.BypassPriority
	if lo <= 0 {
		lo = s.RuleIndex
	}
	hi := s.RuleIndex + ruleBlock - 1
	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		errs = append(errs, fmt.Errorf("list rules: %w", err))
	} else {
		n := 0
		for i := range rules {
			r := rules[i]
			if r.Priority < lo || r.Priority > hi {
				continue
			}
			if err := netlink.RuleDel(&r); err != nil {
				errs = append(errs, fmt.Errorf("delete rule %d: %w", r.Priority, err))
				continue
			}
			n++
		}
		if n > 0 {
			removed = append(removed, fmt.Sprintf("%d ip rules (priority %d-%d)", n, lo, hi))
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: s.TableIndex}, netlink.RT_FILTER_TABLE)
	if err != nil {
		errs = append(errs, fmt.Errorf("list routes of table %d: %w", s.TableIndex, err))
	} else if len(routes) > 0 {
		for i := range routes {
			if err := netlink.RouteDel(&routes[i]); err != nil {
				errs = append(errs, fmt.Errorf("delete route: %w", err))
			}
		}
		removed = append(removed, fmt.Sprintf("%d routes in table %d", len(routes), s.TableIndex))
	}
	return removed, errors.Join(errs...)
}
