package hosttun

// ruleBlock is how many consecutive rule priorities sing-tun may use:
// its teardown deletes every rule in [RuleIndex, RuleIndex+10].
const ruleBlock = 11

// Rule priorities we pick from. sing-box/mihomo default to 9000, and the
// kernel's own main/default rules sit at 32766/32767.
const (
	ruleSearchStart = 9100
	ruleSearchEnd   = 32000
	ruleSearchStep  = 20
)

// freeRuleBlock returns the first priority p in the search window such
// that none of p..p+ruleBlock is in use, or 0 if there is none. p itself
// holds the bypass rules; sing-tun gets p+1..p+ruleBlock.
func freeRuleBlock(used map[int]bool) int {
	for start := ruleSearchStart; start+ruleBlock+1 <= ruleSearchEnd; start += ruleSearchStep {
		free := true
		for p := start; p <= start+ruleBlock; p++ {
			if used[p] {
				free = false
				break
			}
		}
		if free {
			return start
		}
	}
	return 0
}
