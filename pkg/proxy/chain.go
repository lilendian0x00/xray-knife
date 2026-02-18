package proxy

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/lilendian0x00/xray-knife/v9/pkg/core"
	"github.com/lilendian0x00/xray-knife/v9/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v9/utils"
)

// resolveFixedChain parses a fixed chain from either pipe-separated links
// or a file with one link per line.
func resolveFixedChain(c core.Core, chainLinks string, chainFile string) ([]protocol.Protocol, error) {
	var links []string

	if chainLinks != "" {
		links = strings.Split(chainLinks, "|")
	} else if chainFile != "" {
		links = utils.ParseFileByNewline(chainFile)
	} else {
		return nil, fmt.Errorf("no chain links or chain file specified")
	}

	if len(links) < 2 {
		return nil, fmt.Errorf("chain requires at least 2 hops, got %d", len(links))
	}

	hops := make([]protocol.Protocol, 0, len(links))
	for i, link := range links {
		link = strings.TrimSpace(link)
		if link == "" {
			continue
		}
		p, err := c.CreateProtocol(link)
		if err != nil {
			return nil, fmt.Errorf("chain hop %d: failed to create protocol from link: %w", i, err)
		}
		if err := p.Parse(); err != nil {
			return nil, fmt.Errorf("chain hop %d: failed to parse protocol: %w", i, err)
		}
		hops = append(hops, p)
	}

	if len(hops) < 2 {
		return nil, fmt.Errorf("chain requires at least 2 valid hops after parsing, got %d", len(hops))
	}

	return hops, nil
}

// selectChainFromPool randomly selects numHops distinct configs from pool
// and parses them into protocols.
func selectChainFromPool(c core.Core, pool []string, numHops int) ([]protocol.Protocol, error) {
	if numHops < 2 {
		return nil, fmt.Errorf("chain requires at least 2 hops, got %d", numHops)
	}
	if len(pool) < numHops {
		return nil, fmt.Errorf("pool has %d configs but chain requires %d hops", len(pool), numHops)
	}

	// Fisher-Yates shuffle to select numHops distinct indices.
	indices := make([]int, len(pool))
	for i := range indices {
		indices[i] = i
	}
	rand.Shuffle(len(indices), func(i, j int) { indices[i], indices[j] = indices[j], indices[i] })

	hops := make([]protocol.Protocol, 0, numHops)
	for _, idx := range indices[:numHops] {
		link := strings.TrimSpace(pool[idx])
		if link == "" {
			continue
		}
		p, err := c.CreateProtocol(link)
		if err != nil {
			continue // skip unparseable links
		}
		if err := p.Parse(); err != nil {
			continue
		}
		hops = append(hops, p)
	}

	if len(hops) < 2 {
		return nil, fmt.Errorf("could not build a chain of %d hops from pool (only %d valid)", numHops, len(hops))
	}

	return hops, nil
}

// selectExitHopFromPool keeps fixedHops[0..N-2] and selects a new exit hop
// from the pool, excluding the links already used in fixedHops.
func selectExitHopFromPool(c core.Core, pool []string, fixedHops []protocol.Protocol, excludeLink string) ([]protocol.Protocol, error) {
	if len(fixedHops) < 1 {
		return nil, fmt.Errorf("fixedHops must have at least 1 hop for exit rotation")
	}

	// Build set of links already used.
	usedLinks := make(map[string]bool)
	for _, hop := range fixedHops {
		usedLinks[hop.GetLink()] = true
	}
	if excludeLink != "" {
		usedLinks[excludeLink] = true
	}

	// Filter pool to candidates not already in use.
	var candidates []string
	for _, link := range pool {
		link = strings.TrimSpace(link)
		if link != "" && !usedLinks[link] {
			candidates = append(candidates, link)
		}
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no available exit hop candidates in pool")
	}

	// Shuffle and try to parse one.
	rand.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })

	for _, link := range candidates {
		p, err := c.CreateProtocol(link)
		if err != nil {
			continue
		}
		if err := p.Parse(); err != nil {
			continue
		}
		// Build new chain: fixedHops + new exit hop.
		result := make([]protocol.Protocol, len(fixedHops), len(fixedHops)+1)
		copy(result, fixedHops)
		result = append(result, p)
		return result, nil
	}

	return nil, fmt.Errorf("could not find a valid exit hop from %d candidates", len(candidates))
}
