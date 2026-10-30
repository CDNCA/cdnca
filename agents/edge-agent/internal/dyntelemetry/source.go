package dyntelemetry

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

// DefaultGrace is how long a line naming an unknown generation or a site
// object not yet readable waits before it is quarantined: the activation
// registers a generation before it stages it and writes objects first, so
// a wait only happens on an agent restart or a lost registry.
const DefaultGrace = 30 * time.Second

const maxWaiting = 64

// Resolver is eventspool.TailConfig.Resolve for the node-level logs.
type Resolver struct {
	Registry *Registry
	Sites    SiteResolver
	NodeID   string
	Grace    time.Duration // 0 = DefaultGrace
	Now      func() time.Time

	mu      sync.Mutex
	waiting map[string]time.Time // line digest -> first seen unattributed
	counts  Counts
}

// Counts are the resolver's outcomes since start.
type Counts struct {
	Attributed, Waiting, Unattributed, Invalid uint64
	// L2Hops: lines of L1 hops skipped (ErrL2Hop, fix-l2trust)
	L2Hops uint64
}

func (resolver *Resolver) Counts() Counts {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.counts
}

// Resolve binds one line. A line that cannot be attributed yet makes the
// tail stop before it (eventspool.ErrLineNotReady) until the grace period
// ends; then it is quarantined like an invalid line.
func (resolver *Resolver) Resolve(line []byte) (eventspool.ResolvedLine, error) {
	result, err := Normalize(line, resolver.Registry, resolver.Sites, resolver.NodeID)
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.waiting == nil {
		resolver.waiting = map[string]time.Time{}
	}
	key := string(line)
	switch {
	case err == nil:
		delete(resolver.waiting, key)
		resolver.counts.Attributed++
		return eventspool.ResolvedLine{Line: result.Line, Identity: result.Identity, CapturePolicy: result.CapturePolicy}, nil
	case errors.Is(err, ErrL2Hop):
		delete(resolver.waiting, key)
		resolver.counts.L2Hops++
		return eventspool.ResolvedLine{}, eventspool.ErrLineSkipped
	case errors.Is(err, ErrUnattributed):
		now := time.Now
		if resolver.Now != nil {
			now = resolver.Now
		}
		grace := resolver.Grace
		if grace <= 0 {
			grace = DefaultGrace
		}
		first, seen := resolver.waiting[key]
		if !seen {
			// A source waits on one line at a time (its tail stops there),
			// so the map holds about one entry per source sharing the
			// resolver; the bound only guards against misuse.
			if len(resolver.waiting) >= maxWaiting {
				resolver.waiting = map[string]time.Time{}
			}
			resolver.waiting[key] = now()
			resolver.counts.Waiting++
			return eventspool.ResolvedLine{}, eventspool.ErrLineNotReady
		}
		if now().Sub(first) < grace {
			return eventspool.ResolvedLine{}, eventspool.ErrLineNotReady
		}
		delete(resolver.waiting, key)
		resolver.counts.Unattributed++
		// a valid line whose attribution history is gone: quarantined with
		// its own code (TAIL_ATTRIBUTION_MISSING), not as invalid JSON
		return eventspool.ResolvedLine{}, fmt.Errorf("%w: %v", eventspool.ErrLineUnattributable, err)
	default:
		resolver.counts.Invalid++
		return eventspool.ResolvedLine{}, err
	}
}
