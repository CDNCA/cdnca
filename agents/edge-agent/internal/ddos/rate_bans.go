package ddos

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

// Kernel rate bans: a rule over a new connection rate adds the client to a
// ban set in the kernel itself (RateBanSeconds), with no callback to the
// agent. RateBanWatch finds them by listing the ban sets and reporting what
// is new (F4), bounded per step and deduplicated by the ban's
// end.

const (
	// MaxTrackedBans bounds the bans Ban remembers and the bans the watch
	// has reported (the ban sets hold setSize each).
	MaxTrackedBans = 65536
	// MaxRateBanReports bounds the individual reports of one step; the rest
	// are counted in one summary call (client invalid).
	MaxRateBanReports = 256
	// RateBanInterval is the watch's listing interval.
	RateBanInterval = 10 * time.Second
	// rebanMargin: a ban ending this much later than the reported one is a
	// new ban (the kernel never extends an element, so only after expiry).
	rebanMargin = 2 * time.Second
)

// RateBan is one ban set element the agent did not write.
type RateBan struct {
	Client    netip.Addr // IPv4 address or IPv6 /64 network address
	Remaining time.Duration
}

// rememberOwn records bans Ban wrote (caller holds the lock).
func (manager *Manager) rememberOwn(clients []netip.Addr, until time.Time) {
	if manager.own == nil {
		manager.own = map[netip.Addr]time.Time{}
	}
	if len(manager.own)+len(clients) > MaxTrackedBans {
		now := time.Now()
		for client, end := range manager.own {
			if !end.After(now) {
				delete(manager.own, client)
			}
		}
	}
	for _, client := range clients {
		if len(manager.own) >= MaxTrackedBans {
			return // reported as a rate ban later: a label error, never a lost ban
		}
		if until.After(manager.own[client]) {
			manager.own[client] = until
		}
	}
}

// RateBans lists the ban sets without the bans Ban wrote (none without a
// table).
func (manager *Manager) RateBans(ctx context.Context) ([]RateBan, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.active == nil {
		return nil, nil
	}
	now := time.Now()
	var bans []RateBan
	for _, set := range []string{BanSetIPv4, BanSetIPv6} {
		output, err := manager.runner.Run(ctx, "--json", "list", "set", TableFamily, TableName, set)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", set, err)
		}
		elements, err := banElements(output)
		if err != nil {
			return nil, err
		}
		for _, element := range elements {
			if end, ok := manager.own[element.Client]; ok && end.After(now) {
				continue
			}
			bans = append(bans, element)
		}
	}
	return bans, nil
}

// banElements decodes `nft --json list set`: elements are an address string
// or {"elem": {"val": address, "timeout": s, "expires": s}}.
func banElements(output []byte) ([]RateBan, error) {
	var listing struct {
		Objects []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set,omitempty"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &listing); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnhealthy, err)
	}
	var bans []RateBan
	for _, object := range listing.Objects {
		if object.Set == nil {
			continue
		}
		for _, raw := range object.Set.Elem {
			var value string
			var expires int64
			if json.Unmarshal(raw, &value) != nil {
				var wrapped struct {
					Elem struct {
						Val     string `json:"val"`
						Expires int64  `json:"expires"`
					} `json:"elem"`
				}
				if json.Unmarshal(raw, &wrapped) != nil {
					continue
				}
				value, expires = wrapped.Elem.Val, wrapped.Elem.Expires
			}
			client, err := netip.ParseAddr(value)
			if err != nil {
				continue
			}
			bans = append(bans, RateBan{Client: client, Remaining: time.Duration(expires) * time.Second})
		}
	}
	return bans, nil
}

// RateBanWatch reports the kernel's own rate bans.
type RateBanWatch struct {
	manager *Manager
	now     func() time.Time
	// OnBan is called for each new ban; OnBan(netip.Addr{}, n, 0) counts the
	// n new bans beyond MaxRateBanReports of one step.
	OnBan func(client netip.Addr, count int, remaining time.Duration)
	// reported: client -> end of the reported ban, while it is listed (at
	// most MaxTrackedBans).
	reported map[netip.Addr]time.Time
}

func NewRateBanWatch(manager *Manager, now func() time.Time) *RateBanWatch {
	return &RateBanWatch{manager: manager, now: now, reported: map[netip.Addr]time.Time{}}
}

// Run lists every RateBanInterval until ctx ends.
func (watch *RateBanWatch) Run(ctx context.Context) error {
	ticker := time.NewTicker(RateBanInterval)
	defer ticker.Stop()
	for {
		_ = watch.Step(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Step lists the ban sets once and reports the new bans.
func (watch *RateBanWatch) Step(ctx context.Context) error {
	bans, err := watch.manager.RateBans(ctx)
	if err != nil {
		return err
	}
	now := watch.now()
	// A ban that left the sets is forgotten: listed again later, it is new.
	present := make(map[netip.Addr]bool, len(bans))
	for _, ban := range bans {
		present[ban.Client] = true
	}
	for client := range watch.reported {
		if !present[client] {
			delete(watch.reported, client)
		}
	}
	reports, beyond := 0, 0
	for _, ban := range bans {
		end := now.Add(ban.Remaining)
		if previous, ok := watch.reported[ban.Client]; ok && (ban.Remaining == 0 || !end.After(previous.Add(rebanMargin))) {
			continue
		}
		if _, ok := watch.reported[ban.Client]; !ok && len(watch.reported) >= MaxTrackedBans {
			beyond++
			continue
		}
		watch.reported[ban.Client] = end
		if reports >= MaxRateBanReports {
			beyond++
			continue
		}
		reports++
		if watch.OnBan != nil {
			watch.OnBan(ban.Client, 1, ban.Remaining)
		}
	}
	if beyond > 0 && watch.OnBan != nil {
		watch.OnBan(netip.Addr{}, beyond, 0)
	}
	return nil
}
