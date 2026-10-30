package platformpolicy

import (
	"sync"
	"time"
)

const (
	DecisionAllowed            = "allowed"
	DecisionEntitlementDenied  = "entitlement_denied"
	DecisionPolicyStale        = "platform_policy_stale"
	DecisionChannelDenied      = "release_channel_denied"
	DecisionPluginMarketDenied = "plugin_market_denied"
	DecisionCatalogDenied      = "plugin_catalog_denied"
)

type Snapshot struct {
	Policy           Policy
	Source           string
	TargetRevisionID string
	ExpiresAt        time.Time
	Defaulted        bool
}

type Decision struct {
	Allowed bool
	Reason  string
	Source  string
	Stale   bool
}

type State struct {
	mu       sync.RWMutex
	now      func() time.Time
	snapshot Snapshot
}

func DefaultPolicy() Policy {
	return Policy{
		Schema: PolicySchema, MinimumControlVersion: "0.0.0",
		AllowedReleaseChannels: []string{"beta", "lts", "stable"},
		BlockedControlVersions: []string{},
		PluginMarket:           PluginMarket{Enabled: false, TrustedCatalogIDs: []string{}},
	}
}

func NewState(now func() time.Time) *State {
	if now == nil {
		now = time.Now
	}
	return &State{now: now, snapshot: Snapshot{Policy: DefaultPolicy(), Source: "default", Defaulted: true}}
}

func (state *State) Replace(snapshot Snapshot) error {
	if state == nil || validatePolicy(snapshot.Policy) != nil || snapshot.Source == "" ||
		(!snapshot.Defaulted && (snapshot.TargetRevisionID == "" || snapshot.ExpiresAt.IsZero())) {
		return ErrLocalValidation
	}
	snapshot.Policy = clonePolicy(snapshot.Policy)
	state.mu.Lock()
	state.snapshot = snapshot
	state.mu.Unlock()
	return nil
}

func (state *State) Snapshot() (Snapshot, bool) {
	if state == nil {
		return Snapshot{}, true
	}
	state.mu.RLock()
	snapshot := state.snapshot
	snapshot.Policy = clonePolicy(snapshot.Policy)
	state.mu.RUnlock()
	stale := !snapshot.Defaulted && !state.now().UTC().Before(snapshot.ExpiresAt.UTC())
	return snapshot, stale
}

func (state *State) ReleaseChannel(channel string, entitlementAllowed bool) Decision {
	snapshot, stale := state.Snapshot()
	if !entitlementAllowed {
		return denied(snapshot.Source, stale, DecisionEntitlementDenied)
	}
	if stale {
		return denied(snapshot.Source, true, DecisionPolicyStale)
	}
	for _, allowedChannel := range snapshot.Policy.AllowedReleaseChannels {
		if allowedChannel == channel {
			return allowed(snapshot.Source)
		}
	}
	return denied(snapshot.Source, false, DecisionChannelDenied)
}

func (state *State) PluginMarket(entitlementAllowed bool) Decision {
	snapshot, stale := state.Snapshot()
	if !entitlementAllowed {
		return denied(snapshot.Source, stale, DecisionEntitlementDenied)
	}
	if stale {
		return denied(snapshot.Source, true, DecisionPolicyStale)
	}
	if !snapshot.Policy.PluginMarket.Enabled {
		return denied(snapshot.Source, false, DecisionPluginMarketDenied)
	}
	return allowed(snapshot.Source)
}

func (state *State) TrustedCatalog(catalogID string, entitlementAllowed bool) Decision {
	snapshot, stale := state.Snapshot()
	if !entitlementAllowed {
		return denied(snapshot.Source, stale, DecisionEntitlementDenied)
	}
	if stale {
		return denied(snapshot.Source, true, DecisionPolicyStale)
	}
	if !snapshot.Policy.PluginMarket.Enabled {
		return denied(snapshot.Source, false, DecisionPluginMarketDenied)
	}
	for _, trusted := range snapshot.Policy.PluginMarket.TrustedCatalogIDs {
		if trusted == catalogID {
			return allowed(snapshot.Source)
		}
	}
	return denied(snapshot.Source, false, DecisionCatalogDenied)
}

func allowed(source string) Decision {
	return Decision{Allowed: true, Reason: DecisionAllowed, Source: source}
}

func denied(source string, stale bool, reason string) Decision {
	return Decision{Allowed: false, Reason: reason, Source: source, Stale: stale}
}

func clonePolicy(policy Policy) Policy {
	policy.BlockedControlVersions = append([]string(nil), policy.BlockedControlVersions...)
	policy.AllowedReleaseChannels = append([]string(nil), policy.AllowedReleaseChannels...)
	policy.PluginMarket.TrustedCatalogIDs = append([]string(nil), policy.PluginMarket.TrustedCatalogIDs...)
	policy.CCSystemRules = cloneCCSystemRules(policy.CCSystemRules)
	return policy
}
