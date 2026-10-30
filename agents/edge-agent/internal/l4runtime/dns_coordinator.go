package l4runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	dnsStateSchemaVersion = 1
	maximumDNSStateBytes  = 1 << 20
)

type dnsAddressSetState struct {
	SchemaVersion  int       `json:"schema_version"`
	TenantID       string    `json:"tenant_id"`
	SiteID         string    `json:"site_id"`
	StreamID       string    `json:"stream_id"`
	Revision       int64     `json:"revision"`
	SourceRevision int64     `json:"source_revision,omitempty"`
	ConfigDigest   string    `json:"config_digest"`
	Host           string    `json:"host"`
	Addresses      []string  `json:"addresses,omitempty"`
	AddressClass   string    `json:"address_class,omitempty"`
	RefreshedAt    time.Time `json:"refreshed_at,omitempty"`
	RefreshAfter   time.Time `json:"refresh_after,omitempty"`
	StaleUntil     time.Time `json:"stale_until,omitempty"`
	RetryAfter     time.Time `json:"retry_after,omitempty"`
	LastReason     string    `json:"last_reason"`
	Negative       bool      `json:"negative,omitempty"`
	Seal           string    `json:"seal"`
}

type dnsLookupFlight struct {
	done   chan struct{}
	result DNSLookupResult
	err    error
	users  int
}

type DNSCoordinator struct {
	root     string
	resolver DNSResolver
	health   AddressSetHealth
	now      func() time.Time

	mu         sync.Mutex
	scopeLocks map[string]*sync.Mutex
	inflight   map[string]*dnsLookupFlight
}

func NewDNSCoordinator(root string, resolver DNSResolver, health AddressSetHealth, now func() time.Time) (*DNSCoordinator, error) {
	if root == "" || !filepath.IsAbs(root) || resolver == nil {
		return nil, ErrInvalidPath
	}
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create L4 DNS state root: %w", err)
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidPath
	}
	return &DNSCoordinator{root: root, resolver: resolver, health: health, now: now, scopeLocks: make(map[string]*sync.Mutex), inflight: make(map[string]*dnsLookupFlight)}, nil
}

func (c *DNSCoordinator) Resolve(ctx context.Context, config ConfigV2, streamID string) (ResolvedAddressSet, error) {
	normalized, err := normalizeConfigV2(config)
	if err != nil {
		return ResolvedAddressSet{}, err
	}
	listener, found := listenerV2ByID(normalized, streamID)
	if !found {
		return ResolvedAddressSet{}, ErrInvalidConfig
	}
	revision := normalized.Revision
	if listener.ResourceRevision != 0 {
		revision = listener.ResourceRevision
	}
	configDigest, err := configV2Digest(normalized)
	if err != nil {
		return ResolvedAddressSet{}, err
	}
	if listener.Endpoint.Address != "" {
		addresses := []netip.Addr{netip.MustParseAddr(listener.Endpoint.Address)}
		if c.health != nil {
			if err := c.health(ctx, listener, addresses); err != nil {
				return ResolvedAddressSet{}, fmt.Errorf("%w: %v", ErrDNSUnavailable, err)
			}
		}
		return resolvedSet(listener, revision, "", addresses, time.Time{}, time.Time{}, DNSReasonStaticAddress), nil
	}

	lock := c.scopeLock(listener)
	lock.Lock()
	state, exists, err := c.loadState(listener)
	if err != nil {
		lock.Unlock()
		return ResolvedAddressSet{}, err
	}
	if err := fenceDNSState(state, exists, revision, normalized.Revision, configDigest); err != nil {
		lock.Unlock()
		return ResolvedAddressSet{}, err
	}
	now := c.now().UTC()
	if exists && state.Revision == revision && state.ConfigDigest == configDigest && state.Host == listener.Endpoint.Host {
		if len(state.Addresses) != 0 && now.Before(state.RefreshAfter) {
			result, resultErr := state.resolved(listener, DNSReasonFreshLKG)
			lock.Unlock()
			return result, resultErr
		}
		if now.Before(state.RetryAfter) {
			if len(state.Addresses) != 0 && !now.After(state.StaleUntil) {
				result, resultErr := state.resolved(listener, state.LastReason)
				lock.Unlock()
				return result, resultErr
			}
			lock.Unlock()
			if !state.StaleUntil.IsZero() && now.After(state.StaleUntil) {
				return ResolvedAddressSet{}, ErrDNSStale
			}
			return ResolvedAddressSet{}, ErrDNSUnavailable
		}
	}
	// Join the host lookup before releasing the scope's state lock. Otherwise
	// a caller that read empty state could start another lookup after the first
	// caller committed that state and released its flight.
	answer, releaseLookup, lookupErr := c.lookup(ctx, listener.Endpoint.Host)
	lock.Unlock()
	defer releaseLookup()
	if lookupErr != nil || answer.Negative {
		reason := DNSReasonLookupFailedLKG
		if answer.Negative {
			reason = DNSReasonNegativeLKG
		}
		return c.keepLKG(listener, revision, normalized.Revision, configDigest, reason, answer.Negative)
	}
	addresses, err := normalizeResolvedAddresses(answer.Addresses, listener.DNS.AllowPrivateAddresses)
	if err != nil {
		return c.keepLKG(listener, revision, normalized.Revision, configDigest, DNSReasonRebindingRejected, false)
	}
	class := addressClass(addresses[0])
	lock.Lock()
	state, exists, err = c.loadState(listener)
	if err != nil {
		lock.Unlock()
		return ResolvedAddressSet{}, err
	}
	if err := fenceDNSState(state, exists, revision, normalized.Revision, configDigest); err != nil {
		lock.Unlock()
		return ResolvedAddressSet{}, err
	}
	if exists && state.Host == listener.Endpoint.Host && state.AddressClass != "" && state.AddressClass != class {
		lock.Unlock()
		return c.keepLKG(listener, revision, normalized.Revision, configDigest, DNSReasonRebindingRejected, false)
	}
	lock.Unlock()
	if c.health != nil {
		if err := c.health(ctx, listener, addresses); err != nil {
			return c.keepLKG(listener, revision, normalized.Revision, configDigest, DNSReasonHealthRejected, false)
		}
	}

	now = c.now().UTC()
	ttl := clampTTL(answer.TTL, listener.DNS)
	candidate := dnsAddressSetState{
		SchemaVersion: dnsStateSchemaVersion, TenantID: listener.TenantID, SiteID: listener.SiteID, StreamID: listener.StreamID,
		Revision: revision, SourceRevision: optionalSourceRevision(normalized.Revision, revision), ConfigDigest: configDigest, Host: listener.Endpoint.Host, AddressClass: class,
		RefreshedAt: now, RefreshAfter: now.Add(ttl), StaleUntil: now.Add(ttl).Add(time.Duration(listener.DNS.StaleIfErrorSeconds) * time.Second),
		LastReason: DNSReasonPromoted,
	}
	for _, address := range addresses {
		candidate.Addresses = append(candidate.Addresses, address.String())
	}
	lock.Lock()
	defer lock.Unlock()
	latest, latestExists, err := c.loadState(listener)
	if err != nil {
		return ResolvedAddressSet{}, err
	}
	if err := fenceDNSState(latest, latestExists, revision, normalized.Revision, configDigest); err != nil {
		return ResolvedAddressSet{}, err
	}
	if err := c.writeState(listener, candidate); err != nil {
		return ResolvedAddressSet{}, err
	}
	return resolvedSet(listener, revision, listener.Endpoint.Host, addresses, candidate.RefreshAfter, candidate.StaleUntil, DNSReasonPromoted), nil
}

func (c *DNSCoordinator) keepLKG(listener ListenerV2, revision, sourceRevision int64, configDigest, reason string, negative bool) (ResolvedAddressSet, error) {
	lock := c.scopeLock(listener)
	lock.Lock()
	defer lock.Unlock()
	state, exists, err := c.loadState(listener)
	if err != nil {
		return ResolvedAddressSet{}, err
	}
	if err := fenceDNSState(state, exists, revision, sourceRevision, configDigest); err != nil {
		return ResolvedAddressSet{}, err
	}
	now := c.now().UTC()
	if exists && state.Host == listener.Endpoint.Host && len(state.Addresses) != 0 {
		if now.After(state.StaleUntil) {
			return ResolvedAddressSet{}, ErrDNSStale
		}
		if state.Revision == revision && state.ConfigDigest == configDigest {
			state.RetryAfter = now.Add(time.Duration(listener.DNS.NegativeTTLSeconds) * time.Second)
			state.LastReason = reason
			state.Negative = negative
			if err := c.writeState(listener, state); err != nil {
				return ResolvedAddressSet{}, err
			}
		}
		return state.resolved(listener, reason)
	}
	negativeState := dnsAddressSetState{
		SchemaVersion: dnsStateSchemaVersion, TenantID: listener.TenantID, SiteID: listener.SiteID, StreamID: listener.StreamID,
		Revision: revision, SourceRevision: optionalSourceRevision(sourceRevision, revision), ConfigDigest: configDigest, Host: listener.Endpoint.Host,
		RetryAfter: now.Add(time.Duration(listener.DNS.NegativeTTLSeconds) * time.Second), LastReason: reason, Negative: negative,
	}
	if err := c.writeState(listener, negativeState); err != nil {
		return ResolvedAddressSet{}, err
	}
	return ResolvedAddressSet{}, ErrDNSUnavailable
}

func (c *DNSCoordinator) lookup(ctx context.Context, host string) (DNSLookupResult, func(), error) {
	c.mu.Lock()
	flight := c.inflight[host]
	leader := flight == nil
	if leader {
		flight = &dnsLookupFlight{done: make(chan struct{})}
		c.inflight[host] = flight
	}
	flight.users++
	c.mu.Unlock()
	release := func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		flight.users--
		if flight.users == 0 {
			delete(c.inflight, host)
		}
	}
	if leader {
		flight.result, flight.err = c.resolver.LookupIP(ctx, host)
		close(flight.done)
	} else {
		select {
		case <-flight.done:
		case <-ctx.Done():
			return DNSLookupResult{}, release, ctx.Err()
		}
	}
	return cloneDNSLookupResult(flight.result), release, flight.err
}

func (c *DNSCoordinator) scopeLock(listener ListenerV2) *sync.Mutex {
	key := listener.TenantID + "\x00" + listener.SiteID + "\x00" + listener.StreamID
	c.mu.Lock()
	defer c.mu.Unlock()
	lock := c.scopeLocks[key]
	if lock == nil {
		lock = &sync.Mutex{}
		c.scopeLocks[key] = lock
	}
	return lock
}

func (c *DNSCoordinator) statePath(listener ListenerV2) string {
	digest := sha256.Sum256([]byte(listener.TenantID + "\x00" + listener.SiteID + "\x00" + listener.StreamID))
	return filepath.Join(c.root, hex.EncodeToString(digest[:])+".json")
}

func (c *DNSCoordinator) loadState(listener ListenerV2) (dnsAddressSetState, bool, error) {
	encoded, err := os.ReadFile(c.statePath(listener))
	if errors.Is(err, os.ErrNotExist) {
		return dnsAddressSetState{}, false, nil
	}
	if err != nil {
		return dnsAddressSetState{}, false, fmt.Errorf("read L4 DNS state: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maximumDNSStateBytes {
		return dnsAddressSetState{}, false, ErrCorruptState
	}
	var state dnsAddressSetState
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return dnsAddressSetState{}, false, ErrCorruptState
	}
	if err := ensureJSONEOF(decoder); err != nil || !validDNSState(state, listener) {
		return dnsAddressSetState{}, false, ErrCorruptState
	}
	want := dnsStateSeal(state)
	if want == "" || state.Seal != want {
		return dnsAddressSetState{}, false, ErrCorruptState
	}
	return state, true, nil
}

func (c *DNSCoordinator) writeState(listener ListenerV2, state dnsAddressSetState) error {
	state.Seal = dnsStateSeal(state)
	if state.Seal == "" {
		return ErrCorruptState
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return ErrCorruptState
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(c.root, ".l4-dns-*.tmp")
	if err != nil {
		return fmt.Errorf("create L4 DNS state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(encoded)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write L4 DNS state: %w", err)
	}
	if err := os.Rename(temporaryPath, c.statePath(listener)); err != nil {
		return fmt.Errorf("publish L4 DNS state: %w", err)
	}
	directory, err := os.Open(c.root)
	if err != nil {
		return fmt.Errorf("open L4 DNS state root: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return fmt.Errorf("sync L4 DNS state root: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close L4 DNS state root: %w", closeErr)
	}
	return nil
}

func dnsStateSeal(state dnsAddressSetState) string {
	state.Seal = ""
	encoded, err := json.Marshal(state)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validDNSState(state dnsAddressSetState, listener ListenerV2) bool {
	if state.SchemaVersion != dnsStateSchemaVersion || state.TenantID != listener.TenantID || state.SiteID != listener.SiteID || state.StreamID != listener.StreamID ||
		state.Revision < 1 || state.Revision > maxExactJSONInteger || state.SourceRevision < 0 || state.SourceRevision > maxExactJSONInteger || len(state.ConfigDigest) != sha256.Size*2 || state.Host == "" || len(state.Seal) != sha256.Size*2 {
		return false
	}
	if len(state.Addresses) == 0 {
		return !state.RetryAfter.IsZero()
	}
	if state.AddressClass != "public" && state.AddressClass != "private" {
		return false
	}
	for _, raw := range state.Addresses {
		address, err := netip.ParseAddr(raw)
		if err != nil || addressClass(address) != state.AddressClass {
			return false
		}
	}
	return !state.RefreshedAt.IsZero() && state.RefreshedAt.Before(state.RefreshAfter) && state.RefreshAfter.Before(state.StaleUntil)
}

func fenceDNSState(state dnsAddressSetState, exists bool, revision, sourceRevision int64, configDigest string) error {
	if !exists {
		return nil
	}
	previousSource := state.SourceRevision
	if previousSource == 0 {
		previousSource = state.Revision
	}
	if state.Revision > revision || previousSource > sourceRevision || previousSource == sourceRevision && state.ConfigDigest != configDigest {
		return ErrConflict
	}
	return nil
}

func (state dnsAddressSetState) resolved(listener ListenerV2, reason string) (ResolvedAddressSet, error) {
	addresses := make([]netip.Addr, 0, len(state.Addresses))
	for _, raw := range state.Addresses {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return ResolvedAddressSet{}, ErrCorruptState
		}
		addresses = append(addresses, address)
	}
	return resolvedSet(listener, state.Revision, state.Host, addresses, state.RefreshAfter, state.StaleUntil, reason), nil
}

func resolvedSet(listener ListenerV2, revision int64, host string, addresses []netip.Addr, refreshAfter, staleUntil time.Time, reason string) ResolvedAddressSet {
	return ResolvedAddressSet{
		TenantID: listener.TenantID, SiteID: listener.SiteID, StreamID: listener.StreamID, Revision: revision, Host: host,
		Addresses: append([]netip.Addr(nil), addresses...), RefreshAfter: refreshAfter, StaleUntil: staleUntil, ReasonCode: reason,
	}
}

func listenerV2ByID(config ConfigV2, streamID string) (ListenerV2, bool) {
	index := sort.Search(len(config.Listeners), func(index int) bool { return config.Listeners[index].StreamID >= streamID })
	if index < len(config.Listeners) && config.Listeners[index].StreamID == streamID {
		return config.Listeners[index], true
	}
	for _, listener := range config.Listeners {
		if listener.StreamID == streamID {
			return listener, true
		}
	}
	return ListenerV2{}, false
}

func clampTTL(value time.Duration, policy DNSPolicyV2) time.Duration {
	minimum := time.Duration(policy.PositiveMinTTLSeconds) * time.Second
	maximum := time.Duration(policy.PositiveMaxTTLSeconds) * time.Second
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func cloneDNSLookupResult(value DNSLookupResult) DNSLookupResult {
	value.Addresses = append([]netip.Addr(nil), value.Addresses...)
	return value
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrCorruptState
	}
	return nil
}

func optionalSourceRevision(source, resource int64) int64 {
	if source == resource {
		return 0
	}
	return source
}
