package analyticsgeoartifact

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
)

var (
	ErrReleaseRuntimeConfiguration = errors.New("analytics geo release runtime configuration invalid")
	ErrReleaseRuntimeUnavailable   = errors.New("analytics geo release runtime unavailable")
	ErrReleaseRuntimeIdentity      = errors.New("analytics geo release runtime identity mismatch")
)

type ReleaseLookup struct {
	Lookup analyticsgeo.AuthorityLookup
	Active ReleaseFact
	LKG    *ReleaseFact
}

type ReleaseRuntime struct {
	mu        sync.RWMutex
	store     *ReleaseStore
	loader    *analyticsgeo.SignedFileLoader
	state     ReleaseState
	available bool
	poisoned  bool
}

func NewReleaseRuntime(store *ReleaseStore, loader *analyticsgeo.SignedFileLoader) (*ReleaseRuntime, error) {
	if store == nil || loader == nil {
		return nil, ErrReleaseRuntimeConfiguration
	}
	return &ReleaseRuntime{store: store, loader: loader}, nil
}

func (runtime *ReleaseRuntime) Load(ctx context.Context) error {
	if runtime == nil || runtime.store == nil || runtime.loader == nil || ctx == nil {
		return ErrReleaseRuntimeConfiguration
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.makeUnavailable()
	runtime.poisoned = true
	state, err := runtime.store.State(ctx)
	if err != nil {
		return err
	}
	if err := runtime.loader.Poll(ctx, runtime.store.ArtifactTrigger(state.Active)); err != nil {
		return err
	}
	runtime.state = cloneReleaseState(state)
	runtime.available = true
	runtime.poisoned = false
	return nil
}

func (runtime *ReleaseRuntime) Activate(ctx context.Context, request ReleaseRequest) (ReleaseState, error) {
	if runtime == nil || runtime.store == nil || runtime.loader == nil || ctx == nil {
		return ReleaseState{}, ErrReleaseRuntimeConfiguration
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.poisoned {
		return ReleaseState{}, ErrReleaseRuntimeUnavailable
	}
	candidate, err := runtime.store.Prepare(ctx, request)
	if err != nil {
		return ReleaseState{}, err
	}
	if err := runtime.loader.Poll(ctx, candidate.Trigger()); err != nil {
		return ReleaseState{}, err
	}
	if err := runtime.store.Commit(ctx, candidate); err != nil {
		runtime.makePoisoned()
		return ReleaseState{}, err
	}
	state, err := runtime.store.State(ctx)
	if err != nil {
		runtime.makePoisoned()
		return ReleaseState{}, err
	}
	if state.Active != candidate.Fact() {
		runtime.makePoisoned()
		return ReleaseState{}, ErrReleaseRuntimeIdentity
	}
	runtime.state = cloneReleaseState(state)
	runtime.available = true
	return cloneReleaseState(state), nil
}

func (runtime *ReleaseRuntime) Lookup(
	ctx context.Context,
	version string,
	address netip.Addr,
) (analyticsgeo.AuthorityLookup, error) {
	result, err := runtime.LookupWithRelease(ctx, version, address)
	return result.Lookup, err
}

func (runtime *ReleaseRuntime) LookupWithRelease(
	ctx context.Context,
	version string,
	address netip.Addr,
) (ReleaseLookup, error) {
	if runtime == nil || runtime.loader == nil || ctx == nil {
		return ReleaseLookup{}, ErrReleaseRuntimeConfiguration
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if !runtime.available {
		return ReleaseLookup{}, ErrReleaseRuntimeUnavailable
	}
	active := runtime.state.Active
	if version != "" && version != active.CatalogVersion {
		return ReleaseLookup{}, ErrReleaseRuntimeIdentity
	}
	lookup, err := runtime.loader.Lookup(ctx, version, address)
	if err != nil {
		return ReleaseLookup{}, err
	}
	if lookup.Revision != active.Revision || lookup.Provenance.Version != active.CatalogVersion ||
		lookup.Provenance.SHA256 != active.CurrentCatalogSHA256 {
		return ReleaseLookup{}, ErrReleaseRuntimeIdentity
	}
	return ReleaseLookup{Lookup: lookup, Active: active, LKG: cloneReleaseFact(runtime.state.LKG)}, nil
}

func (runtime *ReleaseRuntime) makeUnavailable() {
	runtime.state = ReleaseState{}
	runtime.available = false
}

func (runtime *ReleaseRuntime) makePoisoned() {
	runtime.makeUnavailable()
	runtime.poisoned = true
}

func cloneReleaseState(state ReleaseState) ReleaseState {
	state.LKG = cloneReleaseFact(state.LKG)
	return state
}

func cloneReleaseFact(fact *ReleaseFact) *ReleaseFact {
	if fact == nil {
		return nil
	}
	cloned := *fact
	return &cloned
}

var _ analyticsgeo.AuthorityReader = (*ReleaseRuntime)(nil)
