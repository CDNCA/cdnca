// Package dyntelemetry turns the node-level access and security logs of
// dynamic routing (ADR 0009 D12, docs/edge/dynroute-telemetry.md) back into
// the per-site v7 telemetry the event spool, the gateway and the control
// plane already accept.
//
// A shared server writes one access log and one security log for every site
// of the node. Each line is the v7 line of the site the request selected,
// with config_version_id empty and an attribution object
//
//	"cdnca":{"generation":<g>,"scope":"<configuration scope>","digest":"<site object>","port":<public port>}
//
// The Agent knows from which publication (config version) each scope's sites
// came in every generation it activated: Registry. Normalize checks a line
// against the site object it names (tenant, site, host, port and capture
// policy are that object's), fills config_version_id, drops the attribution
// and returns the v7 line with the trusted identity the v7 tailer took from
// the listener's log path. Nothing in a line is trusted that the site object
// does not confirm.
package dyntelemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// ErrUnattributed: the line names a generation or scope the registry does
// not know (not yet), or a site object not readable yet. The source retries
// and quarantines after its grace period.
var ErrUnattributed = errors.New("dynamic routing log line is not attributable yet")

// ErrL2Hop: the line is an L1's hop this node served as its L2
// (fix-l2trust). Only the L1's line is the visitor's request: the hop is
// skipped, neither spooled (no second access event, metering or site usage)
// nor quarantined.
var ErrL2Hop = errors.New("dynamic routing log line is an L2 hop")

// ErrInvalid: the line can never be attributed (malformed, or it disagrees
// with the site object it names). It is quarantined.
var ErrInvalid = errors.New("dynamic routing log line is invalid")

// Window is how many generations of history every scope keeps: a line of a
// generation in the window is attributed even if its scope changed since; an
// older line only while its scope's version has not changed since (see
// ConfigVersion).
const Window = 64

// step: from generation From on (until the scope's next step), the scope's
// sites are those of config version Version ("" = the scope left the node).
type step struct {
	From    uint64 `json:"from"`
	Version string `json:"version"`
}

// Registry maps (generation, configuration scope) to a config version. The
// activation path calls Register(first, last, scopes) before it stages
// generation first (siteindex.Activator.Prepare): the generations first..last
// it may commit (the parts of a split activation) serve the scopes' new
// versions; a rollback to an older generation resolves to the older versions
// by the same steps, a generation above the newest registration to nothing.
// A scope's step is only added when its version changes, so the registry
// stays small with many scopes.
type Registry struct {
	mu     sync.RWMutex
	path   string
	first  uint64 // first generation of the newest registration
	newest uint64 // its last generation
	scopes map[string][]step
}

type registryFile struct {
	SchemaVersion int               `json:"schema_version"`
	First         uint64            `json:"first"`
	Newest        uint64            `json:"newest"`
	Scopes        map[string][]step `json:"scopes"`
}

// lastRange: first starts the newest registration again (the activation
// that registered it failed before any commit and is retried).
func (registry *Registry) lastRange(first uint64) bool {
	return first == registry.first
}

// NewRegistry is an in-memory registry.
func NewRegistry() *Registry { return &Registry{scopes: map[string][]step{}} }

// OpenRegistry loads (or starts) the registry persisted at path (a private
// file in the agent's state, rewritten atomically by each Register).
func OpenRegistry(path string) (*Registry, error) {
	registry := NewRegistry()
	registry.path = path
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return registry, nil
	}
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var file registryFile
	if err := decoder.Decode(&file); err != nil || decoder.Decode(&struct{}{}) != io.EOF || file.SchemaVersion != 1 ||
		file.First > file.Newest || file.Newest != 0 && file.First == 0 {
		return nil, fmt.Errorf("%w: attribution registry %s is corrupt", ErrInvalid, path)
	}
	for scope, steps := range file.Scopes {
		if !canonicalUUID(scope) || len(steps) == 0 {
			return nil, fmt.Errorf("%w: attribution registry %s is corrupt", ErrInvalid, path)
		}
		for index, value := range steps {
			if value.From == 0 || value.From > file.Newest || len(value.Version) > 128 ||
				index > 0 && steps[index-1].From >= value.From {
				return nil, fmt.Errorf("%w: attribution registry %s is corrupt", ErrInvalid, path)
			}
		}
	}
	registry.first, registry.newest, registry.scopes = file.First, file.Newest, file.Scopes
	if registry.scopes == nil {
		registry.scopes = map[string][]step{}
	}
	return registry, nil
}

// Register records that in generations first..last every scope of the node
// serves the given config version (scopes is the whole node: a scope not in
// it has left). first must be above every earlier registration's last,
// except that re-registering an unused range (an activation that failed
// before commit) replaces it.
func (registry *Registry) Register(first, last uint64, scopes map[string]string) error {
	if first == 0 || last < first || last > 1<<53-1 {
		return fmt.Errorf("%w: registration of generations %d..%d", ErrInvalid, first, last)
	}
	for scope, version := range scopes {
		if !canonicalUUID(scope) || !validVersion(version) {
			return fmt.Errorf("%w: generation %d scope %q version %q", ErrInvalid, first, scope, version)
		}
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if first <= registry.newest && !registry.lastRange(first) {
		return fmt.Errorf("%w: generation %d registered after %d", ErrInvalid, first, registry.newest)
	}
	changed := false
	set := func(scope, version string) {
		steps := registry.scopes[scope]
		if len(steps) > 0 && steps[len(steps)-1].Version == version {
			return
		}
		if len(steps) > 0 && steps[len(steps)-1].From == first {
			steps[len(steps)-1].Version = version // re-registration of an unused generation
		} else {
			steps = append(steps, step{From: first, Version: version})
		}
		registry.scopes[scope] = steps
		changed = true
	}
	for scope, version := range scopes {
		set(scope, version)
	}
	for scope := range registry.scopes {
		if _, present := scopes[scope]; !present {
			set(scope, "")
		}
	}
	changed = changed || registry.newest != last || registry.first != first
	registry.newest, registry.first = last, first
	registry.prune()
	if !changed || registry.path == "" {
		return nil
	}
	return registry.save()
}

// prune drops steps no generation in the window resolves to.
func (registry *Registry) prune() {
	if registry.newest <= Window {
		return
	}
	oldest := registry.newest - Window
	for scope, steps := range registry.scopes {
		keep := 0
		for index := range steps {
			if steps[index].From <= oldest {
				keep = index // the step in force at the oldest attributable generation
			}
		}
		steps = steps[keep:]
		if len(steps) == 1 && steps[0].Version == "" && steps[0].From <= oldest {
			delete(registry.scopes, scope)
			continue
		}
		registry.scopes[scope] = steps
	}
}

func (registry *Registry) save() error {
	ordered := make(map[string][]step, len(registry.scopes))
	for scope, steps := range registry.scopes {
		ordered[scope] = steps
	}
	raw, err := json.Marshal(registryFile{SchemaVersion: 1, First: registry.first, Newest: registry.newest, Scopes: ordered})
	if err != nil {
		return err
	}
	directory := filepath.Dir(registry.path)
	temporary, err := os.CreateTemp(directory, ".dyntelemetry-registry-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(raw, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, registry.path)
}

// ConfigVersion is the config version of scope's sites in generation.
func (registry *Registry) ConfigVersion(generation uint64, scope string) (string, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	if generation == 0 || generation > registry.newest {
		return "", false
	}
	steps := registry.scopes[scope]
	// TF-E04: no node-wide cut at newest-Window. prune keeps, per scope, the
	// step in force at the oldest window generation and every later one, so
	// a generation at or after the scope's first kept step still resolves
	// exactly (the scope's version has not changed since) however many other
	// scopes were published meanwhile. A generation before it may have had
	// another version: unknown, never the newest.
	index := sort.Search(len(steps), func(i int) bool { return steps[i].From > generation }) - 1
	if index < 0 || steps[index].Version == "" {
		return "", false
	}
	return steps[index].Version, true
}

// Newest is the newest registered generation (0 before the first).
func (registry *Registry) Newest() uint64 {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.newest
}

func validVersion(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func canonicalUUID(value string) bool {
	if len(value) != 36 || value == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return false
			}
		}
	}
	return true
}
