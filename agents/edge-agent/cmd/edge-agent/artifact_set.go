package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ipintel"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodeartifacts"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/rulepackvault"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/wafengine"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
)

// Node artifact set layout below deployment_root (ADR 0007 section 4.3,
// ADR 0009 section 8.2). ip-intel/current.ipi is the path the OpenResty IP
// library module maps (edge/openresty/iplib/cdnca_iplib.lua).
const (
	objectStoreDir    = "objects"
	artifactSetDir    = "artifact-set"
	ipIntelLibraryDir = "ip-intel"
)

// Object store owners (objectstore refs) of the node artifact set: the
// object store is shared with site objects, whose fetches Collect every
// object no owner references. artifactSetOwner holds the segments of the
// applied set (current) and of the one before it (previous, LKG);
// artifactSetIncomingOwner the segments received since, which wait for
// their set.
const (
	artifactSetOwner         = "node-artifact-set"
	artifactSetIncomingOwner = "node-artifact-set.incoming"
)

// artifactSetRuntime is the Agent's ARTIFACT_SET v1 executor.
type artifactSetRuntime struct {
	objects  *objectstore.Store
	executor *nodeartifacts.Executor
	ipIntel  *ipintel.Installer
	// engineChanged runs after an applied set changed the engine module item
	// (installed, replaced or removed): the current release is reloaded so
	// its gate picks the module up (nil: the next deployment does).
	engineChanged func(context.Context) error
	// rulePacks opens sealed packs (nil: rule pack items unsupported).
	rulePacks *rulepackvault.Vault
	// rulePacksChanged runs after an applied set changed its rule packs
	// (the dynamic routing runtime re-applies its sites).
	rulePacksChanged func(context.Context) error
	mu               sync.Mutex
}

// assembleArtifactSetRuntime: engine nil leaves engine module items
// unsupported (receipt unsupported_media_type).
func assembleArtifactSetRuntime(deploymentRoot, nodeID string, objects *objectstore.Store, engine *wafengine.Manager,
	engineChanged func(context.Context) error, rulePacks *rulepackvault.Vault) (*artifactSetRuntime, error) {
	if objects == nil {
		return nil, fmt.Errorf("configure node artifact set: object store is required")
	}
	library, err := ipintel.New(filepath.Join(deploymentRoot, ipIntelLibraryDir))
	if err != nil {
		return nil, fmt.Errorf("configure IP intelligence installer: %w", err)
	}
	installers := map[string]nodeartifacts.Installer{artifactset.MediaTypeIPIntel: ipIntelInstaller{library}}
	if engine != nil {
		installers[artifactset.MediaTypeEngineModule] = engineModuleInstaller{engine}
	}
	installers[artifactset.MediaTypeRulePack] = rulePackInstaller{vault: rulePacks, objects: objects}
	executor, err := nodeartifacts.New(nodeartifacts.Config{NodeID: nodeID, StateDir: filepath.Join(deploymentRoot, artifactSetDir),
		Objects: objects, Installers: installers})
	if err != nil {
		return nil, fmt.Errorf("configure node artifact set executor: %w", err)
	}
	return &artifactSetRuntime{objects: objects, executor: executor, ipIntel: library, engineChanged: engineChanged,
		rulePacks: rulePacks}, nil
}

// PutObject stores a segment and references it as incoming before any
// Collect can see it unreferenced.
func (runtime *artifactSetRuntime) PutObject(digest string, data []byte) error {
	release := runtime.objects.Stage([]string{digest})
	defer release()
	if err := runtime.objects.Put(digest, data); err != nil {
		return err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	incoming, err := runtime.objects.Current(artifactSetIncomingOwner)
	if err != nil {
		return err
	}
	return runtime.objects.Commit(artifactSetIncomingOwner, runtime.stored(append(incoming, digest)))
}

// Apply switches the set; an applied set becomes the referenced generation
// (the one it replaced stays referenced as previous), the incoming
// references are cleared and every other object nobody references is
// collected. A set that is not applied keeps its received segments.
func (runtime *artifactSetRuntime) Apply(set artifactset.Set, setSHA256 string, now time.Time) (artifactset.Receipt, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	engineBefore := runtime.activeItem(artifactset.MediaTypeEngineModule)
	packsBefore := runtime.rulePackState()
	receipt, err := runtime.executor.Apply(set, setSHA256, now)
	if err != nil || receipt.Result != artifactset.ResultApplied {
		return receipt, err
	}
	if runtime.rulePacks != nil {
		wraps, err := rulePackWraps(runtime.objects, set.Items)
		if err == nil {
			err = runtime.rulePacks.Replace(wraps)
		}
		if err != nil {
			// Every wrap opened at Prepare; this is local I/O.
			return receipt, fmt.Errorf("store rule pack keys: %w", err)
		}
	}
	if runtime.engineChanged != nil && runtime.activeItem(artifactset.MediaTypeEngineModule) != engineBefore {
		// The set is applied either way; a failed reload is retried by the
		// next deployment, whose Prepare gates the installed module.
		if err := runtime.engineChanged(context.Background()); err != nil {
			slog.Warn("reload after waf engine module change failed", "error", err)
		}
	}
	var segments []string
	for _, item := range set.Items {
		for _, segment := range item.Segments {
			segments = append(segments, segment.SHA256)
		}
	}
	// Installed rule pack objects stay referenced while the set holds them.
	segments = append(segments, rulePackDigests(set.Items)...)
	// A redelivered active set is acknowledged without reading its segments;
	// reference what is still stored.
	if err := runtime.objects.Commit(artifactSetOwner, runtime.stored(segments)); err != nil {
		return receipt, err
	}
	if err := runtime.objects.Commit(artifactSetIncomingOwner, nil); err != nil {
		return receipt, err
	}
	_, _ = runtime.objects.Collect()
	if runtime.rulePacksChanged != nil && runtime.rulePackState() != packsBefore {
		if err := runtime.rulePacksChanged(context.Background()); err != nil {
			slog.Warn("re-apply after rule pack change failed", "error", err)
		}
	}
	return receipt, nil
}

// rulePackState identifies the active set's rule packs and keys.
func (runtime *artifactSetRuntime) rulePackState() string {
	state := runtime.executor.Active()
	if state == nil {
		return ""
	}
	identity := ""
	for _, item := range state.Items {
		if item.MediaType == artifactset.MediaTypeRulePack {
			identity += item.SHA256
			if item.KeyWrap != nil {
				identity += ":" + item.KeyWrap.WrappedKey
			}
			identity += ","
		}
	}
	return identity
}

// activeItem identifies the active set's item of mediaType ("" if none).
func (runtime *artifactSetRuntime) activeItem(mediaType string) string {
	state := runtime.executor.Active()
	if state == nil {
		return ""
	}
	for _, item := range state.Items {
		if item.MediaType == mediaType {
			return item.ArtifactID + "\x00" + item.SHA256
		}
	}
	return ""
}

// stored keeps the digests still present (a corrupt object Get dropped is
// fetched again and referenced then).
func (runtime *artifactSetRuntime) stored(digests []string) []string {
	kept := digests[:0]
	for _, digest := range digests {
		if runtime.objects.Has(digest) {
			kept = append(kept, digest)
		}
	}
	return kept
}

// IPIntelReady: the applied set holds a library and current.ipi still has it.
func (runtime *artifactSetRuntime) IPIntelReady() bool {
	if !runtime.executor.HasItem(artifactset.MediaTypeIPIntel) {
		return false
	}
	state, err := runtime.ipIntel.Current()
	return err == nil && state != nil
}

type ipIntelInstaller struct{ library *ipintel.Installer }

func (installer ipIntelInstaller) Prepare(item artifactset.Item, content []byte, now time.Time) (nodeartifacts.Staged, error) {
	return installer.library.Prepare(content, ipintel.Expected{ArtifactID: item.ArtifactID, Revision: item.Revision, BuildID: item.Version}, now)
}

func (installer ipIntelInstaller) Remove() error { return installer.library.Remove() }
