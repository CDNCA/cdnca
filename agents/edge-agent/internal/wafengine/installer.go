package wafengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule"
)

// Expected is what the node artifact set item says the content is.
type Expected struct {
	ArtifactID string
	Version    string
	Revision   uint64
}

// Staged is a verified build extracted next to the installed ones, ready to
// become the active build (nodeartifacts.Staged).
type Staged struct {
	manager *Manager
	staging string
	target  string
	record  installed
}

// rejected is an install rejection with its receipt reason.
func rejected(reason string, err error) error {
	return &artifactset.InstallError{Reason: reason, Err: err}
}

// PrepareModule verifies an engine module item (the artifactset installer of
// MediaTypeEngineModule): a well-formed bundle (enginemodule.Decode) that is
// the item's build, for this node's OpenResty version and architecture,
// signed by a platform release key this node trusts now, whose payload holds
// exactly the manifest's files. The build is extracted below Root/versions;
// nothing active changes until Commit. Rejections carry the receipt reason:
// signature_invalid, platform_mismatch or install_rejected.
func (m *Manager) PrepareModule(content []byte, expected Expected, now time.Time) (*Staged, error) {
	checked, err := enginemodule.Decode(content)
	switch {
	case errors.Is(err, enginemodule.ErrSignature):
		return nil, rejected(artifactset.ReasonSignatureInvalid, err)
	case err != nil:
		return nil, rejected(artifactset.ReasonInstallRejected, err)
	}
	if checked.ArtifactID() != expected.ArtifactID || checked.Manifest.Version != expected.Version || expected.Revision == 0 {
		return nil, rejected(artifactset.ReasonInstallRejected,
			fmt.Errorf("engine module %s %s is not the item %s %s", checked.ArtifactID(), checked.Manifest.Version,
				expected.ArtifactID, expected.Version))
	}
	if m.config.OpenRestyVersion == "" || m.matchPlatform(checked.Manifest) != nil {
		return nil, rejected(artifactset.ReasonPlatformMismatch, fmt.Errorf("engine module for OpenResty %s linux/%s, node %q/%s",
			checked.Manifest.OpenRestyVersion, checked.Manifest.Architecture, m.config.OpenRestyVersion, m.config.Architecture))
	}
	signer, err := VerifySignature(checked.Bundle.Manifest, checked.Signatures, m.config.Trust)
	if err != nil {
		return nil, rejected(artifactset.ReasonSignatureInvalid, err)
	}
	versions := filepath.Join(m.config.Root, "versions")
	if err := os.MkdirAll(versions, 0o755); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(versions, ".staging-")
	if err != nil {
		return nil, err
	}
	tree := filepath.Join(staging, "tree")
	if err := Extract(checked.Bundle.Payload, checked.Manifest, tree); err != nil {
		_ = os.RemoveAll(staging)
		if errors.Is(err, ErrPayload) {
			return nil, rejected(artifactset.ReasonInstallRejected, err)
		}
		return nil, err
	}
	if err := os.Chmod(tree, 0o755); err != nil {
		_ = os.RemoveAll(staging)
		return nil, err
	}
	digest := enginemodule.Digest(content)
	return &Staged{manager: m, staging: staging, target: filepath.Join(versions, digest), record: installed{
		ArtifactID: expected.ArtifactID, Revision: expected.Revision, BundleSHA256: digest,
		ManifestBytes: checked.Bundle.Manifest, Signatures: checked.Bundle.Signatures,
		Path: filepath.Join(versions, digest), Signer: signer, InstalledAt: now.UTC().Unix()}}, nil
}

// Commit makes the staged build the active one (installed.json replaced by
// rename); undo puts back the build that was active. The build that was
// active stays on disk (a running master may still have it loaded); older
// ones are removed.
func (staged *Staged) Commit() (func() error, error) {
	m := staged.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	defer os.RemoveAll(staged.staging)
	previous, err := os.ReadFile(m.statePath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	manifest, err := enginemodule.DecodeManifest(staged.record.ManifestBytes)
	if err != nil {
		return nil, err
	}
	if VerifyInstalled(staged.target, manifest) != nil {
		if err := os.RemoveAll(staged.target); err != nil {
			return nil, err
		}
		if err := os.Rename(filepath.Join(staged.staging, "tree"), staged.target); err != nil {
			return nil, err
		}
	}
	encoded, err := json.Marshal(staged.record)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(m.statePath(), encoded, 0o644); err != nil {
		return nil, err
	}
	m.pruneVersions(staged.target, previous)
	undo := func() error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if previous == nil {
			return removeIfExists(m.statePath())
		}
		return writeAtomic(m.statePath(), previous, 0o644)
	}
	return undo, nil
}

// Abort discards the staged build.
func (staged *Staged) Abort() { _ = os.RemoveAll(staged.staging) }

// RemoveModule uninstalls the active build (the node artifact set no longer
// holds one). Its files stay until the next install prunes them: the running
// master may still have the module loaded until the next reload.
func (m *Manager) RemoveModule() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return removeIfExists(m.statePath())
}

// pruneVersions keeps the active build and the one before it.
func (m *Manager) pruneVersions(active string, previous []byte) {
	keep := map[string]bool{active: true}
	var before installed
	if previous != nil && json.Unmarshal(previous, &before) == nil {
		keep[before.Path] = true
	}
	versions := filepath.Join(m.config.Root, "versions")
	entries, err := os.ReadDir(versions)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(versions, entry.Name())
		if entry.IsDir() && !keep[path] && entry.Name()[0] != '.' {
			_ = os.RemoveAll(path)
		}
	}
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
