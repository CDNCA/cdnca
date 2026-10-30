package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodeartifacts"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/rulepackvault"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/rulepack"
)

// rulePackInstaller installs rule pack items (mounted packs, CRS profile
// packs; ADR 0007 §6, ADR 0009 §8.4): Prepare checks the content opens (a
// sealed pack with the item's wrapped key and this node's key: a key that
// does not open it rejects the item and the set); Commit puts the bytes in
// the object store under their digest, where precheck and the dynamic
// routing runtime read them. Wrapped keys reach the vault after the whole
// set applied (artifactSetRuntime.Apply), so a rejected set changes no key.
// Without a vault (no artifact encryption key) plain packs (CRS profile
// packs) still install; sealed ones are rejected (control sends them only
// to nodes holding a key wrap).
type rulePackInstaller struct {
	vault   *rulepackvault.Vault
	objects *objectstore.Store
}

func (rulePackInstaller) MultipleItems() {}

func (installer rulePackInstaller) Prepare(item artifactset.Item, content []byte, _ time.Time) (nodeartifacts.Staged, error) {
	keyID, wrapped := "", ""
	if item.KeyWrap != nil {
		keyID, wrapped = item.KeyWrap.RecipientKeyID, item.KeyWrap.WrappedKey
	}
	var err error
	if installer.vault != nil {
		_, err = installer.vault.Check(content, item.SHA256, keyID, wrapped)
	} else if rulepack.IsSealed(content) || wrapped != "" {
		err = rulepackvault.ErrNoKey
	} else {
		_, err = rulepack.Load(content, item.SHA256)
	}
	if err != nil {
		return nil, &artifactset.InstallError{Reason: artifactset.ReasonInstallRejected, Err: err}
	}
	return rulePackStaged{objects: installer.objects, digest: item.SHA256, content: content}, nil
}

// Remove: objects of packs no set holds are collected (object store refs).
func (rulePackInstaller) Remove() error { return nil }

type rulePackStaged struct {
	objects *objectstore.Store
	digest  string
	content []byte
}

func (staged rulePackStaged) Commit() (func() error, error) {
	if err := staged.objects.Put(staged.digest, staged.content); err != nil {
		return nil, err
	}
	return func() error { return nil }, nil
}

func (rulePackStaged) Abort() {}

// rulePackWraps are the vault wraps of the set's sealed packs (pack and
// version from the stored object's public manifest).
func rulePackWraps(objects *objectstore.Store, items []artifactset.Item) ([]rulepackvault.Wrap, error) {
	var wraps []rulepackvault.Wrap
	for _, item := range items {
		if item.MediaType != artifactset.MediaTypeRulePack || item.KeyWrap == nil {
			continue
		}
		content, err := objects.Get(item.SHA256)
		if err != nil {
			return nil, err
		}
		manifest, err := rulepack.OpenManifest(content, item.SHA256)
		if err != nil {
			return nil, err
		}
		wraps = append(wraps, rulepackvault.Wrap{SealedSHA256: item.SHA256, PackID: manifest.Pack.PackID,
			Version: manifest.Pack.Version, RecipientKeyID: item.KeyWrap.RecipientKeyID, WrappedKey: item.KeyWrap.WrappedKey})
	}
	return wraps, nil
}

// rulePackDigests are the rule pack objects of the set (kept referenced).
func rulePackDigests(items []artifactset.Item) []string {
	var digests []string
	for _, item := range items {
		if item.MediaType == artifactset.MediaTypeRulePack {
			digests = append(digests, item.SHA256)
		}
	}
	return digests
}

// Rule pack directories: the vault's wrapped keys below deployment_root;
// plans of the Lua-engine mounts on tmpfs (/run is tmpfs on systemd hosts).
const (
	rulePackStateDir    = "rule-packs"
	rulePackRuntimeRoot = "/run/cdnca/rule-packs"
)

// openRulePackVault opens the node's rule pack vault (nil without an
// artifact encryption key: version 1 identities cannot receive sealed packs
// nor run mounts).
func openRulePackVault(deploymentRoot string, privateKey []byte, objects *objectstore.Store, runtimeRoot string,
	workerGID int) (*rulepackvault.Vault, error) {
	if len(privateKey) == 0 {
		return nil, nil
	}
	vault, err := rulepackvault.Open(rulepackvault.Config{PrivateKey: privateKey,
		StateDir: filepath.Join(deploymentRoot, rulePackStateDir), Objects: objects.Get,
		ModSecurityDir: filepath.Join(runtimeRoot, "modsecurity"), OwnerUID: -1, OwnerGID: -1,
		PlanDir: filepath.Join(runtimeRoot, "plans"), PlanGID: workerGID})
	if err != nil {
		return nil, fmt.Errorf("configure rule pack vault: %w", err)
	}
	return vault, nil
}
