package originauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// Origin auth secret objects (dynamic routing D5b, ADR 0009 §4 "回源鉴权凭据").
//
// Under dynamic routing a site's origin auth binding is in its site object:
// origin.auth[] {pool_id, endpoint, secret: {kind "origin_auth_secret", id,
// revision}}. The workers sign at request time, without a reload, so the
// credential must be readable by them; it never enters the site object or
// the content-addressed site object directory (dynroute contract §5.5).
//
// Delivery is the existing per-node sealed snapshot
// (ProductionSnapshotMediaType: HPKE to the node's key, Ed25519 signed): the
// installer opens it as today and, when a secret object root is set, also
// writes one object per rule:
//
//	<root>/<rule_id>/<publication_revision>.json   0440, group = worker group
//	{"schema":"cdnca.edge.origin-auth-secret/v1","rule_id":...,"revision":N,"rule":{...}}
//
// rule is the compiled rule (provider, algorithm, endpoint, bucket, path
// prefix, region, service, TTL, activation time) with each key carrying its
// credential inline. The site object's secret ref names (rule_id,
// publication_revision): an object never changes under its revision, a
// credential rotation is a new publication (and a new site object revision,
// so the upstream reuse key changes too). The newest two revisions of each
// rule are kept (the active site generation and the one before it); rules
// no longer published are removed.
//
// Trade-off (same tier as the G8-b worker-readable certificate keys): the
// worker group can read the credentials at rest; the agent's own copy stays
// 0600 in the key root.

const (
	SecretObjectSchema = "cdnca.edge.origin-auth-secret/v1"
	// MaxSecretObjectBytes bounds one secret object (the Lua reader too).
	MaxSecretObjectBytes = 64 << 10
	secretObjectsKept    = 2
)

var ErrSecretObject = errors.New("origin auth secret object")

type SecretObject struct {
	Schema   string     `json:"schema"`
	RuleID   string     `json:"rule_id"`
	Revision uint64     `json:"revision"`
	Rule     SecretRule `json:"rule"`
}

type SecretRule struct {
	RuleID                string     `json:"rule_id"`
	Provider              string     `json:"provider"`
	Algorithm             string     `json:"algorithm"`
	Endpoint              Endpoint   `json:"endpoint"`
	Bucket                string     `json:"bucket"`
	PathPrefix            string     `json:"path_prefix"`
	Region                string     `json:"region"`
	Service               string     `json:"service"`
	SignatureTTLSeconds   uint32     `json:"signature_ttl_seconds"`
	CurrentKey            SecretKey  `json:"current_key"`
	PreviousKey           *SecretKey `json:"previous_key,omitempty"`
	ActivateCurrentAtUnix int64      `json:"activate_current_at_unix"`
}

type SecretKey struct {
	KeyID      string     `json:"key_id"`
	Credential Credential `json:"credential"`
}

// SecretObjectDir is where the installer writes secret objects for the
// workers. GID < 0 keeps the process's group (tests).
type SecretObjectDir struct {
	Root string
	GID  int
}

func (dir SecretObjectDir) Path(ruleID string, revision uint64) string {
	return filepath.Join(dir.Root, ruleID, strconv.FormatUint(revision, 10)+".json")
}

func (dir SecretObjectDir) apply(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if dir.GID >= 0 {
		return os.Lchown(path, -1, dir.GID)
	}
	return nil
}

func (dir SecretObjectDir) mkdir(path string) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(path, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	case err != nil:
		return err
	case !info.IsDir() || info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%w: %s is not a directory", ErrSecretObject, path)
	}
	return dir.apply(path, 0o750)
}

// secretObjects builds one object per compiled rule; credentials come from
// the opened snapshot (by revision ref = key ID).
func secretObjects(policy *CompiledPolicy, revision uint64, credentials map[string]productionSnapshotCredential) ([]SecretObject, error) {
	key := func(compiled CompiledKey, provider string) (SecretKey, error) {
		value, ok := credentials[compiled.KeyID]
		if !ok || value.Provider != provider {
			return SecretKey{}, fmt.Errorf("%w: credential %s", ErrSecretObject, compiled.KeyID)
		}
		return SecretKey{KeyID: compiled.KeyID, Credential: Credential{SchemaVersion: CredentialVersion, Provider: value.Provider,
			AccessKeyID: value.AccessKeyID, SecretAccessKey: value.SecretAccessKey, SessionToken: value.SessionToken,
			NotBeforeUnix: value.NotBeforeUnix, ExpiresAtUnix: value.ExpiresAtUnix}}, nil
	}
	objects := make([]SecretObject, 0, len(policy.Rules))
	for _, rule := range policy.Rules {
		current, err := key(rule.CurrentKey, rule.Provider)
		if err != nil {
			return nil, err
		}
		secret := SecretRule{RuleID: rule.RuleID, Provider: rule.Provider, Algorithm: rule.Algorithm, Endpoint: rule.Endpoint,
			Bucket: rule.Bucket, PathPrefix: rule.PathPrefix, Region: rule.Region, Service: rule.Service,
			SignatureTTLSeconds: rule.SignatureTTLSeconds, CurrentKey: current, ActivateCurrentAtUnix: rule.ActivateCurrentAtUnix}
		if rule.PreviousKey != nil {
			previous, err := key(*rule.PreviousKey, rule.Provider)
			if err != nil {
				return nil, err
			}
			secret.PreviousKey = &previous
		}
		objects = append(objects, SecretObject{Schema: SecretObjectSchema, RuleID: rule.RuleID, Revision: revision, Rule: secret})
	}
	return objects, nil
}

// Write stores objects (an existing object of the same revision must be
// byte-identical) and prunes: per rule the newest secretObjectsKept
// revisions, and rules not in objects.
func (dir SecretObjectDir) Write(objects []SecretObject) error {
	if !cleanProductionRoot(dir.Root) {
		return fmt.Errorf("%w: root %q", ErrSecretObject, dir.Root)
	}
	if err := dir.mkdir(dir.Root); err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, object := range objects {
		if object.Schema != SecretObjectSchema || !canonicalProductionUUID(object.RuleID) || object.Revision == 0 || object.Rule.RuleID != object.RuleID {
			return fmt.Errorf("%w: identity", ErrSecretObject)
		}
		raw, err := json.Marshal(object)
		if err != nil || len(raw) > MaxSecretObjectBytes {
			clear(raw)
			return fmt.Errorf("%w: encode", ErrSecretObject)
		}
		wanted[object.RuleID] = true
		err = dir.put(object, raw)
		clear(raw)
		if err != nil {
			return err
		}
	}
	return dir.prune(wanted)
}

func (dir SecretObjectDir) put(object SecretObject, raw []byte) error {
	parent := filepath.Join(dir.Root, object.RuleID)
	if err := dir.mkdir(parent); err != nil {
		return err
	}
	path := dir.Path(object.RuleID, object.Revision)
	if existing, err := os.ReadFile(path); err == nil {
		same := bytes.Equal(existing, raw)
		clear(existing)
		if !same {
			return fmt.Errorf("%w: revision %d of %s changed", ErrSecretObject, object.Revision, object.RuleID)
		}
		return nil
	}
	temp, err := os.CreateTemp(parent, ".secret-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := dir.apply(name, 0o440); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func (dir SecretObjectDir) prune(wanted map[string]bool) error {
	rules, err := os.ReadDir(dir.Root)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		path := filepath.Join(dir.Root, rule.Name())
		if !rule.IsDir() || !canonicalProductionUUID(rule.Name()) {
			continue
		}
		if !wanted[rule.Name()] {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
			continue
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		var revisions []uint64
		for _, entry := range entries {
			name := entry.Name()
			if value, err := strconv.ParseUint(name[:max(0, len(name)-len(".json"))], 10, 64); err == nil && filepath.Ext(name) == ".json" {
				revisions = append(revisions, value)
			}
		}
		sort.Slice(revisions, func(i, j int) bool { return revisions[i] > revisions[j] })
		for index, revision := range revisions {
			if index >= secretObjectsKept {
				if err := os.Remove(dir.Path(rule.Name(), revision)); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return err
				}
			}
		}
	}
	return nil
}
