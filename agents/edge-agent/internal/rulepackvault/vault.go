// Package rulepackvault is the node side of encrypted rule packs (ADR 0007
// §6, PA-14).
//
//   - The control plane delivers, per node, the pack's content key (CEK)
//     wrapped to the node's artifact encryption key (rulepack.WrapKey,
//     purpose node) next to the sealed object (cdnca.rule-pack-sealed/v1)
//     in the object store. Neither is usable without the node's private key,
//     so both may rest on disk: the wraps in an owner-only state file, the
//     sealed bytes in the object store. After a restart the vault reloads
//     the wraps and opens packs again from the object store.
//   - Opening happens in memory only: the CEK is unwrapped, the pack
//     decrypted and compiled (rulepack.Open), and the CEK and plaintext are
//     cleared. The Lua engines receive compiled rules, never a file.
//   - ModSecurity needs a file: WriteModSecurity puts it on a tmpfs (Linux:
//     statfs TMPFS_MAGIC is required), mode 0600, owned by the nginx user
//     when one is configured. tmpfs never reaches the disk and is gone at
//     reboot; the node rewrites it from the vault.
//
// This protects against copying and casual reading, not against node root.
package rulepackvault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/cdnca/cdnca/libs/rulepack"
)

const (
	StateSchema = "cdnca.edge.rule-pack-keys/v1"
	StateFile   = "rule-pack-keys.json"
	maxWraps    = 4096
	maxState    = 4 << 20
)

var (
	ErrInvalidConfig = errors.New("invalid rule pack vault configuration")
	// ErrNoKey: no wrapped key for this sealed object and the node key.
	ErrNoKey = errors.New("no content key for this sealed rule pack")
	// ErrNotTmpfs: the ModSecurity directory is not a tmpfs mount.
	ErrNotTmpfs = errors.New("rule pack directory is not on tmpfs")

	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	siteIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Wrap is one wrapped content key for one sealed object (control plane
// node_rule_pack_keys row).
type Wrap struct {
	SealedSHA256   string `json:"sealed_sha256"`
	PackID         string `json:"pack_id"`
	Version        string `json:"version"`
	RecipientKeyID string `json:"recipient_key_id"`
	WrappedKey     string `json:"wrapped_key"`
}

type state struct {
	Schema string `json:"schema"`
	Wraps  []Wrap `json:"wraps"`
}

// Config: PrivateKey is the node's raw X25519 artifact encryption key;
// Objects returns the bytes of a content-addressed object.
type Config struct {
	PrivateKey []byte
	StateDir   string
	Objects    func(sha256 string) ([]byte, error)
	// ModSecurityDir is a tmpfs directory for ModSecurity packs ("" = none).
	ModSecurityDir string
	// PlanDir is a tmpfs directory for the compiled rule plans of mounted
	// Lua-engine packs (cdnca_security reads <PlanDir>/<resolved>.json;
	// "" = none). Files are 0640, group PlanGID (the worker group; -1 =
	// leave as is): a plan holds a sealed pack's rules in clear.
	PlanDir string
	PlanGID int
	// Owner of the ModSecurity files (the nginx user); -1 = leave as is.
	OwnerUID, OwnerGID int
	// requireTmpfs is false only in tests on hosts without tmpfs.
	requireTmpfs bool
}

type Vault struct {
	config Config
	keyID  string
	mu     sync.Mutex
	wraps  map[string]Wrap // sealed sha256 -> wrap for this node key
}

// Open loads the vault state (wraps for another node key are dropped: the
// key rotated and the control plane wraps again).
func Open(config Config) (*Vault, error) {
	config.requireTmpfs = true
	return open(config)
}

func open(config Config) (*Vault, error) {
	public, err := rulepack.X25519PublicKey(config.PrivateKey)
	if err != nil || config.Objects == nil || !filepath.IsAbs(config.StateDir) ||
		config.ModSecurityDir != "" && !filepath.IsAbs(config.ModSecurityDir) ||
		config.PlanDir != "" && !filepath.IsAbs(config.PlanDir) {
		return nil, ErrInvalidConfig
	}
	config.PrivateKey = bytes.Clone(config.PrivateKey)
	if err := os.MkdirAll(config.StateDir, 0o700); err != nil {
		return nil, err
	}
	vault := &Vault{config: config, keyID: rulepack.X25519KeyID(public), wraps: map[string]Wrap{}}
	encoded, err := readOwnerOnly(filepath.Join(config.StateDir, StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return vault, nil
	}
	if err != nil {
		return nil, err
	}
	var loaded state
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&loaded); err != nil || loaded.Schema != StateSchema {
		return nil, fmt.Errorf("rule pack vault state is invalid: %v", err)
	}
	for _, wrap := range loaded.Wraps {
		if wrap.RecipientKeyID == vault.keyID && digestPattern.MatchString(wrap.SealedSHA256) {
			vault.wraps[wrap.SealedSHA256] = wrap
		}
	}
	return vault, nil
}

// KeyID is the node key the vault opens wraps for.
func (vault *Vault) KeyID() string { return vault.keyID }

// Replace makes wraps the complete set (the delivered set for this node);
// each must open with the node key for its object. Nothing changes when
// one does not.
func (vault *Vault) Replace(wraps []Wrap) error {
	if len(wraps) > maxWraps {
		return fmt.Errorf("%w: too many wrapped keys", rulepack.ErrKeyRejected)
	}
	next := make(map[string]Wrap, len(wraps))
	for _, wrap := range wraps {
		if wrap.RecipientKeyID != vault.keyID {
			return fmt.Errorf("%w: wrapped for %s", rulepack.ErrKeyRejected, wrap.RecipientKeyID)
		}
		cek, err := rulepack.UnwrapKey(vault.config.PrivateKey, wrap.WrappedKey, wrap.context())
		if err != nil {
			return err
		}
		clear(cek)
		next[wrap.SealedSHA256] = wrap
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if err := vault.store(next); err != nil {
		return err
	}
	vault.wraps = next
	return nil
}

func (wrap Wrap) context() rulepack.WrapContext {
	return rulepack.WrapContext{Purpose: rulepack.WrapPurposeNode, RecipientKeyID: wrap.RecipientKeyID,
		PackID: wrap.PackID, Version: wrap.Version, SealedSHA256: wrap.SealedSHA256}
}

// Load returns the compiled pack stored under sha256: a plain pack as is
// (rulepack.Load), a sealed one opened in memory with its wrapped key. It is
// the object loader of rulepackprecheck.
func (vault *Vault) Load(content []byte, sha256 string) (*rulepack.CompiledPack, error) {
	if !rulepack.IsSealed(content) {
		return rulepack.Load(content, sha256)
	}
	vault.mu.Lock()
	wrap, ok := vault.wraps[sha256]
	vault.mu.Unlock()
	if !ok {
		return nil, ErrNoKey
	}
	return vault.open(content, sha256, wrap)
}

// Check opens a pack delivered with the node artifact set before it is
// installed: a plain pack loads; a sealed one must open in memory with the
// item's wrapped key (recipient: this node key). Nothing is stored.
func (vault *Vault) Check(content []byte, sha256, recipientKeyID, wrappedKey string) (*rulepack.CompiledPack, error) {
	if !rulepack.IsSealed(content) {
		if wrappedKey != "" {
			return nil, fmt.Errorf("%w: key for a plain pack", rulepack.ErrKeyRejected)
		}
		return rulepack.Load(content, sha256)
	}
	if wrappedKey == "" {
		return nil, ErrNoKey
	}
	manifest, err := rulepack.OpenManifest(content, sha256)
	if err != nil {
		return nil, err
	}
	if recipientKeyID != vault.keyID {
		return nil, fmt.Errorf("%w: wrapped for %s", rulepack.ErrKeyRejected, recipientKeyID)
	}
	return vault.open(content, sha256, Wrap{SealedSHA256: sha256, PackID: manifest.Pack.PackID, Version: manifest.Pack.Version,
		RecipientKeyID: recipientKeyID, WrappedKey: wrappedKey})
}

func (vault *Vault) open(content []byte, sha256 string, wrap Wrap) (*rulepack.CompiledPack, error) {
	cek, err := rulepack.UnwrapKey(vault.config.PrivateKey, wrap.WrappedKey, wrap.context())
	if err != nil {
		return nil, err
	}
	defer clear(cek)
	compiled, err := rulepack.Open(content, sha256, cek)
	if err != nil {
		return nil, err
	}
	if compiled.Pack.PackID != wrap.PackID || compiled.Pack.Version != wrap.Version {
		return nil, fmt.Errorf("%w: sealed object is %s %s, key is for %s %s", rulepack.ErrSealRejected,
			compiled.Pack.PackID, compiled.Pack.Version, wrap.PackID, wrap.Version)
	}
	return compiled, nil
}

// Object returns the stored bytes of a pack object (precheck's Objects).
func (vault *Vault) Object(sha256 string) ([]byte, error) { return vault.config.Objects(sha256) }

// OpenObject loads a pack from the object store (restart recovery path).
func (vault *Vault) OpenObject(sha256 string) (*rulepack.CompiledPack, error) {
	content, err := vault.config.Objects(sha256)
	if err != nil {
		return nil, err
	}
	return vault.Load(content, sha256)
}

func (vault *Vault) store(wraps map[string]Wrap) error {
	list := make([]Wrap, 0, len(wraps))
	for _, wrap := range wraps {
		list = append(list, wrap)
	}
	sort.Slice(list, func(left, right int) bool { return list[left].SealedSHA256 < list[right].SealedSHA256 })
	encoded, err := json.Marshal(state{Schema: StateSchema, Wraps: list})
	if err != nil {
		return err
	}
	return writeOwnerOnly(vault.config.StateDir, StateFile, encoded, -1, -1)
}

// WriteModSecurity writes a ModSecurity rule file of an opened pack to the
// tmpfs directory (mode 0600, the nginx user as owner) and returns its path.
// name is a file name ([a-z0-9._-]); content is the rendered directives.
func (vault *Vault) WriteModSecurity(name string, content []byte) (string, error) {
	dir := vault.config.ModSecurityDir
	if dir == "" || !regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`).MatchString(name) {
		return "", ErrInvalidConfig
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if vault.config.requireTmpfs {
		onTmpfs, err := isTmpfs(dir)
		if err != nil {
			return "", err
		}
		if !onTmpfs {
			return "", fmt.Errorf("%w: %s", ErrNotTmpfs, dir)
		}
	}
	if err := writeOwnerOnly(dir, name, content, vault.config.OwnerUID, vault.config.OwnerGID); err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// PlanDir is the rule plan directory ("" = none configured).
func (vault *Vault) PlanDir() string { return vault.config.PlanDir }

// WritePlan writes the rule plan of resolved (a site's resolved_sha256) to
// the tmpfs plan directory, group readable by the workers.
func (vault *Vault) WritePlan(resolved string, plan []byte) error {
	if !digestPattern.MatchString(resolved) {
		return ErrInvalidConfig
	}
	return vault.writePlanFile(resolved+".json", plan)
}

// WriteCCPlan writes the CC v2 pack policy of one site of resolved:
// <resolved>.<site_id>.cc.json (the policy names the site, so sites with the
// same mounts each have their own).
func (vault *Vault) WriteCCPlan(resolved, siteID string, policy []byte) error {
	if !digestPattern.MatchString(resolved) || !siteIDPattern.MatchString(siteID) {
		return ErrInvalidConfig
	}
	return vault.writePlanFile(resolved+"."+siteID+".cc.json", policy)
}

func (vault *Vault) writePlanFile(name string, plan []byte) error {
	dir := vault.config.PlanDir
	if dir == "" {
		return ErrInvalidConfig
	}
	// Parents traversable (the workers open the file by path), the
	// directory itself listable by the worker group only.
	// Modes are set explicitly: the agent unit's UMask=0077 would leave them
	// 0700 and the workers could not open any plan.
	if err := mkdirAllMode(filepath.Dir(dir), 0o711); err != nil {
		return err
	}
	// Existing parents too (/run/cdnca and /run/cdnca/rule-packs left 0700
	// by an older agent): an upgraded agent repairs them without a reboot.
	for _, parent := range []string{filepath.Dir(dir), filepath.Dir(filepath.Dir(dir))} {
		if err := ensureTraversable(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	if vault.config.PlanGID >= 0 {
		if err := os.Chown(dir, -1, vault.config.PlanGID); err != nil {
			return err
		}
	}
	if vault.config.requireTmpfs {
		onTmpfs, err := isTmpfs(dir)
		if err != nil {
			return err
		}
		if !onTmpfs {
			return fmt.Errorf("%w: %s", ErrNotTmpfs, dir)
		}
	}
	if err := writeOwnerOnly(dir, name, plan, -1, vault.config.PlanGID); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(dir, name), 0o640)
}

// RetainPlans removes every plan (rule plan or CC pack policy) whose
// resolved digest is not in keep.
func (vault *Vault) RetainPlans(keep map[string]bool) error {
	dir := vault.config.PlanDir
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	names := map[string]bool{}
	for _, entry := range entries {
		// <resolved>.json or <resolved>.<site_id>.cc.json
		if name := entry.Name(); len(name) > 65 && name[64] == '.' && keep[name[:64]] {
			names[name] = true
		}
	}
	return removeExcept(dir, names)
}

// RemoveModSecurity drops every ModSecurity file not in keep.
func (vault *Vault) RemoveModSecurity(keep map[string]bool) error {
	if vault.config.ModSecurityDir == "" {
		return nil
	}
	return removeExcept(vault.config.ModSecurityDir, keep)
}

func removeExcept(dir string, keep map[string]bool) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !keep[entry.Name()] {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func readOwnerOnly(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxState {
		return nil, fmt.Errorf("rule pack vault state %s must be an owner-only regular file", path)
	}
	return os.ReadFile(path)
}

// writeOwnerOnly replaces dir/name atomically with an owner-only file.
// mkdirAllMode is os.MkdirAll that sets mode on every directory it creates
// (the umask does not narrow it); existing directories are left alone.
func mkdirAllMode(dir string, mode os.FileMode) error {
	var missing []string
	for current := dir; ; current = filepath.Dir(current) {
		if _, err := os.Stat(current); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		if filepath.Dir(current) == current {
			break
		}
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	for _, created := range missing {
		if err := os.Chmod(created, mode); err != nil {
			return err
		}
	}
	return nil
}

// ensureTraversable sets an existing plan parent to 0711. It must be a real
// directory (not a symlink) owned by the agent's user (root on nodes);
// anything else is refused, never skipped.
func ensureTraversable(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("rule plan parent %s is not a real directory (mode %v)", dir, info.Mode())
	}
	if uid, ok := ownerUID(info); !ok || uid != os.Geteuid() {
		return fmt.Errorf("rule plan parent %s is owned by uid %d, want %d", dir, uid, os.Geteuid())
	}
	if info.Mode().Perm() == 0o711 {
		return nil
	}
	return os.Chmod(dir, 0o711)
}

func writeOwnerOnly(dir, name string, content []byte, uid, gid int) error {
	temp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	err = temp.Chmod(0o600)
	if err == nil && (uid >= 0 || gid >= 0) {
		err = temp.Chown(uid, gid)
	}
	if err == nil {
		_, err = temp.Write(content)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tempName, filepath.Join(dir, name))
}
