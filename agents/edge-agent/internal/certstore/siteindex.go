package certstore

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Site index (sites/, byversion/, gc/).
//
// A certificate activation is a per-site delta: a command carries the sites it
// changes, each with its binding revision (the control plane's per-site
// binding fact sequence), and the node keeps every site it was given. Each
// site has sites/<shard>/<key>/site.json (binding revision, active binding,
// versions kept for rollback) and one immutable directory per version with
// certificate.pem and private-key.pem (0400, validated before activation).
// byversion/<shard>/<version>/<key>.a|.r names the sites holding a version
// actively or retained, so references are checked and versions collected
// without scanning sites; gc/<version> marks versions that may have lost their
// last holder.
//
// The index changes only after the command's release is healthy. The changes
// are written to index-journal.json, bound to the release target, before the
// current pointer moves, and applied (idempotently) or discarded once the
// outcome is known (settleIndexFor).

const (
	siteRecordSchemaVersion   = "cdnca.edge.certificate-site/v1"
	indexJournalSchemaVersion = "cdnca.edge.certificate-index-journal/v1"
	maxSiteRecordBytes        = 1 << 20
	maxIndexJournalBytes      = 64 << 20
	siteRecordFile            = "site.json"
	siteCertificateFile       = "certificate.pem"
	sitePrivateKeyFile        = "private-key.pem"
	activeHolderSuffix        = ".a"
	retainedHolderSuffix      = ".r"
	siteRecordCacheSize       = 4096
)

// syncSet collects directories whose entries changed; they are synced once,
// before the change that needs them durable (the journal's removal) is made.
// File contents are synced before they become visible.
type syncSet map[string]struct{}

func (set syncSet) add(paths ...string) {
	for _, path := range paths {
		set[path] = struct{}{}
	}
}

// sync syncs and forgets the collected directories.
func (set syncSet) sync() error {
	for path := range set {
		if err := syncDirectory(path); err != nil {
			return err
		}
		delete(set, path)
	}
	return nil
}

// siteBinding is one certificate version as a site binds it.
type siteBinding struct {
	CertificateID        string    `json:"certificate_id"`
	CertificateVersionID string    `json:"certificate_version_id"`
	Version              uint64    `json:"version"`
	Domains              []string  `json:"domains"`
	LeafSHA256           string    `json:"leaf_sha256"`
	CertificateSHA256    string    `json:"certificate_sha256"`
	CertificateBytes     int64     `json:"certificate_bytes"`
	KeySHA256            string    `json:"key_sha256"`
	KeyBytes             int64     `json:"key_bytes"`
	NotBefore            time.Time `json:"not_before"`
	NotAfter             time.Time `json:"not_after"`
}

// siteRecord is a site's certificate state. A removed site keeps its record
// (no active binding) so an older binding cannot be activated again.
type siteRecord struct {
	SchemaVersion   string        `json:"schema_version"`
	TenantID        string        `json:"tenant_id"`
	TenantScopeID   string        `json:"tenant_scope_id"`
	SiteID          string        `json:"site_id"`
	BindingRevision uint64        `json:"binding_revision"`
	Active          *siteBinding  `json:"active,omitempty"`
	Retained        []siteBinding `json:"retained,omitempty"`
}

func validSiteBinding(binding siteBinding) bool {
	if !validIdentifier(binding.CertificateID, MaxSiteIDBytes) || !canonicalUUID(binding.CertificateVersionID) ||
		binding.Version == 0 || len(binding.Domains) == 0 || len(binding.Domains) > MaxDomainsPerSite ||
		!validDigest(binding.LeafSHA256) || !validDigest(binding.CertificateSHA256) || !validDigest(binding.KeySHA256) ||
		binding.CertificateBytes <= 0 || binding.CertificateBytes > MaxCertificateBytes ||
		binding.KeyBytes <= 0 || binding.KeyBytes > MaxPrivateKeyBytes ||
		binding.NotBefore.IsZero() || !binding.NotBefore.Before(binding.NotAfter) {
		return false
	}
	for index, domain := range binding.Domains {
		normalized, err := normalizeDomain(domain, true)
		if err != nil || normalized != domain || (index > 0 && binding.Domains[index-1] >= domain) {
			return false
		}
	}
	return true
}

func validSiteRecord(record siteRecord, key string) bool {
	if record.SchemaVersion != siteRecordSchemaVersion || !validIdentifier(record.TenantID, MaxSiteIDBytes) ||
		!canonicalUUID(record.TenantScopeID) || !validIdentifier(record.SiteID, MaxSiteIDBytes) ||
		record.BindingRevision == 0 || siteKey(record.TenantScopeID, record.SiteID) != key {
		return false
	}
	seen := make(map[string]struct{}, len(record.Retained)+1)
	if record.Active != nil {
		if !validSiteBinding(*record.Active) {
			return false
		}
		seen[record.Active.CertificateVersionID] = struct{}{}
	}
	for _, binding := range record.Retained {
		if _, duplicate := seen[binding.CertificateVersionID]; duplicate || !validSiteBinding(binding) {
			return false
		}
		seen[binding.CertificateVersionID] = struct{}{}
	}
	return true
}

func (record siteRecord) clone() siteRecord {
	result := record
	if record.Active != nil {
		active := cloneSiteBinding(*record.Active)
		result.Active = &active
	}
	result.Retained = make([]siteBinding, len(record.Retained))
	for index, binding := range record.Retained {
		result.Retained[index] = cloneSiteBinding(binding)
	}
	if len(result.Retained) == 0 {
		result.Retained = nil
	}
	return result
}

func cloneSiteBinding(binding siteBinding) siteBinding {
	binding.Domains = append([]string(nil), binding.Domains...)
	return binding
}

// sameVersionContent: two bindings of one version name the same immutable
// material (domains are the site's, and may differ).
func sameVersionContent(left, right siteBinding) bool {
	return left.CertificateID == right.CertificateID && left.CertificateVersionID == right.CertificateVersionID &&
		left.Version == right.Version && left.LeafSHA256 == right.LeafSHA256 &&
		left.CertificateSHA256 == right.CertificateSHA256 && left.KeySHA256 == right.KeySHA256 &&
		left.CertificateBytes == right.CertificateBytes && left.KeyBytes == right.KeyBytes
}

func sameSiteBinding(left, right siteBinding) bool {
	return sameVersionContent(left, right) && slices.Equal(left.Domains, right.Domains) &&
		left.NotBefore.Equal(right.NotBefore) && left.NotAfter.Equal(right.NotAfter)
}

// siteKey names a site's directory: site IDs are only unique within a scope.
func siteKey(tenantScopeID, siteID string) string {
	digest := sha256.Sum256([]byte("cdnca-certificate-site-v1\x00" + tenantScopeID + "\x00" + siteID))
	return hex.EncodeToString(digest[:16])
}

func validSiteKey(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func versionShard(versionID string) string {
	digest := sha256.Sum256([]byte(versionID))
	return hex.EncodeToString(digest[:1])
}

func (store *diskStore) siteDirectory(key string) string {
	return filepath.Join(store.sites, key[:2], key)
}

func (store *diskStore) siteRecordPath(key string) string {
	return filepath.Join(store.siteDirectory(key), siteRecordFile)
}

func (store *diskStore) siteVersionDirectory(key, versionID string) string {
	return filepath.Join(store.siteDirectory(key), versionID)
}

func (store *diskStore) holderDirectory(versionID string) string {
	return filepath.Join(store.byVersion, versionShard(versionID), versionID)
}

// readSiteRecord reads a site's record; found is false when the site has none.
func (store *diskStore) readSiteRecord(key string) (siteRecord, bool, error) {
	if !validSiteKey(key) {
		return siteRecord{}, false, fmt.Errorf("%w: site key is invalid", ErrUnsafeState)
	}
	path := store.siteRecordPath(key)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return siteRecord{}, false, nil
	}
	raw, err := validatePrivateFile(path, maxSiteRecordBytes)
	if err != nil {
		return siteRecord{}, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record siteRecord
	if err := decoder.Decode(&record); err != nil || requireJSONEOF(decoder) != nil || !validSiteRecord(record, key) {
		return siteRecord{}, false, fmt.Errorf("%w: site record is invalid", ErrUnsafeState)
	}
	return record, true, nil
}

func (store *diskStore) writeSiteRecord(key string, record siteRecord, dirs syncSet) error {
	if !validSiteRecord(record, key) {
		return fmt.Errorf("%w: site record is invalid", ErrUnsafeState)
	}
	if err := store.ensureIndexDirectories(dirs, filepath.Join(store.sites, key[:2]), store.siteDirectory(key)); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal site record: %w", err)
	}
	dirs.add(store.siteDirectory(key))
	return replaceFile(store.siteRecordPath(key), append(raw, '\n'))
}

// ensureIndexDirectories creates each missing directory (parents first) as
// a private mutable directory; the parent of a created one must be synced.
func (store *diskStore) ensureIndexDirectories(dirs syncSet, paths ...string) error {
	for _, path := range paths {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			dirs.add(filepath.Dir(path))
		}
		if err := ensurePrivateDirectory(path, true); err != nil {
			return err
		}
	}
	return nil
}

// materializeSiteVersion writes a version's files into the site's directory
// once; an existing directory must hold exactly the binding's files.
func (store *diskStore) materializeSiteVersion(key string, binding siteBinding, certificate, privateKey []byte, dirs syncSet) error {
	directory := store.siteVersionDirectory(key, binding.CertificateVersionID)
	if info, err := os.Lstat(directory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: site version path is unsafe", ErrUnsafeState)
		}
		return store.verifySiteVersion(key, binding)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: inspect site version", ErrUnsafeState)
	}
	parent := store.siteDirectory(key)
	if err := store.ensureIndexDirectories(dirs, filepath.Join(store.sites, key[:2]), parent); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(parent, ".version-")
	if err != nil {
		return fmt.Errorf("stage site version: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Chmod(temporary, 0o700)
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return fmt.Errorf("secure site version: %w", err)
	}
	if err := writeExclusive(filepath.Join(temporary, siteCertificateFile), certificate, 0o400); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(temporary, sitePrivateKeyFile), privateKey, 0o400); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0o500); err != nil {
		return fmt.Errorf("make site version immutable: %w", err)
	}
	if err := os.Rename(temporary, directory); err != nil {
		return fmt.Errorf("commit site version: %w", err)
	}
	committed = true
	dirs.add(parent, directory)
	return store.verifySiteVersion(key, binding)
}

// verifySiteVersion reads a version's files once and checks them against the
// digests recorded when the version was validated.
func (store *diskStore) verifySiteVersion(key string, binding siteBinding) error {
	directory := store.siteVersionDirectory(key, binding.CertificateVersionID)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o500 {
		return fmt.Errorf("%w: site version directory is not immutable", ErrUnsafeState)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 2 {
		return fmt.Errorf("%w: site version directory content is unexpected", ErrUnsafeState)
	}
	for _, file := range []struct {
		name, digest string
		size         int64
	}{
		{siteCertificateFile, binding.CertificateSHA256, binding.CertificateBytes},
		{sitePrivateKeyFile, binding.KeySHA256, binding.KeyBytes},
	} {
		content, err := readImmutableCertificateFile(filepath.Join(directory, file.name), file.size)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(content)
		clearBytesInPlace(content)
		if int64(len(content)) != file.size || hex.EncodeToString(digest[:]) != file.digest {
			return ErrConflict
		}
	}
	return nil
}

// removeSiteVersion removes a version directory a site no longer keeps.
func (store *diskStore) removeSiteVersion(key, versionID string) error {
	directory := store.siteVersionDirectory(key, versionID)
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("remove site version: %w", err)
	}
	if err := os.RemoveAll(directory); err != nil {
		return fmt.Errorf("remove site version: %w", err)
	}
	return syncDirectory(store.siteDirectory(key))
}

// setHolder records that key holds versionID, actively or retained.
func (store *diskStore) setHolder(versionID, key string, active bool, dirs syncSet) error {
	directory := store.holderDirectory(versionID)
	if err := store.ensureIndexDirectories(dirs, filepath.Dir(directory), directory); err != nil {
		return err
	}
	dirs.add(directory)
	want, other := activeHolderSuffix, retainedHolderSuffix
	if !active {
		want, other = retainedHolderSuffix, activeHolderSuffix
	}
	target := filepath.Join(directory, key+want)
	stale := filepath.Join(directory, key+other)
	if _, err := os.Lstat(target); err == nil {
		if err := os.Remove(stale); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("update version holder: %w", err)
		}
		return nil
	}
	if err := os.Rename(stale, target); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("update version holder: %w", err)
		}
		return writeMarker(target)
	}
	return nil
}

// writeMarker creates an empty marker; only its directory entry matters.
func writeMarker(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("write index marker: %w", err)
	}
	return file.Close()
}

// holders lists the sites holding versionID: key -> active.
func (store *diskStore) holders(versionID string) (map[string]bool, error) {
	entries, err := os.ReadDir(store.holderDirectory(versionID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read version holders", ErrUnsafeState)
	}
	result := make(map[string]bool, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		key, active := strings.CutSuffix(name, activeHolderSuffix)
		if !active {
			var retained bool
			key, retained = strings.CutSuffix(name, retainedHolderSuffix)
			if !retained {
				return nil, fmt.Errorf("%w: version holder is invalid", ErrUnsafeState)
			}
		}
		if !entry.Type().IsRegular() || !validSiteKey(key) {
			return nil, fmt.Errorf("%w: version holder is invalid", ErrUnsafeState)
		}
		result[key] = result[key] || active
	}
	return result, nil
}

func (store *diskStore) removeHolder(versionID, key string) error {
	directory := store.holderDirectory(versionID)
	for _, suffix := range []string{activeHolderSuffix, retainedHolderSuffix} {
		if err := os.Remove(filepath.Join(directory, key+suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove version holder: %w", err)
		}
	}
	// The directory stays while another site holds the version.
	if err := os.Remove(directory); err != nil && !errors.Is(err, os.ErrNotExist) &&
		!errors.Is(err, syscall.ENOTEMPTY) && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("remove version holders: %w", err)
	}
	return syncDirectory(filepath.Dir(directory))
}

// markCollectable records that versionID may have lost its last holder.
func (store *diskStore) markCollectable(versionID string, dirs syncSet) error {
	dirs.add(store.gc)
	return writeMarker(filepath.Join(store.gc, versionID))
}

func (store *diskStore) collectable() ([]string, error) {
	entries, err := os.ReadDir(store.gc)
	if err != nil {
		return nil, fmt.Errorf("%w: read collectable versions", ErrUnsafeState)
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !canonicalUUID(entry.Name()) {
			return nil, fmt.Errorf("%w: collectable version is invalid", ErrUnsafeState)
		}
		result = append(result, entry.Name())
	}
	return result, nil
}

func (store *diskStore) clearCollectable(versionID string) error {
	if err := os.Remove(filepath.Join(store.gc, versionID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear collectable version: %w", err)
	}
	return nil
}

// indexJournal is the index change of one release: each changed site's new
// record, the versions to materialize from the release, and the versions that
// left a site's active slot.
type indexJournal struct {
	SchemaVersion string             `json:"schema_version"`
	Target        string             `json:"target"`
	Sites         []indexJournalSite `json:"sites"`
}

type indexJournalSite struct {
	Key         string                 `json:"key"`
	Record      siteRecord             `json:"record"`
	Materialize []indexJournalMaterial `json:"materialize,omitempty"`
	Retire      []string               `json:"retire,omitempty"`
}

// indexJournalMaterial names a version's files in the release (relative).
type indexJournalMaterial struct {
	CertificateVersionID string `json:"certificate_version_id"`
	CertificateFile      string `json:"certificate_file"`
	PrivateKeyFile       string `json:"private_key_file"`
}

func (store *diskStore) writeIndexJournal(journal indexJournal) error {
	journal.SchemaVersion = indexJournalSchemaVersion
	raw, err := json.Marshal(journal)
	if err != nil || len(raw) > maxIndexJournalBytes {
		return fmt.Errorf("%w: index journal is too large", ErrInvalidBundle)
	}
	return writeAtomicFile(store.indexJournalPath, append(raw, '\n'))
}

// readIndexJournal: found is false when no change is pending.
func (store *diskStore) readIndexJournal() (indexJournal, bool, error) {
	if _, err := os.Lstat(store.indexJournalPath); errors.Is(err, os.ErrNotExist) {
		return indexJournal{}, false, nil
	}
	raw, err := validatePrivateFile(store.indexJournalPath, maxIndexJournalBytes)
	if err != nil {
		return indexJournal{}, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var journal indexJournal
	if err := decoder.Decode(&journal); err != nil || requireJSONEOF(decoder) != nil ||
		journal.SchemaVersion != indexJournalSchemaVersion || !validReleaseTarget(journal.Target) {
		return indexJournal{}, false, fmt.Errorf("%w: index journal is invalid", ErrUnsafeState)
	}
	for _, site := range journal.Sites {
		if !validSiteRecord(site.Record, site.Key) {
			return indexJournal{}, false, fmt.Errorf("%w: index journal site is invalid", ErrUnsafeState)
		}
		for _, material := range site.Materialize {
			if !canonicalUUID(material.CertificateVersionID) || !safeRelativePath(material.CertificateFile) ||
				!safeRelativePath(material.PrivateKeyFile) {
				return indexJournal{}, false, fmt.Errorf("%w: index journal material is invalid", ErrUnsafeState)
			}
		}
		for _, versionID := range site.Retire {
			if !canonicalUUID(versionID) {
				return indexJournal{}, false, fmt.Errorf("%w: index journal retirement is invalid", ErrUnsafeState)
			}
		}
	}
	return journal, true, nil
}

func (store *diskStore) removeIndexJournal() error {
	if err := os.Remove(store.indexJournalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove index journal: %w", err)
	}
	return syncDirectory(store.root)
}

// applyIndexJournal applies a journal whose release is active and healthy.
// Every step is idempotent, so an interrupted apply is repeated. Versions are
// materialized and holders recorded before the record that names them, so a
// reader of site.json always finds the files it names.
func (manager *Manager) applyIndexJournal(journal indexJournal) error {
	release := filepath.Join(manager.store.root, journal.Target)
	dirs := syncSet{}
	for _, site := range journal.Sites {
		bindings := make(map[string]siteBinding, len(site.Record.Retained)+1)
		if site.Record.Active != nil {
			bindings[site.Record.Active.CertificateVersionID] = *site.Record.Active
		}
		for _, binding := range site.Record.Retained {
			bindings[binding.CertificateVersionID] = binding
		}
		for _, material := range site.Materialize {
			binding, found := bindings[material.CertificateVersionID]
			if !found {
				return fmt.Errorf("%w: index journal material is not in its record", ErrUnsafeState)
			}
			certificate, err := readImmutableCertificateFile(filepath.Join(release, material.CertificateFile), MaxCertificateBytes)
			if err != nil {
				return err
			}
			privateKey, err := readImmutableCertificateFile(filepath.Join(release, material.PrivateKeyFile), MaxPrivateKeyBytes)
			if err != nil {
				clearBytesInPlace(certificate)
				return err
			}
			err = manager.store.materializeSiteVersion(site.Key, binding, certificate, privateKey, dirs)
			clearBytesInPlace(certificate)
			clearBytesInPlace(privateKey)
			if err != nil {
				return err
			}
		}
		if site.Record.Active != nil {
			if err := manager.store.setHolder(site.Record.Active.CertificateVersionID, site.Key, true, dirs); err != nil {
				return err
			}
		}
		for _, binding := range site.Record.Retained {
			if err := manager.store.setHolder(binding.CertificateVersionID, site.Key, false, dirs); err != nil {
				return err
			}
		}
		for _, versionID := range site.Retire {
			if err := manager.store.markCollectable(versionID, dirs); err != nil {
				return err
			}
		}
		if err := manager.store.writeSiteRecord(site.Key, site.Record, dirs); err != nil {
			return err
		}
		manager.cache.forget(site.Key)
	}
	if err := dirs.sync(); err != nil {
		return err
	}
	return manager.store.removeIndexJournal()
}

// settleIndexFor settles a pending index change once selected is the release
// that stays active: the change is applied when it belongs to selected and
// discarded otherwise.
func (manager *Manager) settleIndexFor(selected string) error {
	journal, found, err := manager.store.readIndexJournal()
	if err != nil || !found {
		return err
	}
	if selected != "" && journal.Target == selected {
		return manager.applyIndexJournal(journal)
	}
	return manager.store.removeIndexJournal()
}

// settlePendingIndex settles a change left by an interrupted apply before
// the index is read. A change is applied only when its release became the
// healthy active release (current, lkg and status all name it); a change
// whose release never became current is discarded. Anything else is the
// state Recover resolves.
func (manager *Manager) settlePendingIndex() error {
	journal, found, err := manager.store.readIndexJournal()
	if err != nil || !found {
		return err
	}
	current, err := manager.store.readPointer("current")
	if err != nil {
		return err
	}
	lkg, err := manager.store.readPointer("lkg")
	if err != nil {
		return err
	}
	status, err := manager.store.readStatus()
	if err != nil {
		return err
	}
	switch {
	case current == journal.Target && lkg == journal.Target && statusTarget(status) == journal.Target:
		return manager.applyIndexJournal(journal)
	case current != journal.Target:
		return manager.store.removeIndexJournal()
	default:
		return fmt.Errorf("%w: a certificate activation was interrupted; recover first", ErrUnsafeState)
	}
}

type siteOutcome int

const (
	siteChanged siteOutcome = iota
	siteUnchanged
	siteStale
	siteConflict
)

// planIndex orders each site of a command by binding revision against the
// index: a lower revision is stale, the same revision must name the same
// binding, a higher one replaces it (another certificate asset included). A
// site's tenant never changes, and a version names the same material on every
// site. Only the command's sites are read.
func (manager *Manager) planIndex(artifact Artifact) (indexJournal, error) {
	activation := artifact.Activation
	if activation == nil {
		return indexJournal{}, nil
	}
	if err := sameCommandTenant(activation); err != nil {
		return indexJournal{}, err
	}
	bindings := make(map[string]ManifestBinding, len(artifact.Manifest.Bindings))
	for _, binding := range artifact.Manifest.Bindings {
		bindings[binding.SiteID] = binding
	}
	files := make(map[string][]byte, len(artifact.Files))
	for _, file := range artifact.Files {
		files[file.Path] = file.Content
	}
	journal := indexJournal{Target: filepath.Join("versions", artifact.VersionID+"-"+artifact.Digest)}
	seenVersions := make(map[string]siteBinding, len(activation.Certificates))
	stale := false
	for _, revision := range activation.Certificates {
		manifestBinding, found := bindings[revision.SiteID]
		if !found {
			return indexJournal{}, ErrInvalidBundle
		}
		incoming, err := incomingSiteBinding(revision, manifestBinding, files)
		if err != nil {
			return indexJournal{}, err
		}
		if previous, exists := seenVersions[incoming.CertificateVersionID]; exists && !sameVersionContent(previous, incoming) {
			return indexJournal{}, ErrConflict
		}
		seenVersions[incoming.CertificateVersionID] = incoming
		key := siteKey(revision.TenantScopeID, revision.SiteID)
		existing, found, err := manager.store.readSiteRecord(key)
		if err != nil {
			return indexJournal{}, err
		}
		record, retire, outcome := advanceSite(existing, found, revision, incoming)
		switch outcome {
		case siteConflict:
			return indexJournal{}, ErrConflict
		case siteStale:
			stale = true
			continue
		case siteUnchanged:
			continue
		}
		if err := manager.checkVersionImmutable(incoming); err != nil {
			return indexJournal{}, err
		}
		journal.Sites = append(journal.Sites, indexJournalSite{
			Key: key, Record: record, Retire: retire,
			Materialize: []indexJournalMaterial{{
				CertificateVersionID: incoming.CertificateVersionID,
				CertificateFile:      manifestBinding.CertificateFile, PrivateKeyFile: manifestBinding.PrivateKeyFile,
			}},
		})
	}
	for _, removed := range activation.RemovedSites {
		key := siteKey(removed.TenantScopeID, removed.SiteID)
		existing, found, err := manager.store.readSiteRecord(key)
		if err != nil {
			return indexJournal{}, err
		}
		record, retire, outcome := removeSite(existing, found, removed)
		switch outcome {
		case siteConflict:
			return indexJournal{}, ErrConflict
		case siteStale:
			stale = true
			continue
		case siteUnchanged:
			continue
		}
		journal.Sites = append(journal.Sites, indexJournalSite{Key: key, Record: record, Retire: retire})
	}
	if stale {
		return indexJournal{}, ErrStaleActivation
	}
	return journal, nil
}

func sameCommandTenant(activation *ActivationMetadata) error {
	tenantID, scopeID := "", ""
	check := func(tenant, scope string) error {
		if tenantID == "" {
			tenantID, scopeID = tenant, scope
			return nil
		}
		if tenant != tenantID || scope != scopeID {
			return ErrConflict
		}
		return nil
	}
	for _, revision := range activation.Certificates {
		if err := check(revision.TenantID, revision.TenantScopeID); err != nil {
			return err
		}
	}
	for _, removed := range activation.RemovedSites {
		if err := check(removed.TenantID, removed.TenantScopeID); err != nil {
			return err
		}
	}
	return nil
}

func incomingSiteBinding(revision CertificateRevision, binding ManifestBinding, files map[string][]byte) (siteBinding, error) {
	certificate, certificateFound := files[binding.CertificateFile]
	privateKey, keyFound := files[binding.PrivateKeyFile]
	if !certificateFound || !keyFound {
		return siteBinding{}, ErrInvalidBundle
	}
	block, _ := pem.Decode(certificate)
	if block == nil || block.Type != "CERTIFICATE" {
		return siteBinding{}, ErrInvalidBundle
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return siteBinding{}, ErrInvalidBundle
	}
	leafDigest := sha256.Sum256(leaf.Raw)
	if hex.EncodeToString(leafDigest[:]) != binding.LeafSHA256 {
		return siteBinding{}, ErrInvalidBundle
	}
	certificateDigest, keyDigest := sha256.Sum256(certificate), sha256.Sum256(privateKey)
	return siteBinding{
		CertificateID: revision.CertificateID, CertificateVersionID: revision.CertificateVersionID, Version: revision.Version,
		Domains: append([]string(nil), binding.Domains...), LeafSHA256: binding.LeafSHA256,
		CertificateSHA256: hex.EncodeToString(certificateDigest[:]), CertificateBytes: int64(len(certificate)),
		KeySHA256: hex.EncodeToString(keyDigest[:]), KeyBytes: int64(len(privateKey)),
		NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(),
	}, nil
}

// advanceSite returns the site's record after the incoming binding and the
// version that leaves its active slot.
func advanceSite(existing siteRecord, found bool, revision CertificateRevision, incoming siteBinding) (siteRecord, []string, siteOutcome) {
	if !found {
		return siteRecord{
			SchemaVersion: siteRecordSchemaVersion, TenantID: revision.TenantID, TenantScopeID: revision.TenantScopeID,
			SiteID: revision.SiteID, BindingRevision: revision.BindingRevision, Active: &incoming,
		}, nil, siteChanged
	}
	if existing.TenantID != revision.TenantID {
		return siteRecord{}, nil, siteConflict
	}
	switch {
	case revision.BindingRevision < existing.BindingRevision:
		return siteRecord{}, nil, siteStale
	case revision.BindingRevision == existing.BindingRevision:
		if existing.Active != nil && sameSiteBinding(*existing.Active, incoming) {
			return siteRecord{}, nil, siteUnchanged
		}
		return siteRecord{}, nil, siteConflict
	}
	record := existing.clone()
	record.BindingRevision = revision.BindingRevision
	var retire []string
	kept := record.Retained[:0]
	for _, binding := range record.Retained {
		if binding.CertificateVersionID == incoming.CertificateVersionID {
			if !sameVersionContent(binding, incoming) {
				return siteRecord{}, nil, siteConflict
			}
			continue
		}
		kept = append(kept, binding)
	}
	record.Retained = kept
	if record.Active != nil && record.Active.CertificateVersionID != incoming.CertificateVersionID {
		record.Retained = append(record.Retained, *record.Active)
		retire = append(retire, record.Active.CertificateVersionID)
	} else if record.Active != nil && !sameVersionContent(*record.Active, incoming) {
		return siteRecord{}, nil, siteConflict
	}
	if len(record.Retained) == 0 {
		record.Retained = nil
	}
	record.Active = &incoming
	return record, retire, siteChanged
}

// removeSite returns the site's record after a removal at removed's binding
// revision. A site the node never had keeps the removal, so a publication
// older than it is refused later.
func removeSite(existing siteRecord, found bool, removed RemovedSite) (siteRecord, []string, siteOutcome) {
	if !found {
		return siteRecord{
			SchemaVersion: siteRecordSchemaVersion, TenantID: removed.TenantID, TenantScopeID: removed.TenantScopeID,
			SiteID: removed.SiteID, BindingRevision: removed.BindingRevision,
		}, nil, siteChanged
	}
	if existing.TenantID != removed.TenantID {
		return siteRecord{}, nil, siteConflict
	}
	switch {
	case removed.BindingRevision < existing.BindingRevision:
		return siteRecord{}, nil, siteStale
	case removed.BindingRevision == existing.BindingRevision:
		if existing.Active == nil {
			return siteRecord{}, nil, siteUnchanged
		}
		return siteRecord{}, nil, siteConflict
	}
	record := existing.clone()
	record.BindingRevision = removed.BindingRevision
	var retire []string
	if record.Active != nil {
		record.Retained = append(record.Retained, *record.Active)
		retire = append(retire, record.Active.CertificateVersionID)
		record.Active = nil
	}
	return record, retire, siteChanged
}

// checkVersionImmutable: a version already held by any site (this one
// included) must name the same files. One holder is read.
func (manager *Manager) checkVersionImmutable(incoming siteBinding) error {
	holders, err := manager.store.holders(incoming.CertificateVersionID)
	if err != nil {
		return err
	}
	for holder := range holders {
		record, found, err := manager.store.readSiteRecord(holder)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		for _, binding := range record.bindings() {
			if binding.CertificateVersionID != incoming.CertificateVersionID {
				continue
			}
			if !sameVersionContent(binding, incoming) {
				return ErrConflict
			}
			return manager.store.verifySiteVersion(holder, incoming)
		}
	}
	return nil
}

// bindings is the active binding (first) and the retained ones.
func (record siteRecord) bindings() []siteBinding {
	result := make([]siteBinding, 0, len(record.Retained)+1)
	if record.Active != nil {
		result = append(result, *record.Active)
	}
	return append(result, record.Retained...)
}
