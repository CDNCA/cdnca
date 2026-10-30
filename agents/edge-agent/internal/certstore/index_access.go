package certstore

import (
	"container/list"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
)

// indexCache keeps recently read site records and the reference set for
// ResolveCertificateVersion, which a compile calls once per site domain. An
// entry is reused only while its file keeps the same identity; the manager
// also forgets a record it rewrites.
type indexCache struct {
	mu         sync.Mutex
	sites      map[string]*list.Element
	order      *list.List
	references cachedReferences
}

type cachedSite struct {
	key      string
	identity fileIdentity
	record   siteRecord
	found    bool
}

type cachedReferences struct {
	identity fileIdentity
	valid    bool
	pinned   map[string]struct{}
}

type fileIdentity struct {
	device, inode uint64
	size, mtime   int64
	exists        bool
}

func newIndexCache() *indexCache {
	return &indexCache{sites: make(map[string]*list.Element), order: list.New()}
}

func identityOf(path string) (fileIdentity, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileIdentity{}, nil
	}
	if err != nil {
		return fileIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, ErrUnsafeState
	}
	return fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), size: info.Size(),
		mtime: info.ModTime().UnixNano(), exists: true}, nil
}

func (cache *indexCache) site(store *diskStore, key string) (siteRecord, bool, error) {
	identity, err := identityOf(store.siteRecordPath(key))
	if err != nil {
		return siteRecord{}, false, err
	}
	cache.mu.Lock()
	if element, exists := cache.sites[key]; exists {
		entry := element.Value.(*cachedSite)
		if entry.identity == identity {
			cache.order.MoveToFront(element)
			record, found := entry.record, entry.found
			cache.mu.Unlock()
			return record, found, nil
		}
	}
	cache.mu.Unlock()
	record, found, err := store.readSiteRecord(key)
	if err != nil {
		return siteRecord{}, false, err
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if element, exists := cache.sites[key]; exists {
		element.Value = &cachedSite{key: key, identity: identity, record: record, found: found}
		cache.order.MoveToFront(element)
	} else {
		cache.sites[key] = cache.order.PushFront(&cachedSite{key: key, identity: identity, record: record, found: found})
		for cache.order.Len() > siteRecordCacheSize {
			oldest := cache.order.Back()
			cache.order.Remove(oldest)
			delete(cache.sites, oldest.Value.(*cachedSite).key)
		}
	}
	return record, found, nil
}

func (cache *indexCache) forget(key string) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if element, exists := cache.sites[key]; exists {
		cache.order.Remove(element)
		delete(cache.sites, key)
	}
}

// pinned reports whether a version is protected by the references (current
// or previous): only then is a retained version resolvable.
func (cache *indexCache) pinned(store *diskStore, versionID string) (bool, error) {
	identity, err := identityOf(store.referencesPath)
	if err != nil {
		return false, err
	}
	cache.mu.Lock()
	if cache.references.valid && cache.references.identity == identity {
		_, found := cache.references.pinned[versionID]
		cache.mu.Unlock()
		return found, nil
	}
	cache.mu.Unlock()
	references, err := store.readCertificateVersionReferences()
	if err != nil {
		return false, err
	}
	pinned := make(map[string]struct{}, len(references.Current)+len(references.Previous))
	for _, value := range references.Current {
		pinned[value] = struct{}{}
	}
	for _, value := range references.Previous {
		pinned[value] = struct{}{}
	}
	cache.mu.Lock()
	cache.references = cachedReferences{identity: identity, valid: true, pinned: pinned}
	cache.mu.Unlock()
	_, found := pinned[versionID]
	return found, nil
}

func (cache *indexCache) forgetReferences() {
	cache.mu.Lock()
	cache.references = cachedReferences{}
	cache.mu.Unlock()
}

// ResolveCertificateVersion returns a site's certificate version files. It
// reads only that site's record (cached) and checks the files' identity; the
// material was validated when it was activated. A version is resolvable while
// it is the site's active binding, or while a retained one is referenced.
// Records are replaced atomically and a version's files exist before any
// record names them, so this does not take the publisher lock.
func (manager *Manager) ResolveCertificateVersion(ctx context.Context, request CertificateResolveRequest) (ResolvedCertificateVersion, error) {
	if err := ctx.Err(); err != nil {
		return ResolvedCertificateVersion{}, err
	}
	if !canonicalUUID(request.TenantScopeID) || !canonicalUUID(request.CertificateVersionID) ||
		!validIdentifier(request.SiteID, MaxSiteIDBytes) ||
		(request.CertificateID != "" && !validIdentifier(request.CertificateID, MaxSiteIDBytes)) {
		return ResolvedCertificateVersion{}, ErrCertificateUnavailable
	}
	domain, err := normalizeDomain(request.Domain, true)
	if err != nil || domain != request.Domain {
		return ResolvedCertificateVersion{}, ErrCertificateUnavailable
	}
	key := siteKey(request.TenantScopeID, request.SiteID)
	record, found, err := manager.cache.site(manager.store, key)
	if err != nil {
		return ResolvedCertificateVersion{}, errors.Join(ErrCertificateUnavailable, err)
	}
	if !found || record.TenantScopeID != request.TenantScopeID || record.SiteID != request.SiteID {
		return ResolvedCertificateVersion{}, ErrCertificateUnavailable
	}
	var binding *siteBinding
	if record.Active != nil && record.Active.CertificateVersionID == request.CertificateVersionID {
		binding = record.Active
	} else {
		for index := range record.Retained {
			if record.Retained[index].CertificateVersionID != request.CertificateVersionID {
				continue
			}
			pinned, err := manager.cache.pinned(manager.store, request.CertificateVersionID)
			if err != nil {
				return ResolvedCertificateVersion{}, errors.Join(ErrCertificateUnavailable, err)
			}
			if pinned {
				binding = &record.Retained[index]
			}
			break
		}
	}
	if binding == nil || (request.CertificateID != "" && binding.CertificateID != request.CertificateID) ||
		!sortedContains(binding.Domains, request.Domain) {
		return ResolvedCertificateVersion{}, ErrCertificateUnavailable
	}
	if now := manager.now().UTC(); now.Before(binding.NotBefore) || !now.Before(binding.NotAfter) {
		return ResolvedCertificateVersion{}, errors.Join(ErrCertificateUnavailable, ErrCertificateNotValidNow)
	}
	directory := manager.store.siteVersionDirectory(key, binding.CertificateVersionID)
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o500 {
		return ResolvedCertificateVersion{}, ErrCertificateUnavailable
	}
	certificatePath := filepath.Join(directory, siteCertificateFile)
	privateKeyPath := filepath.Join(directory, sitePrivateKeyFile)
	if !immutableFileOfSize(certificatePath, binding.CertificateBytes) || !immutableFileOfSize(privateKeyPath, binding.KeyBytes) {
		return ResolvedCertificateVersion{}, ErrCertificateUnavailable
	}
	result := ResolvedCertificateVersion{
		TenantID: record.TenantID, TenantScopeID: record.TenantScopeID, SiteID: record.SiteID,
		CertificateID: binding.CertificateID, CertificateVersionID: binding.CertificateVersionID, Version: binding.Version,
		Domains: append([]string(nil), binding.Domains...), CertificatePath: certificatePath, PrivateKeyPath: privateKeyPath,
		NotBefore: binding.NotBefore, NotAfter: binding.NotAfter,
	}
	for _, digest := range []struct {
		value  string
		target *[32]byte
	}{
		{binding.LeafSHA256, &result.LeafSHA256}, {binding.CertificateSHA256, &result.CertificateSHA256},
		{binding.KeySHA256, &result.PrivateKeySHA256},
	} {
		decoded, err := hex.DecodeString(digest.value)
		if err != nil || len(decoded) != len(digest.target) {
			return ResolvedCertificateVersion{}, ErrCertificateUnavailable
		}
		copy(digest.target[:], decoded)
	}
	return result, nil
}

func immutableFileOfSize(path string, size int64) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o400 &&
		hardLinkCount(info) == 1 && info.Size() == size
}

func sortedContains(values []string, value string) bool {
	index := sort.SearchStrings(values, value)
	return index < len(values) && values[index] == value
}

// SetCertificateVersionReferences records the versions the site runtime uses
// (current) and may roll back to (previous). A current version must be some
// site's active binding, or already protected; a previous one must still be
// kept. Versions that drop out of the references and no longer have an
// active holder are then removed from every site that kept them.
func (manager *Manager) SetCertificateVersionReferences(ctx context.Context, references CertificateVersionReferences) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	normalized, err := normalizeCertificateVersionReferences(references)
	if err != nil {
		return err
	}
	unlock, err := manager.store.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := manager.settlePendingIndex(); err != nil {
		return err
	}
	before, err := manager.store.readCertificateVersionReferences()
	if err != nil {
		return err
	}
	protected := referenceSet(before)
	for _, value := range normalized.Current {
		holders, err := manager.store.holders(value)
		if err != nil {
			return errors.Join(ErrCertificateUnavailable, err)
		}
		active := false
		for _, isActive := range holders {
			active = active || isActive
		}
		if _, wasProtected := protected[value]; !active && !(wasProtected && len(holders) != 0) {
			return ErrCertificateUnavailable
		}
	}
	for _, value := range normalized.Previous {
		holders, err := manager.store.holders(value)
		if err != nil {
			return errors.Join(ErrCertificateUnavailable, err)
		}
		if len(holders) == 0 {
			return ErrCertificateUnavailable
		}
	}
	if err := manager.store.writeCertificateVersionReferences(normalized); err != nil {
		return err
	}
	manager.cache.forgetReferences()
	wanted := referenceSet(normalized)
	var dropped []string
	for value := range protected {
		if _, kept := wanted[value]; !kept {
			dropped = append(dropped, value)
		}
	}
	// Collection is best effort: what it leaves is marked and retried.
	manager.collect(wanted, dropped)
	return nil
}

func referenceSet(references CertificateVersionReferences) map[string]struct{} {
	result := make(map[string]struct{}, len(references.Current)+len(references.Previous))
	for _, value := range references.Current {
		result[value] = struct{}{}
	}
	for _, value := range references.Previous {
		result[value] = struct{}{}
	}
	return result
}

// collect removes versions that are neither referenced nor any site's
// active binding: from each site that retained them, then their holders and
// files. Only versions marked collectable (or just dropped) are examined.
func (manager *Manager) collect(wanted map[string]struct{}, dropped []string) {
	dirs := syncSet{}
	defer func() { _ = dirs.sync() }()
	for _, value := range dropped {
		if manager.store.markCollectable(value, dirs) != nil {
			return
		}
	}
	if dirs.sync() != nil {
		return
	}
	candidates, err := manager.store.collectable()
	if err != nil {
		return
	}
	for _, versionID := range candidates {
		if _, referenced := wanted[versionID]; referenced {
			_ = manager.store.clearCollectable(versionID)
			continue
		}
		holders, err := manager.store.holders(versionID)
		if err != nil {
			continue
		}
		active := false
		for _, isActive := range holders {
			active = active || isActive
		}
		if active {
			// It becomes collectable again when it leaves its last active slot.
			_ = manager.store.clearCollectable(versionID)
			continue
		}
		complete := true
		for key := range holders {
			if manager.dropRetained(key, versionID, dirs) != nil {
				complete = false
			}
		}
		if complete {
			_ = manager.store.clearCollectable(versionID)
		}
	}
}

// dropRetained removes a retained version from one site: record first, so no
// reader is pointed at files that are about to go.
func (manager *Manager) dropRetained(key, versionID string, dirs syncSet) error {
	record, found, err := manager.store.readSiteRecord(key)
	if err != nil {
		return err
	}
	if found {
		if record.Active != nil && record.Active.CertificateVersionID == versionID {
			return ErrUnsafeState
		}
		kept := make([]siteBinding, 0, len(record.Retained))
		for _, binding := range record.Retained {
			if binding.CertificateVersionID != versionID {
				kept = append(kept, binding)
			}
		}
		if len(kept) != len(record.Retained) {
			if len(kept) == 0 {
				kept = nil
			}
			record.Retained = kept
			if err := manager.store.writeSiteRecord(key, record, dirs); err != nil {
				return err
			}
			manager.cache.forget(key)
		}
	}
	// The record must be durable before its files go.
	if err := dirs.sync(); err != nil {
		return err
	}
	if err := manager.store.removeSiteVersion(key, versionID); err != nil {
		return err
	}
	return manager.store.removeHolder(versionID, key)
}
