package dnsacme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/tenantaccess"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Tenant copies of the platform configuration have deterministic identifiers,
// so no mapping table is needed: the provider copy of a tenant scope and the
// zone copy of a platform CNAME domain are UUIDv5 values of their sources.
var platformCopyNamespace = uuid.MustParse("6f9b1f5e-5a43-4a8e-9a0c-1c3d5e7f9b21")

func PlatformProviderCopyID(scopeID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(platformCopyNamespace, []byte("provider/"+scopeID.String()))
}

func PlatformZoneCopyID(scopeID, platformZoneID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(platformCopyNamespace, []byte("zone/"+scopeID.String()+"/"+platformZoneID.String()))
}

// IsPlatformManagedProvider: the row is the platform DNS copy of its tenant
// scope (DNS-SEC-20261027-01). managed_by is the durable mark (migration
// 569); the deterministic copy id also counts, so a copy synced before 569
// is refused before the next platform sync re-marks it.
func IsPlatformManagedProvider(managedBy string, scopeID, providerID uuid.UUID) bool {
	return managedBy == ProviderManagedByPlatform || providerID == PlatformProviderCopyID(scopeID)
}

// refusePlatformManagedUse: ErrPlatformManagedProvider when providerID is
// the platform DNS copy of scopeID and the actor is not a platform
// administrator. Only the platform side may use the platform credentials
// beyond the CNAME records it allocated (a zone or a DNS-01 order it places
// on a tenant's behalf); a tenant cannot widen the delegation. An unknown
// provider is left to the caller.
func refusePlatformManagedUse(ctx context.Context, q tenantaccess.Querier, actor Actor, scopeID, providerID uuid.UUID) error {
	var managedBy string
	err := q.QueryRow(ctx, `SELECT managed_by FROM dns_providers WHERE scope_id=$1 AND id=$2`, scopeID, providerID).
		Scan(&managedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !IsPlatformManagedProvider(managedBy, scopeID, providerID) {
		return nil
	}
	if actor.ScopeKind == "platform" {
		admin, err := tenantaccess.IsPlatformAdmin(ctx, q, actor.UserID, actor.ScopeID)
		if err != nil || admin {
			return err
		}
	}
	return ErrPlatformManagedProvider
}

// platformProviderName is the tenant provider copy's name (unique per scope).
const platformProviderName = "平台DNS配置"

// platformBinding binds the platform credential ciphertext to the document's
// binding identifier (the platform scope has no tenant).
func platformBinding(id uuid.UUID) CredentialBinding {
	return CredentialBinding{TenantID: id, ScopeID: id, ProviderID: id}
}

// platformSyncTenant is an active tenant scope and the member the copied
// provider/zone rows are attributed to (the write runtime requires the
// provider creator to be an active member of the scope).
type platformSyncTenant struct {
	tenantID, scopeID, userID uuid.UUID
}

// platformSyncTenants lists the active tenant scopes to sync; a non-nil
// scopeID restricts the list to that scope.
func (s *Store) platformSyncTenants(ctx context.Context, scopeID *uuid.UUID) ([]platformSyncTenant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT scope.tenant_id, scope.id, member.user_id
		FROM access_scopes scope
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		JOIN LATERAL (
			SELECT membership.user_id FROM memberships membership
			JOIN users member_user ON member_user.id=membership.user_id AND member_user.status='active'
			WHERE membership.scope_id=scope.id AND membership.status='active'
			ORDER BY membership.created_at, membership.user_id LIMIT 1
		) member ON true
		WHERE scope.kind='tenant' AND ($1::uuid IS NULL OR scope.id=$1)
		ORDER BY scope.id`, scopeID)
	if err != nil {
		return nil, fmt.Errorf("list platform DNS tenants: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (platformSyncTenant, error) {
		var value platformSyncTenant
		return value, row.Scan(&value.tenantID, &value.scopeID, &value.userID)
	})
}

// PlatformTenants returns the tenant scopes holding a provider copy.
func (s *Store) PlatformTenants(ctx context.Context) ([]PlatformTenant, error) {
	rows, err := s.pool.Query(ctx, `SELECT scope.tenant_id, scope.id FROM access_scopes scope WHERE scope.kind='tenant'`)
	if err != nil {
		return nil, fmt.Errorf("list tenant scopes: %w", err)
	}
	scopes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (PlatformTenant, error) {
		var value PlatformTenant
		return value, row.Scan(&value.TenantID, &value.ScopeID)
	})
	if err != nil {
		return nil, err
	}
	copies := make([]uuid.UUID, len(scopes))
	byCopy := make(map[uuid.UUID]PlatformTenant, len(scopes))
	for index, scope := range scopes {
		copies[index] = PlatformProviderCopyID(scope.ScopeID)
		byCopy[copies[index]] = scope
	}
	rows, err = s.pool.Query(ctx, `SELECT id FROM dns_providers WHERE id = ANY($1) ORDER BY scope_id`, copies)
	if err != nil {
		return nil, fmt.Errorf("list platform DNS provider copies: %w", err)
	}
	present, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	result := make([]PlatformTenant, 0, len(present))
	for _, id := range present {
		result = append(result, byCopy[id])
	}
	return result, nil
}

func tenantScopes(ctx context.Context, database rowsQuerier) ([]uuid.UUID, error) {
	rows, err := database.Query(ctx, `SELECT id FROM access_scopes WHERE kind='tenant' ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list tenant scopes: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// platformCopyIDs returns the derived provider copy ids of every tenant scope
// and, per platform CNAME domain, the derived ids of its zone copies.
func platformCopyIDs(ctx context.Context, database rowsQuerier, zones []platformZoneV) ([]uuid.UUID, map[uuid.UUID][]uuid.UUID, error) {
	scopes, err := tenantScopes(ctx, database)
	if err != nil {
		return nil, nil, err
	}
	providers := make([]uuid.UUID, len(scopes))
	for index, scope := range scopes {
		providers[index] = PlatformProviderCopyID(scope)
	}
	byZone := make(map[uuid.UUID][]uuid.UUID, len(zones))
	for _, zone := range zones {
		ids := make([]uuid.UUID, len(scopes))
		for index, scope := range scopes {
			ids[index] = PlatformZoneCopyID(scope, zone.ID)
		}
		byZone[zone.ID] = ids
	}
	return providers, byZone, nil
}

// platformZonesInUse reports the platform CNAME domains whose tenant copies
// still hold CNAME hostname claims (allocated site/package CNAMEs).
func platformZonesInUse(ctx context.Context, database rowsQuerier, copies map[uuid.UUID][]uuid.UUID) (map[uuid.UUID]bool, error) {
	owner := map[uuid.UUID]uuid.UUID{}
	all := make([]uuid.UUID, 0)
	for platformID, ids := range copies {
		for _, id := range ids {
			owner[id] = platformID
			all = append(all, id)
		}
	}
	result := map[uuid.UUID]bool{}
	if len(all) == 0 {
		return result, nil
	}
	rows, err := database.Query(ctx, `SELECT DISTINCT claim.zone_id FROM cname_hostname_claims claim WHERE claim.zone_id = ANY($1)`, all)
	if err != nil {
		return nil, fmt.Errorf("load platform CNAME domain usage: %w", err)
	}
	used, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	for _, id := range used {
		result[owner[id]] = true
	}
	return result, nil
}

// SyncPlatformTenants copies the platform DNS configuration into every active
// tenant scope: one verified dns_providers row (credentials re-encrypted for
// the tenant binding), one dns_zones row per CNAME domain and the TTL in
// dns_legacy_settings. It returns the number of tenant scopes in sync; a
// per-tenant failure is recorded as the platform sync error and the remaining
// tenants still sync.
func (s *Service) SyncPlatformTenants(ctx context.Context) (int, error) {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil {
		return 0, ErrInvalidInput
	}
	_, doc, err := loadPlatformDocument(ctx, s.store.pool, false)
	if err != nil {
		return 0, err
	}
	if doc.ProviderType == "" {
		return 0, nil
	}
	boundCipher, ok := s.cipher.(BoundCredentialCipher)
	if !ok {
		return 0, s.store.recordPlatformSync(ctx, "credential_encryption_unavailable")
	}
	plaintext, err := boundCipher.DecryptCredential(platformBinding(doc.BindingID), doc.KeyID, doc.Ciphertext)
	if err != nil {
		return 0, s.store.recordPlatformSync(ctx, "credential_encryption_unavailable")
	}
	defer clear(plaintext)
	tenants, err := s.store.platformSyncTenants(ctx, nil)
	if err != nil {
		return 0, err
	}
	synced, firstFailure := 0, ""
	for _, tenant := range tenants {
		if ctx.Err() != nil {
			return synced, ctx.Err()
		}
		code := s.syncPlatformTenant(ctx, boundCipher, doc, plaintext, tenant)
		if code == "" {
			synced++
		} else if firstFailure == "" {
			firstFailure = code
		}
	}
	return synced, s.store.recordPlatformSync(ctx, firstFailure)
}

var (
	// ErrPlatformTenantSyncRetry: the tenant copy could not be written now
	// (an in-flight DNS mutation claim, a serialization failure); retry later.
	ErrPlatformTenantSyncRetry = errors.New("platform DNS tenant copy: retry later")
	// ErrPlatformTenantSyncFailed: the platform DNS configuration exists but
	// cannot be copied into the tenant (credentials unavailable, no active
	// member, a provider of the same name) until the platform or tenant changes.
	ErrPlatformTenantSyncFailed = errors.New("platform DNS tenant copy failed")
)

// EnsurePlatformTenantCopy copies the platform DNS configuration into one
// tenant scope that has no provider copy yet (a tenant created after the
// platform configuration was saved). It reports whether it wrote the copy; a
// scope that already holds one, or a platform without DNS configuration, is
// left untouched. The platform document's sync status is not changed.
func (s *Service) EnsurePlatformTenantCopy(ctx context.Context, scopeID uuid.UUID) (bool, error) {
	if s == nil || s.store == nil || s.store.pool == nil || ctx == nil || scopeID == uuid.Nil {
		return false, ErrInvalidInput
	}
	var present bool
	if err := s.store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM dns_providers WHERE scope_id=$1 AND id=$2)`,
		scopeID, PlatformProviderCopyID(scopeID)).Scan(&present); err != nil {
		return false, err
	}
	if present {
		return false, nil
	}
	_, doc, err := loadPlatformDocument(ctx, s.store.pool, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if doc.ProviderType == "" {
		return false, nil
	}
	boundCipher, ok := s.cipher.(BoundCredentialCipher)
	if !ok {
		return false, fmt.Errorf("%w: credential_encryption_unavailable", ErrPlatformTenantSyncFailed)
	}
	plaintext, err := boundCipher.DecryptCredential(platformBinding(doc.BindingID), doc.KeyID, doc.Ciphertext)
	if err != nil {
		return false, fmt.Errorf("%w: credential_encryption_unavailable", ErrPlatformTenantSyncFailed)
	}
	defer clear(plaintext)
	tenants, err := s.store.platformSyncTenants(ctx, &scopeID)
	if err != nil {
		return false, err
	}
	if len(tenants) == 0 {
		return false, fmt.Errorf("%w: no active tenant member", ErrPlatformTenantSyncFailed)
	}
	// A zone conflict still commits the provider copy and the other zones;
	// the caller's zone resolution reports what is missing.
	switch code := s.syncPlatformTenant(ctx, boundCipher, doc, plaintext, tenants[0]); code {
	case "", "platform_zone_conflict":
		return true, nil
	case "platform_sync_retry":
		return false, ErrPlatformTenantSyncRetry
	default:
		return false, fmt.Errorf("%w: %s", ErrPlatformTenantSyncFailed, code)
	}
}

func (s *Store) recordPlatformSync(ctx context.Context, failure string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID, doc, err := loadPlatformDocument(ctx, tx, true)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		doc.SyncError, doc.SyncedAt = failure, &now
		return savePlatformDocument(ctx, tx, scopeID, doc)
	})
}

var errPlatformZoneConflict = errors.New("tenant zone of the same name belongs to another provider")

// syncPlatformTenant returns "" on success or a stable failure code.
func (s *Service) syncPlatformTenant(ctx context.Context, cipher BoundCredentialCipher, doc platformDocument,
	plaintext []byte, tenant platformSyncTenant) string {
	conflict := false
	err := pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('dns_zones.default:' || $1::text, 0))`,
			tenant.scopeID); err != nil {
			return err
		}
		providerID, err := syncPlatformProvider(ctx, tx, cipher, doc, plaintext, tenant)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO dns_legacy_settings(scope_id, tenant_id, ttl, revision, updated_by_user_id, updated_at)
			VALUES($1,$2,$3,1,$4,now())
			ON CONFLICT(scope_id) DO UPDATE SET ttl=EXCLUDED.ttl, revision=dns_legacy_settings.revision+1,
				updated_by_user_id=EXCLUDED.updated_by_user_id, updated_at=now()
			WHERE dns_legacy_settings.ttl<>EXCLUDED.ttl`,
			tenant.scopeID, tenant.tenantID, doc.TTL, tenant.userID); err != nil {
			return err
		}
		conflict, err = syncPlatformZones(ctx, tx, providerID, doc.Zones, tenant)
		if err != nil {
			return err
		}
		// Sites created before the DNS configuration existed get their CNAME.
		_, err = RequeueCNAMEConfigFailures(ctx, tx, tenant.scopeID, "platform_dns_sync", time.Now().UTC())
		return err
	})
	switch {
	case err == nil && conflict:
		return "platform_zone_conflict"
	case err == nil:
		return ""
	case errors.Is(err, ErrCredentialUnavailable):
		return "credential_encryption_unavailable"
	case isUniqueViolation(err):
		return "platform_provider_name_conflict"
	default:
		// A provider or zone with an in-flight DNS mutation claim refuses
		// updates (migration 089); the next synchronisation retries.
		return "platform_sync_retry"
	}
}

// syncPlatformProvider creates or refreshes the tenant's provider copy. The
// row keeps its id across provider type and credential changes (zones and
// CNAME claims reference it); an unchanged copy is left untouched so its
// credential version does not move.
func syncPlatformProvider(ctx context.Context, tx pgx.Tx, cipher BoundCredentialCipher, doc platformDocument,
	plaintext []byte, tenant platformSyncTenant) (uuid.UUID, error) {
	providerID := PlatformProviderCopyID(tenant.scopeID)
	binding := CredentialBinding{TenantID: tenant.tenantID, ScopeID: tenant.scopeID, ProviderID: providerID}
	var providerType, status, keyID, managedBy string
	var ciphertext []byte
	err := tx.QueryRow(ctx, `SELECT provider_type, status, credential_key_id, credential_ciphertext, managed_by
		FROM dns_providers WHERE scope_id=$1 AND id=$2 FOR UPDATE`, tenant.scopeID, providerID).
		Scan(&providerType, &status, &keyID, &ciphertext, &managedBy)
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	if exists && managedBy != ProviderManagedByPlatform {
		// A copy written before migration 569 (managed_by is not one of the
		// columns the provider claim guard of 089 protects).
		if _, err := tx.Exec(ctx, `UPDATE dns_providers SET managed_by='platform' WHERE scope_id=$1 AND id=$2`,
			tenant.scopeID, providerID); err != nil {
			return uuid.Nil, err
		}
	}
	if exists && providerType == doc.ProviderType && status == "verified" {
		current, decryptErr := cipher.DecryptCredential(binding, keyID, ciphertext)
		same := decryptErr == nil && bytes.Equal(current, plaintext)
		clear(current)
		if same {
			return providerID, nil
		}
	}
	newKeyID, newCiphertext, err := cipher.EncryptCredential(binding, plaintext)
	if err != nil {
		return uuid.Nil, ErrCredentialUnavailable
	}
	defer clear(newCiphertext)
	if !exists {
		_, err = tx.Exec(ctx, `INSERT INTO dns_providers(id, scope_id, name, provider_type, credential_key_id,
				credential_ciphertext, status, created_by_user_id, updated_by_user_id, managed_by)
			VALUES($1,$2,$3,$4,$5,$6,'verified',$7,$7,'platform')`, providerID, tenant.scopeID, platformProviderName, doc.ProviderType,
			newKeyID, newCiphertext, tenant.userID)
		return providerID, err
	}
	_, err = tx.Exec(ctx, `UPDATE dns_providers SET provider_type=$3, credential_key_id=$4, credential_ciphertext=$5,
			status='verified', revision=revision+1, updated_by_user_id=$6, updated_at=now()
		WHERE scope_id=$1 AND id=$2`, tenant.scopeID, providerID, doc.ProviderType, newKeyID, newCiphertext, tenant.userID)
	return providerID, err
}

// syncPlatformZones gives the tenant one dns_zones row per platform CNAME
// domain; the first one becomes the tenant's default CNAME allocation zone
// when the tenant has none. A tenant zone of the same name on another
// provider is reported (conflict), never taken over. Copies of removed
// platform domains without CNAME claims are deleted.
func syncPlatformZones(ctx context.Context, tx pgx.Tx, providerID uuid.UUID, zones []platformZoneV,
	tenant platformSyncTenant) (bool, error) {
	conflict := false
	keep := make([]uuid.UUID, 0, len(zones))
	ordered := append([]platformZoneV(nil), zones...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].DisplayID < ordered[j].DisplayID })
	for _, zone := range ordered {
		copyID := PlatformZoneCopyID(tenant.scopeID, zone.ID)
		keep = append(keep, copyID)
		rows, err := tx.Query(ctx, `SELECT id, name, COALESCE(provider_zone_apex,''), random_allocation FROM dns_zones
			WHERE scope_id=$1 AND (id=$2 OR name=$3)`, tenant.scopeID, copyID, zone.Name)
		if err != nil {
			return false, err
		}
		type existing struct {
			id         uuid.UUID
			name, apex string
			random     bool
		}
		found, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (existing, error) {
			var value existing
			return value, row.Scan(&value.id, &value.name, &value.apex, &value.random)
		})
		if err != nil {
			return false, err
		}
		var copyRow *existing
		taken := false
		for index := range found {
			if found[index].id == copyID {
				copyRow = &found[index]
			} else {
				taken = true
			}
		}
		switch {
		case taken:
			conflict = true
		case copyRow != nil && copyRow.name != zone.Name:
			if _, err := tx.Exec(ctx, `UPDATE dns_zones SET name=$3, provider_zone_apex=NULLIF($5,''), revision=revision+1,
				updated_by_user_id=$4, updated_at=now()
				WHERE scope_id=$1 AND id=$2`, tenant.scopeID, copyID, zone.Name, tenant.userID, zone.ProviderZoneApex); err != nil {
				return false, err
			}
		case copyRow != nil && zone.ProviderZoneApex != "" && copyRow.apex != zone.ProviderZoneApex:
			// The apex is not zone authority (089 digests): no revision bump.
			if _, err := tx.Exec(ctx, `UPDATE dns_zones SET provider_zone_apex=$3 WHERE scope_id=$1 AND id=$2`,
				tenant.scopeID, copyID, zone.ProviderZoneApex); err != nil {
				return false, err
			}
		case copyRow == nil:
			if _, err := tx.Exec(ctx, `INSERT INTO dns_zones(id, scope_id, provider_id, name, created_by_user_id,
					updated_by_user_id, is_default, provider_zone_apex, random_allocation)
				VALUES($1,$2,$3,$4,$5,$5,NOT EXISTS (SELECT 1 FROM dns_zones WHERE scope_id=$2 AND is_default),NULLIF($6,''),$7)`,
				copyID, tenant.scopeID, providerID, zone.Name, tenant.userID, zone.ProviderZoneApex, zone.RandomAllocation); err != nil {
				return false, err
			}
		}
		// fix-cnamerand (549): the random-allocation mark follows the platform
		// domain. It is not zone authority (089 digests): no revision bump, so
		// an in-flight DNS mutation claim does not block it.
		if copyRow != nil && copyRow.random != zone.RandomAllocation {
			if _, err := tx.Exec(ctx, `UPDATE dns_zones SET random_allocation=$3 WHERE scope_id=$1 AND id=$2`,
				tenant.scopeID, copyID, zone.RandomAllocation); err != nil {
				return false, err
			}
		}
	}
	_, err := tx.Exec(ctx, `DELETE FROM dns_zones zone WHERE zone.scope_id=$1 AND zone.provider_id=$2 AND zone.id <> ALL($3)
		AND NOT EXISTS (SELECT 1 FROM cname_hostname_claims claim WHERE claim.zone_id=zone.id)`,
		tenant.scopeID, providerID, keep)
	return conflict, err
}

// PlatformCredentials decrypts the platform DNS credentials for 记录修复 /
// 清除CDN无关解析 provider listings. The caller clears the returned map.
func (s *Service) PlatformCredentials(ctx context.Context) (string, map[string]string, error) {
	if s == nil || s.store == nil || ctx == nil {
		return "", nil, ErrInvalidInput
	}
	_, doc, err := loadPlatformDocument(ctx, s.store.pool, false)
	if err != nil {
		return "", nil, err
	}
	if doc.ProviderType == "" {
		return "", nil, ErrPlatformNotConfigured
	}
	boundCipher, ok := s.cipher.(BoundCredentialCipher)
	if !ok {
		return "", nil, ErrCredentialUnavailable
	}
	plaintext, err := boundCipher.DecryptCredential(platformBinding(doc.BindingID), doc.KeyID, doc.Ciphertext)
	if err != nil {
		return "", nil, ErrCredentialUnavailable
	}
	defer clear(plaintext)
	credentials := map[string]string{}
	if err := json.Unmarshal(plaintext, &credentials); err != nil {
		return "", nil, ErrCredentialUnavailable
	}
	return doc.ProviderType, credentials, nil
}

// PlatformZoneNames returns the platform CNAME domains by id.
func (s *Store) PlatformZoneNames(ctx context.Context) (map[uuid.UUID]string, error) {
	_, doc, err := loadPlatformDocument(ctx, s.pool, false)
	if err != nil {
		return nil, err
	}
	result := make(map[uuid.UUID]string, len(doc.Zones))
	for _, zone := range doc.Zones {
		result[zone.ID] = zone.Name
	}
	return result, nil
}

func (s *Service) PlatformZoneNames(ctx context.Context) (map[uuid.UUID]string, error) {
	if s == nil || s.store == nil || ctx == nil {
		return nil, ErrInvalidInput
	}
	return s.store.PlatformZoneNames(ctx)
}

// PlatformZoneApex returns the hosted domain of a platform CNAME domain
// (migration 473). A domain saved before 473 has none: it is looked up from
// the platform DNS account once and written back to the platform document
// and its tenant copies. dnsproviderremote.CodeZoneNotHosted: the account
// hosts neither the domain nor a parent of it.
func (s *Service) PlatformZoneApex(ctx context.Context, zoneID uuid.UUID, providerType string,
	credentials map[string]string) (string, error) {
	if s == nil || s.store == nil || ctx == nil {
		return "", ErrInvalidInput
	}
	_, doc, err := loadPlatformDocument(ctx, s.store.pool, false)
	if err != nil {
		return "", err
	}
	var zone *platformZoneV
	for index := range doc.Zones {
		if doc.Zones[index].ID == zoneID {
			zone = &doc.Zones[index]
		}
	}
	if zone == nil {
		return "", ErrNotFound
	}
	if zone.ProviderZoneApex != "" {
		return zone.ProviderZoneApex, nil
	}
	if s.apex == nil {
		return "", ErrProviderVerificationUnavailable
	}
	apex, err := s.apex.ResolveZoneApex(ctx, providerType, credentials, zone.Name)
	if err != nil {
		return "", err
	}
	name := zone.Name
	err = pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		scopeID, locked, err := loadPlatformDocument(ctx, tx, true)
		if err != nil {
			return err
		}
		for index := range locked.Zones {
			if locked.Zones[index].ID == zoneID && locked.Zones[index].Name == name && locked.Zones[index].ProviderZoneApex == "" {
				locked.Zones[index].ProviderZoneApex = apex
				if err := savePlatformDocument(ctx, tx, scopeID, locked); err != nil {
					return err
				}
			}
		}
		scopes, err := tenantScopes(ctx, tx)
		if err != nil {
			return err
		}
		copies := make([]uuid.UUID, len(scopes))
		for index, scope := range scopes {
			copies[index] = PlatformZoneCopyID(scope, zoneID)
		}
		_, err = tx.Exec(ctx, `UPDATE dns_zones SET provider_zone_apex=$3
			WHERE id = ANY($1) AND name=$2 AND provider_zone_apex IS NULL`, copies, name, apex)
		return err
	})
	return apex, err
}

// PlatformTenantCopies returns the tenant scopes holding a provider copy with
// the copy's provider id (for 记录修复 / 清除CDN无关解析).
func (s *Service) PlatformTenantCopies(ctx context.Context) ([]PlatformTenant, error) {
	if s == nil || s.store == nil || ctx == nil {
		return nil, ErrInvalidInput
	}
	return s.store.PlatformTenants(ctx)
}
