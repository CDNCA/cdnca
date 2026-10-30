package dnsacme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// platformDocument is the installation-wide DNS configuration (节点管理 >
// DNS配置 and its CNAME域名). It is stored under the "dns_config" key of the
// existing platform_system_other_settings row, so the page needs no schema
// migration; systemothersettings preserves the key on its own saves.
type platformDocument struct {
	ProviderType string            `json:"provider_type,omitempty"`
	Identifiers  map[string]string `json:"identifiers,omitempty"`
	// The credential ciphertext is bound (AAD) to BindingID, see platformBinding.
	BindingID         uuid.UUID       `json:"binding_id,omitempty"`
	KeyID             string          `json:"key_id,omitempty"`
	Ciphertext        []byte          `json:"ciphertext,omitempty"`
	CredentialVersion int64           `json:"credential_version,omitempty"`
	TTL               int             `json:"ttl,omitempty"`
	IPWeight          bool            `json:"ip_weight,omitempty"`
	Revision          int64           `json:"revision,omitempty"`
	UpdatedAt         *time.Time      `json:"updated_at,omitempty"`
	SyncError         string          `json:"sync_error,omitempty"`
	SyncedAt          *time.Time      `json:"synced_at,omitempty"`
	NextZoneID        int64           `json:"next_zone_id,omitempty"`
	Zones             []platformZoneV `json:"zones,omitempty"`
}

type platformZoneV struct {
	ID        uuid.UUID `json:"id"`
	DisplayID int64     `json:"display_id"`
	Name      string    `json:"name"`
	Remark    string    `json:"remark"`
	// ProviderZoneApex is the hosted domain found when the zone was saved
	// (migration 473); empty for zones saved before it.
	ProviderZoneApex string `json:"provider_zone_apex,omitempty"`
	// RandomAllocation: new CNAMEs without a domain draw one of the marked
	// zones (fix-cnamerand, copied to dns_zones.random_allocation, 549).
	RandomAllocation bool      `json:"random_allocation,omitempty"`
	Revision         int64     `json:"revision"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (doc *platformDocument) normalize() {
	if doc.Revision < 1 {
		doc.Revision = 1
	}
	if doc.TTL == 0 {
		doc.TTL = PlatformDefaultTTL
	}
	if doc.Identifiers == nil {
		doc.Identifiers = map[string]string{}
	}
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// loadPlatformDocument reads the document. With lock it runs in a transaction,
// creates the settings row when absent and locks it.
func loadPlatformDocument(ctx context.Context, database rowQuerier, lock bool) (uuid.UUID, platformDocument, error) {
	var scopeID uuid.UUID
	var raw []byte
	if lock {
		tx, ok := database.(pgx.Tx)
		if !ok {
			return uuid.Nil, platformDocument{}, ErrInvalidInput
		}
		if _, err := tx.Exec(ctx, `INSERT INTO platform_system_other_settings(platform_scope_id, revision, settings, updated_at)
			SELECT id, 0, '{}'::jsonb, now() FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL
			ON CONFLICT (platform_scope_id) DO NOTHING`); err != nil {
			return uuid.Nil, platformDocument{}, fmt.Errorf("prepare platform DNS config: %w", err)
		}
	}
	query := `SELECT scope.id, (settings.settings -> 'dns_config')::text::bytea
		FROM access_scopes scope
		LEFT JOIN platform_system_other_settings settings ON settings.platform_scope_id=scope.id
		WHERE scope.kind='platform' AND scope.tenant_id IS NULL`
	if lock {
		query = `SELECT scope.id, (settings.settings -> 'dns_config')::text::bytea
		FROM access_scopes scope
		JOIN platform_system_other_settings settings ON settings.platform_scope_id=scope.id
		WHERE scope.kind='platform' AND scope.tenant_id IS NULL FOR UPDATE OF settings`
	}
	if err := database.QueryRow(ctx, query).Scan(&scopeID, &raw); err != nil {
		return uuid.Nil, platformDocument{}, fmt.Errorf("load platform DNS config: %w", err)
	}
	var doc platformDocument
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &doc); err != nil {
			return uuid.Nil, platformDocument{}, fmt.Errorf("decode platform DNS config: %w", err)
		}
	}
	doc.normalize()
	return scopeID, doc, nil
}

func savePlatformDocument(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, doc platformDocument) error {
	encoded, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE platform_system_other_settings
		SET settings = jsonb_set(settings, '{dns_config}', $2::jsonb, true) WHERE platform_scope_id=$1`, scopeID, string(encoded))
	return err
}

// PlatformConfig returns the installation-wide DNS configuration with the
// tenant synchronisation summary and the newest DNS write failure.
func (s *Store) PlatformConfig(ctx context.Context) (PlatformConfig, error) {
	_, doc, err := loadPlatformDocument(ctx, s.pool, false)
	if err != nil {
		return PlatformConfig{}, err
	}
	result := PlatformConfig{
		ProviderType: doc.ProviderType, Identifiers: doc.Identifiers, SecretSaved: len(doc.Ciphertext) > 0,
		TTL: doc.TTL, IPWeight: doc.IPWeight, WeightSupported: PlatformWeightSupported(doc.ProviderType),
		Revision: doc.Revision, UpdatedAt: doc.UpdatedAt,
		Sync: PlatformSync{Error: doc.SyncError, At: doc.SyncedAt},
	}
	tenants, err := s.PlatformTenants(ctx)
	if err != nil {
		return PlatformConfig{}, err
	}
	result.Sync.Tenants = len(tenants)
	if doc.SyncError != "" && doc.SyncedAt != nil {
		result.LastError = &PlatformDNSError{Source: "platform_sync", Code: doc.SyncError, At: doc.SyncedAt.UTC()}
		return result, nil
	}
	scopes := make([]uuid.UUID, len(tenants))
	for index, tenant := range tenants {
		scopes[index] = tenant.ScopeID
	}
	result.LastError, err = s.platformLastError(ctx, scopes)
	return result, err
}

// platformLastError returns the newest settled DNS write outcome of the tenant
// copies when it is a failure; a later success hides an earlier failure.
// Sources: CNAME allocation, retarget, 记录修复 and 清除CDN无关解析 jobs (the
// first failed item of a job is its message), and carrier-line records (the
// line scope is the message; dns_line_not_in_plan = the line answers with the
// default line).
func (s *Store) platformLastError(ctx context.Context, scopes []uuid.UUID) (*PlatformDNSError, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	var source, code, message string
	var at time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT source, COALESCE(code, ''), COALESCE(message, ''), at FROM (
			(SELECT 'cname_allocation' AS source, failure_code AS code, NULL::text AS message, updated_at AS at
			 FROM cname_allocations WHERE tenant_scope_id = ANY($1) AND state IN ('done', 'failed')
			 ORDER BY updated_at DESC LIMIT 1)
			UNION ALL
			(SELECT 'cname_retarget', failure_code, NULL, updated_at
			 FROM dns_cname_retargets WHERE tenant_scope_id = ANY($1) AND state IN ('committed', 'failed')
			 ORDER BY updated_at DESC LIMIT 1)
			UNION ALL
			(SELECT CASE job.kind WHEN 'dns.repair.v1' THEN 'dns_repair' ELSE 'dns_cleanup' END,
			        CASE WHEN job.state IN ('failed', 'partial_failed') THEN COALESCE(job.last_error_code, 'dns_job_failed') END,
			        (SELECT item.item_id || ' (' || item.error_code || ')' FROM background_job_items item
			          WHERE item.tenant_id=job.tenant_id AND item.job_id=job.id AND item.state='failed'
			          ORDER BY item.ordinal LIMIT 1),
			        job.completed_at
			 FROM background_jobs job JOIN access_scopes scope ON scope.tenant_id=job.tenant_id AND scope.id = ANY($1)
			 WHERE job.kind IN ('dns.repair.v1', 'dns.cleanup.v1')
			   AND job.state IN ('succeeded', 'partial_failed', 'failed')
			 ORDER BY job.completed_at DESC LIMIT 1)
			UNION ALL
			(SELECT 'cname_line', NULLIF(line.publish_error, ''), line.line_scope, line.updated_at
			 FROM cname_carrier_line_records line JOIN sites ON sites.id=line.site_id AND sites.scope_id = ANY($1)
			 ORDER BY line.updated_at DESC LIMIT 1)
		) outcome ORDER BY at DESC LIMIT 1`, scopes).Scan(&source, &code, &message, &at)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && code == "" {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load platform DNS last error: %w", err)
	}
	return &PlatformDNSError{Source: source, Code: code, Message: message, At: at.UTC()}, nil
}

type platformCredentialWrite struct {
	bindingID   uuid.UUID
	keyID       string
	ciphertext  []byte
	identifiers map[string]string
}

func (s *Store) SavePlatformConfig(ctx context.Context, actor Actor, request SavePlatformConfigRequest,
	credentials *platformCredentialWrite, digest [32]byte) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		replay, err := reserveWrite(ctx, tx, actor, actor.ScopeID, "dns.platform.config", request.IdempotencyKey, digest)
		if err != nil || replay != nil {
			return err
		}
		scopeID, doc, err := loadPlatformDocument(ctx, tx, true)
		if err != nil {
			return err
		}
		if doc.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if credentials == nil && (doc.ProviderType == "" || doc.ProviderType != request.ProviderType) {
			return ErrInvalidInput
		}
		if credentials != nil {
			doc.ProviderType, doc.Identifiers = request.ProviderType, credentials.identifiers
			doc.BindingID, doc.KeyID, doc.Ciphertext = credentials.bindingID, credentials.keyID, credentials.ciphertext
			doc.CredentialVersion++
		}
		now := time.Now().UTC()
		doc.TTL, doc.IPWeight, doc.Revision, doc.UpdatedAt = request.TTL, request.IPWeight, doc.Revision+1, &now
		if err := savePlatformDocument(ctx, tx, scopeID, doc); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, actor.ScopeID, request.RequestID, "dns.platform.config.update",
			"dns_platform_config", uuid.Nil, map[string]any{
				"provider_type": request.ProviderType, "credentials_replaced": credentials != nil,
				"ttl": request.TTL, "ip_weight": request.IPWeight, "version": doc.Revision,
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, "dns.platform.config", request.IdempotencyKey, uuid.Nil,
			map[string]int64{"version": doc.Revision})
	})
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
