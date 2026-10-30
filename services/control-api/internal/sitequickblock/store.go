package sitequickblock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, auditor: audit.New(pool), now: now}
}

func (s *Store) Get(ctx context.Context, actor Actor, siteID uuid.UUID) (State, error) {
	var result State
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		query := `SELECT scope_id,revision FROM sites WHERE id=$1 AND deleted_at IS NULL`
		args := []any{siteID}
		if actor.ScopeKind == "tenant" {
			query += ` AND scope_id=$2`
			args = append(args, actor.ScopeID)
		}
		var scopeID uuid.UUID
		var revision int64
		if err := tx.QueryRow(ctx, query, args...).Scan(&scopeID, &revision); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		override, updatedAt, err := readOverride(ctx, tx, scopeID, siteID, false)
		if err != nil {
			return err
		}
		library, _, err := loadLibrary(ctx, tx, scopeID, siteID, false)
		if err != nil {
			return err
		}
		result = newState(siteID, revision, override, library, updatedAt)
		return nil
	})
	if err != nil {
		return State{}, fmt.Errorf("get site quick block: %w", err)
	}
	return result, nil
}

// AuditAction is the audit event of a site quick block write (success, or
// denied with a reason code).
const AuditAction = "security.site_quick_block.update"

func (s *Store) Update(ctx context.Context, actor Actor, request UpdateRequest, digest [32]byte) (State, error) {
	var result State
	var auditScopeID uuid.UUID
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID, err := targetScope(ctx, tx, actor, request.SiteID)
		if err != nil {
			return err
		}
		auditScopeID = scopeID
		// Publication lock order: configuration scope before the site row
		// (the sites trigger advances the scope's source revision).
		if err := lockEdgeConfigurationScope(ctx, tx, scopeID); err != nil {
			return err
		}
		var deletedAt, lockedAt *time.Time
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT deleted_at,locked_at,revision FROM sites
			WHERE id=$1 AND scope_id=$2 FOR UPDATE`, request.SiteID, scopeID).Scan(&deletedAt, &lockedAt, &revision); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if replayed, err := s.replay(ctx, tx, actor, request, digest, &result); err != nil || replayed {
			return err
		}
		if deletedAt != nil {
			return ErrNotFound
		}
		// FX31: a site locked by a platform administrator is read-only for tenants.
		if lockedAt != nil && actor.ScopeKind == "tenant" {
			return ErrLocked
		}
		if revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		previous, _, err := readOverride(ctx, tx, scopeID, request.SiteID, true)
		if err != nil {
			return err
		}
		library, versions, err := loadLibrary(ctx, tx, scopeID, request.SiteID, true)
		if err != nil {
			return err
		}
		if !request.Override.Inherits() {
			if library == nil {
				return ErrNoLibrary
			}
			// The override must apply to the version the site publishes now
			// and to the latest (the next one it publishes); the library
			// write guard keeps it so for later versions.
			for _, version := range versions {
				if _, err := securitypolicy.SiteQuickBlockPolicy(version, request.Override); err != nil {
					return err
				}
			}
			if request.Override.TurnsOn() {
				if ready, err := ipIntelReady(ctx, tx); err != nil {
					return err
				} else if !ready {
					return securitypolicy.ErrQuickBlockIPIntelUnavailable
				}
			}
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		if err := writeOverride(ctx, tx, scopeID, request.SiteID, actor.UserID, request.Override, now); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE sites SET revision=revision+1,updated_by_user_id=$2,updated_at=$3
			WHERE id=$1 AND revision=$4 AND deleted_at IS NULL`, request.SiteID, actor.UserID, now, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		automatic, err := edgeautopublish.EnqueueSiteSettingTx(ctx, tx, scopeID, request.SiteID, request.RequestID)
		if err != nil {
			return err
		}
		var updatedAt *time.Time
		if !request.Override.Inherits() {
			updatedAt = &now
		}
		result = newState(request.SiteID, request.ExpectedRevision+1, request.Override, library, updatedAt)
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &actor.UserID, Action: AuditAction,
			ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{
				"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "site_id": request.SiteID.String(),
				"from_version": request.ExpectedRevision, "to_version": result.Version,
				"changes": overrideChanges(previous, request.Override), "inherits": request.Override.Inherits(),
				"automatic_publication": automatic,
			},
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, scopeID, request, digest, result, now)
	})
	if err != nil {
		if reason := deniedReason(err); reason != "" && auditScopeID != uuid.Nil {
			// The refused write rolled back; its audit event is its own transaction.
			if auditErr := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
				return s.auditor.Append(ctx, tx, audit.Event{
					ScopeID: auditScopeID, ActorUserID: &actor.UserID, Action: AuditAction,
					ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "denied",
					Payload: map[string]any{
						"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "site_id": request.SiteID.String(),
						"reason_code": reason, "expected_version": request.ExpectedRevision,
						"requested": overrideSummary(request.Override),
					},
				})
			}); auditErr != nil {
				return State{}, fmt.Errorf("update site quick block: %w (audit denied write: %v)", err, auditErr)
			}
		}
		return State{}, fmt.Errorf("update site quick block: %w", err)
	}
	return result, nil
}

// deniedReason is the audit reason code of a refused write ("" for errors
// that are not a decision on the request: not found, persistence).
func deniedReason(err error) string {
	switch {
	case errors.Is(err, ErrLocked):
		return "site_locked"
	case errors.Is(err, ErrRevisionConflict):
		return "revision_conflict"
	case errors.Is(err, ErrIdempotencyConflict):
		return "idempotency_conflict"
	case errors.Is(err, ErrNoLibrary):
		return "no_waf_library"
	case errors.Is(err, securitypolicy.ErrQuickBlockIPIntelUnavailable):
		return "ip_intel_unavailable"
	case errors.Is(err, securitypolicy.ErrQuickBlockUnsupported):
		return "unsupported_policy"
	case errors.Is(err, securitypolicy.ErrQuickBlockLastRules):
		return "last_rules"
	case errors.Is(err, securitypolicy.ErrQuickBlockRuleBudget):
		return "rule_budget"
	}
	return ""
}

// overrideSummary is the audit form of an override: per item "inherit",
// true/false, or the list (crawlers by their networks).
func overrideSummary(override securitypolicy.QuickBlockOverride) map[string]any {
	item := func(set bool, value any) any {
		if !set {
			return "inherit"
		}
		return value
	}
	var blockCN, blockGlobal, carriers, crawlers any
	if override.BlockIDCCN != nil {
		blockCN = *override.BlockIDCCN
	}
	if override.BlockIDCGlobal != nil {
		blockGlobal = *override.BlockIDCGlobal
	}
	if override.Carriers != nil {
		carriers = *override.Carriers
	}
	if override.AllowedCrawlers != nil {
		// The crawler networks (at most MaxQuickBlockCrawlerNetworks).
		networks := []string{}
		for _, crawler := range *override.AllowedCrawlers {
			networks = append(networks, crawler.Networks...)
		}
		crawlers = networks
	}
	return map[string]any{
		"block_idc_cn":     item(override.BlockIDCCN != nil, blockCN),
		"block_idc_global": item(override.BlockIDCGlobal != nil, blockGlobal),
		"carriers":         item(override.Carriers != nil, carriers),
		"allowed_crawlers": item(override.AllowedCrawlers != nil, crawlers),
	}
}

// overrideChanges is the audit change summary: the items whose setting
// changed, each {"from","to"} in overrideSummary form.
func overrideChanges(previous, next securitypolicy.QuickBlockOverride) map[string]any {
	before, after := overrideSummary(previous), overrideSummary(next)
	changes := map[string]any{}
	for key, to := range after {
		from := before[key]
		fromJSON, _ := json.Marshal(from)
		toJSON, _ := json.Marshal(to)
		if !bytes.Equal(fromJSON, toJSON) {
			changes[key] = map[string]any{"from": from, "to": to}
		}
	}
	return changes
}

func newState(siteID uuid.UUID, revision int64, override securitypolicy.QuickBlockOverride, library *Library, updatedAt *time.Time) State {
	state := State{SiteID: siteID, Version: revision, Override: override, Library: library, UpdatedAt: updatedAt}
	if library != nil {
		effective := securitypolicy.EffectiveQuickBlock(&library.QuickBlock, override)
		state.Effective = &effective
	}
	return state
}

func targetScope(ctx context.Context, tx pgx.Tx, actor Actor, siteID uuid.UUID) (uuid.UUID, error) {
	if actor.ScopeKind == "tenant" {
		return actor.ScopeID, nil
	}
	var scopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1`, siteID).Scan(&scopeID); errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	} else if err != nil {
		return uuid.Nil, err
	}
	return scopeID, nil
}

func lockEdgeConfigurationScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
		VALUES($1,1,clock_timestamp()) ON CONFLICT(scope_id) DO NOTHING`, scopeID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT 1 FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`, scopeID)
	return err
}

// readOverride is the site's stored override (none: inherit everything).
func readOverride(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, lock bool) (securitypolicy.QuickBlockOverride, *time.Time, error) {
	query := `SELECT override,updated_at FROM site_quick_block_overrides WHERE scope_id=$1 AND site_id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	var raw []byte
	var updatedAt time.Time
	if err := tx.QueryRow(ctx, query, scopeID, siteID).Scan(&raw, &updatedAt); errors.Is(err, pgx.ErrNoRows) {
		return securitypolicy.QuickBlockOverride{}, nil, nil
	} else if err != nil {
		return securitypolicy.QuickBlockOverride{}, nil, err
	}
	override, err := securitypolicy.DecodeQuickBlockOverride(raw)
	if err != nil {
		return securitypolicy.QuickBlockOverride{}, nil, fmt.Errorf("decode site quick block override: %w", err)
	}
	return override, &updatedAt, nil
}

func writeOverride(ctx context.Context, tx pgx.Tx, scopeID, siteID, userID uuid.UUID, override securitypolicy.QuickBlockOverride, now time.Time) error {
	if override.Inherits() {
		_, err := tx.Exec(ctx, `DELETE FROM site_quick_block_overrides WHERE scope_id=$1 AND site_id=$2`, scopeID, siteID)
		return err
	}
	encoded, err := json.Marshal(override)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO site_quick_block_overrides(scope_id,site_id,override,updated_by_user_id,updated_at)
		VALUES($1,$2,$3,$4,$5)
		ON CONFLICT(site_id) DO UPDATE SET override=EXCLUDED.override,
			updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
		scopeID, siteID, string(encoded), userID, now)
	return err
}

// loadLibrary is the site's WAF rule library binding (nil: none, or its
// policy was deleted) and the versions an override must apply to: the
// latest and, when different, the one the binding publishes. lock takes the
// policy row FOR SHARE, serializing with library writes (whose guard reads
// the overrides).
func loadLibrary(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, lock bool) (*Library, []securitypolicy.Policy, error) {
	query := `SELECT binding.active_policy_version,latest.document,active.document
		FROM security_policy_site_bindings binding
		JOIN security_policies policy ON policy.id=binding.policy_id AND policy.scope_id=binding.tenant_scope_id
		  AND policy.deleted_at IS NULL
		JOIN security_policy_versions latest ON latest.policy_id=policy.id AND latest.revision=policy.revision
		LEFT JOIN security_policy_versions active
		  ON active.policy_id=policy.id AND active.revision=binding.active_policy_version
		WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2 AND binding.policy_kind=$3`
	if lock {
		query += ` FOR SHARE OF policy`
	}
	var activeVersion *int64
	var latestDocument, activeDocument []byte
	if err := tx.QueryRow(ctx, query, scopeID, siteID, securitypolicy.KindWAF).Scan(&activeVersion, &latestDocument, &activeDocument); errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}
	latest, err := decodeVersion(latestDocument, scopeID)
	if err != nil {
		return nil, nil, err
	}
	versions := []securitypolicy.Policy{latest}
	active := int64(0)
	if activeVersion != nil {
		active = *activeVersion
		if active != latest.Revision {
			if activeDocument == nil {
				return nil, nil, errors.New("site WAF binding publishes a missing policy version")
			}
			published, err := decodeVersion(activeDocument, scopeID)
			if err != nil || published.ID != latest.ID || published.Revision != active {
				return nil, nil, errors.New("site WAF binding publishes an invalid policy version")
			}
			versions = append(versions, published)
		}
	}
	library := libraryState(latest, active)
	return &library, versions, nil
}

func decodeVersion(document []byte, scopeID uuid.UUID) (securitypolicy.Policy, error) {
	var policy securitypolicy.Policy
	if err := json.Unmarshal(document, &policy); err != nil || policy.ScopeID != scopeID || policy.Kind != securitypolicy.KindWAF ||
		policy.ID == uuid.Nil || policy.Revision < 1 {
		return securitypolicy.Policy{}, errors.New("decode site WAF policy version")
	}
	return policy, nil
}

// ipIntelReady: the control plane holds a downloaded IP intelligence library
// (the same check as the library's quick block; migration 353 moved the
// library from ip_intel_library to artifactsync's local_artifacts).
func ipIntelReady(ctx context.Context, tx pgx.Tx) (bool, error) {
	revision, err := securitypolicy.IPIntelRevision(ctx, tx)
	return revision > 0, err
}

// replay returns the stored response of the actor's earlier write with the
// same key (same request), or ErrIdempotencyConflict for a different one.
func (s *Store) replay(ctx context.Context, tx pgx.Tx, actor Actor, request UpdateRequest, digest [32]byte, result *State) (bool, error) {
	var storedSiteID uuid.UUID
	var storedDigest, body []byte
	err := tx.QueryRow(ctx, `SELECT site_id,request_digest,response_body FROM site_quick_block_write_requests
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3`,
		actor.ScopeID, actor.UserID, request.IdempotencyKey).Scan(&storedSiteID, &storedDigest, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if storedSiteID != request.SiteID || !bytes.Equal(storedDigest, digest[:]) {
		return false, ErrIdempotencyConflict
	}
	if err := json.Unmarshal(body, result); err != nil {
		return false, fmt.Errorf("decode stored site quick block response: %w", err)
	}
	return true, nil
}

func (s *Store) completeWrite(ctx context.Context, tx pgx.Tx, actor Actor, scopeID uuid.UUID, request UpdateRequest,
	digest [32]byte, result State, now time.Time) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `INSERT INTO site_quick_block_write_requests(
		id,actor_scope_id,actor_user_id,target_scope_id,site_id,idempotency_key,request_digest,response_body,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
	ON CONFLICT(actor_scope_id,actor_user_id,idempotency_key) DO NOTHING`,
		id, actor.ScopeID, actor.UserID, scopeID, request.SiteID, request.IdempotencyKey, digest[:], string(body), now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}
