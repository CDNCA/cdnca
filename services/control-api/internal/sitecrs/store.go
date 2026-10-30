package sitecrs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AppsAuditAction is the audit event of a site CRS write that changed the
// site's application types (with the same write's AuditAction event).
const AppsAuditAction = "rule.site_crs_apps.update"

// AuditAction is the audit event of a site CRS write (success, or denied
// with a reason code); changes name the items whose setting changed.
const AuditAction = "rule.site_crs.update"

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
		library, err := loadLibrary(ctx, tx, scopeID, siteID, false)
		if err != nil {
			return err
		}
		profiles, err := securitypolicy.LoadCRSProfilesTx(ctx, tx, nil)
		if err != nil {
			return err
		}
		apps, err := securitypolicy.LoadCRSAppsTx(ctx, tx)
		if err != nil {
			return err
		}
		result = newState(siteID, revision, override, library, profiles, apps, updatedAt)
		result.RulePackSuspensions, err = rulepackcontrol.SiteSuspensionsTx(ctx, tx, siteID)
		return err
	})
	if err != nil {
		return State{}, fmt.Errorf("get site CRS: %w", err)
	}
	return result, nil
}

func (s *Store) Update(ctx context.Context, actor Actor, request UpdateRequest, digest [32]byte) (State, error) {
	var result State
	var auditScopeID uuid.UUID
	var previous securitypolicy.CRSOverride
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID, err := targetScope(ctx, tx, actor, request.SiteID)
		if err != nil {
			return err
		}
		auditScopeID = scopeID
		// Publication lock order: configuration scope before the site row.
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
		if lockedAt != nil && actor.ScopeKind == "tenant" {
			return ErrLocked
		}
		if revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if previous, _, err = readOverride(ctx, tx, scopeID, request.SiteID, true); err != nil {
			return err
		}
		library, err := loadLibrary(ctx, tx, scopeID, request.SiteID, true)
		if err != nil {
			return err
		}
		profiles, err := securitypolicy.LoadCRSProfilesTx(ctx, tx, nil)
		if err != nil {
			return err
		}
		apps, err := securitypolicy.LoadCRSAppsTx(ctx, tx)
		if err != nil {
			return err
		}
		if !request.Override.Inherits() {
			if library == nil {
				return ErrNoManagedWAF
			}
			if err := checkEffective(effective(library, request.Override), profiles); err != nil {
				return err
			}
			if err := checkApps(request.Override.Apps, apps); err != nil {
				return err
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
		// Mounts the new profile no longer covers are suspended (and covered
		// suspended ones restored) here, so the profile itself goes out with
		// the automatic publication instead of being refused by the pack.
		packs, err := rulepackcontrol.ApplySiteProfileChangeTx(ctx, tx, rulepackcontrol.ProfileChangeInput{
			ScopeID: scopeID, SiteID: request.SiteID, ActorUserID: actor.UserID, ActorScopeKind: actor.ScopeKind,
			SourceIP: request.SourceIP, RequestID: request.RequestID, Now: now})
		if err != nil {
			return err
		}
		automatic, err := edgeautopublish.EnqueueSiteSettingTx(ctx, tx, scopeID, request.SiteID, request.RequestID)
		if err != nil {
			return err
		}
		var updatedAt *time.Time
		if !request.Override.Inherits() {
			updatedAt = &now
		}
		result = newState(request.SiteID, request.ExpectedRevision+1, request.Override, library, profiles, apps, updatedAt)
		if result.RulePackSuspensions, err = rulepackcontrol.SiteSuspensionsTx(ctx, tx, request.SiteID); err != nil {
			return err
		}
		result.RulePackChange = &packs
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &actor.UserID, Action: AuditAction,
			ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{
				"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "site_id": request.SiteID.String(),
				"from_version": request.ExpectedRevision, "to_version": result.Version,
				"changes": overrideChanges(previous, request.Override), "inherits": request.Override.Inherits(),
				"automatic_publication": automatic, "rule_packs_suspended": suspensionNames(packs.Suspended),
				"rule_packs_restored": suspensionNames(packs.Restored),
			},
		}); err != nil {
			return err
		}
		if !slices.Equal(previous.Apps, request.Override.Apps) {
			from, to := previous.Apps, request.Override.Apps
			if from == nil {
				from = []string{}
			}
			if to == nil {
				to = []string{}
			}
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID: scopeID, ActorUserID: &actor.UserID, Action: AppsAuditAction,
				ResourceType: "site", ResourceID: request.SiteID.String(), RequestID: request.RequestID, Result: "success",
				Payload: map[string]any{
					"ip": request.SourceIP, "actor_scope_kind": actor.ScopeKind, "site_id": request.SiteID.String(),
					"changes": map[string]any{"apps": map[string]any{"from": from, "to": to}},
					"automatic_publication": automatic,
				},
			}); err != nil {
				return err
			}
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
				return State{}, fmt.Errorf("update site CRS: %w (audit denied write: %v)", err, auditErr)
			}
		}
		return State{}, fmt.Errorf("update site CRS: %w", err)
	}
	return result, nil
}

// suspensionNames is the audit form of suspended / restored mounts.
func suspensionNames(items []rulepackcontrol.Suspension) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.PackID+"@"+item.Version)
	}
	return out
}

// checkEffective: the effective profile is downloaded and usable and exports
// every effective exclusion.
func checkEffective(value *Library, profiles securitypolicy.CRSProfiles) error {
	profile, ok := profiles[value.Profile]
	if !ok {
		return ErrProfileUnavailable
	}
	for _, id := range value.Exclusions {
		if _, found := slices.BinarySearch(profile.Profile.Exports, id); !found {
			return ErrExclusionNotExported
		}
	}
	return nil
}

func deniedReason(err error) string {
	switch {
	case errors.Is(err, ErrLocked):
		return "site_locked"
	case errors.Is(err, ErrRevisionConflict):
		return "revision_conflict"
	case errors.Is(err, ErrIdempotencyConflict):
		return "idempotency_conflict"
	case errors.Is(err, ErrNoManagedWAF):
		return "no_managed_waf"
	case errors.Is(err, ErrProfileUnavailable):
		return "crs_profile_unavailable"
	case errors.Is(err, ErrExclusionNotExported):
		return "crs_exclusion_not_exported"
	case errors.Is(err, ErrAppUnavailable):
		return "crs_app_unavailable"
	}
	return ""
}

// overrideSummary is the audit form of an override: per item "inherit" or
// the value.
func overrideSummary(override securitypolicy.CRSOverride) map[string]any {
	apps := override.Apps
	if apps == nil {
		apps = []string{}
	}
	summary := map[string]any{"profile": "inherit", "exclusions": "inherit", "apps": apps}
	if override.Profile != nil {
		summary["profile"] = *override.Profile
	}
	if override.Exclusions != nil {
		summary["exclusions"] = *override.Exclusions
	}
	return summary
}

// overrideChanges is the audit change summary: the items whose setting
// changed, each {"from","to"} in overrideSummary form.
func overrideChanges(previous, next securitypolicy.CRSOverride) map[string]any {
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

func newState(siteID uuid.UUID, revision int64, override securitypolicy.CRSOverride, library *Library,
	profiles securitypolicy.CRSProfiles, apps securitypolicy.CRSApps, updatedAt *time.Time) State {
	return State{SiteID: siteID, Version: revision, Override: override, Library: library,
		Effective: effective(library, override), Profiles: profileList(profiles), Apps: apps.Summaries(), UpdatedAt: updatedAt}
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

func readOverride(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, lock bool) (securitypolicy.CRSOverride, *time.Time, error) {
	query := `SELECT override,updated_at FROM site_crs_overrides WHERE scope_id=$1 AND site_id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	var raw []byte
	var updatedAt time.Time
	if err := tx.QueryRow(ctx, query, scopeID, siteID).Scan(&raw, &updatedAt); errors.Is(err, pgx.ErrNoRows) {
		return securitypolicy.CRSOverride{}, nil, nil
	} else if err != nil {
		return securitypolicy.CRSOverride{}, nil, err
	}
	override, err := securitypolicy.DecodeCRSOverride(raw)
	if err != nil {
		return securitypolicy.CRSOverride{}, nil, fmt.Errorf("decode site CRS override: %w", err)
	}
	return override, &updatedAt, nil
}

func writeOverride(ctx context.Context, tx pgx.Tx, scopeID, siteID, userID uuid.UUID, override securitypolicy.CRSOverride, now time.Time) error {
	if override.Inherits() {
		_, err := tx.Exec(ctx, `DELETE FROM site_crs_overrides WHERE scope_id=$1 AND site_id=$2`, scopeID, siteID)
		return err
	}
	encoded, err := json.Marshal(override)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO site_crs_overrides(scope_id,site_id,override,updated_by_user_id,updated_at)
		VALUES($1,$2,$3,$4,$5)
		ON CONFLICT(site_id) DO UPDATE SET override=EXCLUDED.override,
			updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
		scopeID, siteID, string(encoded), userID, now)
	return err
}

// loadLibrary is the managed WAF of the site's WAF rule library (latest
// version; nil: no binding, deleted policy, or no managed WAF rule).
func loadLibrary(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, lock bool) (*Library, error) {
	query := `SELECT latest.document
		FROM security_policy_site_bindings binding
		JOIN security_policies policy ON policy.id=binding.policy_id AND policy.scope_id=binding.tenant_scope_id
		  AND policy.deleted_at IS NULL
		JOIN security_policy_versions latest ON latest.policy_id=policy.id AND latest.revision=policy.revision
		WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2 AND binding.policy_kind=$3`
	if lock {
		query += ` FOR SHARE OF policy`
	}
	var document []byte
	if err := tx.QueryRow(ctx, query, scopeID, siteID, securitypolicy.KindWAF).Scan(&document); errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var policy securitypolicy.Policy
	if err := json.Unmarshal(document, &policy); err != nil || policy.ScopeID != scopeID || policy.Kind != securitypolicy.KindWAF {
		return nil, errors.New("decode site WAF policy version")
	}
	managed := securitypolicy.PolicyManagedWAF(policy)
	if managed == nil {
		return nil, nil
	}
	exclusions := append([]int{}, managed.Exclusions...)
	return &Library{PolicyID: policy.ID, Version: policy.Revision, Profile: managed.Profile, Exclusions: exclusions}, nil
}

func (s *Store) replay(ctx context.Context, tx pgx.Tx, actor Actor, request UpdateRequest, digest [32]byte, result *State) (bool, error) {
	var storedSiteID uuid.UUID
	var storedDigest, body []byte
	err := tx.QueryRow(ctx, `SELECT site_id,request_digest,response_body FROM site_crs_write_requests
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
		return false, fmt.Errorf("decode stored site CRS response: %w", err)
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
	command, err := tx.Exec(ctx, `INSERT INTO site_crs_write_requests(
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

// EffectiveLibraryTx is the managed WAF the site runs once published (its
// WAF rule library's with the site override applied); nil without one.
func EffectiveLibraryTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) (*Library, error) {
	override, _, err := readOverride(ctx, tx, scopeID, siteID, false)
	if err != nil {
		return nil, err
	}
	library, err := loadLibrary(ctx, tx, scopeID, siteID, false)
	if err != nil {
		return nil, err
	}
	return effective(library, override), nil
}

// EffectiveProfileTx is the CRS profile pack ID the site runs once
// published (its WAF rule library's managed WAF with the site override
// applied; "" without a managed WAF) and the downloaded usable profiles.
// The adaptive WAF page reads it for the grey zone challenge and the rule
// sets (wafadapt).
func EffectiveProfileTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) (string, securitypolicy.CRSProfiles, error) {
	override, _, err := readOverride(ctx, tx, scopeID, siteID, false)
	if err != nil {
		return "", nil, err
	}
	library, err := loadLibrary(ctx, tx, scopeID, siteID, false)
	if err != nil {
		return "", nil, err
	}
	profiles, err := securitypolicy.LoadCRSProfilesTx(ctx, tx, nil)
	if err != nil {
		return "", nil, err
	}
	if library = effective(library, override); library == nil {
		return "", profiles, nil
	}
	return library.Profile, profiles, nil
}

// SetAppsSystem sets the site's CRS application types for a market leaf
// (fix-mktsiteconf3): the subscriber sends the site's managed WAF profile
// and exclusions inside its WAF policy, so only the application types are
// the site's own override here. Unlike Update it does not need the site's
// WAF binding yet (the leaf activates the policy after the commit). Every
// pack must be downloaded here (ErrAppUnavailable). Unchanged apps write
// nothing; otherwise the site revision moves, the automatic publication is
// queued and rule.site_crs_apps.update is audited with the system actor.
func (s *Store) SetAppsSystem(ctx context.Context, scopeID, siteID, userID uuid.UUID, apps []string, requestID string) (bool, error) {
	changed := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockEdgeConfigurationScope(ctx, tx, scopeID); err != nil {
			return err
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT revision FROM sites WHERE id=$1 AND scope_id=$2 AND deleted_at IS NULL FOR UPDATE`,
			siteID, scopeID).Scan(&revision); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		previous, _, err := readOverride(ctx, tx, scopeID, siteID, true)
		if err != nil {
			return err
		}
		next := previous
		next.Apps = slices.Clone(apps)
		if err := securitypolicy.NormalizeCRSOverride(&next); err != nil {
			return ErrInvalidInput
		}
		if slices.Equal(previous.Apps, next.Apps) {
			return nil
		}
		available, err := securitypolicy.LoadCRSAppsTx(ctx, tx)
		if err != nil {
			return err
		}
		if err := checkApps(next.Apps, available); err != nil {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		if err := writeOverride(ctx, tx, scopeID, siteID, userID, next, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE sites SET revision=revision+1,updated_at=$2 WHERE id=$1`, siteID, now); err != nil {
			return err
		}
		automatic, err := edgeautopublish.EnqueueSiteSettingTx(ctx, tx, scopeID, siteID, requestID)
		if err != nil {
			return err
		}
		from, to := previous.Apps, next.Apps
		if from == nil {
			from = []string{}
		}
		if to == nil {
			to = []string{}
		}
		changed = true
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, Action: AppsAuditAction, ActorKind: "system", ActorRef: "job:market_leaf_sync",
			ResourceType: "site", ResourceID: siteID.String(), RequestID: requestID, Result: "success",
			Payload: map[string]any{"site_id": siteID.String(), "changes": map[string]any{"apps": map[string]any{"from": from, "to": to}},
				"automatic_publication": automatic, "from_version": revision, "to_version": revision + 1},
		})
	})
	if err != nil {
		return false, fmt.Errorf("set site CRS apps: %w", err)
	}
	return changed, nil
}
