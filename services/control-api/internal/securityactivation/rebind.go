package securityactivation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A WAF, CC or ACL library saved on the general rules page (no site context) is
// republished by the activation worker to every site bound to it whose
// binding is behind the library's current revision (10-22 自动下发: after a
// configuration change, publish to the package's primary/backup line
// groups). The start names no nodes, so siteTargets resolves them and the
// worker's reconcile runs the usual canary and expansion.
//
// A binding is skipped while it has an unfinished candidate (the condition
// of the open-binding unique index of 088) or a capability wait; the next
// pass after the candidate ends starts the latest revision once, so several
// saves merge into one release. A saved revision waits rebindGrace first, so
// a save in a site context (the page starts that site itself) is not raced.
// A start refused for anything else (package feature not enabled, no target
// node, site locked, permission revoked) is retried after rebindBackoff.

const (
	rebindBatchSize = 100
	rebindGrace     = 15 * time.Second
	rebindBackoff   = 5 * time.Minute
)

// rebindItem is one stale WAF/CC/ACL binding and the actor its start runs as:
// the user who saved the revision, through their membership of the site's
// tenant scope, else their platform membership (Start authorizes either).
type rebindItem struct {
	bindingID           uuid.UUID
	scopeID             uuid.UUID
	siteID              uuid.UUID
	policyID            uuid.UUID
	policyRevision      int64
	bindingRevision     int64
	activePolicyVersion int64
	actor               securitypolicy.Actor
}

type rebindStore interface {
	loadRebindItems(ctx context.Context, savedBefore time.Time, after uuid.UUID, limit int) ([]rebindItem, error)
	Start(ctx context.Context, actor securitypolicy.Actor, input StartInput) (StartResult, error)
}

type rebinder struct {
	store  rebindStore
	clock  func() time.Time
	ttl    time.Duration
	cursor uuid.UUID
	// retryAt: bindings whose start was refused, keyed by binding and
	// revision (a newer save is tried at once).
	retryAt map[rebindKey]time.Time
}

type rebindKey struct {
	bindingID uuid.UUID
	revision  int64
}

func newRebinder(store rebindStore, clock func() time.Time, ttl time.Duration) *rebinder {
	return &rebinder{store: store, clock: clock, ttl: ttl, retryAt: map[rebindKey]time.Time{}}
}

// run starts one batch of stale bindings. Only loading failures are
// returned; a refused start backs off that binding.
func (r *rebinder) run(ctx context.Context) error {
	now := r.clock()
	items, err := r.store.loadRebindItems(ctx, now.Add(-rebindGrace), r.cursor, rebindBatchSize)
	if err != nil {
		return err
	}
	for key, at := range r.retryAt {
		if !now.Before(at) {
			delete(r.retryAt, key)
		}
	}
	for _, item := range items {
		key := rebindKey{bindingID: item.bindingID, revision: item.policyRevision}
		if _, waiting := r.retryAt[key]; waiting {
			continue
		}
		if _, err := r.store.Start(ctx, item.actor, rebindInput(item, now, r.ttl)); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			r.retryAt[key] = now.Add(rebindBackoff)
		}
	}
	r.cursor = uuid.Nil
	if len(items) == rebindBatchSize {
		r.cursor = items[len(items)-1].bindingID
	}
	return nil
}

// rebindInput is the start of one stale binding: no nodes and canary 0 (the
// site's package line groups, one canary node), keyed by binding and
// revision so concurrent controllers cannot start it twice.
func rebindInput(item rebindItem, now time.Time, ttl time.Duration) StartInput {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%d", item.scopeID, item.bindingID, item.policyRevision)))
	key := "rebind." + hex.EncodeToString(digest[:])
	taskID := "security-activation-rebind"
	return StartInput{
		TenantScopeID: item.scopeID, SiteID: item.siteID, PolicyID: item.policyID,
		PolicyVersion: item.policyRevision, ExpectedBindingRevision: item.bindingRevision,
		ExpectedActivePolicyVersion: item.activePolicyVersion,
		IdempotencyKey:              key,
		RequestID:                   uuid.NewSHA1(item.bindingID, []byte(key)).String(),
		CorrelationID:               item.bindingID.String(),
		Traceparent:                 activationTraceparent(item.bindingID, key),
		TaskID:                      &taskID,
		ExpiresAt:                   now.Add(ttl - time.Minute),
	}
}

// staleBindingsFrom / staleBindingsWhere select WAF/CC/ACL bindings (ACL
// needs no package feature; RebindStatus counts WAF and CC only) of live
// sites whose live library has a revision newer than both the active and the
// last claimed version and that have no unfinished candidate.
const staleBindingsFrom = `FROM security_policy_site_bindings binding
	JOIN security_policies policy ON policy.scope_id=binding.tenant_scope_id AND policy.id=binding.policy_id
	  AND policy.kind=binding.policy_kind AND policy.deleted_at IS NULL
	JOIN sites site ON site.scope_id=binding.tenant_scope_id AND site.id=binding.site_id AND site.deleted_at IS NULL`

const staleBindingsWhere = `binding.policy_kind IN ('waf','cc','acl')
	  AND policy.revision>GREATEST(COALESCE(binding.active_policy_version,0),COALESCE(binding.last_claimed_policy_version,0))
	  AND NOT EXISTS (SELECT 1 FROM security_policy_activation_candidates open
	    WHERE open.tenant_scope_id=binding.tenant_scope_id AND open.binding_id=binding.id
	      AND (open.candidate_status IN ('claimed','canary','expanding','healthy') OR
	           (open.candidate_status IN ('failed','cancelled','expired') AND open.recovered_at IS NULL)))`

// loadRebindItems also skips bindings with a capability wait (waiting, or
// already recorded for this revision or a newer one: it resumes or failed
// through the wait, not here) and revisions saved after savedBefore.
func (store *Store) loadRebindItems(ctx context.Context, savedBefore time.Time, after uuid.UUID, limit int) ([]rebindItem, error) {
	if limit < 1 || limit > 1000 {
		return nil, ErrInvalidInput
	}
	rows, err := store.pool.Query(ctx, `SELECT binding.id,binding.tenant_scope_id,binding.site_id,binding.policy_id,
		policy.revision,binding.revision,COALESCE(binding.active_policy_version,0),
		version.created_by_user_id,actor.scope_id,actor.kind
		`+staleBindingsFrom+`
		JOIN security_policy_versions version ON version.policy_id=policy.id AND version.revision=policy.revision
		JOIN LATERAL (SELECT membership.scope_id,scope.kind FROM memberships membership
		    JOIN access_scopes scope ON scope.id=membership.scope_id
		    WHERE membership.user_id=version.created_by_user_id AND membership.status='active'
		      AND (membership.scope_id=binding.tenant_scope_id OR scope.kind='platform')
		    ORDER BY (membership.scope_id=binding.tenant_scope_id) DESC, membership.scope_id LIMIT 1) actor ON true
		WHERE `+staleBindingsWhere+`
		  AND version.created_at<=$1
		  AND NOT EXISTS (SELECT 1 FROM security_activation_capability_waits wait
		    WHERE wait.tenant_scope_id=binding.tenant_scope_id AND wait.site_id=binding.site_id
		      AND wait.policy_kind=binding.policy_kind AND (wait.status='waiting' OR wait.policy_version>=policy.revision))
		  AND ($3::uuid='00000000-0000-0000-0000-000000000000'::uuid OR binding.id>$3)
		ORDER BY binding.id LIMIT $2`, savedBefore, limit, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]rebindItem, 0, limit)
	for rows.Next() {
		var item rebindItem
		if err := rows.Scan(&item.bindingID, &item.scopeID, &item.siteID, &item.policyID, &item.policyRevision,
			&item.bindingRevision, &item.activePolicyVersion, &item.actor.UserID, &item.actor.ScopeID,
			&item.actor.ScopeKind); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// rebindStatusLimit bounds the sites RebindStatus checks one by one.
const rebindStatusLimit = 200

// RebindStatus is what the rules page shows for one policy kind: how many of
// the scope's bound sites still run an older library version and, of them,
// how many are not republished because their package does not include the
// feature (the worker keeps retrying them; they publish once it is enabled).
type RebindStatus struct {
	PendingSites       int `json:"pending_sites"`
	PackageDeniedSites int `json:"package_denied_sites"`
}

type rebindStatusSite struct {
	siteID, policyID uuid.UUID
	revision         int64
}

// RebindStatus counts the actor's own scope only.
func (store *Store) RebindStatus(ctx context.Context, actor securitypolicy.Actor, policyKind string) (RebindStatus, error) {
	if store == nil || store.pool == nil || !validActor(actor) ||
		(policyKind != securitypolicy.KindWAF && policyKind != securitypolicy.KindCC) {
		return RebindStatus{}, ErrInvalidInput
	}
	var sites []rebindStatusSite
	// Not a read-only transaction: authorizePermission takes the IAM shared lock,
	// which iam_global_lock_shared_v1 refuses in read-only transactions (P6900).
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := authorizePermission(ctx, tx, actor, actor.ScopeID, activationReadPermission); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT binding.site_id,binding.policy_id,policy.revision `+staleBindingsFrom+`
			WHERE binding.tenant_scope_id=$1 AND binding.policy_kind=$2 AND `+staleBindingsWhere+`
			ORDER BY binding.site_id LIMIT $3`, actor.ScopeID, policyKind, rebindStatusLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var site rebindStatusSite
			if err := rows.Scan(&site.siteID, &site.policyID, &site.revision); err != nil {
				return err
			}
			sites = append(sites, site)
		}
		return rows.Err()
	})
	if err != nil {
		return RebindStatus{}, err
	}
	result := RebindStatus{PendingSites: len(sites)}
	now := store.clock().UTC()
	for _, site := range sites {
		denied, err := store.packageDenied(ctx, actor.ScopeID, site, now)
		if err != nil {
			return RebindStatus{}, err
		}
		if denied {
			result.PackageDeniedSites++
		}
	}
	return result, nil
}

// packageDenied runs the publication's own package check for one site in
// its own rolled-back transaction (the check locks the site's subscription;
// one lock at a time cannot deadlock with a release).
func (store *Store) packageDenied(ctx context.Context, scopeID uuid.UUID, site rebindStatusSite, at time.Time) (bool, error) {
	denied := false
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		policy, err := loadPolicyVersion(ctx, tx, scopeID, site.policyID, site.revision)
		if err != nil {
			return err
		}
		err = securitybinding.CheckSitePolicyFeature(ctx, tx, scopeID, site.siteID, policy, at)
		denied = errors.Is(err, packageaddon.ErrFeatureDenied) || errors.Is(err, packageaddon.ErrSubscriptionInactive)
		if err != nil && !denied && !errors.Is(err, securitybinding.ErrNotFound) {
			return err
		}
		// A library deleted or a site removed since the list counts as pending only.
		return errRebindStatusRollback
	})
	if errors.Is(err, errRebindStatusRollback) || errors.Is(err, ErrConflict) {
		err = nil
	}
	return denied, err
}

var errRebindStatusRollback = errors.New("security activation rebind status read")
