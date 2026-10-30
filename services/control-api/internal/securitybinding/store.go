package securitybinding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybundle"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/sitelock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool      *pgxpool.Pool
	publisher *securitybundle.Publisher
	auditor   *audit.Log
	clock     func() time.Time
}

type storedPublication struct {
	publication       Publication
	requestDigest     [32]byte
	planRequestDigest [32]byte
	canonicalPayload  []byte
	idempotencyKey    string
}

type bindingState struct {
	id                 uuid.UUID
	policyID           uuid.UUID
	kind               string
	activeVersion      int64
	lastClaimedVersion int64
	revision           int64
	// lastPolicyID/lastDetach: the library and kind of the last claim
	// (last_bundle_id); a claimed version is only comparable within it.
	lastPolicyID uuid.UUID
	lastDetach   bool
}

func NewStore(pool *pgxpool.Pool, publisher *securitybundle.Publisher, clock func() time.Time) (*Store, error) {
	if pool == nil || publisher == nil || clock == nil {
		return nil, ErrInvalidInput
	}
	return &Store{pool: pool, publisher: publisher, auditor: audit.New(pool), clock: clock}, nil
}

func (store *Store) Publish(ctx context.Context, actor securitypolicy.Actor, request PublishRequest) (Publication, error) {
	if !validInput(actor, request) {
		return Publication{}, ErrInvalidInput
	}
	var result Publication
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var err error
		result, err = store.publishTx(ctx, tx, actor, request)
		return err
	})
	if err != nil {
		return Publication{}, fmt.Errorf("publish security policy: %w", mapDatabaseError(err))
	}
	return result, nil
}

// PublishTx persists a publication inside the caller's transaction. Callers
// must first lock the site/subscription with LockSiteSubscription, then the
// edge configuration scope, preserving site -> subscription -> scope -> binding.
func (store *Store) PublishTx(
	ctx context.Context,
	tx pgx.Tx,
	actor securitypolicy.Actor,
	request PublishRequest,
) (Publication, error) {
	if tx == nil || !validInput(actor, request) {
		return Publication{}, ErrInvalidInput
	}
	result, err := store.publishTx(ctx, tx, actor, request)
	if err != nil {
		return Publication{}, mapDatabaseError(err)
	}
	return result, nil
}

func (store *Store) publishTx(ctx context.Context, tx pgx.Tx, actor securitypolicy.Actor, request PublishRequest) (Publication, error) {
	if err := authorize(ctx, tx, actor, request.TenantScopeID); err != nil {
		return Publication{}, err
	}
	if err := LockSiteSubscription(ctx, tx, request.TenantScopeID, request.SiteID); err != nil {
		return Publication{}, err
	}
	policy, current, deleted, err := loadPolicyVersion(ctx, tx, request.TenantScopeID, request.PolicyID, request.PolicyVersion)
	if err != nil {
		return Publication{}, err
	}
	bundleRequest := securitybundle.PublishRequest{
		TenantScopeID: request.TenantScopeID, SiteID: request.SiteID, Policy: policy,
		TargetNodeIDs: request.TargetNodeIDs, ExpectedActiveVersion: request.ExpectedActiveVersion,
		RolloutID: request.RolloutID, IdempotencyKey: request.IdempotencyKey,
	}
	if existing, found, err := loadPublication(ctx, tx, request.TenantScopeID, request.IdempotencyKey); err != nil {
		return Publication{}, err
	} else if found {
		return store.replay(ctx, bundleRequest, request.ExpectedBindingRevision, request.Detach, existing)
	}
	if !request.Detach && !current {
		if deleted {
			return Publication{}, ErrPolicyDeleted
		}
		return Publication{}, ErrPolicyVersionConflict
	}
	// FX31: a site locked by a platform administrator is read-only for tenants.
	if err := sitelock.RequireUnlocked(ctx, tx, actor.ScopeID, request.SiteID); errors.Is(err, sitelock.ErrLocked) {
		return Publication{}, ErrSiteLocked
	} else if err != nil {
		return Publication{}, err
	}
	if err := validateSiteAndNodes(ctx, tx, request.TenantScopeID, request.SiteID, request.TargetNodeIDs); err != nil {
		return Publication{}, err
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	// Detaching withdraws the feature: the package need not grant it.
	if !request.Detach {
		if err := CheckSitePolicyFeature(ctx, tx, request.TenantScopeID, request.SiteID, policy, now); err != nil {
			return Publication{}, err
		}
	}
	binding, err := lockBinding(ctx, tx, request.TenantScopeID, request.SiteID, policy.ID, policy.Kind, now)
	if err != nil {
		return Publication{}, err
	}
	if existing, found, err := loadPublication(ctx, tx, request.TenantScopeID, request.IdempotencyKey); err != nil {
		return Publication{}, err
	} else if found {
		return store.replay(ctx, bundleRequest, request.ExpectedBindingRevision, request.Detach, existing)
	}
	if err := checkClaim(binding, policy.ID, policy.Kind, request); err != nil {
		return Publication{}, err
	}

	planned, err := store.publisher.Plan(ctx, bundleRequest, nil)
	if err != nil {
		return Publication{}, err
	}
	claimTime := store.clock().UTC().Truncate(time.Microsecond)
	if !time.Unix(planned.Plan.Bundle.Payload.ExpiresAt, 0).After(claimTime) {
		return Publication{}, ErrPlanExpired
	}
	requestDigest, err := bindingRequestDigest(planned.Plan.RequestSHA256, request.ExpectedBindingRevision)
	if err != nil {
		return Publication{}, err
	}
	if err := releaseExpiredTargets(ctx, tx, request.TenantScopeID, claimTime); err != nil {
		return Publication{}, err
	}
	result, err := insertPublication(ctx, tx, actor, request, binding, planned.Plan, requestDigest, claimTime)
	if err != nil {
		return Publication{}, err
	}
	if err := insertTargets(ctx, tx, result, claimTime); err != nil {
		return Publication{}, err
	}
	command, err := tx.Exec(ctx, `UPDATE security_policy_site_bindings SET
		last_claimed_policy_version=$2,last_bundle_id=$3,revision=revision+1,updated_at=$4
		WHERE id=$1 AND revision=$5`, binding.id, request.PolicyVersion, result.BundleID, claimTime, request.ExpectedBindingRevision)
	if err != nil {
		return Publication{}, err
	}
	if command.RowsAffected() != 1 {
		return Publication{}, ErrBindingRevision
	}
	if err := store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: request.TenantScopeID, ActorUserID: &actor.UserID,
		Action: "security_policy.publication.claim", ResourceType: "security_policy_publication",
		ResourceID: result.BundleID.String(), RequestID: request.RequestID, Result: "success",
		Payload: map[string]any{
			"site_id": request.SiteID.String(), "policy_id": request.PolicyID.String(),
			"policy_kind": policy.Kind, "policy_version": request.PolicyVersion,
			"binding_revision": result.BindingRevision, "expected_active_version": request.ExpectedActiveVersion,
			"rollout_id": request.RolloutID.String(), "target_count": len(result.TargetNodeIDs),
		},
	}); err != nil {
		return Publication{}, err
	}
	return result, nil
}

// checkClaim is a claim's binding precondition (sec-rebind): the binding's
// revision and active version are compare-and-set; a claim of the binding's
// own library must move its version forward (past the active one and past
// the last claim of that library, unless that claim was a detach); a claim
// of another library rebinds and compares no version (versions of different
// libraries are unrelated); a detach names the active library and version.
// The database trigger (migration 470) enforces the same.
func checkClaim(binding bindingState, policyID uuid.UUID, kind string, request PublishRequest) error {
	if binding.kind != kind {
		return ErrBindingConflict
	}
	if binding.revision != request.ExpectedBindingRevision {
		return ErrBindingRevision
	}
	if binding.activeVersion != request.ExpectedActiveVersion {
		return ErrActiveVersionConflict
	}
	if request.Detach {
		if binding.activeVersion == 0 || binding.policyID != policyID || request.PolicyVersion != binding.activeVersion {
			return ErrBindingConflict
		}
		return nil
	}
	if binding.policyID != policyID {
		return nil
	}
	if request.PolicyVersion <= binding.activeVersion ||
		(binding.lastClaimedVersion > 0 && binding.lastPolicyID == policyID && !binding.lastDetach &&
			request.PolicyVersion <= binding.lastClaimedVersion) {
		return ErrPolicyVersionConflict
	}
	return nil
}

func (store *Store) replay(ctx context.Context, request securitybundle.PublishRequest, expectedBindingRevision int64,
	detach bool, existing storedPublication) (Publication, error) {
	if existing.publication.Detach != detach {
		return Publication{}, ErrIdempotencyConflict
	}
	planned, err := store.publisher.Plan(ctx, request, &securitybundle.PublicationPlan{
		IdempotencyKey: existing.idempotencyKey, RequestSHA256: existing.planRequestDigest,
		BundleID: existing.publication.BundleID, CanonicalPayload: existing.canonicalPayload,
		CanonicalPayloadSHA256: existing.publication.CanonicalPayloadSHA256,
		RuntimeSnapshotSHA256:  existing.publication.RuntimeSnapshotSHA256,
		BundleJSON:             existing.publication.BundleJSON,
	})
	if err != nil {
		if errors.Is(err, securitybundle.ErrIdempotencyConflict) {
			return Publication{}, ErrIdempotencyConflict
		}
		return Publication{}, err
	}
	digest, err := bindingRequestDigest(planned.Plan.RequestSHA256, expectedBindingRevision)
	if err != nil {
		return Publication{}, err
	}
	if digest != existing.requestDigest {
		return Publication{}, ErrIdempotencyConflict
	}
	result := existing.publication
	result.Replayed = true
	return result, nil
}

func validInput(actor securitypolicy.Actor, request PublishRequest) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil &&
		(actor.ScopeKind == "tenant" || actor.ScopeKind == "platform") &&
		request.TenantScopeID != uuid.Nil && request.SiteID != uuid.Nil && request.PolicyID != uuid.Nil &&
		request.PolicyVersion > 0 && request.ExpectedBindingRevision >= 0 && request.ExpectedActiveVersion >= 0 &&
		len(request.TargetNodeIDs) >= 1 && len(request.TargetNodeIDs) <= 10_000 &&
		request.RolloutID != uuid.Nil && validRequestID(request.RequestID)
}

func validRequestID(value string) bool {
	if !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < 1 || length > 128 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}

func authorize(ctx context.Context, tx pgx.Tx, actor securitypolicy.Actor, tenantScopeID uuid.UUID) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || tenantScopeID == uuid.Nil ||
		(actor.ScopeKind != "tenant" && actor.ScopeKind != "platform") {
		return ErrPermissionDenied
	}
	if err := iamlock.AcquireShared(ctx, tx); err != nil {
		return err
	}
	if _, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{actor.ScopeID, tenantScopeID}); err != nil {
		return err
	}
	var actualKind, targetKind, accountStatus, membershipStatus, tenantStatus string
	err := tx.QueryRow(ctx, `SELECT actor_scope.kind,target_scope.kind,account.status,membership.status,tenant.status
		FROM access_scopes actor_scope
		JOIN memberships membership ON membership.scope_id=actor_scope.id AND membership.user_id=$2
		JOIN users account ON account.id=membership.user_id
		JOIN access_scopes target_scope ON target_scope.id=$3
		JOIN tenants tenant ON tenant.id=target_scope.tenant_id
		WHERE actor_scope.id=$1`, actor.ScopeID, actor.UserID, tenantScopeID).
		Scan(&actualKind, &targetKind, &accountStatus, &membershipStatus, &tenantStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPermissionDenied
	}
	if err != nil {
		return err
	}
	if actualKind != actor.ScopeKind || targetKind != "tenant" || accountStatus != "active" ||
		membershipStatus != "active" || tenantStatus != "active" ||
		(actor.ScopeKind == "tenant" && actor.ScopeID != tenantScopeID) {
		return ErrPermissionDenied
	}
	var permitted bool
	if actor.ScopeKind == "tenant" {
		err = tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM custom_rbac_effective_permissions($1,$2)
			WHERE permission_name='security_policies.manage')`, tenantScopeID, actor.UserID).Scan(&permitted)
	} else {
		err = tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM role_assignments assignment
			JOIN role_permissions permission ON permission.role_id=assignment.role_id
			WHERE assignment.scope_id=$1 AND assignment.user_id=$2
			  AND permission.permission_name IN ('security_policies.manage','platform.admin'))`, actor.ScopeID, actor.UserID).Scan(&permitted)
	}
	if err != nil {
		return err
	}
	if !permitted {
		return ErrPermissionDenied
	}
	return nil
}

func loadPolicyVersion(ctx context.Context, tx pgx.Tx, scopeID, policyID uuid.UUID, revision int64) (securitypolicy.Policy, bool, bool, error) {
	var document []byte
	var currentRevision int64
	var deletedAt *time.Time
	err := tx.QueryRow(ctx, `SELECT version.document,p.revision,p.deleted_at
		FROM security_policy_versions version JOIN security_policies p ON p.id=version.policy_id
		WHERE p.scope_id=$1 AND version.policy_id=$2 AND version.revision=$3`, scopeID, policyID, revision).
		Scan(&document, &currentRevision, &deletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return securitypolicy.Policy{}, false, false, ErrNotFound
	}
	if err != nil {
		return securitypolicy.Policy{}, false, false, err
	}
	var policy securitypolicy.Policy
	if err := json.Unmarshal(document, &policy); err != nil || policy.ID != policyID || policy.ScopeID != scopeID || policy.Revision != revision {
		return securitypolicy.Policy{}, false, false, ErrInvalidInput
	}
	return policy, currentRevision == revision && deletedAt == nil, deletedAt != nil, nil
}

func validateSiteAndNodes(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, rawNodeIDs []uuid.UUID) error {
	var siteExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sites
		WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL)`, scopeID, siteID).Scan(&siteExists); err != nil {
		return err
	}
	if !siteExists {
		return ErrNotFound
	}
	seen := make(map[uuid.UUID]struct{}, len(rawNodeIDs))
	for _, nodeID := range rawNodeIDs {
		if nodeID == uuid.Nil {
			return ErrInvalidInput
		}
		seen[nodeID] = struct{}{}
	}
	if len(seen) == 0 {
		return ErrInvalidInput
	}
	nodeIDs := make([]uuid.UUID, 0, len(seen))
	for nodeID := range seen {
		nodeIDs = append(nodeIDs, nodeID)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM nodes
		WHERE id=ANY($2::uuid[]) AND admin_state='active' AND tenant_carries_node_287($1,id)`, scopeID, nodeIDs).Scan(&count); err != nil {
		return err
	}
	if count != len(nodeIDs) {
		return ErrNotFound
	}
	return nil
}

// LockSiteSubscription also applies to cleanup operations: expiry must never
// prevent disabling protection or recovering an already running deployment.
func LockSiteSubscription(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) error {
	var subscriptionID *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT package_subscription_id FROM sites
		WHERE scope_id=$1 AND id=$2 FOR UPDATE`, scopeID, siteID).Scan(&subscriptionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil || subscriptionID == nil {
		return err
	}
	var found uuid.UUID
	return tx.QueryRow(ctx, `SELECT id FROM package_subscriptions
		WHERE tenant_scope_id=$1 AND id=$2 FOR UPDATE`, scopeID, *subscriptionID).Scan(&found)
}

// CheckSitePolicyFeature requires LockSiteSubscription before any policy or
// binding lock. A disabled policy is a removal and does not need new rights.
func CheckSitePolicyFeature(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, policy securitypolicy.Policy, at time.Time) error {
	if !policy.Enabled || policy.Kind == securitypolicy.KindACL {
		return nil
	}
	var subscriptionID *uuid.UUID
	var ownerID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT package_subscription_id,owner_user_id FROM sites
		WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL`, scopeID, siteID).Scan(&subscriptionID, &ownerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if subscriptionID == nil {
		return packageaddon.ErrSubscriptionInactive
	}
	limits, err := packageaddon.LockRuntimeLimits(ctx, tx, scopeID, *subscriptionID, at)
	if err != nil {
		return err
	}
	if limits.OwnerUserID != ownerID || policy.Kind == securitypolicy.KindCC && !limits.CustomCC ||
		policy.Kind == securitypolicy.KindWAF && !limits.WAF {
		return packageaddon.ErrFeatureDenied
	}
	return nil
}

func lockBinding(ctx context.Context, tx pgx.Tx, scopeID, siteID, policyID uuid.UUID, kind string, now time.Time) (bindingState, error) {
	bindingID := uuid.NewSHA1(siteID, []byte("security-policy-site-binding\x00"+kind))
	_, err := tx.Exec(ctx, `INSERT INTO security_policy_site_bindings
		(id,tenant_scope_id,site_id,policy_id,policy_kind,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$6) ON CONFLICT(tenant_scope_id,site_id,policy_kind) DO NOTHING`,
		bindingID, scopeID, siteID, policyID, kind, now)
	if err != nil {
		return bindingState{}, err
	}
	var binding bindingState
	var active, claimed *int64
	var lastPolicyID *uuid.UUID
	var lastDetach *bool
	err = tx.QueryRow(ctx, `SELECT binding.id,binding.policy_id,binding.policy_kind,binding.active_policy_version,
		binding.last_claimed_policy_version,binding.revision,publication.policy_id,publication.detach
		FROM security_policy_site_bindings binding
		LEFT JOIN security_policy_publications publication ON publication.id=binding.last_bundle_id
		WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2 AND binding.policy_kind=$3 FOR UPDATE OF binding`,
		scopeID, siteID, kind).Scan(&binding.id, &binding.policyID, &binding.kind, &active, &claimed, &binding.revision,
		&lastPolicyID, &lastDetach)
	if err != nil {
		return bindingState{}, err
	}
	if lastPolicyID != nil {
		binding.lastPolicyID = *lastPolicyID
	}
	binding.lastDetach = lastDetach != nil && *lastDetach
	if active != nil {
		binding.activeVersion = *active
	}
	if claimed != nil {
		binding.lastClaimedVersion = *claimed
	}
	return binding, nil
}

func loadPublication(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, idempotencyKey string) (storedPublication, bool, error) {
	var stored storedPublication
	var requestDigest, planDigest, payloadDigest, runtimeDigest, bundleDigest []byte
	publication := &stored.publication
	err := tx.QueryRow(ctx, `SELECT p.id,p.binding_id,p.binding_revision,p.tenant_scope_id,p.site_id,
		p.policy_id,p.policy_kind,p.policy_version,p.expected_active_version,p.rollout_id,
		p.canonical_payload,p.canonical_payload_sha256,p.runtime_snapshot_sha256,
		p.bundle_bytes,p.bundle_sha256,p.signing_key_id,p.issued_at,p.expires_at,p.created_at,
		p.request_digest,p.plan_request_digest,p.idempotency_key,p.detach,p.expected_active_policy_id,
		(SELECT COALESCE(array_agg(target.node_id ORDER BY target.node_id), '{}'::uuid[])
		 FROM security_policy_publication_targets target WHERE target.publication_id=p.id)
		FROM security_policy_publications p
		WHERE p.tenant_scope_id=$1 AND p.idempotency_key=$2
		FOR UPDATE OF p`, scopeID, idempotencyKey).Scan(
		&publication.BundleID, &publication.BindingID, &publication.BindingRevision, &publication.TenantScopeID,
		&publication.SiteID, &publication.PolicyID, &publication.PolicyKind, &publication.PolicyVersion,
		&publication.ExpectedActiveVersion, &publication.RolloutID, &stored.canonicalPayload, &payloadDigest,
		&runtimeDigest, &publication.BundleJSON, &bundleDigest, &publication.SigningKeyID,
		&publication.IssuedAt, &publication.ExpiresAt, &publication.CreatedAt,
		&requestDigest, &planDigest, &stored.idempotencyKey, &publication.Detach, &publication.ExpectedActivePolicyID,
		&publication.TargetNodeIDs)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedPublication{}, false, nil
	}
	if err != nil {
		return storedPublication{}, false, err
	}
	if copyDigest(&stored.requestDigest, requestDigest) != nil || copyDigest(&stored.planRequestDigest, planDigest) != nil ||
		copyDigest(&publication.CanonicalPayloadSHA256, payloadDigest) != nil ||
		copyDigest(&publication.RuntimeSnapshotSHA256, runtimeDigest) != nil ||
		copyDigest(&publication.BundleSHA256, bundleDigest) != nil {
		return storedPublication{}, false, ErrInvalidInput
	}
	return stored, true, nil
}

func insertPublication(ctx context.Context, tx pgx.Tx, actor securitypolicy.Actor, request PublishRequest,
	binding bindingState, plan securitybundle.PublicationPlan, requestDigest [32]byte, now time.Time) (Publication, error) {
	bundleDigest := sha256.Sum256(plan.BundleJSON)
	payload := plan.Bundle.Payload
	issuedAt, expiresAt := time.Unix(payload.IssuedAt, 0).UTC(), time.Unix(payload.ExpiresAt, 0).UTC()
	result := Publication{
		BundleID: plan.BundleID, BindingID: binding.id, BindingRevision: request.ExpectedBindingRevision + 1,
		TenantScopeID: request.TenantScopeID, SiteID: request.SiteID, PolicyID: request.PolicyID,
		PolicyKind: payload.RuntimeSnapshot.Kind, PolicyVersion: request.PolicyVersion,
		ExpectedActiveVersion: request.ExpectedActiveVersion, Detach: request.Detach, RolloutID: request.RolloutID,
		TargetNodeIDs: append([]uuid.UUID(nil), payload.TargetNodeIDs...), BundleJSON: append([]byte(nil), plan.BundleJSON...),
		BundleSHA256: bundleDigest, CanonicalPayloadSHA256: plan.CanonicalPayloadSHA256,
		RuntimeSnapshotSHA256: plan.RuntimeSnapshotSHA256, SigningKeyID: plan.Bundle.KeyID,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, CreatedAt: now,
	}
	if request.ExpectedActiveVersion > 0 {
		activePolicyID := binding.policyID
		result.ExpectedActivePolicyID = &activePolicyID
	}
	_, err := tx.Exec(ctx, `INSERT INTO security_policy_publications(
		id,binding_id,tenant_scope_id,site_id,policy_id,policy_kind,policy_version,
		expected_binding_revision,binding_revision,expected_active_version,rollout_id,idempotency_key,
		request_digest,plan_request_digest,canonical_payload,canonical_payload_sha256,
		runtime_snapshot_sha256,bundle_bytes,bundle_sha256,signing_key_id,issued_at,expires_at,
		actor_scope_id,actor_user_id,request_id,created_at,detach,expected_active_policy_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`,
		result.BundleID, result.BindingID, result.TenantScopeID, result.SiteID, result.PolicyID,
		result.PolicyKind, result.PolicyVersion, request.ExpectedBindingRevision, result.BindingRevision,
		result.ExpectedActiveVersion, result.RolloutID, request.IdempotencyKey, requestDigest[:], plan.RequestSHA256[:],
		plan.CanonicalPayload, result.CanonicalPayloadSHA256[:], result.RuntimeSnapshotSHA256[:], result.BundleJSON,
		result.BundleSHA256[:], result.SigningKeyID, result.IssuedAt, result.ExpiresAt,
		actor.ScopeID, actor.UserID, request.RequestID, result.CreatedAt, result.Detach, result.ExpectedActivePolicyID)
	if err != nil {
		return Publication{}, err
	}
	return result, nil
}

func insertTargets(ctx context.Context, tx pgx.Tx, publication Publication, now time.Time) error {
	for _, nodeID := range publication.TargetNodeIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO security_policy_publication_targets
			(publication_id,tenant_scope_id,binding_id,node_id,claimed_at,expires_at)
			VALUES($1,$2,$3,$4,$5,$6)`, publication.BundleID, publication.TenantScopeID,
			publication.BindingID, nodeID, now, publication.ExpiresAt); err != nil {
			return err
		}
	}
	return nil
}

func releaseExpiredTargets(ctx context.Context, tx pgx.Tx, tenantScopeID uuid.UUID, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE security_policy_publication_targets
		SET released_at=$1,release_reason='expired'
		WHERE tenant_scope_id=$2 AND released_at IS NULL AND expires_at <= $1`, now, tenantScopeID)
	return err
}

func bindingRequestDigest(planDigest [32]byte, expectedBindingRevision int64) ([32]byte, error) {
	document := struct {
		PlanRequestSHA256       string `json:"plan_request_sha256"`
		ExpectedBindingRevision int64  `json:"expected_binding_revision"`
	}{hex.EncodeToString(planDigest[:]), expectedBindingRevision}
	encoded, err := json.Marshal(document)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func copyDigest(destination *[32]byte, source []byte) error {
	if len(source) != sha256.Size {
		return ErrInvalidInput
	}
	copy(destination[:], source)
	return nil
}

func mapDatabaseError(err error) error {
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		return err
	}
	switch databaseError.ConstraintName {
	case "security_policy_publication_targets_open_node_tenant_287_idx":
		return ErrTargetConflict
	case "security_policy_publications_scope_idempotency_key":
		return ErrIdempotencyConflict
	case "security_policy_site_bindings_scope_site_kind":
		return ErrBindingConflict
	}
	if strings.Contains(databaseError.Message, "security publication binding or version conflict") {
		return ErrBindingRevision
	}
	return err
}
