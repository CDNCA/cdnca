package securityactivation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var activationIdempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

const (
	activationReadPermission   = "security_policies.read"
	activationManagePermission = "security_policies.manage"
)

type Store struct {
	pool        *pgxpool.Pool
	clock       func() time.Time
	auditor     *audit.Log
	bindings    *securitybinding.Store
	publisher   *edgepublish.Service
	deployments *edgedeployment.Store
	config      Config
}

func NewStore(pool *pgxpool.Pool, clock func() time.Time) (*Store, error) {
	if pool == nil || clock == nil {
		return nil, ErrInvalidInput
	}
	return &Store{pool: pool, clock: clock, auditor: audit.New(pool), config: DefaultConfig()}, nil
}

func NewProductionStore(
	pool *pgxpool.Pool,
	clock func() time.Time,
	bindings *securitybinding.Store,
	publisher *edgepublish.Service,
	deployments *edgedeployment.Store,
	config Config,
) (*Store, error) {
	if pool == nil || clock == nil || bindings == nil || publisher == nil || deployments == nil || config.validate() != nil {
		return nil, ErrInvalidInput
	}
	return &Store{
		pool: pool, clock: clock, auditor: audit.New(pool), bindings: bindings,
		publisher: publisher, deployments: deployments, config: config,
	}, nil
}

func (store *Store) Claim(ctx context.Context, actor securitypolicy.Actor, input ClaimInput) (ClaimResult, error) {
	if store == nil || store.pool == nil || store.clock == nil {
		return ClaimResult{}, ErrUnavailable
	}
	input.CanaryNodeIDs = canonicalNodes(input.CanaryNodeIDs)
	input.ExpandNodeIDs = canonicalNodes(input.ExpandNodeIDs)
	capabilities, _, err := canonicalCapabilities(input.RequiredCapabilities)
	if err != nil {
		return ClaimResult{}, err
	}
	input.RequiredCapabilities = capabilities
	if !validClaim(actor, input) {
		return ClaimResult{}, ErrInvalidInput
	}
	digest, err := claimDigest(input)
	if err != nil {
		return ClaimResult{}, err
	}
	var result ClaimResult
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, input.TenantScopeID); err != nil {
			return err
		}
		if err := securitybinding.LockSiteSubscription(ctx, tx, input.TenantScopeID, input.SiteID); err != nil {
			return err
		}
		var sourceRevision int64
		if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
			WHERE scope_id=$1 FOR UPDATE`, input.TenantScopeID).Scan(&sourceRevision); errors.Is(err, pgx.ErrNoRows) {
			return ErrSourceRevisionConflict
		} else if err != nil {
			return err
		}
		if err := lockCandidateBinding(ctx, tx, input.TenantScopeID, input.BindingID, input.SiteID); err != nil {
			return err
		}
		if existing, storedDigest, found, err := loadCandidateByKey(ctx, tx, input.TenantScopeID, input.IdempotencyKey, true); err != nil {
			return err
		} else if found {
			if !bytes.Equal(storedDigest, digest[:]) {
				return ErrIdempotencyConflict
			}
			result = ClaimResult{Candidate: existing, Replayed: true}
			return nil
		}
		if err := checkBindingPackageFeature(ctx, tx, input.TenantScopeID, input.SiteID, input.BindingID,
			input.LastBundleID, input.LastClaimedPolicyVersion, store.clock().UTC()); err != nil {
			return err
		}
		if err := store.validateClaimFacts(ctx, tx, input, sourceRevision); err != nil {
			return err
		}
		now := store.clock().UTC().Truncate(time.Microsecond)
		if !input.ExpiresAt.After(now) {
			return ErrInvalidInput
		}
		candidate := Candidate{
			ID: uuid.New(), TenantScopeID: input.TenantScopeID, SiteID: input.SiteID,
			BindingID: input.BindingID, BindingRevision: input.BindingRevision,
			LastBundleID: input.LastBundleID, LastClaimedPolicyVersion: input.LastClaimedPolicyVersion,
			ExpectedActivePolicyVersion: input.ExpectedActivePolicyVersion,
			CandidateSourceRevision:     input.CandidateSourceRevision,
			CandidateConfigVersionID:    input.CandidateConfigVersionID,
			CandidateArtifactSHA256:     input.CandidateArtifactSHA256,
			TargetSnapshotSHA256:        input.TargetSnapshotSHA256,
			RequiredCapabilities:        cloneCapabilities(input.RequiredCapabilities), Status: StatusClaimed,
			CanaryNodeIDs: input.CanaryNodeIDs, ExpandNodeIDs: input.ExpandNodeIDs,
			ExpiresAt: input.ExpiresAt.UTC().Truncate(time.Microsecond), CreatedAt: now, UpdatedAt: now,
		}
		_, capabilitiesJSON, err := canonicalCapabilities(candidate.RequiredCapabilities)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO security_policy_activation_candidates(
			id,tenant_scope_id,site_id,binding_id,binding_revision,last_bundle_id,
			last_claimed_policy_version,expected_active_policy_version,candidate_source_revision,
			candidate_config_version_id,candidate_artifact_sha256,target_snapshot_sha256,required_capabilities,candidate_status,
			canary_node_ids,expand_node_ids,idempotency_key,request_digest,request_id,
			actor_scope_id,actor_user_id,expires_at,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$23)`,
			candidate.ID, candidate.TenantScopeID, candidate.SiteID, candidate.BindingID,
			candidate.BindingRevision, candidate.LastBundleID, candidate.LastClaimedPolicyVersion,
			candidate.ExpectedActivePolicyVersion, candidate.CandidateSourceRevision,
			candidate.CandidateConfigVersionID, candidate.CandidateArtifactSHA256[:],
			candidate.TargetSnapshotSHA256[:], capabilitiesJSON, candidate.Status, candidate.CanaryNodeIDs,
			candidate.ExpandNodeIDs, input.IdempotencyKey, digest[:], input.RequestID,
			actor.ScopeID, actor.UserID, candidate.ExpiresAt, now)
		if err != nil {
			return err
		}
		if err := appendActivationEvent(ctx, tx, candidate, actor, "claimed", digest, "claim", "", StatusClaimed, input.RequestID, now); err != nil {
			return err
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: input.TenantScopeID, ActorUserID: &actor.UserID,
			Action: "security_policy.activation.claim", ResourceType: "security_policy_activation",
			ResourceID: candidate.ID.String(), RequestID: input.RequestID, Result: "success",
			Payload: map[string]any{
				"binding_id": input.BindingID.String(), "binding_revision": input.BindingRevision,
				"candidate_source_revision":   input.CandidateSourceRevision,
				"candidate_config_version_id": input.CandidateConfigVersionID.String(),
				"candidate_artifact_sha256":   hex.EncodeToString(input.CandidateArtifactSHA256[:]),
				"target_snapshot_sha256":      hex.EncodeToString(input.TargetSnapshotSHA256[:]),
			},
		}); err != nil {
			return err
		}
		result = ClaimResult{Candidate: candidate}
		return nil
	})
	return result, err
}

func (store *Store) Get(ctx context.Context, actor securitypolicy.Actor, candidateID uuid.UUID) (Candidate, error) {
	if !validActor(actor) || candidateID == uuid.Nil {
		return Candidate{}, ErrInvalidInput
	}
	var result Candidate
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var scopeID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT tenant_scope_id FROM security_policy_activation_candidates WHERE id=$1`,
			candidateID).Scan(&scopeID); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if err := authorizePermission(ctx, tx, actor, scopeID, activationReadPermission); err != nil {
			return err
		}
		var err error
		result, _, err = scanCandidate(tx.QueryRow(ctx, candidateSelect+` WHERE id=$1`, candidateID))
		return err
	})
	return result, err
}

func (store *Store) Status(
	ctx context.Context,
	actor securitypolicy.Actor,
	siteID uuid.UUID,
	policyKind string,
) (StatusResult, error) {
	if store == nil || store.pool == nil || !validActor(actor) || siteID == uuid.Nil ||
		(policyKind != securitypolicy.KindWAF && policyKind != securitypolicy.KindCC && policyKind != securitypolicy.KindACL) {
		return StatusResult{}, ErrInvalidInput
	}
	var result StatusResult
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		scopeID, err := siteTenantScopeTx(ctx, tx, actor, siteID)
		if err != nil {
			return err
		}
		if err := authorizePermission(ctx, tx, actor, scopeID, activationReadPermission); err != nil {
			return err
		}
		var binding Binding
		err = tx.QueryRow(ctx, `SELECT id,policy_id,revision,
			COALESCE(active_policy_version,0),COALESCE(last_claimed_policy_version,0)
			FROM security_policy_site_bindings
			WHERE tenant_scope_id=$1 AND site_id=$2 AND policy_kind=$3`,
			scopeID, siteID, policyKind).Scan(&binding.ID, &binding.PolicyID, &binding.BindingRevision,
			&binding.ActivePolicyVersion, &binding.LastClaimedPolicyVersion)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		result.Binding = &binding
		wait, err := loadCapabilityWait(ctx, tx, scopeID, siteID, policyKind)
		if err != nil {
			return err
		}
		result.CapabilityWait = wait
		facts, err := loadRollbackFacts(ctx, tx, scopeID, binding.ID)
		if err != nil {
			return err
		}
		availability := rollbackAvailability(facts)
		result.Rollback = &availability

		var candidateID uuid.UUID
		var operation string
		err = tx.QueryRow(ctx, `SELECT candidate.id,
			CASE WHEN EXISTS (
				SELECT 1 FROM security_policy_activation_events event
				WHERE event.candidate_id=candidate.id AND event.action='rollback'
			) THEN 'rollback' ELSE 'activation' END
			FROM security_policy_activation_candidates candidate
			WHERE candidate.tenant_scope_id=$1 AND candidate.site_id=$2 AND candidate.binding_id=$3
			ORDER BY candidate.created_at DESC,candidate.id DESC LIMIT 1`,
			scopeID, siteID, binding.ID).Scan(&candidateID, &operation)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		candidate, _, err := scanCandidate(tx.QueryRow(ctx, candidateSelect+` WHERE id=$1`, candidateID))
		if err != nil {
			return err
		}
		result.LatestCandidate = &candidate
		result.Operation = &operation
		if err := tx.QueryRow(ctx, `SELECT detach FROM security_policy_publications
			WHERE tenant_scope_id=$1 AND id=$2`, scopeID, candidate.LastBundleID).Scan(&result.LatestDetach); err != nil {
			return err
		}
		if candidate.Status == StatusFailed {
			if result.FailureReasons, err = loadFailureReasons(ctx, tx, candidate.ID); err != nil {
				return err
			}
		}
		return nil
	})
	return result, err
}

func (store *Store) Promote(
	ctx context.Context,
	actor securitypolicy.Actor,
	candidateID uuid.UUID,
	expected PromotionCAS,
) (PromoteResult, error) {
	if !validActor(actor) || candidateID == uuid.Nil {
		return PromoteResult{}, ErrInvalidInput
	}
	if err := expected.validate(); err != nil {
		return PromoteResult{}, err
	}
	var result PromoteResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var scopeID, bindingID, siteID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT tenant_scope_id,binding_id,site_id FROM security_policy_activation_candidates WHERE id=$1`,
			candidateID).Scan(&scopeID, &bindingID, &siteID); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if err := authorize(ctx, tx, actor, scopeID); err != nil {
			return err
		}
		if err := securitybinding.LockSiteSubscription(ctx, tx, scopeID, siteID); err != nil {
			return err
		}
		if _, err := lockActivationScope(ctx, tx, scopeID); err != nil {
			return err
		}
		if err := lockCandidateBinding(ctx, tx, scopeID, bindingID, siteID); err != nil {
			return err
		}
		candidate, _, err := scanCandidate(tx.QueryRow(ctx, candidateSelect+` WHERE id=$1 FOR UPDATE`, candidateID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if candidate.PromotionCAS() != expected {
			return ErrConflict
		}
		if candidate.Status == StatusPromoted {
			result = PromoteResult{Candidate: candidate, Replayed: true}
			return nil
		}
		now := store.clock().UTC().Truncate(time.Microsecond)
		if candidate.Status != StatusHealthy || !candidate.ExpiresAt.After(now) {
			return ErrNotHealthy
		}
		if err := checkBindingPackageFeature(ctx, tx, scopeID, siteID, bindingID, candidate.LastBundleID, candidate.LastClaimedPolicyVersion, now); err != nil {
			return err
		}
		targetsHealthy, err := lockCandidateTargetsHealthy(ctx, tx, candidate)
		if err != nil {
			return err
		}
		if !targetsHealthy {
			return ErrNotHealthy
		}
		healthy, err := candidateReceiptsHealthy(ctx, tx, candidate)
		if err != nil {
			return err
		}
		if !healthy {
			return ErrNotHealthy
		}
		// sec-rebind: the binding now points at the claimed library (another
		// one after a rebind); a detach leaves no active version.
		command, err := tx.Exec(ctx, `UPDATE security_policy_site_bindings binding SET
			policy_id=publication.policy_id,
			active_policy_version=CASE WHEN publication.detach THEN NULL ELSE $2::bigint END,
			revision=binding.revision+1,updated_at=$3
			FROM security_policy_publications publication
			WHERE publication.id=binding.last_bundle_id
			  AND binding.tenant_scope_id=$1 AND binding.id=$4 AND binding.revision=$5 AND binding.last_bundle_id=$6
			  AND binding.last_claimed_policy_version=$7 AND COALESCE(binding.active_policy_version,0)=$8`,
			candidate.TenantScopeID, candidate.LastClaimedPolicyVersion, now, candidate.BindingID,
			candidate.BindingRevision, candidate.LastBundleID, candidate.LastClaimedPolicyVersion,
			candidate.ExpectedActivePolicyVersion)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrConflict
		}
		command, err = tx.Exec(ctx, `UPDATE edge_configuration_scopes SET source_revision=$2,updated_at=$3
			WHERE scope_id=$1 AND source_revision=$4`, candidate.TenantScopeID,
			candidate.CandidateSourceRevision, now, candidate.CandidateSourceRevision-1)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrSourceRevisionConflict
		}
		command, err = tx.Exec(ctx, `UPDATE security_policy_activation_candidates
			SET candidate_status='promoted',promoted_at=$2,updated_at=$2
			WHERE id=$1 AND candidate_status='healthy'`, candidate.ID, now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrConflict
		}
		candidate.Status, candidate.UpdatedAt = StatusPromoted, now
		if err := releaseCandidateTargets(ctx, tx, candidate, "completed", now); err != nil {
			return err
		}
		digest := sha256.Sum256([]byte("promote:" + candidate.ID.String()))
		if err := appendActivationEvent(ctx, tx, candidate, actor, "promoted", digest, "promote", StatusHealthy, StatusPromoted, candidate.ID.String(), now); err != nil {
			return err
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: candidate.TenantScopeID, ActorUserID: &actor.UserID,
			Action: "security_policy.activation.promote", ResourceType: "security_policy_activation",
			ResourceID: candidate.ID.String(), RequestID: candidate.ID.String(), Result: "success",
			Payload: map[string]any{
				"active_policy_version": candidate.LastClaimedPolicyVersion,
				"source_revision":       candidate.CandidateSourceRevision,
				"config_version_id":     candidate.CandidateConfigVersionID.String(),
			},
		}); err != nil {
			return err
		}
		result = PromoteResult{Candidate: candidate}
		return nil
	})
	return result, err
}

func lockCandidateTargetsHealthy(ctx context.Context, tx pgx.Tx, candidate Candidate) (bool, error) {
	expected := canonicalNodes(append(append([]uuid.UUID(nil), candidate.CanaryNodeIDs...), candidate.ExpandNodeIDs...))
	rows, err := tx.Query(ctx, `SELECT node_id FROM node_config_state
		WHERE configuration_scope_id=$1 AND node_id=ANY($2)
		  AND NOT reconciliation_required
		  AND current_config_identity_schema=1
		  AND current_config_version_id=$3
		  AND current_config_artifact_sha256=security_policy_activation_node_artifact_sha256_333($1,$3,node_id,$4)
		  AND active_config_identity_artifact_valid_087(
		      node_id,current_config_version_id,current_config_artifact_sha256
		  )
		ORDER BY node_id FOR UPDATE`, candidate.TenantScopeID, expected,
		candidate.CandidateConfigVersionID, candidate.CandidateArtifactSHA256[:])
	if err != nil {
		return false, err
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil {
			return false, err
		}
		if index >= len(expected) || nodeID != expected[index] {
			return false, nil
		}
		index++
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return index == len(expected), nil
}

func (store *Store) validateClaimFacts(ctx context.Context, tx pgx.Tx, input ClaimInput, sourceRevision int64) error {
	var revision, claimed int64
	var active *int64
	var bundle uuid.UUID
	var policyKind string
	err := tx.QueryRow(ctx, `SELECT binding.revision,binding.last_bundle_id,binding.last_claimed_policy_version,
		binding.active_policy_version,binding.policy_kind
		FROM security_policy_site_bindings binding
		JOIN sites site ON site.scope_id=binding.tenant_scope_id AND site.id=binding.site_id
		WHERE binding.tenant_scope_id=$1 AND binding.id=$2 AND binding.site_id=$3
		  AND site.enabled AND site.status='active' AND site.deleted_at IS NULL FOR UPDATE OF binding`,
		input.TenantScopeID, input.BindingID, input.SiteID).Scan(&revision, &bundle, &claimed, &active, &policyKind)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	activeVersion := int64(0)
	if active != nil {
		activeVersion = *active
	}
	if revision != input.BindingRevision || bundle != input.LastBundleID ||
		claimed != input.LastClaimedPolicyVersion || activeVersion != input.ExpectedActivePolicyVersion {
		return ErrConflict
	}
	if sourceRevision != input.CandidateSourceRevision-1 {
		return ErrSourceRevisionConflict
	}
	var publicationExpires time.Time
	if err := tx.QueryRow(ctx, `SELECT expires_at FROM security_policy_publications
		WHERE tenant_scope_id=$1 AND id=$2 AND binding_id=$3 AND binding_revision=$4
		  AND policy_version=$5`, input.TenantScopeID, input.LastBundleID, input.BindingID,
		input.BindingRevision, input.LastClaimedPolicyVersion).Scan(&publicationExpires); errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	} else if err != nil {
		return err
	}
	if input.ExpiresAt.After(publicationExpires) {
		return ErrConflict
	}
	var configExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM config_versions version
		JOIN configuration_artifacts artifact ON artifact.config_version_id=version.id AND artifact.kind='configuration'
		WHERE version.configuration_scope_id=$1 AND version.id=$2 AND version.status='releasable'
		  AND artifact.sha256=$3 AND artifact.sha256=sha256(artifact.wire_bytes))`,
		input.TenantScopeID, input.CandidateConfigVersionID, input.CandidateArtifactSHA256[:]).Scan(&configExists); err != nil {
		return err
	}
	if !configExists {
		return ErrConflict
	}
	_, capabilitiesJSON, err := canonicalCapabilities(input.RequiredCapabilities)
	if err != nil || len(input.RequiredCapabilities) == 0 {
		return ErrConflict
	}
	var authoritative bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM security_policy_activation_config_facts fact
		WHERE fact.tenant_scope_id=$1 AND fact.config_version_id=$2 AND fact.artifact_sha256=$3
		  AND fact.policy_kind=$4 AND fact.required_capabilities=$5::jsonb
	)`, input.TenantScopeID, input.CandidateConfigVersionID, input.CandidateArtifactSHA256[:],
		policyKind, capabilitiesJSON).Scan(&authoritative); err != nil {
		return err
	}
	if !authoritative || !store.requiredCapabilitiesValid(policyKind, input.RequiredCapabilities) {
		return ErrConflict
	}
	nodes := append(append([]uuid.UUID(nil), input.CanaryNodeIDs...), input.ExpandNodeIDs...)
	var targetCount, matchingTargetCount int
	if err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER (
		WHERE target.released_at IS NULL AND target.expires_at >= $4 AND target.node_id=ANY($5)
	) FROM security_policy_publication_targets target
		WHERE target.tenant_scope_id=$1 AND target.publication_id=$2 AND target.binding_id=$3
		`, input.TenantScopeID, input.LastBundleID, input.BindingID, input.ExpiresAt, nodes).
		Scan(&targetCount, &matchingTargetCount); err != nil {
		return err
	}
	if targetCount != len(nodes) || matchingTargetCount != len(nodes) {
		return ErrConflict
	}
	var activeNodeCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM nodes node
		JOIN node_config_state state ON state.node_id=node.id AND state.configuration_scope_id=$1
		WHERE node.id=ANY($2) AND node.admin_state='active'
		  AND state.current_config_identity_schema=1 AND state.current_config_version_id IS NOT NULL
		  AND octet_length(state.current_config_artifact_sha256)=32
		  AND active_config_identity_artifact_valid_087(
		      node.id,state.current_config_version_id,state.current_config_artifact_sha256
		  )`, input.TenantScopeID, nodes).Scan(&activeNodeCount); err != nil {
		return err
	}
	if activeNodeCount != len(nodes) {
		return ErrConflict
	}
	targetDigest, _, err := canonicalTargetSnapshot(input.TenantScopeID, input.SiteID,
		nodes)
	if err != nil || targetDigest != input.TargetSnapshotSHA256 {
		return ErrConflict
	}
	return nil
}

func (store *Store) requiredCapabilitiesValid(kind string, capabilities []*agentv1.Capability) bool {
	required := map[agentv1.CapabilityName]uint32{
		agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE:  1,
		agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1:        1,
	}
	if kind == securitypolicy.KindCC {
		required[agentv1.CapabilityName_CAPABILITY_NAME_CC] = store.config.RequiredCCAPIVersion
	} else if kind == securitypolicy.KindWAF || kind == securitypolicy.KindACL {
		required[agentv1.CapabilityName_CAPABILITY_NAME_WAF] = store.config.RequiredWAFAPIVersion
	} else {
		return false
	}
	// CC accepts RequiredCCAPIVersion (v2) up to v5: v3 adds proof-of-work
	// challenges, v4 counting keys and v5 the auto switch, each required by
	// releases using them.
	ccValid := func(version uint32) bool {
		return version >= store.config.RequiredCCAPIVersion && version <= maxCCAPIVersion
	}
	// WAF accepts RequiredWAFAPIVersion (v1), v2 (challenge / ban actions,
	// auto block, observe mode; edgeconfig.WAFActionAPIVersion) and v3 (the
	// managed WAF's c3 context, WAFAdaptiveAPIVersion) and v4 (content_type /
	// http_version conditions and IP lists, WAFConditionsAPIVersion), required
	// by releases using them.
	wafValid := func(version uint32) bool {
		return version >= store.config.RequiredWAFAPIVersion && version <= edgeconfig.WAFNodeAPIVersion
	}
	for _, capability := range capabilities {
		if capability == nil {
			return false
		}
		if expected, ok := required[capability.Name]; ok {
			if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_CC && !ccValid(capability.ApiVersion) ||
				capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_WAF && !wafValid(capability.ApiVersion) ||
				capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_CC && capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_WAF &&
					capability.ApiVersion != expected {
				return false
			}
			delete(required, capability.Name)
		}
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_WAF && !wafValid(capability.ApiVersion) ||
			capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_CC && !ccValid(capability.ApiVersion) {
			return false
		}
	}
	return len(required) == 0
}

// maxCCAPIVersion is the newest CC API a security release may require
// (edgepublish: v3 for proof-of-work challenges, v4 for counting keys, v5
// for an auto switch).
const maxCCAPIVersion uint32 = 5

func lockCandidateBinding(ctx context.Context, tx pgx.Tx, scopeID, bindingID, siteID uuid.UUID) error {
	var found uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM security_policy_site_bindings
		WHERE tenant_scope_id=$1 AND id=$2 AND site_id=$3 FOR UPDATE`, scopeID, bindingID, siteID).Scan(&found); errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	} else if err != nil {
		return err
	}
	return nil
}

func authorize(ctx context.Context, tx pgx.Tx, actor securitypolicy.Actor, tenantScopeID uuid.UUID) error {
	return authorizePermission(ctx, tx, actor, tenantScopeID, activationManagePermission)
}

func authorizePermission(
	ctx context.Context,
	tx pgx.Tx,
	actor securitypolicy.Actor,
	tenantScopeID uuid.UUID,
	permission string,
) error {
	if !validActor(actor) || tenantScopeID == uuid.Nil {
		return ErrPermissionDenied
	}
	if permission != activationReadPermission && permission != activationManagePermission {
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
		actor.ScopeKind == "tenant" && actor.ScopeID != tenantScopeID {
		return ErrPermissionDenied
	}
	var permitted bool
	if actor.ScopeKind == "tenant" {
		err = tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM custom_rbac_effective_permissions($1,$2)
			WHERE permission_name=$3)`, tenantScopeID, actor.UserID, permission).Scan(&permitted)
	} else {
		err = tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM role_assignments assignment
			JOIN role_permissions permission ON permission.role_id=assignment.role_id
			WHERE assignment.scope_id=$1 AND assignment.user_id=$2
			  AND permission.permission_name IN ($3,'platform.admin'))`, actor.ScopeID, actor.UserID, permission).Scan(&permitted)
	}
	if err != nil {
		return err
	}
	if !permitted {
		return ErrPermissionDenied
	}
	return nil
}

func validActor(actor securitypolicy.Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil &&
		(actor.ScopeKind == "tenant" || actor.ScopeKind == "platform")
}

func validClaim(actor securitypolicy.Actor, input ClaimInput) bool {
	if !validActor(actor) || input.TenantScopeID == uuid.Nil || input.SiteID == uuid.Nil ||
		input.BindingID == uuid.Nil || input.BindingRevision < 1 || input.LastBundleID == uuid.Nil ||
		input.LastClaimedPolicyVersion < 1 || input.ExpectedActivePolicyVersion < 0 ||
		input.CandidateSourceRevision < 2 || input.CandidateConfigVersionID == uuid.Nil ||
		input.CandidateArtifactSHA256 == ([sha256.Size]byte{}) ||
		input.TargetSnapshotSHA256 == ([sha256.Size]byte{}) ||
		len(input.RequiredCapabilities) == 0 ||
		!activationIdempotencyPattern.MatchString(input.IdempotencyKey) ||
		!validRequestID(input.RequestID) || input.ExpiresAt.IsZero() ||
		len(input.CanaryNodeIDs) == 0 || len(input.CanaryNodeIDs)+len(input.ExpandNodeIDs) > 10_000 {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(input.CanaryNodeIDs)+len(input.ExpandNodeIDs))
	for _, nodeID := range append(append([]uuid.UUID(nil), input.CanaryNodeIDs...), input.ExpandNodeIDs...) {
		if nodeID == uuid.Nil {
			return false
		}
		if _, duplicate := seen[nodeID]; duplicate {
			return false
		}
		seen[nodeID] = struct{}{}
	}
	return true
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

func canonicalNodes(values []uuid.UUID) []uuid.UUID {
	result := append([]uuid.UUID(nil), values...)
	sort.Slice(result, func(left, right int) bool {
		return bytes.Compare(result[left][:], result[right][:]) < 0
	})
	return result
}

func claimDigest(input ClaimInput) ([sha256.Size]byte, error) {
	_, capabilities, err := canonicalCapabilities(input.RequiredCapabilities)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	document := struct {
		TenantScopeID               uuid.UUID       `json:"tenant_scope_id"`
		SiteID                      uuid.UUID       `json:"site_id"`
		BindingID                   uuid.UUID       `json:"binding_id"`
		BindingRevision             int64           `json:"binding_revision"`
		LastBundleID                uuid.UUID       `json:"last_bundle_id"`
		LastClaimedPolicyVersion    int64           `json:"last_claimed_policy_version"`
		ExpectedActivePolicyVersion int64           `json:"expected_active_policy_version"`
		CandidateSourceRevision     int64           `json:"candidate_source_revision"`
		CandidateConfigVersionID    uuid.UUID       `json:"candidate_config_version_id"`
		CandidateArtifactSHA256     string          `json:"candidate_artifact_sha256"`
		TargetSnapshotSHA256        string          `json:"target_snapshot_sha256"`
		CanaryNodeIDs               []uuid.UUID     `json:"canary_node_ids"`
		ExpandNodeIDs               []uuid.UUID     `json:"expand_node_ids"`
		RequiredCapabilities        json.RawMessage `json:"required_capabilities"`
		ExpiresAt                   string          `json:"expires_at"`
	}{
		input.TenantScopeID, input.SiteID, input.BindingID, input.BindingRevision,
		input.LastBundleID, input.LastClaimedPolicyVersion, input.ExpectedActivePolicyVersion,
		input.CandidateSourceRevision, input.CandidateConfigVersionID,
		hex.EncodeToString(input.CandidateArtifactSHA256[:]), hex.EncodeToString(input.TargetSnapshotSHA256[:]),
		input.CanaryNodeIDs, input.ExpandNodeIDs, capabilities, input.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

const candidateSelect = `SELECT id,tenant_scope_id,site_id,binding_id,binding_revision,last_bundle_id,
	last_claimed_policy_version,expected_active_policy_version,candidate_source_revision,
	candidate_config_version_id,candidate_artifact_sha256,target_snapshot_sha256,required_capabilities,candidate_status,
	canary_node_ids,expand_node_ids,expires_at,created_at,updated_at,recovered_at,request_digest
	FROM security_policy_activation_candidates`

func loadCandidateByKey(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	key string,
	lock bool,
) (Candidate, []byte, bool, error) {
	suffix := ` WHERE tenant_scope_id=$1 AND idempotency_key=$2`
	if lock {
		suffix += ` FOR UPDATE`
	}
	candidate, digest, err := scanCandidate(tx.QueryRow(ctx, candidateSelect+suffix, scopeID, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return Candidate{}, nil, false, nil
	}
	return candidate, digest, err == nil, err
}

func scanCandidate(row interface{ Scan(...any) error }) (Candidate, []byte, error) {
	var candidate Candidate
	var artifact, target, capabilities, requestDigest []byte
	err := row.Scan(
		&candidate.ID, &candidate.TenantScopeID, &candidate.SiteID, &candidate.BindingID,
		&candidate.BindingRevision, &candidate.LastBundleID, &candidate.LastClaimedPolicyVersion,
		&candidate.ExpectedActivePolicyVersion, &candidate.CandidateSourceRevision,
		&candidate.CandidateConfigVersionID, &artifact, &target, &capabilities, &candidate.Status,
		&candidate.CanaryNodeIDs, &candidate.ExpandNodeIDs, &candidate.ExpiresAt,
		&candidate.CreatedAt, &candidate.UpdatedAt, &candidate.RecoveredAt, &requestDigest,
	)
	if err != nil {
		return Candidate{}, nil, err
	}
	if len(artifact) != sha256.Size || len(target) != sha256.Size || len(requestDigest) != sha256.Size {
		return Candidate{}, nil, ErrConflict
	}
	copy(candidate.CandidateArtifactSHA256[:], artifact)
	copy(candidate.TargetSnapshotSHA256[:], target)
	candidate.RequiredCapabilities, err = decodeCapabilities(capabilities)
	if err != nil {
		return Candidate{}, nil, err
	}
	return candidate, requestDigest, nil
}

func appendActivationEvent(
	ctx context.Context,
	tx pgx.Tx,
	candidate Candidate,
	actor securitypolicy.Actor,
	eventKey string,
	requestDigest [sha256.Size]byte,
	action string,
	from, to CandidateStatus,
	requestID string,
	now time.Time,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO security_policy_activation_events(
		id,candidate_id,tenant_scope_id,event_key,request_digest,action,from_status,to_status,
		actor_scope_id,actor_user_id,request_id,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		uuid.New(), candidate.ID, candidate.TenantScopeID, eventKey, requestDigest[:], action,
		nullableStatus(from), to, actor.ScopeID, actor.UserID, requestID, now)
	return err
}

func nullableStatus(value CandidateStatus) any {
	if value == "" {
		return nil
	}
	return value
}
