package securityactivation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *Store) Start(ctx context.Context, actor securitypolicy.Actor, input StartInput) (StartResult, error) {
	if store == nil || store.bindings == nil || store.publisher == nil || store.deployments == nil {
		return StartResult{}, ErrUnavailable
	}
	input.TargetNodeIDs = canonicalNodes(input.TargetNodeIDs)
	recovery, err := normalizeCIDRRecoveryIntent(input.Recovery)
	if err != nil {
		return StartResult{}, err
	}
	input.Recovery = recovery
	if validActor(actor) {
		input.TargetNodeIDs, input.CanarySize, err = store.siteTargets(ctx, input.TenantScopeID, input.SiteID,
			input.TargetNodeIDs, input.CanarySize)
		if err != nil {
			return StartResult{}, err
		}
	}
	if input.ExpiresAt.After(store.clock().Add(store.config.CandidateTTL)) {
		return StartResult{}, ErrExpiryTooLate
	}
	if !validStart(actor, input, store.clock(), store.config.CandidateTTL) {
		return StartResult{}, ErrInvalidInput
	}
	digest, err := startDigest(input)
	if err != nil {
		return StartResult{}, err
	}
	var result StartResult
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var err error
		// The schema the candidate is built for, recorded with a capability
		// wait so the resumed start builds the same (input is local here; the
		// digest above was taken as requested).
		result, err = store.startTx(ctx, tx, actor, input, digest, &input.SiteRuntimeSchema)
		return err
	})
	var refusal *edgepublish.TargetCapabilityError
	if errors.As(err, &refusal) {
		// Nothing of the release was persisted; keep the request so it is
		// published once the nodes declare the capability.
		if recordErr := store.recordCapabilityWait(ctx, actor, input, refusal); recordErr == nil {
			refusal.AutoResume = waitableCapability(refusal.Capability) && waitableStart(input)
		}
		return result, err
	}
	var packs *edgepublish.RulePackUnavailableError
	if errors.As(err, &packs) {
		// Likewise kept until every target node has applied the site's rule
		// packs from its node artifact set (sa-rulepack-wait).
		if recordErr := store.recordRulePackWait(ctx, actor, input, packs); recordErr == nil {
			packs.AutoResume = waitableStart(input) && len(packs.Required) != 0
		}
		return result, err
	}
	if err == nil && !result.Replayed {
		if supersedeErr := store.supersedeCapabilityWaits(ctx, input); supersedeErr != nil {
			return result, supersedeErr
		}
	}
	return result, err
}

func (store *Store) startTx(
	ctx context.Context,
	tx pgx.Tx,
	actor securitypolicy.Actor,
	input StartInput,
	digest [sha256.Size]byte,
	resolvedSchema *string,
) (StartResult, error) {
	if err := authorize(ctx, tx, actor, input.TenantScopeID); err != nil {
		return StartResult{}, err
	}
	if err := securitybinding.LockSiteSubscription(ctx, tx, input.TenantScopeID, input.SiteID); err != nil {
		return StartResult{}, err
	}
	sourceRevision, err := lockActivationScope(ctx, tx, input.TenantScopeID)
	if err != nil {
		return StartResult{}, err
	}
	if err := lockStartPolicyAndBinding(ctx, tx, input.TenantScopeID, input.SiteID, input.PolicyID, input.Detach); err != nil {
		return StartResult{}, err
	}
	if existing, storedDigest, found, err := loadCandidateByKey(ctx, tx, input.TenantScopeID, input.IdempotencyKey, true); err != nil {
		return StartResult{}, err
	} else if found {
		if !bytes.Equal(storedDigest, digest[:]) {
			return StartResult{}, ErrIdempotencyConflict
		}
		result := StartResult{Candidate: existing, Replayed: true}
		if input.Recovery != nil {
			result.ReasonCode = RecoveryResultReplayed
		}
		return result, nil
	}
	targetDigest, targets, err := canonicalTargetSnapshot(input.TenantScopeID, input.SiteID, input.TargetNodeIDs)
	if err != nil {
		return StartResult{}, err
	}
	canary, expand, err := partitionTargets(targets, input.CanarySize)
	if err != nil {
		return StartResult{}, err
	}
	if expand == nil {
		expand = []uuid.UUID{}
	}
	var policy securitypolicy.Policy
	if input.Recovery != nil {
		active, err := loadPolicyVersion(ctx, tx, input.TenantScopeID, input.PolicyID, input.ExpectedActivePolicyVersion)
		if err != nil {
			return StartResult{}, err
		}
		policy, err = loadPolicyVersion(ctx, tx, input.TenantScopeID, input.PolicyID, input.PolicyVersion)
		if err != nil {
			return StartResult{}, err
		}
		if err := validateCIDRRecoveryPolicy(active, policy, input.Recovery); err != nil {
			return StartResult{}, err
		}
	}
	publicationRolloutID := uuid.New()
	publication, err := store.bindings.PublishTx(ctx, tx, actor, securitybinding.PublishRequest{
		TenantScopeID: input.TenantScopeID, SiteID: input.SiteID, PolicyID: input.PolicyID,
		PolicyVersion: input.PolicyVersion, TargetNodeIDs: targets,
		ExpectedBindingRevision: input.ExpectedBindingRevision,
		ExpectedActiveVersion:   input.ExpectedActivePolicyVersion,
		RolloutID:               publicationRolloutID, IdempotencyKey: derivedKey("publication", input.IdempotencyKey),
		RequestID: input.RequestID, Detach: input.Detach,
	})
	if err != nil {
		return StartResult{}, mapDependencyError(err)
	}
	if input.ExpiresAt.After(publication.ExpiresAt) {
		return StartResult{}, ErrConflict
	}
	if input.Recovery == nil {
		// A detach withdraws the active version, of a library possibly deleted.
		policy, err = loadPolicyVersionFor(ctx, tx, input.TenantScopeID, input.PolicyID, input.PolicyVersion, input.Detach)
		if err != nil {
			return StartResult{}, err
		}
	}
	schema := edgepublish.ResolveSiteRuntimeSchema(input.SiteRuntimeSchema)
	if resolvedSchema != nil {
		*resolvedSchema = schema
	}
	candidateID := uuid.New()
	configID := uuid.NewSHA1(candidateID, []byte("security-activation-config"))
	persisted, err := store.publisher.PersistSecurityCandidateTx(ctx, tx, edgepublish.SecurityCandidateRequest{
		ConfigurationScopeID: input.TenantScopeID, SiteID: input.SiteID,
		SourceRevision: sourceRevision + 1, ConfigVersionID: configID,
		PublicationID: publication.BundleID, BindingID: publication.BindingID, BindingRevision: publication.BindingRevision,
		Policy: policy, RuntimeSHA256: publication.RuntimeSnapshotSHA256,
		IdempotencyKey:    derivedKey("candidate", input.IdempotencyKey),
		SiteRuntimeSchema: schema, TargetNodeIDs: targets, Detach: input.Detach,
	})
	if err != nil {
		return StartResult{}, mapDependencyError(err)
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	// A v2 rollout must require exactly its document's capabilities
	// (edgedeployment requireReleasableConfig); v1 raises WAF/CC to the
	// configured floors.
	requiredCapabilities := persisted.RequiredCapabilities
	if !persisted.SiteRuntimeV2 {
		requiredCapabilities = store.requiredSecurityCapability(requiredCapabilities)
	}
	requiredCapabilities, _, err = canonicalCapabilities(requiredCapabilities)
	if err != nil || len(requiredCapabilities) == 0 {
		return StartResult{}, ErrConflict
	}
	// A proof-of-work CC policy or a CRS managed WAF on a node whose agent
	// predates it would only fail that node's precheck; refuse it here with
	// the node and feature named (edgepublish.TargetCapabilityError).
	if err := edgepublish.ValidateFeatureCapabilityTargets(ctx, tx, targets, requiredCapabilities); err != nil {
		return StartResult{}, err
	}
	candidate := Candidate{
		ID: candidateID, TenantScopeID: input.TenantScopeID, SiteID: input.SiteID,
		BindingID: publication.BindingID, BindingRevision: publication.BindingRevision,
		LastBundleID: publication.BundleID, LastClaimedPolicyVersion: input.PolicyVersion,
		ExpectedActivePolicyVersion: input.ExpectedActivePolicyVersion,
		CandidateSourceRevision:     sourceRevision + 1, CandidateConfigVersionID: configID,
		CandidateArtifactSHA256: persisted.ArtifactSHA256, TargetSnapshotSHA256: targetDigest,
		RequiredCapabilities: requiredCapabilities,
		Status:               StatusClaimed, CanaryNodeIDs: canary, ExpandNodeIDs: expand,
		ExpiresAt: input.ExpiresAt.UTC().Truncate(time.Microsecond), CreatedAt: now, UpdatedAt: now,
	}
	if err := insertCandidate(ctx, tx, candidate, actor, input.IdempotencyKey, digest, input.RequestID); err != nil {
		return StartResult{}, err
	}
	rollout, err := store.createPhaseRollout(ctx, tx, candidate, "canary", canary,
		candidate.RequiredCapabilities, input.RequestID, input.CorrelationID, input.Traceparent, input.TaskID)
	if err != nil {
		return StartResult{}, err
	}
	if err := appendActivationEvent(ctx, tx, candidate, actor, "claimed", digest, "claim", "", StatusClaimed, input.RequestID, now); err != nil {
		return StartResult{}, err
	}
	if err := appendActivationEvent(ctx, tx, candidate, actor, "canary", digest, "canary", StatusClaimed, StatusClaimed, input.RequestID, now); err != nil {
		return StartResult{}, err
	}
	auditPayload := map[string]any{
		"site_id": input.SiteID.String(), "policy_id": input.PolicyID.String(),
		"policy_version": input.PolicyVersion, "source_revision": candidate.CandidateSourceRevision,
		"config_version_id":      configID.String(),
		"artifact_sha256":        hex.EncodeToString(candidate.CandidateArtifactSHA256[:]),
		"target_snapshot_sha256": hex.EncodeToString(targetDigest[:]),
		"canary_rollout_id":      rollout.Rollout.ID.String(),
	}
	if input.Detach {
		auditPayload["detach"] = true
	}
	if publication.ExpectedActivePolicyID != nil && *publication.ExpectedActivePolicyID != input.PolicyID {
		auditPayload["rebind_from_policy_id"] = publication.ExpectedActivePolicyID.String()
	}
	for key, value := range cidrRecoveryAuditPayload(input.Recovery, RecoveryResultClaimed) {
		auditPayload[key] = value
	}
	if err := store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: input.TenantScopeID, ActorUserID: &actor.UserID,
		Action: "security_policy.activation.start", ResourceType: "security_policy_activation",
		ResourceID: candidate.ID.String(), RequestID: input.RequestID, Result: "success",
		Payload: auditPayload,
	}); err != nil {
		return StartResult{}, err
	}
	result := StartResult{Candidate: candidate}
	if input.Recovery != nil {
		result.ReasonCode = RecoveryResultClaimed
	}
	return result, nil
}

func (store *Store) Reconcile(
	ctx context.Context,
	actor securitypolicy.Actor,
	input ReconcileInput,
) (ReconcileResult, error) {
	if store == nil || store.deployments == nil || !validActor(actor) || input.CandidateID == uuid.Nil ||
		input.PromotionCAS.validate() != nil || !activationIdempotencyPattern.MatchString(input.IdempotencyKey) ||
		!validRequestID(input.RequestID) {
		return ReconcileResult{}, ErrInvalidInput
	}
	digest, err := reconcileDigest(input)
	if err != nil {
		return ReconcileResult{}, err
	}
	var result ReconcileResult
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var scopeID, bindingID, siteID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT tenant_scope_id,binding_id,site_id FROM security_policy_activation_candidates WHERE id=$1`,
			input.CandidateID).Scan(&scopeID, &bindingID, &siteID); errors.Is(err, pgx.ErrNoRows) {
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
		candidate, _, err := scanCandidate(tx.QueryRow(ctx, candidateSelect+` WHERE id=$1 FOR UPDATE`, input.CandidateID))
		if err != nil {
			return err
		}
		if candidate.PromotionCAS() != input.PromotionCAS {
			return ErrConflict
		}
		eventKey := derivedEventKey("reconcile", input.IdempotencyKey)
		if action, replay, err := loadActivationEventReplay(ctx, tx, candidate.ID, eventKey, digest); err != nil {
			return err
		} else if replay {
			result = ReconcileResult{Candidate: candidate, Action: action, Replayed: true}
			return nil
		}
		now := store.clock().UTC().Truncate(time.Microsecond)
		if recoveryTerminal(candidate.Status) {
			if candidate.RecoveredAt != nil {
				result = ReconcileResult{Candidate: candidate}
				return nil
			}
			if err := store.createRecoveryRollouts(ctx, tx, candidate, input.RequestID,
				input.CorrelationID, input.Traceparent, input.TaskID, now); err != nil {
				return err
			}
			complete, err := recoveryComplete(ctx, tx, candidate.ID)
			if err != nil {
				return err
			}
			action := actionWait
			if complete {
				if err := markCandidateRecovered(ctx, tx, &candidate, now); err != nil {
					return err
				}
				if err := releaseCandidateTargets(ctx, tx, candidate, terminalReleaseReason(candidate.Status), now); err != nil {
					return err
				}
				action = actionRecover
			}
			if err := appendActivationEvent(ctx, tx, candidate, actor, eventKey, digest,
				string(action), candidate.Status, candidate.Status, input.RequestID, now); err != nil {
				return err
			}
			result = ReconcileResult{Candidate: candidate, Action: string(action)}
			return nil
		}
		from := candidate.Status
		canaryFacts, canaryIdentity, err := loadPhaseReceipts(ctx, tx, candidate, "canary", candidate.CanaryNodeIDs, now)
		if err != nil {
			return err
		}
		expandFacts := phaseFacts{total: len(candidate.ExpandNodeIDs)}
		var expandIdentity PhaseIdentity
		if len(candidate.ExpandNodeIDs) > 0 {
			expandFacts, expandIdentity, err = loadPhaseReceipts(ctx, tx, candidate, "expand", candidate.ExpandNodeIDs, now)
			if errors.Is(err, pgx.ErrNoRows) && (candidate.Status == StatusClaimed || candidate.Status == StatusCanary) {
				expandFacts = phaseFacts{total: len(candidate.ExpandNodeIDs)}
				err = nil
			} else if err != nil {
				return err
			}
		}
		expired := !candidate.ExpiresAt.After(now)
		if !expired && candidate.Status == StatusClaimed && canaryIdentity.RolloutID != uuid.Nil &&
			canaryFacts.total > 0 && canaryFacts.healthy == canaryFacts.total {
			if err := transitionCandidate(ctx, tx, &candidate, StatusCanary, now); err != nil {
				return err
			}
		}
		if !expired && candidate.Status == StatusCanary && len(candidate.ExpandNodeIDs) > 0 &&
			expandIdentity.RolloutID != uuid.Nil && expandFacts.total > 0 && expandFacts.healthy == expandFacts.total {
			if err := transitionCandidate(ctx, tx, &candidate, StatusExpanding, now); err != nil {
				return err
			}
		}
		action := decideReconcile(candidate.Status, expired, canaryFacts, expandFacts)
		switch action {
		case actionNone:
			result = ReconcileResult{Candidate: candidate}
			return nil
		case actionWait:
		case actionExpand:
			// Until every expand node is healthy loadPhaseReceipts reports no
			// expand identity, so the candidate stays canary and this branch
			// is reached on every pass. The rollout already exists then: a
			// replay with this pass's request ID differs in digest and fails
			// with an idempotency conflict, which stopped the worker (N2).
			started, err := phaseRolloutExists(ctx, tx, candidate, "expand")
			if err != nil {
				return err
			}
			if started {
				action = actionWait
				break
			}
			if err := checkBindingPackageFeature(ctx, tx, scopeID, siteID, bindingID, candidate.LastBundleID, candidate.LastClaimedPolicyVersion, now); err != nil {
				return err
			}
			_, err = store.createPhaseRollout(ctx, tx, candidate, "expand", candidate.ExpandNodeIDs,
				candidate.RequiredCapabilities, input.RequestID, input.CorrelationID, input.Traceparent, input.TaskID)
			if err != nil {
				return err
			}
		case actionPromote:
			if err := transitionCandidate(ctx, tx, &candidate, StatusHealthy, now); err != nil {
				return err
			}
		case actionFail:
			if err := store.createRecoveryRollouts(ctx, tx, candidate, input.RequestID,
				input.CorrelationID, input.Traceparent, input.TaskID, now); err != nil {
				return err
			}
			if err := transitionCandidate(ctx, tx, &candidate, StatusFailed, now); err != nil {
				return err
			}
		case actionCancel:
			if err := store.createRecoveryRollouts(ctx, tx, candidate, input.RequestID,
				input.CorrelationID, input.Traceparent, input.TaskID, now); err != nil {
				return err
			}
			if err := transitionCandidate(ctx, tx, &candidate, StatusCancelled, now); err != nil {
				return err
			}
		case actionExpire:
			if err := store.createRecoveryRollouts(ctx, tx, candidate, input.RequestID,
				input.CorrelationID, input.Traceparent, input.TaskID, now); err != nil {
				return err
			}
			if err := transitionCandidate(ctx, tx, &candidate, StatusExpired, now); err != nil {
				return err
			}
		default:
			return ErrConflict
		}
		if err := appendActivationEvent(ctx, tx, candidate, actor, eventKey, digest, string(action), from, candidate.Status, input.RequestID, now); err != nil {
			return err
		}
		result = ReconcileResult{Candidate: candidate, Action: string(action)}
		return nil
	})
	if err != nil {
		return ReconcileResult{}, err
	}
	if result.Action == string(actionPromote) && result.Candidate.Status == StatusHealthy {
		promoted, err := store.Promote(ctx, actor, result.Candidate.ID, input.PromotionCAS)
		if err != nil {
			if errors.Is(err, ErrConflict) || errors.Is(err, ErrSourceRevisionConflict) || errors.Is(err, ErrNotHealthy) {
				recoveryContext, cancelRecovery := context.WithTimeout(context.WithoutCancel(ctx), store.config.HealthCheck)
				defer cancelRecovery()
				if recoveryErr := store.failPromotion(recoveryContext, actor, result.Candidate.ID,
					input.RequestID, input.CorrelationID, input.Traceparent, input.TaskID, digest); recoveryErr != nil {
					return ReconcileResult{}, errors.Join(err, recoveryErr)
				}
			}
			return ReconcileResult{}, err
		}
		result.Candidate = promoted.Candidate
	}
	return result, nil
}

func (store *Store) reconcileRevokedCandidate(
	ctx context.Context,
	actor securitypolicy.Actor,
	input ReconcileInput,
) (ReconcileResult, error) {
	digest, err := reconcileDigest(input)
	if err != nil {
		return ReconcileResult{}, err
	}
	var result ReconcileResult
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var scopeID, bindingID, siteID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT tenant_scope_id,binding_id,site_id
			FROM security_policy_activation_candidates WHERE id=$1`, input.CandidateID).
			Scan(&scopeID, &bindingID, &siteID); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if err := authorize(ctx, tx, actor, scopeID); !errors.Is(err, ErrPermissionDenied) {
			if err != nil {
				return err
			}
			return ErrConflict
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
		candidate, _, err := scanCandidate(tx.QueryRow(ctx, candidateSelect+` WHERE id=$1 FOR UPDATE`, input.CandidateID))
		if err != nil {
			return err
		}
		if candidate.PromotionCAS() != input.PromotionCAS {
			return ErrConflict
		}
		eventKey := derivedEventKey("permission-revoked", input.IdempotencyKey)
		if action, replay, err := loadActivationEventReplay(ctx, tx, candidate.ID, eventKey, digest); err != nil {
			return err
		} else if replay {
			result = ReconcileResult{Candidate: candidate, Action: action, Replayed: true}
			return nil
		}
		now := store.clock().UTC().Truncate(time.Microsecond)
		from := candidate.Status
		action := actionWait
		switch {
		case candidate.Status == StatusClaimed || candidate.Status == StatusCanary ||
			candidate.Status == StatusExpanding || candidate.Status == StatusHealthy:
			if err := store.createRecoveryRollouts(ctx, tx, candidate, input.RequestID,
				input.CorrelationID, input.Traceparent, input.TaskID, now); err != nil {
				return err
			}
			if err := transitionCandidate(ctx, tx, &candidate, StatusCancelled, now); err != nil {
				return err
			}
			action = actionCancel
		case recoveryTerminal(candidate.Status):
			if candidate.RecoveredAt != nil {
				result = ReconcileResult{Candidate: candidate}
				return nil
			}
			if err := store.createRecoveryRollouts(ctx, tx, candidate, input.RequestID,
				input.CorrelationID, input.Traceparent, input.TaskID, now); err != nil {
				return err
			}
			complete, err := recoveryComplete(ctx, tx, candidate.ID)
			if err != nil {
				return err
			}
			if complete {
				if err := markCandidateRecovered(ctx, tx, &candidate, now); err != nil {
					return err
				}
				if err := releaseCandidateTargets(ctx, tx, candidate, terminalReleaseReason(candidate.Status), now); err != nil {
					return err
				}
				action = actionRecover
			}
		default:
			return ErrConflict
		}
		if err := appendActivationEvent(ctx, tx, candidate, actor, eventKey, digest, string(action),
			from, candidate.Status, input.RequestID, now); err != nil {
			return err
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, Action: "security_policy.activation.permission_revoked_reconcile",
			ResourceType: "security_policy_activation", ResourceID: candidate.ID.String(),
			RequestID: input.RequestID, Result: "success",
			Payload: map[string]any{
				"action": action, "initiating_actor_scope_id": actor.ScopeID.String(),
				"initiating_actor_user_id": actor.UserID.String(),
			},
		}); err != nil {
			return err
		}
		result = ReconcileResult{Candidate: candidate, Action: string(action)}
		return nil
	})
	return result, err
}

func (store *Store) Rollback(
	ctx context.Context,
	actor securitypolicy.Actor,
	input RollbackInput,
) (StartResult, error) {
	input.TargetNodeIDs = canonicalNodes(input.TargetNodeIDs)
	if store != nil && store.pool != nil && validActor(actor) && input.CandidateID != uuid.Nil && len(input.TargetNodeIDs) == 0 {
		siteID, scopeID, err := store.rollbackSite(ctx, actor, input.CandidateID)
		if err != nil {
			return StartResult{}, err
		}
		if input.TargetNodeIDs, input.CanarySize, err = store.siteTargets(ctx, scopeID, siteID,
			input.TargetNodeIDs, input.CanarySize); err != nil {
			return StartResult{}, err
		}
	}
	if store != nil && input.ExpiresAt.After(store.clock().Add(store.config.CandidateTTL)) {
		return StartResult{}, ErrExpiryTooLate
	}
	if store == nil || store.bindings == nil || store.publisher == nil || store.deployments == nil ||
		!validActor(actor) || input.CandidateID == uuid.Nil || input.SourcePolicyVersion < 1 ||
		input.ExpectedBindingRevision < 1 || input.ExpectedActivePolicyVersion < 0 ||
		!activationIdempotencyPattern.MatchString(input.IdempotencyKey) || !validRequestID(input.RequestID) ||
		len(input.TargetNodeIDs) == 0 || input.CanarySize < 1 || input.CanarySize > len(input.TargetNodeIDs) ||
		!input.ExpiresAt.After(store.clock()) || input.ExpiresAt.After(store.clock().Add(store.config.CandidateTTL)) {
		return StartResult{}, ErrInvalidInput
	}
	digest, err := rollbackDigest(input)
	if err != nil {
		return StartResult{}, err
	}
	var result StartResult
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var scopeID, siteID, bindingID, policyID uuid.UUID
		var originalStatus CandidateStatus
		var originalPolicyVersion int64
		// sec-rebind: the library restored is the one this candidate claimed
		// (the binding may point at another one since); a detach restores
		// nothing.
		if err := tx.QueryRow(ctx, `SELECT candidate.tenant_scope_id,candidate.site_id,candidate.binding_id,publication.policy_id,
			candidate.candidate_status,candidate.last_claimed_policy_version
			FROM security_policy_activation_candidates candidate
			JOIN security_policy_publications publication ON publication.tenant_scope_id=candidate.tenant_scope_id
			  AND publication.id=candidate.last_bundle_id AND NOT publication.detach
			WHERE candidate.id=$1`, input.CandidateID).Scan(&scopeID, &siteID, &bindingID, &policyID,
			&originalStatus, &originalPolicyVersion); errors.Is(err, pgx.ErrNoRows) {
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
		if originalStatus != StatusPromoted || originalPolicyVersion != input.SourcePolicyVersion {
			return ErrConflict
		}
		if err := lockRollbackPolicyAndBinding(ctx, tx, scopeID, bindingID, siteID, policyID); err != nil {
			return err
		}
		original, _, err := scanCandidate(tx.QueryRow(ctx, candidateSelect+` WHERE id=$1 FOR UPDATE`, input.CandidateID))
		if err != nil {
			return err
		}
		if original.Status != StatusPromoted || original.LastClaimedPolicyVersion != input.SourcePolicyVersion ||
			original.BindingID != bindingID || original.SiteID != siteID {
			return ErrConflict
		}
		eventKey := derivedEventKey("rollback", input.IdempotencyKey)
		if _, replay, err := loadActivationEventReplay(ctx, tx, input.CandidateID, eventKey, digest); err != nil {
			return err
		} else if replay {
			existing, _, found, err := loadCandidateByKey(ctx, tx, scopeID, derivedKey("rollback", input.IdempotencyKey), true)
			if err != nil || !found {
				return ErrConflict
			}
			result = StartResult{Candidate: existing, Replayed: true}
			return nil
		}
		rolled, err := store.clonePolicyVersionTx(ctx, tx, actor, scopeID, policyID, input.SourcePolicyVersion, input.RequestID)
		if err != nil {
			return err
		}
		start := StartInput{
			TenantScopeID: scopeID, SiteID: siteID, PolicyID: policyID, PolicyVersion: rolled.Revision,
			ExpectedBindingRevision:     input.ExpectedBindingRevision,
			ExpectedActivePolicyVersion: input.ExpectedActivePolicyVersion,
			TargetNodeIDs:               input.TargetNodeIDs, CanarySize: input.CanarySize,
			IdempotencyKey: derivedKey("rollback", input.IdempotencyKey), RequestID: input.RequestID,
			CorrelationID: input.CorrelationID, Traceparent: input.Traceparent,
			TaskID:    cloneStringPointer(input.TaskID),
			ExpiresAt: input.ExpiresAt, SiteRuntimeSchema: input.SiteRuntimeSchema,
		}
		startRequestDigest, err := startDigest(start)
		if err != nil {
			return err
		}
		result, err = store.startTx(ctx, tx, actor, start, startRequestDigest, nil)
		if err != nil {
			return err
		}
		now := store.clock().UTC().Truncate(time.Microsecond)
		if err := appendActivationEvent(ctx, tx, result.Candidate, actor, "operation.rollback", digest,
			OperationRollback, result.Candidate.Status, result.Candidate.Status, input.RequestID, now); err != nil {
			return err
		}
		return appendActivationEvent(ctx, tx, original, actor, eventKey, digest, "rollback", original.Status, original.Status, input.RequestID, now)
	})
	return result, err
}

func validStart(actor securitypolicy.Actor, input StartInput, now time.Time, ttl time.Duration) bool {
	return validActor(actor) && input.TenantScopeID != uuid.Nil && input.SiteID != uuid.Nil &&
		input.PolicyID != uuid.Nil && validStartVersions(input) &&
		input.ExpectedBindingRevision >= 0 && input.ExpectedActivePolicyVersion >= 0 &&
		(input.Recovery == nil || input.ExpectedActivePolicyVersion > 0) &&
		len(input.TargetNodeIDs) > 0 && len(input.TargetNodeIDs) <= 10_000 &&
		input.CanarySize > 0 && input.CanarySize <= len(input.TargetNodeIDs) &&
		activationIdempotencyPattern.MatchString(input.IdempotencyKey) && validRequestID(input.RequestID) &&
		input.ExpiresAt.After(now) && !input.ExpiresAt.After(now.Add(ttl))
}

// validStartVersions: the versions a start can name (sec-rebind). The
// expected active version is the binding's, possibly of another library
// (a rebind): versions of different libraries are unrelated, so only the
// binding layer (securitybinding checkClaim) orders them within a library.
// A detach names the active version itself; a recovery stays in its library.
func validStartVersions(input StartInput) bool {
	if input.Detach {
		return input.Recovery == nil && input.ExpectedActivePolicyVersion > 0 &&
			input.PolicyVersion == input.ExpectedActivePolicyVersion
	}
	if input.Recovery != nil {
		return input.PolicyVersion > input.ExpectedActivePolicyVersion
	}
	return input.PolicyVersion > 0
}

func lockActivationScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (int64, error) {
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
		scopeID).Scan(&revision); errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrSourceRevisionConflict
	} else if err != nil {
		return 0, err
	}
	if revision < 1 {
		return 0, ErrSourceRevisionConflict
	}
	return revision, nil
}

// lockStartPolicyAndBinding locks the claimed library (policy before
// binding, as D3 delete does). A deleted library cannot be bound again; it
// can only be detached (sec-rebind).
func lockStartPolicyAndBinding(ctx context.Context, tx pgx.Tx, scopeID, siteID, policyID uuid.UUID, detach bool) error {
	var found uuid.UUID
	var deleted bool
	if err := tx.QueryRow(ctx, `SELECT id,deleted_at IS NOT NULL FROM security_policies
		WHERE scope_id=$1 AND id=$2 FOR UPDATE`, scopeID, policyID).Scan(&found, &deleted); errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	} else if err != nil {
		return err
	}
	if deleted && !detach {
		return ErrPolicyDeleted
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM security_policy_site_bindings
		WHERE tenant_scope_id=$1 AND site_id=$2 AND policy_id=$3 FOR UPDATE`, scopeID, siteID, policyID).Scan(&found); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}

func lockRollbackPolicyAndBinding(ctx context.Context, tx pgx.Tx, scopeID, bindingID, siteID, policyID uuid.UUID) error {
	if err := lockCandidateBinding(ctx, tx, scopeID, bindingID, siteID); err != nil {
		return err
	}
	var found uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM security_policies
		WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, scopeID, policyID).Scan(&found); errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	} else if err != nil {
		return err
	}
	return nil
}

func insertCandidate(ctx context.Context, tx pgx.Tx, candidate Candidate, actor securitypolicy.Actor,
	key string, digest [sha256.Size]byte, requestID string) error {
	_, capabilities, err := canonicalCapabilities(candidate.RequiredCapabilities)
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
		candidate.ID, candidate.TenantScopeID, candidate.SiteID, candidate.BindingID, candidate.BindingRevision,
		candidate.LastBundleID, candidate.LastClaimedPolicyVersion, candidate.ExpectedActivePolicyVersion,
		candidate.CandidateSourceRevision, candidate.CandidateConfigVersionID, candidate.CandidateArtifactSHA256[:],
		candidate.TargetSnapshotSHA256[:], capabilities, candidate.Status, candidate.CanaryNodeIDs, candidate.ExpandNodeIDs,
		key, digest[:], requestID, actor.ScopeID, actor.UserID, candidate.ExpiresAt, candidate.CreatedAt)
	return err
}

func (store *Store) createPhaseRollout(ctx context.Context, tx pgx.Tx, candidate Candidate, phase string,
	nodes []uuid.UUID, capabilities []*agentv1.Capability, requestID, correlationID, traceparent string,
	taskID *string) (edgedeployment.CreateRolloutResult, error) {
	nodeArtifacts, err := loadCandidateNodeArtifacts(ctx, tx, candidate)
	if err != nil {
		return edgedeployment.CreateRolloutResult{}, err
	}
	// v1: every node gets the candidate artifact, retried up to MaxAttempts.
	// v2: each node its own artifact, bound to attempt 1 (no retry; a failure
	// fails the candidate and recovers, as a v2 publication).
	maxAttempts := store.config.MaxAttempts
	var bindings []edgedeployment.NodeArtifactBinding
	if nodeArtifacts == nil {
		capabilities = store.requiredSecurityCapability(capabilities)
	} else {
		if bindings, err = nodeArtifacts.phaseBindings(nodes); err != nil {
			return edgedeployment.CreateRolloutResult{}, err
		}
		capabilities = cloneCapabilities(capabilities)
		maxAttempts = 1
	}
	requestUUID := uuid.NewSHA1(candidate.ID, []byte(phase+":"+requestID))
	if correlationID == "" {
		correlationID = candidate.ID.String()
	}
	if traceparent == "" {
		traceparent = activationTraceparent(candidate.ID, phase)
	}
	return store.deployments.CreateRolloutTx(ctx, tx, edgedeployment.CreateRolloutRequest{
		ConfigurationScopeID: candidate.TenantScopeID, ConfigVersionID: candidate.CandidateConfigVersionID,
		Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, NodeIDs: nodes,
		NodeArtifactBindings: bindings,
		RequiredCapabilities: capabilities,
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: store.config.HealthCheck, ObservationWindow: store.config.ObservationWindow,
			RequiredConsecutiveSuccesses: store.config.RequiredSuccesses,
		},
		Deadline: candidate.ExpiresAt, IdempotencyKey: derivedKey(phase, candidate.ID.String()),
		RequestID: requestUUID.String(), CorrelationID: correlationID, Traceparent: traceparent,
		TaskID:      cloneStringPointer(taskID),
		MaxAttempts: maxAttempts, ContractVersion: 1,
	})
}

func (store *Store) requiredSecurityCapability(values []*agentv1.Capability) []*agentv1.Capability {
	result := make([]*agentv1.Capability, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		copyOfValue := &agentv1.Capability{Name: value.GetName(), ApiVersion: value.GetApiVersion()}
		switch copyOfValue.Name {
		case agentv1.CapabilityName_CAPABILITY_NAME_WAF:
			// RequiredWAFAPIVersion is the floor; a release with WAF v2
			// actions keeps v2 so v1 agents refuse it.
			copyOfValue.ApiVersion = max(copyOfValue.ApiVersion, store.config.RequiredWAFAPIVersion)
		case agentv1.CapabilityName_CAPABILITY_NAME_CC:
			// RequiredCCAPIVersion is the floor; a release with proof-of-work
			// challenges needs CC v3 and must keep it, or v2 (1.0.33) agents
			// would accept the command and fail to decode the challenge.
			copyOfValue.ApiVersion = max(copyOfValue.ApiVersion, store.config.RequiredCCAPIVersion)
		}
		result = append(result, copyOfValue)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result
}

func (store *Store) createRecoveryRollouts(ctx context.Context, tx pgx.Tx, candidate Candidate,
	requestID, correlationID, traceparent string, taskID *string, now time.Time) error {
	if err := store.cancelPendingActivationDeployments(ctx, tx, candidate, requestID, now); err != nil {
		return err
	}
	type recoveryTarget struct {
		nodeID         uuid.UUID
		configID       uuid.UUID
		artifactSHA256 [sha256.Size]byte
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (pending.node_id)
		pending.node_id,pending.recovery_config_version_id,pending.recovery_artifact_sha256
		FROM security_policy_activation_recovery_pending_095 pending
		JOIN security_policy_activation_candidates stored_candidate
		  ON stored_candidate.id=pending.candidate_id
		 AND stored_candidate.tenant_scope_id=pending.tenant_scope_id
		 AND stored_candidate.candidate_config_version_id=pending.candidate_config_version_id
		 AND stored_candidate.candidate_artifact_sha256=pending.candidate_artifact_sha256
		 AND stored_candidate.target_snapshot_sha256=pending.candidate_target_snapshot_sha256
		JOIN node_deployments deployment
		  ON deployment.id=pending.deployment_id
		 AND deployment.attempt=pending.deployment_attempt
		 AND deployment.rollout_id=pending.rollout_id
		 AND deployment.node_id=pending.node_id
		JOIN edge_command_outbox outbox
		  ON outbox.id=pending.outbox_id
		 AND outbox.deployment_id=pending.deployment_id
		 AND outbox.deployment_attempt=pending.deployment_attempt
		 AND outbox.node_id=pending.node_id
		JOIN node_config_state node_state
		  ON node_state.node_id=pending.node_id
		 AND node_state.configuration_scope_id=pending.tenant_scope_id
		JOIN configuration_artifacts previous_artifact
		  ON previous_artifact.config_version_id=pending.recovery_config_version_id
		 AND previous_artifact.kind='configuration'
		 AND previous_artifact.sha256=pending.recovery_artifact_sha256
		 AND previous_artifact.sha256=sha256(previous_artifact.wire_bytes)
		WHERE pending.candidate_id=$1 AND pending.tenant_scope_id=$2 AND pending.action='apply'
		  AND pending.candidate_config_version_id=$3 AND pending.candidate_artifact_sha256=$4
		  AND pending.candidate_target_snapshot_sha256=$5
		  AND pending.recovery_config_version_id IS NOT NULL
		  AND octet_length(pending.recovery_artifact_sha256)=32
		  AND deployment.action='apply'
		  AND deployment.config_version_id=pending.candidate_config_version_id
		  AND deployment.previous_config_version_id=pending.recovery_config_version_id
		  AND node_state.current_config_identity_schema=1
		  AND node_state.current_config_version_id=pending.candidate_config_version_id
		  AND node_state.current_config_artifact_sha256=security_policy_activation_node_artifact_sha256_333(
		      pending.tenant_scope_id,pending.candidate_config_version_id,pending.node_id,pending.candidate_artifact_sha256)
		  AND pending.generation=(
		    SELECT max(latest.generation)
		    FROM security_policy_activation_recovery_pending_095 latest
		    WHERE latest.candidate_id=pending.candidate_id AND latest.node_id=pending.node_id
		      AND latest.action='apply'
		  )
		  AND pending.deployment_attempt=(
		    SELECT max(latest_attempt.attempt)
		    FROM node_deployments latest_attempt
		    WHERE latest_attempt.rollout_id=pending.rollout_id
		      AND latest_attempt.node_id=pending.node_id
		  )
		ORDER BY pending.node_id,pending.generation DESC`, candidate.ID, candidate.TenantScopeID,
		candidate.CandidateConfigVersionID, candidate.CandidateArtifactSHA256[:], candidate.TargetSnapshotSHA256[:])
	if err != nil {
		return err
	}
	targets := make([]recoveryTarget, 0)
	for rows.Next() {
		var target recoveryTarget
		var artifact []byte
		if err := rows.Scan(&target.nodeID, &target.configID, &artifact); err != nil {
			rows.Close()
			return err
		}
		if len(artifact) != sha256.Size {
			rows.Close()
			return ErrConflict
		}
		copy(target.artifactSHA256[:], artifact)
		targets = append(targets, target)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	type recoveryGroup struct {
		configID       uuid.UUID
		artifactSHA256 [sha256.Size]byte
		nodes          []uuid.UUID
	}
	groups := make(map[string]*recoveryGroup)
	for _, target := range targets {
		var covered bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM security_policy_activation_recovery_rollouts recovery
			JOIN node_deployments deployment ON deployment.rollout_id=recovery.rollout_id
			LEFT JOIN LATERAL (
				SELECT event.state FROM deployment_status_events event
				WHERE event.deployment_id=deployment.id AND event.attempt=deployment.attempt
				ORDER BY event.transition_sequence DESC LIMIT 1
			) latest ON true
			WHERE recovery.candidate_id=$1 AND recovery.recovery_config_version_id=$2
			  AND recovery.recovery_artifact_sha256=$3 AND deployment.node_id=$4
			  AND (COALESCE(latest.state,deployment.state) NOT IN ('failed','rollback_failed')
			       OR `+edgedeployment.SupersededDeploymentSQL+`)
		)`, candidate.ID, target.configID, target.artifactSHA256[:], target.nodeID).Scan(&covered); err != nil {
			return err
		}
		if covered {
			continue
		}
		key := target.configID.String() + ":" + hex.EncodeToString(target.artifactSHA256[:])
		group := groups[key]
		if group == nil {
			group = &recoveryGroup{configID: target.configID, artifactSHA256: target.artifactSHA256}
			groups[key] = group
		}
		group.nodes = append(group.nodes, target.nodeID)
	}
	candidateArtifacts, err := loadCandidateNodeArtifacts(ctx, tx, candidate)
	if err != nil {
		return err
	}
	deadline := now.Add(store.config.HealthCheck + store.config.ObservationWindow + time.Minute)
	for _, group := range groups {
		capabilities, err := recoveryCapabilities(ctx, tx, candidate, candidateArtifacts != nil, group.configID)
		if err != nil {
			return err
		}
		nodes := canonicalNodes(group.nodes)
		targetDigest, _, err := canonicalTargetSnapshot(candidate.TenantScopeID, candidate.SiteID, nodes)
		if err != nil {
			return err
		}
		requestUUID := uuid.NewSHA1(candidate.ID, []byte("recovery:"+group.configID.String()+":"+
			hex.EncodeToString(targetDigest[:])+":"+requestID))
		if correlationID == "" {
			correlationID = candidate.ID.String()
		}
		if traceparent == "" {
			traceparent = activationTraceparent(candidate.ID, "recovery")
		}
		rollout, err := store.deployments.CreateRolloutTx(ctx, tx, edgedeployment.CreateRolloutRequest{
			ConfigurationScopeID: candidate.TenantScopeID, ConfigVersionID: group.configID,
			Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK, NodeIDs: nodes,
			RequiredCapabilities: capabilities,
			HealthCheck: edgedeployment.HealthCheckPolicy{
				ActivationTimeout: store.config.HealthCheck, ObservationWindow: store.config.ObservationWindow,
				RequiredConsecutiveSuccesses: store.config.RequiredSuccesses,
			},
			Deadline: deadline, IdempotencyKey: derivedKey("recovery", requestUUID.String()),
			RequestID: requestUUID.String(), CorrelationID: correlationID, Traceparent: traceparent,
			TaskID:      cloneStringPointer(taskID),
			MaxAttempts: store.config.MaxAttempts, ContractVersion: 1,
		})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_policy_activation_recovery_rollouts(
			candidate_id,tenant_scope_id,rollout_id,recovery_config_version_id,recovery_artifact_sha256,
			target_snapshot_sha256,node_ids,request_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, candidate.ID, candidate.TenantScopeID,
			rollout.Rollout.ID, group.configID, group.artifactSHA256[:], candidate.TargetSnapshotSHA256[:],
			nodes, requestUUID, rollout.Rollout.CreatedAt); err != nil {
			return err
		}
	}
	return nil
}

func (store *Store) cancelPendingActivationDeployments(
	ctx context.Context,
	tx pgx.Tx,
	candidate Candidate,
	requestID string,
	now time.Time,
) error {
	type pendingRollout struct {
		id           uuid.UUID
		configID     uuid.UUID
		action       string
		revision     int64
		maxAttempts  int
		createdAt    time.Time
		actorScopeID uuid.UUID
		actorUserID  uuid.UUID
	}
	rows, err := tx.Query(ctx, `SELECT rollout.id,rollout.config_version_id,rollout.action,
		rollout.revision,rollout.max_attempts,rollout.created_at,
		stored_candidate.actor_scope_id,stored_candidate.actor_user_id
		FROM rollouts rollout
		JOIN security_policy_activation_candidates stored_candidate ON stored_candidate.id=$1
		WHERE stored_candidate.tenant_scope_id=$2
		  AND stored_candidate.candidate_config_version_id=$3
		  AND stored_candidate.candidate_artifact_sha256=$4
		  AND stored_candidate.target_snapshot_sha256=$5
		  AND rollout.configuration_scope_id=stored_candidate.tenant_scope_id
		  AND rollout.config_version_id=stored_candidate.candidate_config_version_id
		  AND rollout.action='apply' AND rollout.status='queued' AND rollout.contract_version=1
		  AND EXISTS (
		    SELECT 1 FROM security_policy_activation_recovery_pending_095 pending
		    WHERE pending.candidate_id=stored_candidate.id
		      AND pending.tenant_scope_id=stored_candidate.tenant_scope_id
		      AND pending.rollout_id=rollout.id AND pending.action='apply'
		      AND pending.candidate_config_version_id=stored_candidate.candidate_config_version_id
		      AND pending.candidate_artifact_sha256=stored_candidate.candidate_artifact_sha256
		      AND pending.candidate_target_snapshot_sha256=stored_candidate.target_snapshot_sha256
		  )
		ORDER BY rollout.id FOR UPDATE OF rollout`, candidate.ID, candidate.TenantScopeID,
		candidate.CandidateConfigVersionID, candidate.CandidateArtifactSHA256[:], candidate.TargetSnapshotSHA256[:])
	if err != nil {
		return err
	}
	rollouts := make([]pendingRollout, 0)
	for rows.Next() {
		var rollout pendingRollout
		if err := rows.Scan(&rollout.id, &rollout.configID, &rollout.action, &rollout.revision,
			&rollout.maxAttempts, &rollout.createdAt, &rollout.actorScopeID, &rollout.actorUserID); err != nil {
			rows.Close()
			return err
		}
		rollouts = append(rollouts, rollout)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	type pendingDeployment struct {
		id       uuid.UUID
		attempt  int
		outboxID uuid.UUID
	}
	for _, rollout := range rollouts {
		var expected int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM node_deployments deployment
			WHERE deployment.rollout_id=$1 AND deployment.state='queued' AND NOT EXISTS (
			  SELECT 1 FROM node_deployments newer
			  WHERE newer.id=deployment.id AND newer.attempt>deployment.attempt
			)`, rollout.id).Scan(&expected); err != nil {
			return err
		}
		if expected == 0 {
			continue
		}
		deploymentRows, err := tx.Query(ctx, `SELECT deployment.id,deployment.attempt,outbox.id
			FROM node_deployments deployment
			JOIN security_policy_activation_recovery_pending_095 pending
			  ON pending.rollout_id=deployment.rollout_id
			 AND pending.deployment_id=deployment.id
			 AND pending.deployment_attempt=deployment.attempt
			 AND pending.node_id=deployment.node_id
			JOIN edge_command_outbox outbox
			  ON outbox.id=pending.outbox_id
			 AND outbox.deployment_id=deployment.id
			 AND outbox.deployment_attempt=deployment.attempt
			 AND outbox.node_id=deployment.node_id
			JOIN node_config_state state
			  ON state.node_id=pending.node_id
			 AND state.configuration_scope_id=pending.tenant_scope_id
			WHERE pending.candidate_id=$1 AND pending.tenant_scope_id=$2
			  AND pending.rollout_id=$3 AND pending.action='apply'
			  AND pending.candidate_config_version_id=$4
			  AND pending.candidate_artifact_sha256=$5
			  AND pending.candidate_target_snapshot_sha256=$6
			  AND pending.recovery_config_version_id IS NOT NULL
			  AND octet_length(pending.recovery_artifact_sha256)=32
			  AND deployment.action='apply' AND deployment.state='queued'
				  AND deployment.config_version_id=pending.candidate_config_version_id
				  AND deployment.previous_config_version_id=pending.recovery_config_version_id
				  AND outbox.status IN ('pending','failed')
				  AND pending.generation=(
				    SELECT max(latest.generation)
				    FROM security_policy_activation_recovery_pending_095 latest
				    WHERE latest.candidate_id=pending.candidate_id
				      AND latest.node_id=pending.node_id AND latest.action='apply'
				  )
				  AND state.current_config_identity_schema=1 AND (
			    (state.current_config_version_id=pending.candidate_config_version_id AND
			     state.current_config_artifact_sha256=security_policy_activation_node_artifact_sha256_333(
			       pending.tenant_scope_id,pending.candidate_config_version_id,pending.node_id,
			       pending.candidate_artifact_sha256)) OR
			    (state.current_config_version_id=pending.recovery_config_version_id AND
			     state.current_config_artifact_sha256=pending.recovery_artifact_sha256)
			  ) AND NOT EXISTS (
			    SELECT 1 FROM node_deployments newer
			    WHERE newer.id=deployment.id AND newer.attempt>deployment.attempt
			  )
			ORDER BY deployment.node_id FOR UPDATE OF deployment,outbox,state`, candidate.ID,
			candidate.TenantScopeID, rollout.id, candidate.CandidateConfigVersionID,
			candidate.CandidateArtifactSHA256[:], candidate.TargetSnapshotSHA256[:])
		if err != nil {
			return err
		}
		deployments := make([]pendingDeployment, 0, expected)
		for deploymentRows.Next() {
			var deployment pendingDeployment
			if err := deploymentRows.Scan(&deployment.id, &deployment.attempt, &deployment.outboxID); err != nil {
				deploymentRows.Close()
				return err
			}
			deployments = append(deployments, deployment)
		}
		deploymentRows.Close()
		if err := deploymentRows.Err(); err != nil {
			return err
		}
		if len(deployments) != expected {
			return ErrConflict
		}

		commandRequestID := uuid.NewSHA1(candidate.ID,
			[]byte("cancel:"+rollout.id.String()+":"+requestID))
		commandKey := derivedKey("recovery-cancel", candidate.ID.String()+":"+rollout.id.String())
		commandDigest, err := canonicalDigest(struct {
			ScopeID          string `json:"scope_id"`
			RolloutID        string `json:"rollout_id"`
			ExpectedRevision int64  `json:"expected_revision"`
		}{candidate.TenantScopeID.String(), rollout.id.String(), rollout.revision})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO edge_rollout_write_requests(
			id,actor_user_id,actor_scope_id,configuration_scope_id,rollout_id,operation,
			idempotency_key,request_digest,expected_revision,request_id,created_at)
			VALUES($1,$2,$3,$4,$5,'edge_rollout.cancel',$6,$7,$8,$9,$10)`, uuid.New(),
			rollout.actorUserID, rollout.actorScopeID, candidate.TenantScopeID, rollout.id,
			commandKey, commandDigest[:], rollout.revision, commandRequestID, now); err != nil {
			return err
		}
		for _, deployment := range deployments {
			command, err := tx.Exec(ctx, `UPDATE edge_command_outbox SET status='cancelled',updated_at=$2
					WHERE id=$1 AND status IN ('pending','failed')`, deployment.outboxID, now)
			if err != nil || command.RowsAffected() != 1 {
				if err != nil {
					return err
				}
				return ErrConflict
			}
			command, err = tx.Exec(ctx, `UPDATE node_deployments SET state='cancelled',updated_at=$3
				WHERE id=$1 AND attempt=$2 AND state='queued'`, deployment.id, deployment.attempt, now)
			if err != nil || command.RowsAffected() != 1 {
				if err != nil {
					return err
				}
				return ErrConflict
			}
		}
		command, err := tx.Exec(ctx, `UPDATE rollouts SET status='cancelled',revision=revision+1,updated_at=$3
			WHERE configuration_scope_id=$1 AND id=$2 AND status='queued' AND revision=$4`,
			candidate.TenantScopeID, rollout.id, now, rollout.revision)
		if err != nil || command.RowsAffected() != 1 {
			if err != nil {
				return err
			}
			return ErrConflict
		}
		var progress edgedeployment.RolloutProgress
		if err := tx.QueryRow(ctx, `SELECT count(*),
			count(*) FILTER (WHERE deployment.state='queued'),
			count(*) FILTER (WHERE deployment.state='healthy'),
			count(*) FILTER (WHERE deployment.state IN ('failed','rollback_failed') AND NOT `+edgedeployment.SupersededDeploymentSQL+`),
			count(*) FILTER (WHERE deployment.state='cancelled'),
			count(*) FILTER (WHERE `+edgedeployment.SupersededDeploymentSQL+`)
			FROM node_deployments deployment WHERE deployment.rollout_id=$1 AND NOT EXISTS (
			  SELECT 1 FROM node_deployments newer
			  WHERE newer.id=deployment.id AND newer.attempt>deployment.attempt
			)`, rollout.id).Scan(&progress.Total, &progress.Pending, &progress.Succeeded,
			&progress.Failed, &progress.Cancelled, &progress.Superseded); err != nil {
			return err
		}
		progress.Running = progress.Total - progress.Pending - progress.Succeeded - progress.Failed - progress.Cancelled - progress.Superseded
		state := edgedeployment.RolloutStateRunning
		terminal := progress.Succeeded + progress.Superseded + progress.Failed + progress.Cancelled
		switch {
		case progress.Cancelled == progress.Total:
			state = edgedeployment.RolloutStateCancelled
		case progress.Succeeded+progress.Superseded == progress.Total:
			state = edgedeployment.RolloutStateSucceeded
		case terminal == progress.Total && progress.Failed > 0 && progress.Succeeded == 0:
			state = edgedeployment.RolloutStateFailed
		case terminal == progress.Total && (progress.Failed > 0 || progress.Cancelled > 0):
			state = edgedeployment.RolloutStatePartialFailed
		case progress.Pending == progress.Total:
			state = edgedeployment.RolloutStateQueued
		}
		response, err := json.Marshal(edgedeployment.RolloutCommandResult{Rollout: edgedeployment.RolloutSnapshot{
			ID: rollout.id, ConfigurationScopeID: candidate.TenantScopeID, ConfigVersionID: rollout.configID,
			Action: rollout.action, State: state, Revision: rollout.revision + 1,
			MaxAttempts: uint32(rollout.maxAttempts), Progress: progress,
			CreatedAt: rollout.createdAt, UpdatedAt: now,
		}})
		if err != nil {
			return err
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: rollout.actorScopeID, ActorUserID: &rollout.actorUserID,
			Action: "edge_rollout.cancel", ResourceType: "edge_rollout", ResourceID: rollout.id.String(),
			RequestID: commandRequestID.String(), Result: "success", Payload: map[string]any{
				"configuration_scope_id": candidate.TenantScopeID.String(),
				"previous_revision":      rollout.revision, "revision": rollout.revision + 1,
				"state": edgedeployment.RolloutStateCancelled,
			},
		}); err != nil {
			return err
		}
		command, err = tx.Exec(ctx, `UPDATE edge_rollout_write_requests
			SET response_body=$4,completed_at=$5
			WHERE actor_user_id=$1 AND operation='edge_rollout.cancel' AND idempotency_key=$2
			  AND request_id=$3 AND completed_at IS NULL`, rollout.actorUserID, commandKey,
			commandRequestID, response, now)
		if err != nil || command.RowsAffected() != 1 {
			if err != nil {
				return err
			}
			return ErrConflict
		}
	}
	return nil
}

func (store *Store) failPromotion(ctx context.Context, actor securitypolicy.Actor, candidateID uuid.UUID,
	requestID, correlationID, traceparent string, taskID *string, digest [sha256.Size]byte) error {
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var scopeID, bindingID, siteID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT tenant_scope_id,binding_id,site_id
			FROM security_policy_activation_candidates WHERE id=$1`, candidateID).Scan(&scopeID, &bindingID, &siteID); err != nil {
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
		if err != nil {
			return err
		}
		if candidate.Status != StatusHealthy {
			return nil
		}
		now := store.clock().UTC().Truncate(time.Microsecond)
		if err := store.createRecoveryRollouts(ctx, tx, candidate, requestID,
			correlationID, traceparent, taskID, now); err != nil {
			return err
		}
		if err := transitionCandidate(ctx, tx, &candidate, StatusFailed, now); err != nil {
			return err
		}
		return appendActivationEvent(ctx, tx, candidate, actor, derivedEventKey("promotion-failed", candidateID.String()),
			digest, "fail", StatusHealthy, StatusFailed, requestID, now)
	})
}

func terminalReleaseReason(status CandidateStatus) string {
	switch status {
	case StatusFailed, StatusCancelled:
		return "cancelled"
	case StatusExpired:
		return "expired"
	default:
		return ""
	}
}

func recoveryTerminal(status CandidateStatus) bool {
	return status == StatusFailed || status == StatusCancelled || status == StatusExpired
}

func recoveryComplete(ctx context.Context, tx pgx.Tx, candidateID uuid.UUID) (bool, error) {
	var complete bool
	if err := tx.QueryRow(ctx, `SELECT security_policy_activation_recovered_095($1)`, candidateID).Scan(&complete); err != nil {
		return false, err
	}
	return complete, nil
}

func markCandidateRecovered(ctx context.Context, tx pgx.Tx, candidate *Candidate, now time.Time) error {
	command, err := tx.Exec(ctx, `UPDATE security_policy_activation_candidates
		SET recovered_at=$2,updated_at=$2
		WHERE id=$1 AND recovered_at IS NULL AND candidate_status IN ('failed','cancelled','expired')`,
		candidate.ID, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	candidate.RecoveredAt = &now
	candidate.UpdatedAt = now
	return nil
}

func releaseCandidateTargets(ctx context.Context, tx pgx.Tx, candidate Candidate, reason string, now time.Time) error {
	if reason != "completed" && reason != "cancelled" && reason != "expired" {
		return ErrInvalidInput
	}
	_, err := tx.Exec(ctx, `UPDATE security_policy_publication_targets SET released_at=$1,release_reason=$2
		WHERE tenant_scope_id=$3 AND publication_id=$4 AND binding_id=$5 AND released_at IS NULL`,
		now, reason, candidate.TenantScopeID, candidate.LastBundleID, candidate.BindingID)
	return err
}

func insertPhaseIdentity(ctx context.Context, tx pgx.Tx, candidate Candidate, phase string,
	nodes []uuid.UUID, rolloutID uuid.UUID, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO security_policy_activation_rollouts(
		candidate_id,tenant_scope_id,phase,rollout_id,candidate_config_version_id,
		candidate_artifact_sha256,target_snapshot_sha256,node_ids,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, candidate.ID, candidate.TenantScopeID, phase,
		rolloutID, candidate.CandidateConfigVersionID, candidate.CandidateArtifactSHA256[:],
		candidate.TargetSnapshotSHA256[:], nodes, now)
	return err
}

func transitionCandidate(ctx context.Context, tx pgx.Tx, candidate *Candidate, status CandidateStatus, now time.Time) error {
	command, err := tx.Exec(ctx, `UPDATE security_policy_activation_candidates SET candidate_status=$2,updated_at=$3
		WHERE id=$1 AND candidate_status=$4`, candidate.ID, status, now, candidate.Status)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	candidate.Status, candidate.UpdatedAt = status, now
	return nil
}

func loadPhaseReceipts(ctx context.Context, tx pgx.Tx, candidate Candidate, phase string,
	targets []uuid.UUID, now time.Time) (phaseFacts, PhaseIdentity, error) {
	expectedTargets := candidate.CanaryNodeIDs
	if phase == "expand" {
		expectedTargets = candidate.ExpandNodeIDs
	} else if phase != "canary" {
		return phaseFacts{}, PhaseIdentity{}, ErrConflict
	}
	if len(targets) == 0 || len(targets) != len(expectedTargets) {
		return phaseFacts{}, PhaseIdentity{}, ErrConflict
	}
	for index := range targets {
		if targets[index] != expectedTargets[index] {
			return phaseFacts{}, PhaseIdentity{}, ErrConflict
		}
	}

	var identity PhaseIdentity
	var artifact, target []byte
	var persistedNodes []uuid.UUID
	persisted := true
	err := tx.QueryRow(ctx, `SELECT candidate_id,rollout_id,phase,candidate_config_version_id,
		candidate_artifact_sha256,target_snapshot_sha256,node_ids FROM security_policy_activation_rollouts
		WHERE candidate_id=$1 AND phase=$2`, candidate.ID, phase).Scan(
		&identity.CandidateID, &identity.RolloutID, &identity.Phase, &identity.ConfigVersionID,
		&artifact, &target, &persistedNodes)
	if errors.Is(err, pgx.ErrNoRows) {
		persisted = false
		identity, err = loadDerivedPhaseIdentity(ctx, tx, candidate, phase, targets,
			derivedKey(phase, candidate.ID.String()))
		artifact, target = identity.ArtifactSHA256[:], identity.TargetSnapshotSHA256[:]
	}
	if err != nil {
		return phaseFacts{}, PhaseIdentity{}, err
	}
	if persisted && len(persistedNodes) != len(targets) {
		return phaseFacts{}, PhaseIdentity{}, ErrConflict
	}
	for index := range persistedNodes {
		if persistedNodes[index] != targets[index] {
			return phaseFacts{}, PhaseIdentity{}, ErrConflict
		}
	}
	if len(artifact) != sha256.Size || len(target) != sha256.Size {
		return phaseFacts{}, PhaseIdentity{}, ErrConflict
	}
	copy(identity.ArtifactSHA256[:], artifact)
	copy(identity.TargetSnapshotSHA256[:], target)
	if err := validatePhaseIdentity(candidate, identity); err != nil {
		return phaseFacts{}, PhaseIdentity{}, err
	}
	rows, err := tx.Query(ctx, `SELECT deployment.id,deployment.node_id,deployment.attempt,deployment.action,deployment.state,
		`+edgedeployment.SupersededDeploymentSQL+`,
		event.transition_sequence,event.state,event.active_config_version_id,event.active_config_artifact_sha256
		FROM node_deployments deployment
		LEFT JOIN deployment_status_events event ON event.deployment_id=deployment.id AND event.attempt=deployment.attempt
		WHERE deployment.rollout_id=$1 AND deployment.attempt=(
			SELECT max(latest.attempt) FROM node_deployments latest WHERE latest.id=deployment.id
		)
		ORDER BY deployment.node_id,deployment.attempt,event.transition_sequence`, identity.RolloutID)
	if err != nil {
		return phaseFacts{}, PhaseIdentity{}, err
	}
	defer rows.Close()
	receipts := make([]ReceiptFact, 0)
	for rows.Next() {
		var fact ReceiptFact
		var sequence *int64
		var state *string
		var projectedState string
		var activeConfigID *uuid.UUID
		var activeDigest []byte
		fact.RolloutID, fact.Phase = identity.RolloutID, phase
		if err := rows.Scan(&fact.DeploymentID, &fact.NodeID, &fact.Attempt, &fact.Action,
			&projectedState, &fact.Superseded, &sequence, &state, &activeConfigID, &activeDigest); err != nil {
			return phaseFacts{}, PhaseIdentity{}, err
		}
		if (sequence == nil) != (state == nil) {
			return phaseFacts{}, PhaseIdentity{}, ErrConflict
		}
		if sequence == nil {
			fact.TransitionSequence, fact.State = 1, projectedState
			receipts = append(receipts, fact)
			continue
		}
		fact.TransitionSequence, fact.State = *sequence, *state
		if activeConfigID != nil {
			fact.ConfigVersionID = *activeConfigID
		}
		if len(activeDigest) == sha256.Size {
			copy(fact.ArtifactSHA256[:], activeDigest)
		}
		receipts = append(receipts, fact)
	}
	if err := rows.Err(); err != nil {
		return phaseFacts{}, PhaseIdentity{}, err
	}
	nodeArtifacts, err := loadCandidateNodeArtifacts(ctx, tx, candidate)
	if err != nil {
		return phaseFacts{}, PhaseIdentity{}, err
	}
	facts, err := aggregateReceiptFacts(candidate, targets, receipts, nodeArtifacts.digestMap())
	if err != nil {
		return phaseFacts{}, PhaseIdentity{}, err
	}
	if !persisted && facts.total > 0 && facts.healthy == facts.total {
		if err := insertPhaseIdentity(ctx, tx, candidate, phase, targets, identity.RolloutID, now); err != nil {
			return phaseFacts{}, PhaseIdentity{}, err
		}
		persisted = true
	}
	if !persisted {
		return facts, PhaseIdentity{}, nil
	}
	return facts, identity, nil
}

func phaseRolloutExists(ctx context.Context, tx pgx.Tx, candidate Candidate, phase string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rollouts
		WHERE configuration_scope_id=$1 AND idempotency_key=$2)`,
		candidate.TenantScopeID, derivedKey(phase, candidate.ID.String())).Scan(&exists)
	return exists, err
}

func loadDerivedPhaseIdentity(ctx context.Context, tx pgx.Tx, candidate Candidate, phase string,
	targets []uuid.UUID, rolloutKey string) (PhaseIdentity, error) {
	var identity PhaseIdentity
	var artifact, target []byte
	err := tx.QueryRow(ctx, `SELECT candidate.id,rollout.id,$2,candidate.candidate_config_version_id,
			candidate.candidate_artifact_sha256,candidate.target_snapshot_sha256
			FROM security_policy_activation_candidates candidate
			JOIN security_policy_site_bindings binding
			  ON binding.tenant_scope_id=candidate.tenant_scope_id
			 AND binding.id=candidate.binding_id AND binding.site_id=candidate.site_id
			JOIN security_policy_publications publication
			  ON publication.tenant_scope_id=candidate.tenant_scope_id AND publication.id=candidate.last_bundle_id
			JOIN security_policies policy
			  ON policy.scope_id=candidate.tenant_scope_id AND policy.id=publication.policy_id
			 AND policy.kind=binding.policy_kind AND (policy.deleted_at IS NULL OR publication.detach)
			JOIN security_policy_activation_config_facts fact
			  ON fact.tenant_scope_id=candidate.tenant_scope_id
			 AND fact.config_version_id=candidate.candidate_config_version_id
			 AND fact.artifact_sha256=candidate.candidate_artifact_sha256
			 AND fact.policy_kind=binding.policy_kind
			 AND fact.required_capabilities=candidate.required_capabilities
			JOIN rollouts rollout
			  ON rollout.configuration_scope_id=candidate.tenant_scope_id
			 AND rollout.config_version_id=candidate.candidate_config_version_id
			 AND rollout.idempotency_key=$9 AND rollout.action='apply'
			 AND rollout.status IN ('queued','completed') AND rollout.contract_version=1
			 AND rollout.deadline_at=candidate.expires_at
			WHERE candidate.id=$1 AND candidate.tenant_scope_id=$3 AND candidate.site_id=$4
			  AND candidate.binding_id=$5 AND candidate.candidate_config_version_id=$6
			  AND candidate.candidate_artifact_sha256=$7 AND candidate.target_snapshot_sha256=$8
			  AND (SELECT count(*) FROM node_deployments deployment
			       WHERE deployment.rollout_id=rollout.id AND deployment.attempt=1)=cardinality($10::uuid[])
			  AND NOT EXISTS (
			      SELECT 1 FROM node_deployments deployment
			      WHERE deployment.rollout_id=rollout.id AND deployment.attempt=1
			        AND (NOT deployment.node_id=ANY($10::uuid[]) OR deployment.action<>'apply'
			             OR deployment.config_version_id<>candidate.candidate_config_version_id)
			  )`, candidate.ID, phase, candidate.TenantScopeID, candidate.SiteID, candidate.BindingID,
		candidate.CandidateConfigVersionID, candidate.CandidateArtifactSHA256[:],
		candidate.TargetSnapshotSHA256[:], rolloutKey, targets).Scan(
		&identity.CandidateID, &identity.RolloutID, &identity.Phase, &identity.ConfigVersionID,
		&artifact, &target)
	if err != nil {
		return PhaseIdentity{}, err
	}
	if len(artifact) != sha256.Size || len(target) != sha256.Size {
		return PhaseIdentity{}, ErrConflict
	}
	copy(identity.ArtifactSHA256[:], artifact)
	copy(identity.TargetSnapshotSHA256[:], target)
	if err := validatePhaseIdentity(candidate, identity); err != nil {
		return PhaseIdentity{}, err
	}
	return identity, nil
}

func candidateReceiptsHealthy(ctx context.Context, tx pgx.Tx, candidate Candidate) (bool, error) {
	var canary bool
	if err := tx.QueryRow(ctx, `SELECT security_policy_activation_phase_healthy_088($1,'canary')`, candidate.ID).Scan(&canary); err != nil {
		return false, err
	}
	if !canary || len(candidate.ExpandNodeIDs) == 0 {
		return canary, nil
	}
	var expand bool
	if err := tx.QueryRow(ctx, `SELECT security_policy_activation_phase_healthy_088($1,'expand')`, candidate.ID).Scan(&expand); err != nil {
		return false, err
	}
	return expand, nil
}

func (store *Store) candidateCapabilities(ctx context.Context, tx pgx.Tx, candidate Candidate) ([]*agentv1.Capability, error) {
	var kind string
	if err := tx.QueryRow(ctx, `SELECT policy_kind FROM security_policy_site_bindings
		WHERE tenant_scope_id=$1 AND id=$2`, candidate.TenantScopeID, candidate.BindingID).Scan(&kind); err != nil {
		return nil, err
	}
	capabilities := []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
	}
	if kind == securitypolicy.KindCC {
		capabilities = append(capabilities, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_CC, ApiVersion: store.config.RequiredCCAPIVersion})
	} else {
		capabilities = append(capabilities, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: store.config.RequiredWAFAPIVersion})
	}
	return capabilities, nil
}

func loadPolicyVersion(ctx context.Context, tx pgx.Tx, scopeID, policyID uuid.UUID, revision int64) (securitypolicy.Policy, error) {
	return loadPolicyVersionFor(ctx, tx, scopeID, policyID, revision, false)
}

// loadPolicyVersionFor: includeDeleted reads a deleted library's version
// (a detach withdraws it, sec-rebind).
func loadPolicyVersionFor(ctx context.Context, tx pgx.Tx, scopeID, policyID uuid.UUID, revision int64,
	includeDeleted bool) (securitypolicy.Policy, error) {
	var document []byte
	if err := tx.QueryRow(ctx, `SELECT version.document FROM security_policy_versions version
		JOIN security_policies policy ON policy.id=version.policy_id
		WHERE policy.scope_id=$1 AND version.policy_id=$2 AND version.revision=$3 AND (policy.deleted_at IS NULL OR $4)`,
		scopeID, policyID, revision, includeDeleted).Scan(&document); errors.Is(err, pgx.ErrNoRows) {
		return securitypolicy.Policy{}, ErrConflict
	} else if err != nil {
		return securitypolicy.Policy{}, err
	}
	var policy securitypolicy.Policy
	if err := json.Unmarshal(document, &policy); err != nil || policy.ID != policyID || policy.ScopeID != scopeID || policy.Revision != revision {
		return securitypolicy.Policy{}, ErrConflict
	}
	return policy, nil
}

func (store *Store) clonePolicyVersionTx(ctx context.Context, tx pgx.Tx, actor securitypolicy.Actor, scopeID, policyID uuid.UUID,
	sourceRevision int64, requestID string) (securitypolicy.Policy, error) {
	var currentRevision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM security_policies WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`,
		scopeID, policyID).Scan(&currentRevision); errors.Is(err, pgx.ErrNoRows) {
		return securitypolicy.Policy{}, ErrNotFound
	} else if err != nil {
		return securitypolicy.Policy{}, err
	}
	source, err := loadPolicyVersion(ctx, tx, scopeID, policyID, sourceRevision)
	if err != nil {
		return securitypolicy.Policy{}, err
	}
	rolled, err := cloneRollbackPolicy(source, currentRevision+1)
	if err != nil {
		return securitypolicy.Policy{}, err
	}
	rules, err := json.Marshal(rolled.Rules)
	if err != nil {
		return securitypolicy.Policy{}, err
	}
	// The rolled-back rules carry that version's quick block rules: restore
	// its switches with them (WAF only), so later edits re-derive the same.
	var quickBlock []byte
	if rolled.QuickBlock != nil {
		if quickBlock, err = json.Marshal(rolled.QuickBlock); err != nil {
			return securitypolicy.Policy{}, err
		}
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	command, err := tx.Exec(ctx, `UPDATE security_policies SET name=$3,description=$4,enabled=$5,default_action=$6,
		rules=$7,revision=$8,updated_by_user_id=$9,updated_at=$10,
		quick_block=CASE WHEN kind='waf' THEN $13::jsonb ELSE quick_block END
		WHERE scope_id=$1 AND id=$2 AND revision=$11 AND kind=$12 AND deleted_at IS NULL`, scopeID, policyID,
		rolled.Name, rolled.Description, rolled.Enabled, rolled.DefaultAction, rules, rolled.Revision,
		actor.UserID, now, currentRevision, rolled.Kind, quickBlock)
	if err != nil {
		return securitypolicy.Policy{}, err
	}
	if command.RowsAffected() != 1 {
		return securitypolicy.Policy{}, ErrConflict
	}
	rolled.UpdatedAt = now
	document, err := json.Marshal(rolled)
	if err != nil {
		return securitypolicy.Policy{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at)
		VALUES($1,$2,$3,$4,$5)`, policyID, rolled.Revision, document, actor.UserID, now); err != nil {
		return securitypolicy.Policy{}, err
	}
	if err := securitypolicy.CheckSiteQuickBlockOverridesTx(ctx, tx, rolled); err != nil {
		return securitypolicy.Policy{}, err
	}
	if err := store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorUserID: &actor.UserID,
		Action: "security_policy.activation.rollback_clone", ResourceType: "security_policy",
		ResourceID: policyID.String(), RequestID: requestID, Result: "success",
		Payload: map[string]any{
			"source_policy_version": sourceRevision, "new_policy_version": rolled.Revision,
		},
	}); err != nil {
		return securitypolicy.Policy{}, err
	}
	return rolled, nil
}

func loadActivationEventReplay(ctx context.Context, tx pgx.Tx, candidateID uuid.UUID, eventKey string,
	digest [sha256.Size]byte) (string, bool, error) {
	var stored []byte
	var action string
	err := tx.QueryRow(ctx, `SELECT request_digest,action FROM security_policy_activation_events
		WHERE candidate_id=$1 AND event_key=$2 FOR UPDATE`, candidateID, eventKey).Scan(&stored, &action)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !bytes.Equal(stored, digest[:]) {
		return "", false, ErrIdempotencyConflict
	}
	return action, true, nil
}

func startDigest(input StartInput) ([sha256.Size]byte, error) {
	return canonicalDigest(struct {
		TenantScopeID               uuid.UUID           `json:"tenant_scope_id"`
		SiteID                      uuid.UUID           `json:"site_id"`
		PolicyID                    uuid.UUID           `json:"policy_id"`
		PolicyVersion               int64               `json:"policy_version"`
		ExpectedBindingRevision     int64               `json:"expected_binding_revision"`
		ExpectedActivePolicyVersion int64               `json:"expected_active_policy_version"`
		TargetNodeIDs               []uuid.UUID         `json:"target_node_ids"`
		CanarySize                  int                 `json:"canary_size"`
		ExpiresAt                   string              `json:"expires_at"`
		Recovery                    *CIDRRecoveryIntent `json:"recovery,omitempty"`
		SiteRuntimeSchema           string              `json:"site_runtime_schema,omitempty"`
		Detach                      bool                `json:"detach,omitempty"`
	}{input.TenantScopeID, input.SiteID, input.PolicyID, input.PolicyVersion,
		input.ExpectedBindingRevision, input.ExpectedActivePolicyVersion, input.TargetNodeIDs,
		input.CanarySize, input.ExpiresAt.UTC().Format(time.RFC3339Nano), input.Recovery,
		input.SiteRuntimeSchema, input.Detach})
}

func reconcileDigest(input ReconcileInput) ([sha256.Size]byte, error) {
	return canonicalDigest(struct {
		CandidateID uuid.UUID    `json:"candidate_id"`
		CAS         PromotionCAS `json:"promotion_cas"`
	}{input.CandidateID, input.PromotionCAS})
}

func rollbackDigest(input RollbackInput) ([sha256.Size]byte, error) {
	return canonicalDigest(struct {
		CandidateID                 uuid.UUID   `json:"candidate_id"`
		SourcePolicyVersion         int64       `json:"source_policy_version"`
		ExpectedBindingRevision     int64       `json:"expected_binding_revision"`
		ExpectedActivePolicyVersion int64       `json:"expected_active_policy_version"`
		TargetNodeIDs               []uuid.UUID `json:"target_node_ids"`
		CanarySize                  int         `json:"canary_size"`
		ExpiresAt                   string      `json:"expires_at"`
		SiteRuntimeSchema           string      `json:"site_runtime_schema,omitempty"`
	}{input.CandidateID, input.SourcePolicyVersion, input.ExpectedBindingRevision,
		input.ExpectedActivePolicyVersion, input.TargetNodeIDs, input.CanarySize,
		input.ExpiresAt.UTC().Format(time.RFC3339Nano), input.SiteRuntimeSchema})
}

func canonicalDigest(value any) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func derivedKey(prefix, value string) string {
	digest := sha256.Sum256([]byte(prefix + ":" + value))
	return prefix + "." + hex.EncodeToString(digest[:])
}

func derivedEventKey(prefix, value string) string {
	digest := sha256.Sum256([]byte(prefix + ":" + value))
	return prefix + ":" + hex.EncodeToString(digest[:])
}

func activationTraceparent(candidateID uuid.UUID, phase string) string {
	digest := sha256.Sum256([]byte(candidateID.String() + ":" + phase))
	return fmt.Sprintf("00-%x-%x-01", digest[:16], digest[16:24])
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	copyOfValue := *value
	return &copyOfValue
}

func mapDependencyError(err error) error {
	switch {
	case errors.Is(err, securitybinding.ErrIdempotencyConflict), errors.Is(err, edgepublish.ErrIdempotencyConflict):
		return ErrIdempotencyConflict
	case errors.Is(err, securitybinding.ErrPermissionDenied), errors.Is(err, edgepublish.ErrPermissionDenied):
		return ErrPermissionDenied
	case errors.Is(err, securitybinding.ErrSiteLocked):
		return ErrSiteLocked
	case errors.Is(err, securitybinding.ErrPolicyDeleted):
		return ErrPolicyDeleted
	case errors.Is(err, securitybinding.ErrBindingRevision), errors.Is(err, securitybinding.ErrActiveVersionConflict),
		errors.Is(err, securitybinding.ErrPolicyVersionConflict), errors.Is(err, securitybinding.ErrBindingConflict),
		errors.Is(err, securitybinding.ErrTargetConflict), errors.Is(err, edgepublish.ErrTargetSnapshotConflict):
		return ErrConflict
	default:
		return fmt.Errorf("security activation dependency: %w", err)
	}
}
