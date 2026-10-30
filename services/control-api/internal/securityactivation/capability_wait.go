package securityactivation

import (
	"context"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Activations refused because target nodes predate a gated capability
// (CC v4 counting keys, CC v3 proof of work, JA4 for counting by TLS
// fingerprint, the CRS managed WAF module) are not lost: the request waits
// in security_activation_capability_waits and the activation worker starts
// it again once every target node's latest session declares the capability
// (the node upgraded). The operator sees the wait in Status. Any activation
// later started for the same site and policy kind supersedes it.

const capabilityWaitBatchSize = 50

// waitableCapability: CC (counting keys v4, proof of work v3), JA4 (a CC
// rule counting by TLS fingerprint needs the node's JA4 module), the OWASP
// CRS managed WAF module (a manually activated WAF rule takes
// effect by itself once the nodes are upgraded) and IP_INTEL (carrier / IDC /
// ASN / region WAF rules need the node's IP library; the activation resumes
// once every target node declares it) and SITE_QUIC (a v2 site with HTTP/3
// on also listens on QUIC; a node whose OpenResty lacks the HTTP/3
// module does not declare it, and declares it once upgraded).
func waitableCapability(name agentv1.CapabilityName) bool {
	return name == agentv1.CapabilityName_CAPABILITY_NAME_CC || name == agentv1.CapabilityName_CAPABILITY_NAME_JA4 ||
		name == agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE || name == agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL ||
		name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC
}

// CapabilityWait is a refused activation waiting for its target nodes:
// for a node capability (wait_kind capability) or for rule packs the site
// uses that the nodes have not applied yet (wait_kind rule_pack, 478).
type CapabilityWait struct {
	WaitKind          string      `json:"wait_kind"`
	NodeIDs           []uuid.UUID `json:"node_ids"`
	RequiredCCVersion uint32      `json:"required_cc_version"`
	// RulePacks: for a rule pack wait, every pack the nodes must hold.
	RulePacks     []string  `json:"rule_packs,omitempty"`
	PolicyVersion int64     `json:"policy_version"`
	CreatedAt     time.Time `json:"created_at"`
}

const (
	waitKindCapability = "capability"
	waitKindRulePack   = "rule_pack"
)

// activationWait is what a refused start waits for.
type activationWait struct {
	kind       string
	capability *agentv1.Capability
	rulePacks  []string
	blocking   []uuid.UUID
	reasonCode string
}

// waitableStart: a recovery or a detach is not resumed (the resumed start
// would claim the library).
func waitableStart(input StartInput) bool { return input.Recovery == nil && !input.Detach }

// recordCapabilityWait stores input as waiting for refusal's capability,
// replacing the site's previous waiting request of the same policy kind.
func (store *Store) recordCapabilityWait(ctx context.Context, actor securitypolicy.Actor, input StartInput,
	refusal *edgepublish.TargetCapabilityError) error {
	if !waitableCapability(refusal.Capability) || !waitableStart(input) {
		return nil
	}
	return store.recordWait(ctx, actor, input, activationWait{kind: waitKindCapability,
		capability: &agentv1.Capability{Name: refusal.Capability, ApiVersion: refusal.Required},
		blocking:   append([]uuid.UUID{refusal.NodeID}, refusal.OtherNodeIDs...), reasonCode: "node_capability_unavailable"})
}

// recordRulePackWait stores input as waiting for the rule packs refusal
// names: it is started again once every target node has applied them
// (node artifact set receipt), like a capability wait.
func (store *Store) recordRulePackWait(ctx context.Context, actor securitypolicy.Actor, input StartInput,
	refusal *edgepublish.RulePackUnavailableError) error {
	if !waitableStart(input) || len(refusal.Required) == 0 {
		return nil
	}
	return store.recordWait(ctx, actor, input, activationWait{kind: waitKindRulePack, rulePacks: refusal.Required,
		blocking: append([]uuid.UUID{refusal.NodeID}, refusal.OtherNodeIDs...), reasonCode: "rule_pack_unavailable"})
}

func (store *Store) recordWait(ctx context.Context, actor securitypolicy.Actor, input StartInput, wait activationWait) error {
	now := store.clock().UTC().Truncate(time.Microsecond)
	var capability, version *int32
	if wait.capability != nil {
		name, required := int32(wait.capability.GetName()), int32(wait.capability.GetApiVersion())
		capability, version = &name, &required
	}
	waitID := uuid.New()
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var kind string
		if err := tx.QueryRow(ctx, `SELECT kind FROM security_policies WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL`,
			input.TenantScopeID, input.PolicyID).Scan(&kind); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE security_activation_capability_waits SET status='superseded',updated_at=$4
			WHERE tenant_scope_id=$1 AND site_id=$2 AND policy_kind=$3 AND status='waiting'`,
			input.TenantScopeID, input.SiteID, kind, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_activation_capability_waits(id,tenant_scope_id,site_id,policy_id,
			policy_kind,policy_version,expected_binding_revision,expected_active_policy_version,target_node_ids,canary_size,
			actor_user_id,actor_scope_id,actor_scope_kind,capability,required_api_version,
			blocking_node_ids,created_at,updated_at,site_runtime_schema,wait_kind,rule_pack_sha256)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17,$18,$19,$20)`,
			waitID, input.TenantScopeID, input.SiteID, input.PolicyID, kind, input.PolicyVersion,
			input.ExpectedBindingRevision, input.ExpectedActivePolicyVersion, input.TargetNodeIDs, input.CanarySize,
			actor.UserID, actor.ScopeID, actor.ScopeKind, capability, version, wait.blocking, now,
			capabilityWaitSchema(input.SiteRuntimeSchema), wait.kind, wait.rulePacks); err != nil {
			return err
		}
		payload := map[string]any{"site_id": input.SiteID.String(), "policy_id": input.PolicyID.String(),
			"policy_version": input.PolicyVersion, "wait_kind": wait.kind, "blocking_node_count": len(wait.blocking),
			"first_blocking_node_id": wait.blocking[0].String()}
		if wait.capability != nil {
			payload["capability"] = wait.capability.GetName().String()
			payload["required_version"] = wait.capability.GetApiVersion()
		}
		if len(wait.rulePacks) != 0 {
			payload["rule_packs"] = wait.rulePacks
		}
		return store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: input.TenantScopeID, ActorUserID: &actor.UserID,
			Action: "security_policy.activation.wait", ResourceType: "security_policy_activation_wait",
			ResourceID: waitID.String(), RequestID: input.RequestID, Result: "failure", ReasonCode: wait.reasonCode,
			Payload: payload, OccurredAt: now,
		})
	})
}

// capabilityWaitSchema is the site runtime a wait resumes on (the column
// is never empty): the one the start chose, else the default.
func capabilityWaitSchema(schema string) string {
	return edgepublish.ResolveSiteRuntimeSchema(schema)
}

// supersedeCapabilityWaits marks the site's other waiting requests of the
// policy's kind superseded once an activation has started.
func (store *Store) supersedeCapabilityWaits(ctx context.Context, input StartInput) error {
	_, err := store.pool.Exec(ctx, `UPDATE security_activation_capability_waits wait SET status='superseded',updated_at=$5
		FROM security_policies policy
		WHERE policy.scope_id=$1 AND policy.id=$3 AND wait.tenant_scope_id=$1 AND wait.site_id=$2
		  AND wait.policy_kind=policy.kind AND wait.status='waiting' AND wait.id IS DISTINCT FROM $4`,
		input.TenantScopeID, input.SiteID, input.PolicyID, input.resumeWaitID, store.clock().UTC().Truncate(time.Microsecond))
	return err
}

func loadCapabilityWait(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, policyKind string) (*CapabilityWait, error) {
	var wait CapabilityWait
	var required *int32
	err := tx.QueryRow(ctx, `SELECT wait_kind,blocking_node_ids,required_api_version,rule_pack_sha256,policy_version,created_at
		FROM security_activation_capability_waits
		WHERE tenant_scope_id=$1 AND site_id=$2 AND policy_kind=$3 AND status='waiting'`,
		scopeID, siteID, policyKind).Scan(&wait.WaitKind, &wait.NodeIDs, &required, &wait.RulePacks, &wait.PolicyVersion,
		&wait.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if required != nil {
		wait.RequiredCCVersion = uint32(*required)
	}
	return &wait, nil
}

type capabilityWaitRow struct {
	id    uuid.UUID
	actor securitypolicy.Actor
	input StartInput
	// capability (wait_kind capability) or rulePacks (wait_kind rule_pack).
	capability *agentv1.Capability
	rulePacks  []string
}

// resumeCapabilityWaits starts every waiting request whose target nodes now
// all declare the capability it waits for, or all hold the rule packs it
// waits for (applied node artifact set). A request that fails for another
// reason (stale revision, revoked permission, deleted policy) is marked
// failed; one whose nodes still lack it keeps waiting with the current
// blocking nodes. At most capabilityWaitBatchSize per pass. Only database
// failures are returned.
func (store *Store) resumeCapabilityWaits(ctx context.Context) error {
	rows, err := store.pool.Query(ctx, `SELECT id,tenant_scope_id,site_id,policy_id,policy_version,expected_binding_revision,
		expected_active_policy_version,target_node_ids,canary_size,actor_user_id,actor_scope_id,
		actor_scope_kind,capability,required_api_version,rule_pack_sha256,site_runtime_schema
		FROM security_activation_capability_waits WHERE status='waiting' ORDER BY updated_at,id LIMIT $1`, capabilityWaitBatchSize)
	if err != nil {
		return err
	}
	var waits []capabilityWaitRow
	for rows.Next() {
		var row capabilityWaitRow
		var capability, version *int32
		if err := rows.Scan(&row.id, &row.input.TenantScopeID, &row.input.SiteID, &row.input.PolicyID, &row.input.PolicyVersion,
			&row.input.ExpectedBindingRevision, &row.input.ExpectedActivePolicyVersion, &row.input.TargetNodeIDs,
			&row.input.CanarySize, &row.actor.UserID, &row.actor.ScopeID, &row.actor.ScopeKind,
			&capability, &version, &row.rulePacks, &row.input.SiteRuntimeSchema); err != nil {
			rows.Close()
			return err
		}
		if capability != nil && version != nil {
			row.capability = &agentv1.Capability{Name: agentv1.CapabilityName(*capability), ApiVersion: uint32(*version)}
		}
		waits = append(waits, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, wait := range waits {
		if err := store.resumeCapabilityWait(ctx, wait); err != nil {
			return err
		}
	}
	return nil
}

// waitBlocking is the nodes still blocking wait (nil: none, it can start).
func (store *Store) waitBlocking(ctx context.Context, wait capabilityWaitRow) ([]uuid.UUID, error) {
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if wait.capability == nil {
			return edgepublish.ValidateRulePackTargets(ctx, tx, wait.input.TargetNodeIDs, wait.rulePacks)
		}
		return edgepublish.ValidateFeatureCapabilityTargets(ctx, tx, wait.input.TargetNodeIDs, []*agentv1.Capability{wait.capability})
	})
	var capability *edgepublish.TargetCapabilityError
	var packs *edgepublish.RulePackUnavailableError
	switch {
	case errors.As(err, &capability):
		return append([]uuid.UUID{capability.NodeID}, capability.OtherNodeIDs...), nil
	case errors.As(err, &packs):
		return append([]uuid.UUID{packs.NodeID}, packs.OtherNodeIDs...), nil
	}
	return nil, err
}

func (store *Store) resumeCapabilityWait(ctx context.Context, wait capabilityWaitRow) error {
	blocking, err := store.waitBlocking(ctx, wait)
	if err != nil {
		return err
	}
	if blocking != nil {
		return store.updateCapabilityWait(ctx, wait.id, "waiting", nil, "", blocking)
	}
	now := store.clock()
	input := wait.input
	// One idempotency key per wait. A pass after a crash between Start and
	// the status update finds the candidate it started (its expiry, part of
	// the digest, differs per pass) instead of starting the request again.
	input.IdempotencyKey = "capability-wait." + wait.id.String()
	var started *uuid.UUID
	if err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		candidate, _, found, err := loadCandidateByKey(ctx, tx, input.TenantScopeID, input.IdempotencyKey, false)
		if found {
			started = &candidate.ID
		}
		return err
	}); err != nil {
		return err
	}
	if started != nil {
		return store.updateCapabilityWait(ctx, wait.id, "resumed", started, "", nil)
	}
	input.RequestID = uuid.NewSHA1(wait.id, []byte("capability-wait-resume")).String()
	input.CorrelationID = wait.id.String()
	input.Traceparent = activationTraceparent(wait.id, "capability-wait")
	taskID := "security-activation-capability-wait"
	input.TaskID = &taskID
	input.ExpiresAt = now.Add(store.config.CandidateTTL - time.Minute)
	input.resumeWaitID = wait.id
	result, err := store.Start(ctx, wait.actor, input)
	var capability *edgepublish.TargetCapabilityError
	var packs *edgepublish.RulePackUnavailableError
	switch {
	case err == nil:
		return store.updateCapabilityWait(ctx, wait.id, "resumed", &result.Candidate.ID, "", nil)
	case errors.As(err, &capability), errors.As(err, &packs):
		// Start recorded a fresh wait for what still blocks it; this one is
		// superseded by it.
		return nil
	case errors.Is(err, ErrConflict), errors.Is(err, ErrSourceRevisionConflict):
		return store.updateCapabilityWait(ctx, wait.id, "failed", nil, "conflict", nil)
	case errors.Is(err, ErrPermissionDenied):
		return store.updateCapabilityWait(ctx, wait.id, "failed", nil, "permission_denied", nil)
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrNotFound), errors.Is(err, ErrIdempotencyConflict),
		errors.Is(err, edgepublish.ErrTargetIneligible):
		return store.updateCapabilityWait(ctx, wait.id, "failed", nil, "rejected", nil)
	default:
		return fmt.Errorf("resume security activation capability wait %s: %w", wait.id, err)
	}
}

func (store *Store) updateCapabilityWait(ctx context.Context, id uuid.UUID, status string, candidateID *uuid.UUID,
	reason string, blocking []uuid.UUID) error {
	var lastError *string
	if reason != "" {
		lastError = &reason
	}
	_, err := store.pool.Exec(ctx, `UPDATE security_activation_capability_waits SET status=$2,resumed_candidate_id=$3,
		last_error=$4,blocking_node_ids=COALESCE($5,blocking_node_ids),updated_at=$6
		WHERE id=$1 AND status='waiting'`,
		id, status, candidateID, lastError, blocking, store.clock().UTC().Truncate(time.Microsecond))
	return err
}
