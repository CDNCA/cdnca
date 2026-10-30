package challengepolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

type publicationPolicySource interface {
	UsePublicationSnapshot(context.Context, Actor, uuid.UUID, uuid.UUID, int64, PublicationConsumer) error
	ReadPublicationSnapshot(context.Context, Actor, uuid.UUID, uuid.UUID, PublicationConsumer) error
}

type publicationRuntime interface {
	Publish(context.Context, challengepublication.PublishRequest) (challengepublication.SecretPublication, error)
	Status(context.Context, challengepublication.StatusRequest) (challengepublication.RolloutStatus, error)
	Promote(context.Context, challengepublication.PromoteRequest) (challengepublication.PromotionStatus, error)
}

type PublicationPlan struct {
	NodeIDs              []uuid.UUID
	RequiredCapabilities []*agentv1.Capability
	HealthCheck          edgedeployment.HealthCheckPolicy
	Deadline             time.Time
}

type PublicationPlanner interface {
	Plan(context.Context, pgx.Tx, PublicationSnapshot) (PublicationPlan, error)
}

type PublicationIdentityVerifier interface {
	Verify(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, int64) ([]uuid.UUID, error)
	// Readiness classifies the secret rollout's nodes for promotion against
	// the scope's planned nodes (challengepublication.ClassifyPromotionNodes).
	Readiness(ctx context.Context, tx pgx.Tx, tenantScopeID, rolloutID uuid.UUID,
		planned []uuid.UUID) (challengepublication.NodeReadiness, error)
}

type PublicationCoordinator struct {
	policies publicationPolicySource
	runtime  publicationRuntime
	planner  PublicationPlanner
	verifier PublicationIdentityVerifier
}

func NewPublicationCoordinator(
	policies publicationPolicySource,
	runtime publicationRuntime,
	planner PublicationPlanner,
	verifier PublicationIdentityVerifier,
) (*PublicationCoordinator, error) {
	if isNilDependency(policies) || isNilDependency(runtime) || isNilDependency(planner) || isNilDependency(verifier) {
		return nil, ErrInvalidHandlerConfig
	}
	return &PublicationCoordinator{policies: policies, runtime: runtime, planner: planner, verifier: verifier}, nil
}

func (coordinator *PublicationCoordinator) Publish(ctx context.Context, request PublicationRequest) (PublicationStatus, error) {
	if !validPublicationCommand(request, false) {
		return PublicationStatus{}, ErrInvalidInput
	}
	var result PublicationStatus
	err := coordinator.policies.UsePublicationSnapshot(ctx, request.Actor, request.TenantScopeID, request.PolicyID,
		request.ExpectedRevision, func(ctx context.Context, tx pgx.Tx, snapshot PublicationSnapshot) error {
			plan, err := coordinator.planner.Plan(ctx, tx, snapshot)
			if err != nil {
				return err
			}
			actor, edgeActor, err := publicationActors(request.Actor)
			if err != nil {
				return err
			}
			publication, err := coordinator.runtime.Publish(ctx, challengepublication.PublishRequest{
				Policy: publicationRuntimeSnapshot(snapshot), Actor: actor, EdgeActor: edgeActor,
				NodeIDs:              slices.Clone(plan.NodeIDs),
				RequiredCapabilities: clonePublicationCapabilities(plan.RequiredCapabilities), HealthCheck: plan.HealthCheck,
				Deadline: plan.Deadline, IdempotencyKey: request.Metadata.IdempotencyKey,
				RequestID: request.Metadata.RequestID, CorrelationID: request.Metadata.TraceID,
			})
			if err != nil {
				return err
			}
			status, err := coordinator.runtime.Status(ctx, challengepublication.StatusRequest{
				Actor: actor, TenantScopeID: snapshot.TenantScopeID, RolloutID: publication.RolloutID,
			})
			if err != nil {
				return err
			}
			if status.ConfigVersionID != publication.ConfigVersionID || status.Revision != publication.Revision {
				return challengepublication.ErrInvalidRuntime
			}
			if _, err := coordinator.verifier.Verify(ctx, tx, snapshot.TenantScopeID, status.RolloutID,
				status.ConfigVersionID, snapshot.PolicyID, snapshot.Revision); err != nil {
				return err
			}
			result = publicationStatusView(snapshot, status, nil)
			return nil
		})
	return result, err
}

func (coordinator *PublicationCoordinator) Status(ctx context.Context, request PublicationRequest) (PublicationStatus, error) {
	if !validPublicationCommand(request, true) || request.ExpectedRevision != 0 || request.Metadata.IdempotencyKey != "" {
		return PublicationStatus{}, ErrInvalidInput
	}
	var result PublicationStatus
	err := coordinator.policies.ReadPublicationSnapshot(ctx, request.Actor, request.TenantScopeID, request.PolicyID,
		func(ctx context.Context, tx pgx.Tx, snapshot PublicationSnapshot) error {
			actor, err := publicationDeploymentActor(request.Actor)
			if err != nil {
				return err
			}
			status, err := coordinator.runtime.Status(ctx, challengepublication.StatusRequest{
				Actor: actor, TenantScopeID: snapshot.TenantScopeID, RolloutID: request.RolloutID,
			})
			if err != nil {
				return err
			}
			if _, err := coordinator.verifier.Verify(ctx, tx, snapshot.TenantScopeID, status.RolloutID,
				status.ConfigVersionID, snapshot.PolicyID, snapshot.Revision); err != nil {
				return err
			}
			result = publicationStatusView(snapshot, status, nil)
			return nil
		})
	return result, err
}

func (coordinator *PublicationCoordinator) Promote(ctx context.Context, request PublicationRequest) (PublicationStatus, error) {
	if !validPublicationCommand(request, true) || request.ExpectedRevision < 1 || request.Metadata.IdempotencyKey == "" {
		return PublicationStatus{}, ErrInvalidInput
	}
	var result PublicationStatus
	err := coordinator.policies.UsePublicationSnapshot(ctx, request.Actor, request.TenantScopeID, request.PolicyID,
		request.ExpectedRevision, func(ctx context.Context, tx pgx.Tx, snapshot PublicationSnapshot) error {
			actor, edgeActor, err := publicationActors(request.Actor)
			if err != nil {
				return err
			}
			status, err := coordinator.runtime.Status(ctx, challengepublication.StatusRequest{
				Actor: actor, TenantScopeID: snapshot.TenantScopeID, RolloutID: request.RolloutID,
			})
			if err != nil {
				return err
			}
			nodeIDs, err := coordinator.verifier.Verify(ctx, tx, snapshot.TenantScopeID, status.RolloutID,
				status.ConfigVersionID, snapshot.PolicyID, snapshot.Revision)
			if err != nil {
				return err
			}
			plan, err := coordinator.planner.Plan(ctx, tx, snapshot)
			if err != nil {
				return err
			}
			// A planned node the rollout missed has no secret: republish. A
			// rollout node no longer planned (disabled since) is deferred.
			if !containsPublicationNodes(nodeIDs, plan.NodeIDs) {
				return ErrConflict
			}
			readiness, err := coordinator.verifier.Readiness(ctx, tx, snapshot.TenantScopeID, status.RolloutID, plan.NodeIDs)
			if err != nil {
				return err
			}
			promotion, err := coordinator.runtime.Promote(ctx, challengepublication.PromoteRequest{
				PublishRequest: challengepublication.PublishRequest{
					Policy: publicationRuntimeSnapshot(snapshot), Actor: actor, EdgeActor: edgeActor,
					NodeIDs:              slices.Clone(nodeIDs),
					RequiredCapabilities: clonePublicationCapabilities(plan.RequiredCapabilities), HealthCheck: plan.HealthCheck,
					Deadline: plan.Deadline, IdempotencyKey: request.Metadata.IdempotencyKey,
					RequestID: request.Metadata.RequestID, CorrelationID: request.Metadata.TraceID,
				},
				Secret: challengepublication.SecretPublication{RolloutID: status.RolloutID,
					ConfigVersionID: status.ConfigVersionID, Revision: status.Revision},
				Readiness: readiness,
			})
			result = publicationStatusView(snapshot, promotion.RolloutStatus, promotion.ConfigPublication)
			return err
		})
	return result, err
}

func validPublicationCommand(request PublicationRequest, rollout bool) bool {
	return request.Actor.UserID != uuid.Nil && request.Actor.ScopeID != uuid.Nil && request.TenantScopeID != uuid.Nil &&
		request.PolicyID != uuid.Nil && (request.RolloutID != uuid.Nil) == rollout && request.Metadata.RequestID != "" &&
		request.Metadata.TraceID != ""
}

func publicationDeploymentActor(actor Actor) (edgedeployment.Actor, error) {
	if actor.Credential.Kind != CredentialKindSession || actor.Credential.ID == uuid.Nil || actor.rawCredential == "" {
		return edgedeployment.Actor{}, ErrPermissionDenied
	}
	result, err := edgedeployment.NewSessionActor(actor.UserID, actor.ScopeID, actor.ScopeKind,
		actor.Credential.ID, actor.rawCredential)
	if err != nil {
		return edgedeployment.Actor{}, ErrPermissionDenied
	}
	return result, nil
}

func publicationActors(actor Actor) (edgedeployment.Actor, edgepublish.Actor, error) {
	deploymentActor, err := publicationDeploymentActor(actor)
	if err != nil {
		return edgedeployment.Actor{}, edgepublish.Actor{}, err
	}
	edgeActor, err := edgepublish.NewSessionActor(actor.UserID, actor.ScopeID, actor.ScopeKind,
		actor.Credential.ID, actor.rawCredential)
	if err != nil {
		return edgedeployment.Actor{}, edgepublish.Actor{}, ErrPermissionDenied
	}
	return deploymentActor, edgeActor, nil
}

func publicationRuntimeSnapshot(snapshot PublicationSnapshot) challengepublication.PublicationSnapshot {
	result := challengepublication.PublicationSnapshot{
		PolicyID: snapshot.PolicyID, TenantScopeID: snapshot.TenantScopeID, TenantID: snapshot.TenantID,
		SiteID: snapshot.SiteID, Host: snapshot.Host, Revision: snapshot.Revision, Priority: snapshot.Priority,
		Mode: snapshot.Mode, MinDelaySeconds: snapshot.MinDelaySeconds, ChallengeTTLSeconds: snapshot.ChallengeTTLSeconds,
		PassTTLSeconds: snapshot.PassTTLSeconds, ClockSkewSeconds: snapshot.ClockSkewSeconds,
		AttemptsPerNonce: snapshot.AttemptsPerNonce, FailureWindowSeconds: snapshot.FailureWindowSeconds,
		MaxFailuresPerWindow: snapshot.MaxFailuresPerWindow, IPBinding: snapshot.IPBinding,
		BindUserAgent: snapshot.BindUserAgent, KeyReference: snapshot.KeyReference,
	}
	result.BypassRoutes = make([]challengepublication.BypassRoute, len(snapshot.BypassRoutes))
	for index, route := range snapshot.BypassRoutes {
		result.BypassRoutes[index] = challengepublication.BypassRoute{Kind: route.Kind, Path: route.Path}
	}
	if snapshot.ExternalProvider != nil {
		result.ExternalProvider = &challengepublication.ExternalProviderReference{
			Provider: snapshot.ExternalProvider.Provider, AppReference: snapshot.ExternalProvider.AppReference,
		}
	}
	return result
}

func publicationStatusView(snapshot PublicationSnapshot, status challengepublication.RolloutStatus,
	config *challengepublication.ConfigPublication) PublicationStatus {
	reason := status.Reason
	if reason == "" {
		reason = "-"
	}
	return PublicationStatus{
		PolicyID: snapshot.PolicyID, PolicyRevision: snapshot.Revision, RolloutID: status.RolloutID,
		ConfigVersionID: status.ConfigVersionID, State: status.State, Reason: reason, Total: status.Total,
		Pending: status.Pending, Running: status.Running, Healthy: status.Healthy, Failed: status.Failed,
		Cancelled: status.Cancelled, Superseded: status.Superseded, ConfigPublication: config,
	}
}

func clonePublicationCapabilities(values []*agentv1.Capability) []*agentv1.Capability {
	result := make([]*agentv1.Capability, len(values))
	for index, value := range values {
		if value != nil {
			result[index] = proto.Clone(value).(*agentv1.Capability)
		}
	}
	return result
}

// containsPublicationNodes reports whether every node of subset is in nodes.
func containsPublicationNodes(nodes, subset []uuid.UUID) bool {
	for _, nodeID := range subset {
		if !slices.Contains(nodes, nodeID) {
			return false
		}
	}
	return true
}

func equalPublicationNodes(left, right []uuid.UUID) bool {
	left, right = slices.Clone(left), slices.Clone(right)
	slices.SortFunc(left, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	slices.SortFunc(right, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Equal(left, right)
}

type PublicationPlannerConfig struct {
	Clock                        func() time.Time
	ActivationTimeout            time.Duration
	ObservationWindow            time.Duration
	RequiredConsecutiveSuccesses uint32
	Deadline                     time.Duration
}

type PostgresPublicationPlanner struct{ config PublicationPlannerConfig }

func NewPostgresPublicationPlanner(config PublicationPlannerConfig) (*PostgresPublicationPlanner, error) {
	if config.Clock == nil || config.ActivationTimeout <= 0 || config.ObservationWindow <= 0 ||
		config.RequiredConsecutiveSuccesses == 0 || config.Deadline <= config.ActivationTimeout+config.ObservationWindow {
		return nil, ErrInvalidInput
	}
	return &PostgresPublicationPlanner{config: config}, nil
}

func (planner *PostgresPublicationPlanner) Plan(ctx context.Context, tx pgx.Tx, snapshot PublicationSnapshot) (PublicationPlan, error) {
	if planner == nil || ctx == nil || tx == nil || snapshot.TenantScopeID == uuid.Nil {
		return PublicationPlan{}, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, `
		SELECT id FROM nodes
		WHERE scope_id=$1 AND admin_state='active'
		ORDER BY id
		FOR SHARE`, snapshot.TenantScopeID)
	if err != nil {
		return PublicationPlan{}, ErrUnavailable
	}
	defer rows.Close()
	var nodeIDs []uuid.UUID
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil || nodeID == uuid.Nil {
			return PublicationPlan{}, ErrUnavailable
		}
		nodeIDs = append(nodeIDs, nodeID)
	}
	if rows.Err() != nil || len(nodeIDs) == 0 || len(nodeIDs) > 10000 {
		return PublicationPlan{}, ErrUnavailable
	}
	return PublicationPlan{
		NodeIDs: nodeIDs,
		RequiredCapabilities: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
		},
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: planner.config.ActivationTimeout, ObservationWindow: planner.config.ObservationWindow,
			RequiredConsecutiveSuccesses: planner.config.RequiredConsecutiveSuccesses,
		},
		Deadline: planner.config.Clock().UTC().Add(planner.config.Deadline),
	}, nil
}

type PostgresPublicationIdentityVerifier struct{}

func (PostgresPublicationIdentityVerifier) Verify(ctx context.Context, tx pgx.Tx, tenantScopeID, rolloutID,
	configVersionID, policyID uuid.UUID, policyRevision int64) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil || tenantScopeID == uuid.Nil || rolloutID == uuid.Nil || configVersionID == uuid.Nil ||
		policyID == uuid.Nil || policyRevision < 1 {
		return nil, ErrInvalidInput
	}
	var snapshot, digest []byte
	var generator, status string
	err := tx.QueryRow(ctx, `
		SELECT version.canonical_snapshot,version.canonical_snapshot_sha256,version.generator_name,version.status
		FROM rollouts rollout
		JOIN config_versions version ON version.configuration_scope_id=rollout.configuration_scope_id
		 AND version.id=rollout.config_version_id
		WHERE rollout.configuration_scope_id=$1 AND rollout.id=$2 AND rollout.config_version_id=$3
		FOR SHARE OF rollout,version`, tenantScopeID, rolloutID, configVersionID).Scan(&snapshot, &digest, &generator, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	wantDigest := sha256.Sum256(snapshot)
	if len(digest) != sha256.Size || !bytes.Equal(digest, wantDigest[:]) ||
		generator != "cdnca-challengepublication" || (status != "releasable" && status != "superseded") {
		return nil, ErrNotFound
	}
	var policy challengepublication.Policy
	decoder := json.NewDecoder(bytes.NewReader(snapshot))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		policy.SchemaVersion != challengepublication.PolicySchemaVersion ||
		policy.PolicyVersion != uint64(policyRevision) || len(policy.Rules) != 1 || policy.Rules[0].RuleID != policyID.String() {
		return nil, ErrNotFound
	}
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT node_id FROM node_deployments
		WHERE rollout_id=$1 AND config_version_id=$2
		ORDER BY node_id`, rolloutID, configVersionID)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var nodeIDs []uuid.UUID
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil || nodeID == uuid.Nil {
			return nil, ErrUnavailable
		}
		nodeIDs = append(nodeIDs, nodeID)
	}
	if rows.Err() != nil || len(nodeIDs) == 0 || len(nodeIDs) > 10000 {
		return nil, ErrNotFound
	}
	return nodeIDs, nil
}

// Readiness reads, for each node of the rollout, its latest deployment and
// whether the node is active, online and isolated now, and classifies them
// (challengepublication.ClassifyPromotionNodes).
func (PostgresPublicationIdentityVerifier) Readiness(ctx context.Context, tx pgx.Tx, tenantScopeID, rolloutID uuid.UUID,
	planned []uuid.UUID) (challengepublication.NodeReadiness, error) {
	if ctx == nil || tx == nil || tenantScopeID == uuid.Nil || rolloutID == uuid.Nil {
		return challengepublication.NodeReadiness{}, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (deployment.node_id) deployment.node_id,deployment.state,
			`+edgedeployment.SupersededDeploymentSQL+`,deployment.deadline_at<=clock_timestamp(),node.admin_state='active',
			EXISTS(SELECT 1 FROM node_presence presence WHERE presence.node_id=node.id AND presence.status='online'),
			EXISTS(SELECT 1 FROM node_isolation_states isolation WHERE isolation.node_id=node.id AND isolation.status='isolated')
		FROM rollouts rollout
		JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
		JOIN nodes node ON node.id=deployment.node_id
		WHERE rollout.configuration_scope_id=$1 AND rollout.id=$2
		ORDER BY deployment.node_id,deployment.attempt DESC`, tenantScopeID, rolloutID)
	if err != nil {
		return challengepublication.NodeReadiness{}, ErrUnavailable
	}
	facts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (challengepublication.PromotionNodeFact, error) {
		var fact challengepublication.PromotionNodeFact
		err := row.Scan(&fact.NodeID, &fact.DeploymentState, &fact.Superseded, &fact.DeadlinePassed, &fact.Active, &fact.Online, &fact.Isolated)
		return fact, err
	})
	if err != nil {
		return challengepublication.NodeReadiness{}, ErrUnavailable
	}
	if len(facts) == 0 || len(facts) > 10000 {
		return challengepublication.NodeReadiness{}, ErrNotFound
	}
	return challengepublication.ClassifyPromotionNodes(facts, planned), nil
}

var _ PublicationDomain = (*PublicationCoordinator)(nil)
var _ PublicationPlanner = (*PostgresPublicationPlanner)(nil)
var _ PublicationIdentityVerifier = PostgresPublicationIdentityVerifier{}
