package certificatepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

const (
	PublicationSnapshotSchema = "cdnca.edge.certificate-publication/v1"
	defaultGeneratorName      = "cdnca-certificatepublish"
	defaultGeneratorVersion   = "1.0.0"

	// auditPublicationPublish: a certificate publication rollout was created.
	auditPublicationPublish               = "certificate.publication.publish"
	certificatePublicationRecoverAction   = "certificate.publication.recover"
	certificatePublicationUnpublishAction = "certificate.publication.unpublish"
	partialFailureRecoveryReason          = "partial_failure_recovery"
	bindingRemovedReason                  = "binding_removed"
)

type publicationMaterialStore interface {
	UsePublicationMaterialsInTx(
		context.Context,
		pgx.Tx,
		certificateasset.PublicationRequest,
		certificateasset.PublicationConsumer,
	) error
}

type secretDeploymentStore interface {
	CreateCertificateSecretRolloutFromSourceTx(
		context.Context,
		pgx.Tx,
		edgedeployment.SecretRolloutRequest,
		edgedeployment.CertificateActorReference,
		[sha256.Size]byte,
		edgedeployment.CertificateSecretRolloutSource,
	) (edgedeployment.CreateRolloutResult, error)
	ReplaceSecretRollout(
		context.Context,
		edgedeployment.SecretReplacementRequest,
		edgedeployment.SecretReplacementSource,
	) (edgedeployment.SecretReplacementResult, error)
}

type secretDeploymentReceiptStore interface {
	ResolveCertificatePublicationReceipt(
		context.Context,
		edgedeployment.CertificatePublicationReceiptRequest,
	) (edgedeployment.CertificatePublicationReceipt, error)
}

type PublicationConfig struct {
	GeneratorName    string
	GeneratorVersion string
	OpaqueResolver   certificateasset.OpaquePublicationResolver
}

func DefaultPublicationConfig() PublicationConfig {
	return PublicationConfig{
		GeneratorName: defaultGeneratorName, GeneratorVersion: defaultGeneratorVersion,
	}
}

type PublicationService struct {
	pool        *pgxpool.Pool
	materials   publicationMaterialStore
	deployments secretDeploymentStore
	producer    *Producer
	config      PublicationConfig
}

type PublicationRequest struct {
	Actor                edgedeployment.Actor
	TenantScopeID        uuid.UUID
	SiteIDs              []uuid.UUID
	NodeIDs              []uuid.UUID
	AssetID              uuid.UUID
	VersionID            uuid.UUID
	BindingRevision      int64
	RequiredCapabilities []*agentv1.Capability
	HealthCheck          edgedeployment.HealthCheckPolicy
	Deadline             time.Time
	IdempotencyKey       string
	RequestID            string
	CorrelationID        string
	Traceparent          string
	TaskID               *string
	ActorUserRevision    int64
	TargetTenantID       uuid.UUID
	TargetTenantRevision int64
}

type RetryPublicationRequest struct {
	PublicationRequest
	OriginalRolloutID uuid.UUID
	ExpectedRevision  int64
}

type RecoverPartialRequest struct {
	PublicationRequest
	SourceRolloutID        uuid.UUID
	ExpectedSourceRevision int64
}

type UnpublishRequest struct {
	PublicationRequest
	SourceRolloutID        uuid.UUID
	ExpectedSourceRevision int64
	RemovedSiteIDs         []uuid.UUID
}

type LifecycleResult struct {
	SourceRolloutID uuid.UUID
	SourceRevision  int64
	Rollout         edgedeployment.Rollout
	Replayed        bool
}

func NewPublicationService(
	pool *pgxpool.Pool,
	materials publicationMaterialStore,
	deployments secretDeploymentStore,
	producer *Producer,
	config PublicationConfig,
) (*PublicationService, error) {
	if pool == nil || nilPublicationDependency(materials) || nilPublicationDependency(deployments) ||
		producer == nil || !validIdentifier(config.GeneratorName) || !validIdentifier(config.GeneratorVersion) {
		return nil, ErrInvalidInput
	}
	return &PublicationService{
		pool: pool, materials: materials, deployments: deployments, producer: producer, config: config,
	}, nil
}

func (s *PublicationService) Publish(
	ctx context.Context,
	request PublicationRequest,
) (edgedeployment.CreateRolloutResult, error) {
	if s == nil || ctx == nil {
		return edgedeployment.CreateRolloutResult{}, ErrInvalidInput
	}
	siteIDs, err := normalizeLifecycleUUIDs(request.SiteIDs, false)
	if err != nil {
		return edgedeployment.CreateRolloutResult{}, err
	}
	domainDigest := publicationDomainRequestDigest(
		"certificate.publication.publish", request.TenantScopeID, siteIDs, uuid.Nil, 0, nil,
	)
	var result edgedeployment.CreateRolloutResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var createErr error
		result, createErr = s.createSecretRolloutFromSourceTx(
			ctx, tx, request, domainDigest,
			func(ctx context.Context, tx pgx.Tx) (edgedeployment.SecretRolloutMaterial, error) {
				snapshot, sourceErr := s.loadPublicationSnapshot(ctx, tx, request, siteIDs)
				if sourceErr != nil {
					return edgedeployment.SecretRolloutMaterial{}, sourceErr
				}
				return edgedeployment.SecretRolloutMaterial{
					CanonicalSnapshot: snapshot,
					PayloadDigest:     sha256.Sum256(snapshot),
					Builder:           s.publicationArtifactBuilder(tx, request, siteIDs),
				}, nil
			},
		)
		if createErr != nil || result.Replayed {
			return createErr
		}
		return s.auditPublish(ctx, tx, request, siteIDs, result.Rollout)
	})
	if err != nil {
		return edgedeployment.CreateRolloutResult{}, err
	}
	return result, nil
}

// auditPublish records a new publication rollout (a replay records nothing).
func (s *PublicationService) auditPublish(
	ctx context.Context,
	tx pgx.Tx,
	request PublicationRequest,
	siteIDs []uuid.UUID,
	rollout edgedeployment.Rollout,
) error {
	actorUserID := request.Actor.UserID
	nodeIDs := make([]string, len(rollout.Deployments))
	for index, deployment := range rollout.Deployments {
		nodeIDs[index] = deployment.NodeID.String()
	}
	payload := map[string]any{
		"actor_scope_id": request.Actor.ScopeID.String(), "target_scope_id": request.TenantScopeID.String(),
		"operation": auditPublicationPublish, "site_ids": lifecycleUUIDStrings(siteIDs), "node_ids": nodeIDs,
		"asset_id": request.AssetID.String(), "version_id": request.VersionID.String(),
		"binding_revision":  request.BindingRevision,
		"result_rollout_id": rollout.ID.String(), "result_rollout_revision": rollout.Revision,
	}
	if ip := audit.SourceIPFrom(ctx); ip != "" {
		payload["ip"] = ip
	}
	if err := audit.New(s.pool).Append(ctx, tx, audit.Event{
		ScopeID: request.TenantScopeID, ActorUserID: &actorUserID,
		Action: auditPublicationPublish, ResourceType: "certificate_publication", ResourceID: rollout.ID.String(),
		RequestID: request.RequestID, Result: "success", Payload: payload,
	}); err != nil {
		return fmt.Errorf("audit certificate publication: %w", err)
	}
	return nil
}

func (s *PublicationService) ResolvePublicationReceipt(
	ctx context.Context,
	request PublicationRequest,
	rollout edgedeployment.Rollout,
) (edgedeployment.CertificatePublicationReceipt, error) {
	if s == nil || ctx == nil || request.TenantScopeID == uuid.Nil ||
		request.Actor.UserID == uuid.Nil || request.Actor.ScopeID == uuid.Nil ||
		request.Actor.SessionID == uuid.Nil || request.ActorUserRevision < 1 ||
		request.TargetTenantID == uuid.Nil || request.TargetTenantRevision < 1 ||
		rollout.ID == uuid.Nil || rollout.ConfigurationScopeID != request.TenantScopeID ||
		rollout.ConfigVersionID == uuid.Nil || rollout.Revision < 1 {
		return edgedeployment.CertificatePublicationReceipt{}, ErrInvalidInput
	}
	resolver, ok := s.deployments.(secretDeploymentReceiptStore)
	if !ok || resolver == nil || nilPublicationDependency(resolver) {
		return edgedeployment.CertificatePublicationReceipt{}, edgedeployment.ErrUnavailable
	}
	return resolver.ResolveCertificatePublicationReceipt(ctx, edgedeployment.CertificatePublicationReceiptRequest{
		Actor: request.Actor, ConfigurationScopeID: request.TenantScopeID,
		ActorReference: edgedeployment.CertificateActorReference{
			UserRevision: request.ActorUserRevision, TargetTenantID: request.TargetTenantID,
			TargetTenantRevision: request.TargetTenantRevision,
		},
		RolloutID: rollout.ID, ConfigVersionID: rollout.ConfigVersionID,
		RolloutRevision: rollout.Revision,
	})
}

func (s *PublicationService) createSecretRolloutFromSourceTx(
	ctx context.Context,
	tx pgx.Tx,
	request PublicationRequest,
	domainRequestDigest [sha256.Size]byte,
	source edgedeployment.CertificateSecretRolloutSource,
) (edgedeployment.CreateRolloutResult, error) {
	reference := edgedeployment.CertificateActorReference{
		UserRevision: request.ActorUserRevision, TargetTenantID: request.TargetTenantID,
		TargetTenantRevision: request.TargetTenantRevision,
	}
	if request.ActorUserRevision < 1 || request.TargetTenantID == uuid.Nil || request.TargetTenantRevision < 1 {
		return edgedeployment.CreateRolloutResult{}, edgedeployment.ErrInvalidInput
	}
	return s.deployments.CreateCertificateSecretRolloutFromSourceTx(
		ctx, tx, s.publicationSecretRolloutRequest(request), reference,
		domainRequestDigest, source,
	)
}

func (s *PublicationService) publicationSecretRolloutRequest(request PublicationRequest) edgedeployment.SecretRolloutRequest {
	return edgedeployment.SecretRolloutRequest{
		Actor: request.Actor, ConfigurationScopeID: request.TenantScopeID,
		NodeIDs: request.NodeIDs, GeneratorName: s.config.GeneratorName, GeneratorVersion: s.config.GeneratorVersion,
		RequiredCapabilities: request.RequiredCapabilities, HealthCheck: request.HealthCheck, Deadline: request.Deadline,
		IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
		CorrelationID: request.CorrelationID, Traceparent: request.Traceparent, TaskID: request.TaskID,
	}
}

func (s *PublicationService) ResolveCertificateUnpublishSource(
	ctx context.Context,
	command certificateasset.CertificatePublicationCommandV1,
) (certificateUnpublishSource, error) {
	if s == nil || s.pool == nil || ctx == nil || command.TenantScopeID == uuid.Nil ||
		command.SiteID == uuid.Nil || command.BindingRevision < 1 {
		return certificateUnpublishSource{}, ErrInvalidInput
	}
	var source certificateUnpublishSource
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT latest.rollout_id,latest.rollout_revision
			FROM certificate_publication_intents intent
			JOIN LATERAL (
				SELECT state,rollout_id,rollout_revision
				FROM certificate_publication_intent_state_facts state
				WHERE state.tenant_scope_id=intent.tenant_scope_id AND state.site_id=intent.site_id
				  AND state.binding_revision=intent.binding_revision
				ORDER BY sequence DESC LIMIT 1
			) latest ON true
			WHERE intent.tenant_scope_id=$1 AND intent.site_id=$2 AND intent.operation='publish'
			  AND intent.binding_revision<$3 AND latest.state='succeeded'
			ORDER BY intent.binding_revision DESC LIMIT 1`, command.TenantScopeID, command.SiteID,
			command.BindingRevision).Scan(&source.RolloutID, &source.Revision); errors.Is(err, pgx.ErrNoRows) {
			return edgedeployment.ErrNotFound
		} else if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT node_id FROM node_deployments
			WHERE rollout_id=$1 AND attempt=1 ORDER BY node_id`, source.RolloutID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var nodeID uuid.UUID
			if err := rows.Scan(&nodeID); err != nil {
				return err
			}
			if nodeID == uuid.Nil {
				return edgedeployment.ErrUnavailable
			}
			source.NodeIDs = append(source.NodeIDs, nodeID)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if source.RolloutID == uuid.Nil || source.Revision < 1 || len(source.NodeIDs) == 0 {
			return edgedeployment.ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return certificateUnpublishSource{}, err
	}
	return source, nil
}

func (s *PublicationService) loadPublicationSnapshot(
	ctx context.Context,
	tx pgx.Tx,
	request PublicationRequest,
	siteIDs []uuid.UUID,
) ([]byte, error) {
	var snapshot []byte
	err := s.materials.UsePublicationMaterialsInTx(ctx, tx, certificateasset.PublicationRequest{
		TenantScopeID: request.TenantScopeID, SiteIDs: siteIDs, AssetID: request.AssetID,
		VersionID: request.VersionID, BindingRevision: request.BindingRevision,
		OpaqueResolver: s.config.OpaqueResolver,
	}, func(materials []certificateasset.PublicationMaterial) error {
		var err error
		snapshot, err = buildPublicationSnapshot(request.TenantScopeID, materials)
		return err
	})
	return snapshot, err
}

func (s *PublicationService) publicationArtifactBuilder(
	tx pgx.Tx,
	request PublicationRequest,
	siteIDs []uuid.UUID,
) edgedeployment.SecretArtifactBuilder {
	return func(ctx context.Context, binding edgedeployment.SecretArtifactBinding) (edgedeployment.ArtifactInput, error) {
		var artifact edgedeployment.ArtifactInput
		err := s.materials.UsePublicationMaterialsInTx(ctx, tx, certificateasset.PublicationRequest{
			TenantScopeID: request.TenantScopeID, SiteIDs: siteIDs, AssetID: request.AssetID,
			VersionID: request.VersionID, BindingRevision: request.BindingRevision,
			OpaqueResolver: s.config.OpaqueResolver,
		}, func(materials []certificateasset.PublicationMaterial) error {
			var err error
			artifact, err = s.producer.Build(ctx, BuildRequest{
				EventID: binding.EventID, DeploymentID: binding.DeploymentID, Attempt: binding.Attempt,
				ConfigVersionID: binding.ConfigVersionID, ArtifactID: binding.ArtifactID,
				RecipientKeyID: binding.RecipientKeyID, RecipientPublicKey: binding.RecipientPublicKey,
				Materials: materials,
			})
			return err
		})
		return artifact, err
	}
}

func (s *PublicationService) RetryPublication(
	ctx context.Context,
	request RetryPublicationRequest,
) (edgedeployment.SecretReplacementResult, error) {
	if s == nil || ctx == nil {
		return edgedeployment.SecretReplacementResult{}, ErrInvalidInput
	}
	result, err := s.deployments.ReplaceSecretRollout(ctx, edgedeployment.SecretReplacementRequest{
		Actor: request.Actor, ConfigurationScopeID: request.TenantScopeID,
		NodeIDs: request.NodeIDs, OriginalRolloutID: request.OriginalRolloutID,
		ExpectedRevision: request.ExpectedRevision,
		GeneratorName:    s.config.GeneratorName, GeneratorVersion: s.config.GeneratorVersion,
		RequiredCapabilities: request.RequiredCapabilities,
		HealthCheck:          request.HealthCheck, Deadline: request.Deadline,
		IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
		CorrelationID: request.CorrelationID, Traceparent: request.Traceparent,
		TaskID: request.TaskID,
	}, func(ctx context.Context, tx pgx.Tx, consume edgedeployment.SecretReplacementConsume) error {
		return s.materials.UsePublicationMaterialsInTx(ctx, tx, certificateasset.PublicationRequest{
			TenantScopeID: request.TenantScopeID, SiteIDs: request.SiteIDs,
			AssetID: request.AssetID, VersionID: request.VersionID, BindingRevision: request.BindingRevision,
			OpaqueResolver: s.config.OpaqueResolver,
		}, func(materials []certificateasset.PublicationMaterial) error {
			snapshot, err := buildPublicationSnapshot(request.TenantScopeID, materials)
			if err != nil {
				return err
			}
			return consume(edgedeployment.SecretReplacementMaterial{
				CanonicalSnapshot: snapshot, PayloadDigest: sha256.Sum256(snapshot),
			}, func(ctx context.Context, bindings []edgedeployment.SecretArtifactBinding) ([]edgedeployment.ArtifactInput, error) {
				artifacts := make([]edgedeployment.ArtifactInput, len(bindings))
				for index, binding := range bindings {
					artifact, err := s.producer.Build(ctx, BuildRequest{
						EventID: binding.EventID, DeploymentID: binding.DeploymentID, Attempt: binding.Attempt,
						ConfigVersionID: binding.ConfigVersionID, ArtifactID: binding.ArtifactID,
						RecipientKeyID:     binding.RecipientKeyID,
						RecipientPublicKey: binding.RecipientPublicKey,
						Materials:          materials,
					})
					if err != nil {
						return nil, err
					}
					artifacts[index] = artifact
				}
				return artifacts, nil
			})
		})
	})
	if err != nil {
		return edgedeployment.SecretReplacementResult{}, err
	}
	if !validRetryPublicationResult(request, result) {
		return edgedeployment.SecretReplacementResult{}, edgedeployment.ErrUnavailable
	}
	return result, nil
}

func validRetryPublicationResult(request RetryPublicationRequest, result edgedeployment.SecretReplacementResult) bool {
	nodeIDs, err := normalizeLifecycleUUIDs(request.NodeIDs, false)
	rollout := result.Rollout
	if err != nil || request.TenantScopeID == uuid.Nil || request.OriginalRolloutID == uuid.Nil ||
		request.ExpectedRevision <= 0 || result.OriginalRolloutID != request.OriginalRolloutID ||
		result.OriginalRevision <= 0 || result.OriginalRevision-1 != request.ExpectedRevision ||
		rollout.ID == uuid.Nil || rollout.ConfigurationScopeID != request.TenantScopeID ||
		rollout.ConfigVersionID == uuid.Nil || rollout.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY ||
		rollout.Revision != 1 || rollout.MaxAttempts != 1 || rollout.CreatedAt.IsZero() ||
		rollout.QueuedAt.IsZero() || rollout.QueuedAt.Before(rollout.CreatedAt) ||
		len(rollout.Deployments) != len(nodeIDs) {
		return false
	}
	expectedNodes := make(map[uuid.UUID]struct{}, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		expectedNodes[nodeID] = struct{}{}
	}
	for _, deployment := range rollout.Deployments {
		command := deployment.Command
		if deployment.ID == uuid.Nil || deployment.NodeID == uuid.Nil || deployment.Subject == "" || command == nil ||
			command.DeploymentId != deployment.ID.String() || command.Attempt != 1 ||
			command.ConfigVersionId != rollout.ConfigVersionID.String() ||
			command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY || len(command.Artifacts) != 1 ||
			command.Artifacts[0] == nil || command.Artifacts[0].Kind != agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE ||
			len(command.Artifacts[0].Sha256) != sha256.Size || command.DeadlineTime == nil ||
			command.DeadlineTime.CheckValid() != nil || !command.DeadlineTime.AsTime().After(rollout.QueuedAt) {
			return false
		}
		if _, found := expectedNodes[deployment.NodeID]; !found {
			return false
		}
		delete(expectedNodes, deployment.NodeID)
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
		if err != nil || !bytes.Equal(encoded, deployment.CommandBytes) {
			return false
		}
	}
	return len(expectedNodes) == 0
}

func (s *PublicationService) RecoverPartial(
	ctx context.Context,
	request RecoverPartialRequest,
) (LifecycleResult, error) {
	if s == nil || ctx == nil || request.SourceRolloutID == uuid.Nil || request.ExpectedSourceRevision <= 0 {
		return LifecycleResult{}, ErrInvalidInput
	}
	requestedSites, err := normalizeLifecycleUUIDs(request.SiteIDs, false)
	if err != nil {
		return LifecycleResult{}, err
	}
	domainDigest := publicationDomainRequestDigest(certificatePublicationRecoverAction,
		request.TenantScopeID, requestedSites, request.SourceRolloutID, request.ExpectedSourceRevision, nil)
	var result LifecycleResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var source lifecycleSource
		created, createErr := s.createSecretRolloutFromSourceTx(
			ctx, tx, request.PublicationRequest, domainDigest,
			func(ctx context.Context, tx pgx.Tx) (edgedeployment.SecretRolloutMaterial, error) {
				var sourceErr error
				source, sourceErr = s.loadLifecycleSource(ctx, tx, request.TenantScopeID, request.SourceRolloutID)
				if sourceErr != nil {
					return edgedeployment.SecretRolloutMaterial{}, sourceErr
				}
				if source.revision != request.ExpectedSourceRevision {
					return edgedeployment.SecretRolloutMaterial{}, edgedeployment.ErrRevisionConflict
				}
				// The sites the source sent: an unpublication sent its removal,
				// not the sites that remain.
				if !equalLifecycleUUIDs(requestedSites, source.sentSiteIDs()) {
					return edgedeployment.SecretRolloutMaterial{}, edgedeployment.ErrInvalidInput
				}
				failedNodes, partial := source.partialFailureNodes()
				requestedNodes, normalizeErr := normalizeLifecycleUUIDs(request.NodeIDs, false)
				if normalizeErr != nil || !partial || !equalLifecycleUUIDs(requestedNodes, failedNodes) {
					return edgedeployment.SecretRolloutMaterial{}, edgedeployment.ErrInvalidInput
				}
				if len(source.removed) != 0 {
					// Each site must still be unbound at the recorded unbind: a
					// site bound again since is the newer publication's.
					removed, sourceErr := lockUnboundLifecycleSites(ctx, tx, request.TenantScopeID, requestedSites)
					if sourceErr != nil {
						return edgedeployment.SecretRolloutMaterial{}, sourceErr
					}
					if !reflect.DeepEqual(removed, source.removed) {
						return edgedeployment.SecretRolloutMaterial{}, edgedeployment.ErrRevisionConflict
					}
					return edgedeployment.SecretRolloutMaterial{
						CanonicalSnapshot: source.snapshot, PayloadDigest: sha256.Sum256(source.snapshot),
						Builder: s.removalArtifactBuilder(request.TenantScopeID, removed),
					}, nil
				}
				snapshot, sourceErr := s.loadPublicationSnapshot(ctx, tx, request.PublicationRequest, requestedSites)
				if sourceErr != nil {
					return edgedeployment.SecretRolloutMaterial{}, sourceErr
				}
				if !bytes.Equal(snapshot, source.snapshot) {
					return edgedeployment.SecretRolloutMaterial{}, edgedeployment.ErrRevisionConflict
				}
				return edgedeployment.SecretRolloutMaterial{
					CanonicalSnapshot: snapshot, PayloadDigest: sha256.Sum256(snapshot),
					Builder: s.publicationArtifactBuilder(tx, request.PublicationRequest, requestedSites),
				}, nil
			},
		)
		if createErr != nil {
			return createErr
		}
		result, createErr = s.createLifecycleRollout(ctx, tx, request.PublicationRequest, source,
			request.SourceRolloutID, request.ExpectedSourceRevision, created,
			certificatePublicationRecoverAction, partialFailureRecoveryReason, requestedSites)
		return createErr
	})
	if err != nil {
		return LifecycleResult{}, err
	}
	return result, nil
}

func (s *PublicationService) Unpublish(
	ctx context.Context,
	request UnpublishRequest,
) (LifecycleResult, error) {
	if s == nil || ctx == nil || request.SourceRolloutID == uuid.Nil || request.ExpectedSourceRevision <= 0 ||
		len(request.SiteIDs) != 0 {
		return LifecycleResult{}, ErrInvalidInput
	}
	removedSites, err := normalizeLifecycleUUIDs(request.RemovedSiteIDs, false)
	if err != nil {
		return LifecycleResult{}, err
	}
	domainDigest := publicationDomainRequestDigest(certificatePublicationUnpublishAction,
		request.TenantScopeID, nil, request.SourceRolloutID, request.ExpectedSourceRevision, removedSites)
	var result LifecycleResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var source lifecycleSource
		created, createErr := s.createSecretRolloutFromSourceTx(
			ctx, tx, request.PublicationRequest, domainDigest,
			func(ctx context.Context, tx pgx.Tx) (edgedeployment.SecretRolloutMaterial, error) {
				var sourceErr error
				source, sourceErr = s.loadLifecycleSource(ctx, tx, request.TenantScopeID, request.SourceRolloutID)
				if sourceErr != nil {
					return edgedeployment.SecretRolloutMaterial{}, sourceErr
				}
				if source.revision != request.ExpectedSourceRevision {
					return edgedeployment.SecretRolloutMaterial{}, edgedeployment.ErrRevisionConflict
				}
				if !source.terminal() {
					return edgedeployment.SecretRolloutMaterial{}, edgedeployment.ErrUnavailable
				}
				requestedNodes, normalizeErr := normalizeLifecycleUUIDs(request.NodeIDs, false)
				if normalizeErr != nil || !equalLifecycleUUIDs(requestedNodes, source.nodeIDs) ||
					!lifecycleUUIDSubset(removedSites, source.siteIDs) {
					return edgedeployment.SecretRolloutMaterial{}, edgedeployment.ErrInvalidInput
				}
				removed, sourceErr := lockUnboundLifecycleSites(ctx, tx, request.TenantScopeID, removedSites)
				if sourceErr != nil {
					return edgedeployment.SecretRolloutMaterial{}, sourceErr
				}
				// The nodes keep every site they were given: the command names
				// only the removed sites (binding revision of their unbind).
				// The rollout's snapshot still lists the sites that remain.
				remainingSites := subtractLifecycleUUIDs(source.siteIDs, removedSites)
				var snapshot []byte
				if len(remainingSites) == 0 {
					snapshot, sourceErr = buildRemovalSnapshot(request.TenantScopeID)
				} else {
					snapshot, sourceErr = s.loadPublicationSnapshot(ctx, tx, request.PublicationRequest, remainingSites)
				}
				if sourceErr == nil {
					snapshot, sourceErr = withRemovedSites(snapshot, removed)
				}
				if sourceErr != nil {
					return edgedeployment.SecretRolloutMaterial{}, sourceErr
				}
				return edgedeployment.SecretRolloutMaterial{
					CanonicalSnapshot: snapshot, PayloadDigest: sha256.Sum256(snapshot),
					Builder: s.removalArtifactBuilder(request.TenantScopeID, removed),
				}, nil
			},
		)
		if createErr != nil {
			return createErr
		}
		result, createErr = s.createLifecycleRollout(ctx, tx, request.PublicationRequest, source,
			request.SourceRolloutID, request.ExpectedSourceRevision, created,
			certificatePublicationUnpublishAction, bindingRemovedReason, removedSites)
		return createErr
	})
	if err != nil {
		return LifecycleResult{}, err
	}
	return result, nil
}

// removalArtifactBuilder builds each node's removal command artifact.
func (s *PublicationService) removalArtifactBuilder(tenantScopeID uuid.UUID, removed []RemovedSite) edgedeployment.SecretArtifactBuilder {
	return func(ctx context.Context, binding edgedeployment.SecretArtifactBinding) (edgedeployment.ArtifactInput, error) {
		return s.producer.BuildRemoval(ctx, RemovalBuildRequest{
			EventID: binding.EventID, DeploymentID: binding.DeploymentID, Attempt: binding.Attempt,
			ConfigVersionID: binding.ConfigVersionID, ArtifactID: binding.ArtifactID,
			RecipientKeyID: binding.RecipientKeyID, RecipientPublicKey: binding.RecipientPublicKey,
			TenantScopeID: tenantScopeID, RemovedSites: removed,
		})
	}
}

type lifecycleSource struct {
	rolloutID uuid.UUID
	configID  uuid.UUID
	revision  int64
	snapshot  []byte
	siteIDs   []uuid.UUID
	// removed is an unpublication's removal; siteIDs are then the sites
	// that remain, which it did not send.
	removed []RemovedSite
	nodeIDs []uuid.UUID
	states  []string
}

// sentSiteIDs are the sites the rollout's command named.
func (source lifecycleSource) sentSiteIDs() []uuid.UUID {
	if len(source.removed) == 0 {
		return source.siteIDs
	}
	sites := make([]uuid.UUID, len(source.removed))
	for index, site := range source.removed {
		sites[index] = site.SiteID
	}
	return sites
}

func (s *PublicationService) loadLifecycleSource(
	ctx context.Context,
	tx pgx.Tx,
	tenantScopeID, rolloutID uuid.UUID,
) (lifecycleSource, error) {
	if tenantScopeID == uuid.Nil || rolloutID == uuid.Nil {
		return lifecycleSource{}, ErrInvalidInput
	}
	source := lifecycleSource{rolloutID: rolloutID}
	var action, status string
	var maxAttempts int
	err := tx.QueryRow(ctx, `SELECT config_version_id,action,status,revision,max_attempts
		FROM rollouts WHERE configuration_scope_id=$1 AND id=$2 FOR UPDATE`, tenantScopeID, rolloutID).Scan(
		&source.configID, &action, &status, &source.revision, &maxAttempts,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return lifecycleSource{}, edgedeployment.ErrNotFound
	}
	if err != nil {
		return lifecycleSource{}, fmt.Errorf("lock certificate publication rollout: %w", err)
	}
	if action != "apply" || status != "queued" || maxAttempts != 1 || source.revision <= 0 {
		return lifecycleSource{}, edgedeployment.ErrUnavailable
	}
	var generatorName, generatorVersion string
	if err := tx.QueryRow(ctx, `SELECT canonical_snapshot,generator_name,generator_version
		FROM config_versions WHERE configuration_scope_id=$1 AND id=$2 FOR SHARE`,
		tenantScopeID, source.configID).Scan(&source.snapshot, &generatorName, &generatorVersion); err != nil {
		return lifecycleSource{}, fmt.Errorf("lock certificate publication config: %w", err)
	}
	if generatorName != s.config.GeneratorName || generatorVersion != s.config.GeneratorVersion {
		return lifecycleSource{}, edgedeployment.ErrUnavailable
	}
	source.siteIDs, source.removed, err = parsePublicationSnapshot(tenantScopeID, source.snapshot)
	if err != nil {
		return lifecycleSource{}, edgedeployment.ErrUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT deployment.node_id,deployment.attempt,
		deployment.config_version_id,deployment.action,deployment.state
		FROM node_deployments deployment
		WHERE deployment.rollout_id=$1 AND NOT EXISTS(
			SELECT 1 FROM node_deployments newer
			WHERE newer.id=deployment.id AND newer.attempt>deployment.attempt
		)
		ORDER BY deployment.node_id FOR UPDATE OF deployment`, rolloutID)
	if err != nil {
		return lifecycleSource{}, fmt.Errorf("lock certificate publication deployments: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID, configID uuid.UUID
		var attempt int
		var deploymentAction, state string
		if err := rows.Scan(&nodeID, &attempt, &configID, &deploymentAction, &state); err != nil {
			return lifecycleSource{}, fmt.Errorf("scan certificate publication deployment: %w", err)
		}
		if nodeID == uuid.Nil || attempt != 1 || configID != source.configID || deploymentAction != "apply" {
			return lifecycleSource{}, edgedeployment.ErrUnavailable
		}
		source.nodeIDs = append(source.nodeIDs, nodeID)
		source.states = append(source.states, state)
	}
	if err := rows.Err(); err != nil {
		return lifecycleSource{}, fmt.Errorf("iterate certificate publication deployments: %w", err)
	}
	if len(source.nodeIDs) == 0 {
		return lifecycleSource{}, edgedeployment.ErrUnavailable
	}
	var totalArtifacts, secretArtifacts int
	if err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(
		WHERE kind='node_secret_bundle' AND encryption_algorithm='hpke_x25519_hkdf_sha256_aes_256_gcm'
		AND recipient_key_id IS NOT NULL) FROM configuration_artifacts WHERE config_version_id=$1`, source.configID).Scan(
		&totalArtifacts, &secretArtifacts,
	); err != nil {
		return lifecycleSource{}, fmt.Errorf("verify certificate publication artifacts: %w", err)
	}
	if totalArtifacts != len(source.nodeIDs) || secretArtifacts != len(source.nodeIDs) {
		return lifecycleSource{}, edgedeployment.ErrUnavailable
	}
	return source, nil
}

func (source lifecycleSource) partialFailureNodes() ([]uuid.UUID, bool) {
	failed := make([]uuid.UUID, 0, len(source.nodeIDs))
	healthy := 0
	for index, state := range source.states {
		switch state {
		case "healthy":
			healthy++
		case "failed", "rollback_failed":
			failed = append(failed, source.nodeIDs[index])
		default:
			return nil, false
		}
	}
	return failed, healthy > 0 && len(failed) > 0
}

func (source lifecycleSource) terminal() bool {
	for _, state := range source.states {
		switch state {
		case "healthy", "failed", "rollback_failed", "cancelled":
		default:
			return false
		}
	}
	return len(source.states) > 0
}

func (s *PublicationService) createLifecycleRollout(
	ctx context.Context,
	tx pgx.Tx,
	request PublicationRequest,
	source lifecycleSource,
	sourceRolloutID uuid.UUID,
	expectedSourceRevision int64,
	created edgedeployment.CreateRolloutResult,
	action, reason string,
	siteIDs []uuid.UUID,
) (LifecycleResult, error) {
	result := LifecycleResult{
		SourceRolloutID: sourceRolloutID, SourceRevision: expectedSourceRevision + 1,
		Rollout: created.Rollout, Replayed: created.Replayed,
	}
	if created.Replayed {
		return result, nil
	}
	if source.rolloutID != sourceRolloutID || source.revision != expectedSourceRevision {
		return LifecycleResult{}, edgedeployment.ErrRevisionConflict
	}
	command, err := tx.Exec(ctx, `UPDATE rollouts
		SET revision=revision+1,updated_at=GREATEST(updated_at,CURRENT_TIMESTAMP)
		WHERE configuration_scope_id=$1 AND id=$2 AND revision=$3`,
		request.TenantScopeID, sourceRolloutID, expectedSourceRevision)
	if err != nil {
		return LifecycleResult{}, fmt.Errorf("advance certificate publication source revision: %w", err)
	}
	if command.RowsAffected() != 1 {
		return LifecycleResult{}, edgedeployment.ErrRevisionConflict
	}
	actorUserID := request.Actor.UserID
	nodeIDs := make([]string, len(created.Rollout.Deployments))
	for index, deployment := range created.Rollout.Deployments {
		nodeIDs[index] = deployment.NodeID.String()
	}
	payload := map[string]any{
		"actor_scope_id": request.Actor.ScopeID.String(), "target_scope_id": request.TenantScopeID.String(),
		"operation": action, "reason": reason,
		"source_rollout_id": sourceRolloutID.String(), "source_revision": result.SourceRevision,
		"result_rollout_id": created.Rollout.ID.String(), "result_rollout_revision": created.Rollout.Revision,
		"node_ids": nodeIDs, "site_ids": lifecycleUUIDStrings(siteIDs),
	}
	if ip := audit.SourceIPFrom(ctx); ip != "" {
		payload["ip"] = ip
	}
	if err := audit.New(s.pool).Append(ctx, tx, audit.Event{
		ScopeID: request.TenantScopeID, ActorUserID: &actorUserID,
		Action: action, ResourceType: "certificate_publication", ResourceID: created.Rollout.ID.String(),
		RequestID: request.RequestID, Result: "success", Payload: payload,
	}); err != nil {
		return LifecycleResult{}, fmt.Errorf("audit certificate publication lifecycle: %w", err)
	}
	return result, nil
}

func publicationDomainRequestDigest(
	action string,
	tenantScopeID uuid.UUID,
	siteIDs []uuid.UUID,
	sourceRolloutID uuid.UUID,
	expectedSourceRevision int64,
	removedSiteIDs []uuid.UUID,
) [sha256.Size]byte {
	encoded, _ := json.Marshal(struct {
		Operation              string   `json:"operation"`
		TenantScopeID          string   `json:"tenant_scope_id"`
		SiteIDs                []string `json:"site_ids"`
		SourceRolloutID        string   `json:"source_rollout_id"`
		ExpectedSourceRevision int64    `json:"expected_source_revision"`
		RemovedSiteIDs         []string `json:"removed_site_ids"`
	}{
		Operation: action, TenantScopeID: tenantScopeID.String(), SiteIDs: lifecycleUUIDStrings(siteIDs),
		SourceRolloutID: sourceRolloutID.String(), ExpectedSourceRevision: expectedSourceRevision,
		RemovedSiteIDs: lifecycleUUIDStrings(removedSiteIDs),
	})
	return sha256.Sum256(encoded)
}

// lockUnboundLifecycleSites locks each site and its latest binding fact,
// which must be an unbind, and returns the removal the nodes apply: the
// site's tenant and the unbind's binding revision.
func lockUnboundLifecycleSites(
	ctx context.Context,
	tx pgx.Tx,
	tenantScopeID uuid.UUID,
	siteIDs []uuid.UUID,
) ([]RemovedSite, error) {
	removed := make([]RemovedSite, 0, len(siteIDs))
	for _, siteID := range siteIDs {
		site := RemovedSite{SiteID: siteID}
		err := tx.QueryRow(ctx, `SELECT scope.tenant_id FROM sites site
			JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
			WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL FOR UPDATE OF site`,
			tenantScopeID, siteID).Scan(&site.TenantID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, certificateasset.ErrNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("lock certificate unpublish site: %w", err)
		}
		var action string
		err = tx.QueryRow(ctx, `SELECT action,sequence FROM certificate_site_binding_facts
			WHERE tenant_scope_id=$1 AND site_id=$2 ORDER BY sequence DESC LIMIT 1 FOR SHARE`,
			tenantScopeID, siteID).Scan(&action, &site.BindingRevision)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, certificateasset.ErrInvalidTransition
		}
		if err != nil {
			return nil, fmt.Errorf("lock certificate unbind fact: %w", err)
		}
		if action != "unbind" {
			return nil, certificateasset.ErrInvalidTransition
		}
		removed = append(removed, site)
	}
	return removed, nil
}

func normalizeLifecycleUUIDs(values []uuid.UUID, allowEmpty bool) ([]uuid.UUID, error) {
	if len(values) == 0 && !allowEmpty {
		return nil, ErrInvalidInput
	}
	result := append([]uuid.UUID(nil), values...)
	sort.Slice(result, func(left, right int) bool { return bytes.Compare(result[left][:], result[right][:]) < 0 })
	for index, value := range result {
		if value == uuid.Nil || (index > 0 && value == result[index-1]) {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}

func equalLifecycleUUIDs(left, right []uuid.UUID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func lifecycleUUIDSubset(subset, values []uuid.UUID) bool {
	available := make(map[uuid.UUID]struct{}, len(values))
	for _, value := range values {
		available[value] = struct{}{}
	}
	for _, value := range subset {
		if _, found := available[value]; !found {
			return false
		}
	}
	return true
}

func subtractLifecycleUUIDs(values, removed []uuid.UUID) []uuid.UUID {
	removedSet := make(map[uuid.UUID]struct{}, len(removed))
	for _, value := range removed {
		removedSet[value] = struct{}{}
	}
	result := make([]uuid.UUID, 0, len(values)-len(removed))
	for _, value := range values {
		if _, found := removedSet[value]; !found {
			result = append(result, value)
		}
	}
	return result
}

func lifecycleUUIDStrings(values []uuid.UUID) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

type publicationSnapshot struct {
	Schema        string                           `json:"schema"`
	TenantScopeID string                           `json:"tenant_scope_id"`
	Certificates  []publicationSnapshotCertificate `json:"certificates"`
	// RemovedSites is the removal an unpublication sent (the certificates
	// are the sites that remain); a recovery sends it again.
	RemovedSites []publicationSnapshotRemovedSite `json:"removed_sites,omitempty"`
}

type publicationSnapshotRemovedSite struct {
	TenantID        string `json:"tenant_id"`
	SiteID          string `json:"site_id"`
	BindingRevision int64  `json:"binding_revision"`
}

type publicationSnapshotCertificate struct {
	TenantID             string `json:"tenant_id"`
	SiteID               string `json:"site_id"`
	SiteDomain           string `json:"site_domain"`
	AssetID              string `json:"certificate_id"`
	AssetRevision        int64  `json:"asset_revision"`
	CertificateVersionID string `json:"certificate_version_id"`
	CertificateVersion   int64  `json:"certificate_version"`
	BindingRevision      int64  `json:"binding_revision"`
	FingerprintSHA256    string `json:"fingerprint_sha256"`
	PublicKeySHA256      string `json:"public_key_sha256"`
	NotBefore            string `json:"not_before"`
	NotAfter             string `json:"not_after"`
}

func buildPublicationSnapshot(
	tenantScopeID uuid.UUID,
	materials []certificateasset.PublicationMaterial,
) ([]byte, error) {
	if tenantScopeID == uuid.Nil || len(materials) == 0 {
		return nil, ErrInvalidInput
	}
	ordered := append([]certificateasset.PublicationMaterial(nil), materials...)
	sort.Slice(ordered, func(left, right int) bool {
		return bytes.Compare(ordered[left].SiteID[:], ordered[right].SiteID[:]) < 0
	})
	snapshot := publicationSnapshot{
		Schema: PublicationSnapshotSchema, TenantScopeID: tenantScopeID.String(),
		Certificates: make([]publicationSnapshotCertificate, len(ordered)),
	}
	for index, material := range ordered {
		if material.TenantID == uuid.Nil || material.TenantScopeID != tenantScopeID ||
			material.SiteID == uuid.Nil || material.AssetID == uuid.Nil || material.AssetRevision <= 0 ||
			material.CertificateVersionID == uuid.Nil || material.CertificateVersion <= 0 ||
			material.BindingRevision <= 0 || material.SiteDomain == "" ||
			(index > 0 && (material.SiteID == ordered[index-1].SiteID || material.TenantID != ordered[0].TenantID)) {
			return nil, ErrInvalidInput
		}
		snapshot.Certificates[index] = publicationSnapshotCertificate{
			TenantID: material.TenantID.String(), SiteID: material.SiteID.String(), SiteDomain: material.SiteDomain,
			AssetID: material.AssetID.String(), AssetRevision: material.AssetRevision,
			CertificateVersionID: material.CertificateVersionID.String(), CertificateVersion: material.CertificateVersion,
			BindingRevision:   material.BindingRevision,
			FingerprintSHA256: hex.EncodeToString(material.FingerprintSHA256[:]),
			PublicKeySHA256:   hex.EncodeToString(material.PublicKeySHA256[:]),
			NotBefore:         material.NotBefore.UTC().Format(time.RFC3339Nano),
			NotAfter:          material.NotAfter.UTC().Format(time.RFC3339Nano),
		}
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

func buildRemovalSnapshot(tenantScopeID uuid.UUID) ([]byte, error) {
	if tenantScopeID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	encoded, err := json.Marshal(publicationSnapshot{
		Schema: PublicationSnapshotSchema, TenantScopeID: tenantScopeID.String(),
		Certificates: make([]publicationSnapshotCertificate, 0),
	})
	if err != nil {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

// withRemovedSites records an unpublication's removal in its snapshot.
func withRemovedSites(encoded []byte, removed []RemovedSite) ([]byte, error) {
	var snapshot publicationSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil || len(removed) == 0 {
		return nil, ErrInvalidInput
	}
	ordered := append([]RemovedSite(nil), removed...)
	sort.Slice(ordered, func(left, right int) bool {
		return bytes.Compare(ordered[left].SiteID[:], ordered[right].SiteID[:]) < 0
	})
	snapshot.RemovedSites = make([]publicationSnapshotRemovedSite, len(ordered))
	for index, site := range ordered {
		snapshot.RemovedSites[index] = publicationSnapshotRemovedSite{
			TenantID: site.TenantID.String(), SiteID: site.SiteID.String(), BindingRevision: site.BindingRevision,
		}
	}
	result, err := json.Marshal(snapshot)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return result, nil
}

func parsePublicationSnapshot(tenantScopeID uuid.UUID, encoded []byte) ([]uuid.UUID, []RemovedSite, error) {
	if tenantScopeID == uuid.Nil || len(encoded) == 0 {
		return nil, nil, ErrInvalidInput
	}
	var snapshot publicationSnapshot
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, nil, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, nil, ErrInvalidInput
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil || !bytes.Equal(canonical, encoded) || snapshot.Schema != PublicationSnapshotSchema ||
		snapshot.TenantScopeID != tenantScopeID.String() || snapshot.Certificates == nil {
		return nil, nil, ErrInvalidInput
	}
	siteIDs := make([]uuid.UUID, len(snapshot.Certificates))
	var tenantID uuid.UUID
	for index, certificate := range snapshot.Certificates {
		currentTenantID, tenantErr := canonicalLifecycleUUID(certificate.TenantID)
		siteID, siteErr := canonicalLifecycleUUID(certificate.SiteID)
		_, assetErr := canonicalLifecycleUUID(certificate.AssetID)
		_, versionErr := canonicalLifecycleUUID(certificate.CertificateVersionID)
		notBefore, beforeErr := time.Parse(time.RFC3339Nano, certificate.NotBefore)
		notAfter, afterErr := time.Parse(time.RFC3339Nano, certificate.NotAfter)
		if tenantErr != nil || siteErr != nil || assetErr != nil || versionErr != nil ||
			certificate.AssetRevision <= 0 || certificate.CertificateVersion <= 0 || certificate.BindingRevision <= 0 ||
			certificate.SiteDomain == "" || strings.TrimSpace(certificate.SiteDomain) != certificate.SiteDomain ||
			!utf8.ValidString(certificate.SiteDomain) || !validLifecycleDigest(certificate.FingerprintSHA256) ||
			!validLifecycleDigest(certificate.PublicKeySHA256) || beforeErr != nil || afterErr != nil ||
			certificate.NotBefore != notBefore.UTC().Format(time.RFC3339Nano) ||
			certificate.NotAfter != notAfter.UTC().Format(time.RFC3339Nano) || !notBefore.Before(notAfter) {
			return nil, nil, ErrInvalidInput
		}
		if index == 0 {
			tenantID = currentTenantID
		} else if currentTenantID != tenantID || bytes.Compare(siteIDs[index-1][:], siteID[:]) >= 0 {
			return nil, nil, ErrInvalidInput
		}
		siteIDs[index] = siteID
	}
	removed := make([]RemovedSite, len(snapshot.RemovedSites))
	for index, site := range snapshot.RemovedSites {
		siteTenantID, tenantErr := canonicalLifecycleUUID(site.TenantID)
		siteID, siteErr := canonicalLifecycleUUID(site.SiteID)
		if tenantErr != nil || siteErr != nil || site.BindingRevision <= 0 ||
			(len(siteIDs) != 0 && siteTenantID != tenantID) ||
			(index > 0 && (siteTenantID != removed[0].TenantID || bytes.Compare(removed[index-1].SiteID[:], siteID[:]) >= 0)) ||
			slices.Contains(siteIDs, siteID) {
			return nil, nil, ErrInvalidInput
		}
		removed[index] = RemovedSite{TenantID: siteTenantID, SiteID: siteID, BindingRevision: site.BindingRevision}
	}
	return siteIDs, removed, nil
}

func canonicalLifecycleUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, ErrInvalidInput
	}
	return parsed, nil
}

func validLifecycleDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func nilPublicationDependency(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface ||
		kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}
