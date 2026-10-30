package edgepublish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ErrorPageProductionSource interface {
	Build(context.Context, pgx.Tx, errorpagecontrol.ProductionSnapshotRequest) (errorpagecontrol.ProductionSnapshotArtifact, error)
}

type ErrorPagePublishRequest struct {
	PublishRequest
	TenantID uuid.UUID
}

type ErrorPagePublishResult struct {
	PublishResult
	Binding errorpagecontrol.ProductionSnapshotBinding
}

type ErrorPagePublisher struct {
	service *Service
	source  ErrorPageProductionSource
}

func NewErrorPagePublisher(service *Service, source ErrorPageProductionSource) (*ErrorPagePublisher, error) {
	if service == nil || nilErrorPageProductionSource(source) {
		return nil, ErrInvalidInput
	}
	return &ErrorPagePublisher{service: service, source: source}, nil
}

func (publisher *ErrorPagePublisher) Publish(ctx context.Context, request ErrorPagePublishRequest) (ErrorPagePublishResult, error) {
	if publisher == nil || publisher.service == nil || nilErrorPageProductionSource(publisher.source) || ctx == nil ||
		request.TenantID == uuid.Nil {
		return ErrorPagePublishResult{}, ErrInvalidInput
	}
	now := publisher.service.config.Clock().UTC().Truncate(time.Microsecond)
	normalized, err := normalizePublishRequest(request.PublishRequest, now)
	if err != nil {
		return ErrorPagePublishResult{}, err
	}
	var result ErrorPagePublishResult
	err = pgx.BeginFunc(ctx, publisher.service.pool, func(tx pgx.Tx) error {
		var publishErr error
		result, publishErr = publisher.publishTx(ctx, tx, normalized, request, now)
		return publishErr
	})
	if err != nil {
		return ErrorPagePublishResult{}, err
	}
	return result, nil
}

func (publisher *ErrorPagePublisher) publishTx(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedPublishRequest,
	errorPageRequest ErrorPagePublishRequest,
	now time.Time,
) (ErrorPagePublishResult, error) {
	if err := publisher.service.writeAuth.Authorize(ctx, tx, request.Actor, request.ConfigurationScopeID, PermissionManage); err != nil {
		return ErrorPagePublishResult{}, err
	}
	return publisher.publishAuthorizedTx(ctx, tx, request, errorPageRequest.TenantID, now)
}

// publishAuthorizedTx publishes the scope's error page snapshot once the
// caller is authorized: a session actor by publishTx, the control plane
// itself (system republication, trigger theme_activation) by construction.
func (publisher *ErrorPagePublisher) publishAuthorizedTx(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedPublishRequest,
	tenantID uuid.UUID,
	now time.Time,
) (ErrorPagePublishResult, error) {
	service := publisher.service
	sourceRevision, err := lockConfigurationScope(ctx, tx, request.ConfigurationScopeID, now)
	if err != nil {
		return ErrorPagePublishResult{}, err
	}
	if sourceRevision != request.ExpectedSourceRevision {
		return ErrorPagePublishResult{}, ErrRevisionConflict
	}
	target, targetDigest, err := service.resolveTarget(ctx, tx, request)
	if err != nil {
		return ErrorPagePublishResult{}, err
	}
	decision, authorizationErr := service.authorizer.AuthorizePublication(ctx, tx, EntitlementRequest{
		Actor: request.Actor, ConfigurationScopeID: request.ConfigurationScopeID,
		ExpectedSourceRevision: sourceRevision, NodeCount: len(target.NodeIDs), EvaluatedAt: now,
	})
	if authorizationErr != nil || !validEntitlementDecision(decision, now) {
		return ErrorPagePublishResult{}, ErrEntitlementDenied
	}
	artifact, err := publisher.source.Build(ctx, tx, errorpagecontrol.ProductionSnapshotRequest{
		TenantID: tenantID, ScopeID: request.ConfigurationScopeID,
	})
	if err != nil {
		return ErrorPagePublishResult{}, err
	}
	configID, artifactInput, snapshotDigest, err := errorPageArtifactInput(request.ConfigurationScopeID, artifact)
	if err != nil {
		return ErrorPagePublishResult{}, err
	}
	configResult, err := service.deployments.PersistReleasableConfigTx(ctx, tx, configID, edgedeployment.PersistConfigRequest{
		ConfigurationScopeID: request.ConfigurationScopeID,
		CanonicalSnapshot:    bytes.Clone(artifact.WireBytes),
		GeneratorName:        service.config.GeneratorName,
		GeneratorVersion:     service.config.GeneratorVersion,
		Artifacts:            []edgedeployment.ArtifactInput{artifactInput},
		IdempotencyKey:       "ep." + artifact.SHA256,
	})
	if err != nil {
		return ErrorPagePublishResult{}, err
	}
	rollout, err := service.deployments.CreateRolloutTx(ctx, tx, edgedeployment.CreateRolloutRequest{
		ConfigurationScopeID: request.ConfigurationScopeID,
		ConfigVersionID:      configID,
		Action:               agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		NodeIDs:              target.NodeIDs,
		RequiredCapabilities: errorPageRolloutCapabilities(artifact.HasSlots),
		HealthCheck:          request.HealthCheck, Deadline: request.Deadline,
		IdempotencyKey: "ep.rollout." + request.IdempotencyKey,
		RequestID:      request.RequestID, CorrelationID: request.CorrelationID, Traceparent: request.Traceparent,
		TaskID: request.TaskID, MaxAttempts: request.MaxAttempts, ContractVersion: 1,
	})
	if err != nil {
		return ErrorPagePublishResult{}, err
	}
	base := PublishResult{
		PublicationID:        uuid.NewSHA1(configID, []byte("error-page-publication\x00"+request.IdempotencyKey)),
		ConfigurationScopeID: request.ConfigurationScopeID, SourceRevision: sourceRevision,
		ConfigVersionID: configID, RolloutID: rollout.Rollout.ID,
		CanonicalSnapshotSHA256: snapshotDigest, ArtifactSHA256: snapshotDigest,
		TargetKind: targetKind(request), TargetSnapshot: cloneTargetReference(request.TargetSnapshot),
		TargetSnapshotSHA256: targetDigest, NodeCount: len(target.NodeIDs), CreatedAt: rollout.Rollout.CreatedAt,
		Replayed: configResult.Replayed && rollout.Replayed,
	}
	result := ErrorPagePublishResult{PublishResult: base, Binding: artifact.Binding}
	if err := service.auditor.Append(ctx, tx, audit.Event{
		ScopeID: request.Actor.ScopeID, ActorUserID: auditActorUserID(request.Actor),
		Action: "edge_error_page.publish", ResourceType: "edge_error_page_bundle",
		ResourceID: result.PublicationID.String(), RequestID: request.RequestID, Result: "success",
		Payload: publishAuditPayload(request, map[string]any{
			"configuration_scope_id": request.ConfigurationScopeID.String(), "tenant_id": tenantID.String(),
			"publication_revision": artifact.Binding.PublicationRevision,
			"config_version_id":    configID.String(), "rollout_id": rollout.Rollout.ID.String(),
			"node_count": len(target.NodeIDs), "artifact_sha256": artifact.SHA256,
		}),
	}); err != nil {
		return ErrorPagePublishResult{}, fmt.Errorf("%w: append error page publication audit", ErrPersistence)
	}
	// Dynamic routing nodes read the pages from the site objects (D13-b2 1).
	if !result.Replayed {
		if err := RequestSiteFactsRepublicationTx(ctx, tx, request.ConfigurationScopeID, SystemTriggerErrorPagePublished); err != nil {
			return ErrorPagePublishResult{}, err
		}
	}
	return result, nil
}

// errorPageRolloutCapabilities: a snapshot with slot node pages needs
// ERROR_PAGE_SLOTS (errpage-3); an earlier agent decodes snapshots strictly.
func errorPageRolloutCapabilities(slots bool) []*agentv1.Capability {
	capabilities := []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
	}
	if slots {
		capabilities = append(capabilities, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_ERROR_PAGE_SLOTS, ApiVersion: siteobject.ErrorPageSlotsAPIVersion})
	}
	return capabilities
}

func errorPageArtifactInput(
	scopeID uuid.UUID,
	artifact errorpagecontrol.ProductionSnapshotArtifact,
) (uuid.UUID, edgedeployment.ArtifactInput, [sha256.Size]byte, error) {
	if scopeID == uuid.Nil || artifact.MediaType != errorpagecontrol.ProductionSnapshotMediaType ||
		len(artifact.WireBytes) == 0 || uint64(len(artifact.WireBytes)) > uint64(errorpagecontrol.MaxEdgePolicyBytes) ||
		len(artifact.Signature) != ed25519.SignatureSize || len(artifact.SigningPublicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(artifact.SigningPublicKey, artifact.WireBytes, artifact.Signature) ||
		artifact.SigningKeyID == "" {
		return uuid.Nil, edgedeployment.ArtifactInput{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	digest := sha256.Sum256(artifact.WireBytes)
	decodedDigest, err := hex.DecodeString(artifact.SHA256)
	if err != nil || len(decodedDigest) != sha256.Size || !bytes.Equal(decodedDigest, digest[:]) {
		return uuid.Nil, edgedeployment.ArtifactInput{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	tenantID, tenantErr := uuid.Parse(artifact.Binding.TenantID)
	bindingScopeID, scopeErr := uuid.Parse(artifact.Binding.ConfigurationScopeID)
	if tenantErr != nil || scopeErr != nil || tenantID == uuid.Nil || bindingScopeID != scopeID || artifact.Binding.PublicationRevision == 0 {
		return uuid.Nil, edgedeployment.ArtifactInput{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	identity := []byte("cdnca.error-page.snapshot.config/v1\x00" + artifact.Binding.TenantID + "\x00" +
		artifact.Binding.ConfigurationScopeID + "\x00" + fmt.Sprint(artifact.Binding.PublicationRevision) + "\x00" + artifact.SHA256)
	configID := uuid.NewSHA1(scopeID, identity)
	artifactID := uuid.NewSHA1(configID, append([]byte("cdnca.error-page.snapshot.artifact/v1\x00"), digest[:]...))
	return configID, edgedeployment.ArtifactInput{
		ID: artifactID, Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION,
		WireBytes: bytes.Clone(artifact.WireBytes), SizeBytes: uint64(len(artifact.WireBytes)), SHA256: bytes.Clone(digest[:]),
		Signature: bytes.Clone(artifact.Signature), SigningKeyID: artifact.SigningKeyID,
		SigningPublicKey:   append(ed25519.PublicKey(nil), artifact.SigningPublicKey...),
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: artifact.MediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
	}, digest, nil
}

func nilErrorPageProductionSource(source ErrorPageProductionSource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	return value.Kind() == reflect.Pointer && value.IsNil()
}
