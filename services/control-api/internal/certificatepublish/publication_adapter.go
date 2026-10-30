package certificatepublish

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
)

type publisherAdapterService interface {
	Publish(context.Context, PublicationRequest) (edgedeployment.CreateRolloutResult, error)
	Unpublish(context.Context, UnpublishRequest) (LifecycleResult, error)
}

type publicationReceiptService interface {
	ResolvePublicationReceipt(
		context.Context,
		PublicationRequest,
		edgedeployment.Rollout,
	) (edgedeployment.CertificatePublicationReceipt, error)
}

type CertificateTargetResolver interface {
	ResolveCertificateTarget(
		context.Context,
		certificateasset.CertificatePublicationCommandV1,
	) (edgeautopublish.CertificateTargetPolicy, error)
}

type certificateUnpublishSource struct {
	RolloutID uuid.UUID
	Revision  int64
	NodeIDs   []uuid.UUID
}

type certificateUnpublishSourceResolver interface {
	ResolveCertificateUnpublishSource(
		context.Context,
		certificateasset.CertificatePublicationCommandV1,
	) (certificateUnpublishSource, error)
}

type PublisherAdapter struct {
	service  publisherAdapterService
	resolver CertificateTargetResolver
}

func NewPublisherAdapter(
	service publisherAdapterService,
	resolver CertificateTargetResolver,
) (*PublisherAdapter, error) {
	if service == nil || nilPublicationDependency(service) || resolver == nil || nilPublicationDependency(resolver) {
		return nil, ErrInvalidInput
	}
	return &PublisherAdapter{service: service, resolver: resolver}, nil
}

func (adapter *PublisherAdapter) Publish(
	ctx context.Context,
	command certificateasset.CertificatePublicationCommandV1,
) (certificateasset.PublicationResult, error) {
	if adapter == nil || adapter.service == nil || adapter.resolver == nil || ctx == nil {
		return publicationAdapterPermanent("publication_contract_invalid"), nil
	}
	if command.Operation == "unpublish" {
		return adapter.unpublish(ctx, command, adapter.publicationRequest(command, edgeautopublish.CertificateTargetPolicy{}))
	}
	policy, err := adapter.resolver.ResolveCertificateTarget(ctx, command)
	if err != nil {
		return classifyPublicationAdapterError(err), nil
	}
	request := adapter.publicationRequest(command, policy)
	result, err := adapter.service.Publish(ctx, request)
	if err != nil {
		return classifyPublicationAdapterError(err), nil
	}
	return adapter.resolvePublicationResult(ctx, command, request, result.Rollout)
}

func (adapter *PublisherAdapter) unpublish(
	ctx context.Context,
	command certificateasset.CertificatePublicationCommandV1,
	request PublicationRequest,
) (certificateasset.PublicationResult, error) {
	resolver, ok := adapter.service.(certificateUnpublishSourceResolver)
	if !ok {
		return publicationAdapterRetry("publication_unavailable"), nil
	}
	source, err := resolver.ResolveCertificateUnpublishSource(ctx, command)
	if err != nil {
		return classifyPublicationAdapterError(err), nil
	}
	request.NodeIDs = append([]uuid.UUID(nil), source.NodeIDs...)
	request.SiteIDs = nil
	result, err := adapter.service.Unpublish(ctx, UnpublishRequest{
		PublicationRequest: request, SourceRolloutID: source.RolloutID,
		ExpectedSourceRevision: source.Revision, RemovedSiteIDs: []uuid.UUID{command.SiteID},
	})
	if err != nil {
		return classifyPublicationAdapterError(err), nil
	}
	return adapter.resolvePublicationResult(ctx, command, request, result.Rollout)
}

func (adapter *PublisherAdapter) resolvePublicationResult(
	ctx context.Context,
	command certificateasset.CertificatePublicationCommandV1,
	request PublicationRequest,
	rollout edgedeployment.Rollout,
) (certificateasset.PublicationResult, error) {
	resolver, ok := adapter.service.(publicationReceiptService)
	if !ok || resolver == nil || nilPublicationDependency(resolver) {
		return publicationAdapterRetry("publication_unavailable"), nil
	}
	receipt, err := resolver.ResolvePublicationReceipt(ctx, request, rollout)
	if err != nil {
		return classifyPublicationAdapterError(err), nil
	}
	return publicationAdapterResult(command, request, rollout, receipt)
}

func (adapter *PublisherAdapter) publicationRequest(
	command certificateasset.CertificatePublicationCommandV1,
	policy edgeautopublish.CertificateTargetPolicy,
) PublicationRequest {
	requestID := uuid.NewSHA1(command.SiteID, []byte("certificate-publication-request/"+command.IdempotencyKey))
	correlationID := uuid.NewSHA1(command.VersionID, []byte("certificate-publication-correlation/"+command.IdempotencyKey))
	storageID := uuid.NewSHA1(command.TenantScopeID, []byte(command.IdempotencyKey))
	activationTimeout := policy.ActivationTimeout
	if activationTimeout <= 0 {
		activationTimeout = time.Minute
	}
	observationWindow := policy.ObservationWindow
	if observationWindow <= 0 {
		observationWindow = 10 * time.Second
	}
	consecutiveSuccesses := policy.RequiredConsecutiveSuccesses
	if consecutiveSuccesses == 0 {
		consecutiveSuccesses = 1
	}
	capabilities := policy.RequiredCapabilities
	if len(capabilities) == 0 {
		capabilities = edgeautopublish.CertificatePublicationCapabilities()
	}
	return PublicationRequest{
		Actor: edgedeployment.Actor{
			UserID: command.ActorUserID, ScopeID: command.ActorScopeID,
			ScopeKind: command.ActorScopeKind, SessionID: command.ActorSessionID,
		},
		TenantScopeID: command.TenantScopeID, SiteIDs: []uuid.UUID{command.SiteID},
		AssetID: command.AssetID, VersionID: command.VersionID, BindingRevision: command.BindingRevision,
		NodeIDs:              append([]uuid.UUID(nil), policy.NodeIDs...),
		RequiredCapabilities: capabilities,
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: activationTimeout, ObservationWindow: observationWindow,
			RequiredConsecutiveSuccesses: consecutiveSuccesses,
		},
		Deadline: command.Deadline, IdempotencyKey: "certpub." + storageID.String(),
		RequestID: requestID.String(), CorrelationID: correlationID.String(),
		ActorUserRevision: command.ActorUserRevision, TargetTenantID: command.TargetTenantID,
		TargetTenantRevision: command.TargetTenantRevision,
	}
}

func publicationAdapterResult(
	command certificateasset.CertificatePublicationCommandV1,
	request PublicationRequest,
	rollout edgedeployment.Rollout,
	receipt edgedeployment.CertificatePublicationReceipt,
) (certificateasset.PublicationResult, error) {
	if rollout.ID == uuid.Nil || rollout.ConfigurationScopeID == uuid.Nil ||
		rollout.ConfigVersionID == uuid.Nil || rollout.Revision < 1 ||
		receipt.RolloutID != rollout.ID || receipt.ConfigurationScopeID != rollout.ConfigurationScopeID ||
		receipt.ConfigVersionID != rollout.ConfigVersionID || receipt.RolloutRevision != rollout.Revision ||
		receipt.Total < 1 || receipt.Pending+receipt.Running+receipt.Succeeded+
		receipt.Failed+receipt.Cancelled != receipt.Total {
		return publicationAdapterPermanent("publication_contract_invalid"), nil
	}
	switch receipt.State {
	case edgedeployment.CertificatePublicationReceiptPending:
		if receipt.Succeeded+receipt.Failed+receipt.Cancelled == receipt.Total {
			return publicationAdapterPermanent("publication_contract_invalid"), nil
		}
		return publicationAdapterRetry("publication_pending"), nil
	case edgedeployment.CertificatePublicationReceiptSucceeded:
		if receipt.Succeeded != receipt.Total {
			return publicationAdapterPermanent("publication_contract_invalid"), nil
		}
		publicationID := publicationSourceIdentity(command, request, rollout)
		if publicationID == uuid.Nil {
			return publicationAdapterPermanent("publication_contract_invalid"), nil
		}
		return certificateasset.PublicationResult{
			Outcome:             certificateasset.PublicationAck,
			PublicationID:       publicationID,
			PublicationRevision: rollout.Revision, ConfigVersionID: rollout.ConfigVersionID,
			RolloutID: rollout.ID, RolloutRevision: rollout.Revision,
		}, nil
	case edgedeployment.CertificatePublicationReceiptFailed:
		if receipt.Failed+receipt.Cancelled == 0 ||
			receipt.Succeeded+receipt.Failed+receipt.Cancelled != receipt.Total {
			return publicationAdapterPermanent("publication_contract_invalid"), nil
		}
		return publicationAdapterPermanent("publication_terminal_failed"), nil
	default:
		return publicationAdapterPermanent("publication_contract_invalid"), nil
	}
}

func publicationSourceIdentity(
	command certificateasset.CertificatePublicationCommandV1,
	request PublicationRequest,
	rollout edgedeployment.Rollout,
) uuid.UUID {
	if command.Schema != certificateasset.CertificatePublicationSchemaV1 ||
		command.TenantScopeID == uuid.Nil || command.SiteID == uuid.Nil || command.AssetID == uuid.Nil ||
		command.VersionID == uuid.Nil || command.BindingRevision < 1 ||
		(command.Operation != "publish" && command.Operation != "unpublish") ||
		request.TenantScopeID != command.TenantScopeID || request.AssetID != command.AssetID ||
		request.VersionID != command.VersionID || request.BindingRevision != command.BindingRevision ||
		rollout.ID == uuid.Nil || rollout.ConfigurationScopeID != command.TenantScopeID ||
		rollout.ConfigVersionID == uuid.Nil || rollout.Revision < 1 || len(request.NodeIDs) == 0 {
		return uuid.Nil
	}
	if command.Operation == "publish" &&
		(len(request.SiteIDs) != 1 || request.SiteIDs[0] != command.SiteID) {
		return uuid.Nil
	}
	if command.Operation == "unpublish" && len(request.SiteIDs) != 0 {
		return uuid.Nil
	}

	nodeIDs := make([]string, len(request.NodeIDs))
	for index, nodeID := range request.NodeIDs {
		if nodeID == uuid.Nil {
			return uuid.Nil
		}
		nodeIDs[index] = nodeID.String()
	}
	slices.Sort(nodeIDs)
	for index := 1; index < len(nodeIDs); index++ {
		if nodeIDs[index] == nodeIDs[index-1] {
			return uuid.Nil
		}
	}

	identity, err := json.Marshal(struct {
		Schema          string   `json:"schema"`
		TenantScopeID   string   `json:"tenant_scope_id"`
		SiteID          string   `json:"site_id"`
		AssetID         string   `json:"asset_id"`
		VersionID       string   `json:"version_id"`
		BindingRevision int64    `json:"binding_revision"`
		Operation       string   `json:"operation"`
		Default         bool     `json:"default"`
		NodeIDs         []string `json:"node_ids"`
		RolloutID       string   `json:"rollout_id"`
		RolloutRevision int64    `json:"rollout_revision"`
		ConfigVersionID string   `json:"config_version_id"`
	}{
		Schema:        "cdnca.certificate-publication-identity.v1",
		TenantScopeID: command.TenantScopeID.String(), SiteID: command.SiteID.String(),
		AssetID: command.AssetID.String(), VersionID: command.VersionID.String(),
		BindingRevision: command.BindingRevision, Operation: command.Operation, Default: command.Default,
		NodeIDs: nodeIDs, RolloutID: rollout.ID.String(), RolloutRevision: rollout.Revision,
		ConfigVersionID: rollout.ConfigVersionID.String(),
	})
	if err != nil {
		return uuid.Nil
	}
	return uuid.NewSHA1(rollout.ConfigVersionID, identity)
}

func classifyPublicationAdapterError(err error) certificateasset.PublicationResult {
	switch {
	case errors.Is(err, edgedeployment.ErrUnauthenticated), errors.Is(err, edgedeployment.ErrPermissionDenied):
		return publicationAdapterPermanent("actor_unauthenticated")
	case errors.Is(err, edgedeployment.ErrIdempotencyConflict):
		return publicationAdapterPermanent("publication_conflict")
	default:
		return publicationAdapterRetry("publication_unavailable")
	}
}

func publicationAdapterRetry(code string) certificateasset.PublicationResult {
	return certificateasset.PublicationResult{Outcome: certificateasset.PublicationRetry, FailureCode: code}
}

func publicationAdapterPermanent(code string) certificateasset.PublicationResult {
	return certificateasset.PublicationResult{Outcome: certificateasset.PublicationPermanent, FailureCode: code}
}

var _ certificateasset.CertificatePublisher = (*PublisherAdapter)(nil)
