package certificatepublish

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
)

type publicationAdapterService47 struct {
	publishRequest     PublicationRequest
	publishResult      edgedeployment.CreateRolloutResult
	publishErr         error
	unpublishRequest   *UnpublishRequest
	unpublishResult    LifecycleResult
	unpublishSource    certificateUnpublishSource
	unpublishSourceErr error
	receipt            edgedeployment.CertificatePublicationReceipt
	receiptErr         error
	receiptCalls       int
}

func (service *publicationAdapterService47) ResolveCertificateUnpublishSource(
	context.Context,
	certificateasset.CertificatePublicationCommandV1,
) (certificateUnpublishSource, error) {
	if service.unpublishSourceErr != nil {
		return certificateUnpublishSource{}, service.unpublishSourceErr
	}
	return service.unpublishSource, nil
}

func (service *publicationAdapterService47) Publish(
	_ context.Context,
	request PublicationRequest,
) (edgedeployment.CreateRolloutResult, error) {
	service.publishRequest = request
	return service.publishResult, service.publishErr
}

func (service *publicationAdapterService47) Unpublish(
	_ context.Context,
	request UnpublishRequest,
) (LifecycleResult, error) {
	service.unpublishRequest = &request
	if service.unpublishResult.Rollout.ID != uuid.Nil {
		return service.unpublishResult, nil
	}
	return LifecycleResult{}, errors.New("unexpected unpublish")
}

func (service *publicationAdapterService47) ResolvePublicationReceipt(
	_ context.Context,
	_ PublicationRequest,
	_ edgedeployment.Rollout,
) (edgedeployment.CertificatePublicationReceipt, error) {
	service.receiptCalls++
	return service.receipt, service.receiptErr
}

type publicationTargetResolver47 struct {
	policy edgeautopublish.CertificateTargetPolicy
	err    error
}

type publicationReceiptDeploymentStore49 struct {
	secretDeploymentStore
	request edgedeployment.CertificatePublicationReceiptRequest
	receipt edgedeployment.CertificatePublicationReceipt
}

func (store *publicationReceiptDeploymentStore49) ResolveCertificatePublicationReceipt(
	_ context.Context,
	request edgedeployment.CertificatePublicationReceiptRequest,
) (edgedeployment.CertificatePublicationReceipt, error) {
	store.request = request
	return store.receipt, nil
}

func (resolver publicationTargetResolver47) ResolveCertificateTarget(
	context.Context,
	certificateasset.CertificatePublicationCommandV1,
) (edgeautopublish.CertificateTargetPolicy, error) {
	return resolver.policy, resolver.err
}

func TestPublisherAdapterMapsExactIdentityPolicyAndDurableResult47(t *testing.T) {
	command := certificatePublicationCommand47()
	nodeID := uuid.New()
	policy := edgeautopublish.CertificateTargetPolicy{
		PolicyRevision: 5, NodeIDs: []uuid.UUID{nodeID},
		RequiredCapabilities: edgeautopublish.CertificatePublicationCapabilities(),
		ActivationTimeout:    20 * time.Second, ObservationWindow: 10 * time.Second,
		RequiredConsecutiveSuccesses: 2, Deadline: time.Now().Add(time.Minute),
	}
	configID, rolloutID := uuid.New(), uuid.New()
	rollout := edgedeployment.Rollout{
		ID: rolloutID, ConfigurationScopeID: command.TenantScopeID, ConfigVersionID: configID,
		Revision: 1, CreatedAt: time.Now(), QueuedAt: time.Now(),
	}
	service := &publicationAdapterService47{publishResult: edgedeployment.CreateRolloutResult{
		Rollout: edgedeployment.Rollout{
			ID: rolloutID, ConfigurationScopeID: command.TenantScopeID, ConfigVersionID: configID,
			Revision: 1, CreatedAt: time.Now(), QueuedAt: time.Now(),
		},
	}, receipt: terminalReceipt47(rollout, edgedeployment.CertificatePublicationReceiptSucceeded)}
	adapter, err := NewPublisherAdapter(service, publicationTargetResolver47{policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Publish(t.Context(), command)
	if err != nil || result.Outcome != certificateasset.PublicationAck ||
		result.PublicationID != publicationSourceIdentity(command, service.publishRequest, rollout) ||
		result.PublicationRevision != 1 || result.ConfigVersionID != configID ||
		result.RolloutID != rolloutID || result.RolloutRevision != 1 {
		t.Fatalf("Publish() result=%+v err=%v", result, err)
	}
	request := service.publishRequest
	if request.Actor.UserID != command.ActorUserID || request.Actor.ScopeID != command.ActorScopeID ||
		request.Actor.SessionID != command.ActorSessionID || request.Actor.ScopeKind != command.ActorScopeKind ||
		request.ActorUserRevision != command.ActorUserRevision || request.TargetTenantID != command.TargetTenantID ||
		request.TargetTenantRevision != command.TargetTenantRevision || len(request.NodeIDs) != 1 ||
		request.NodeIDs[0] != nodeID || request.IdempotencyKey == "" || request.RequestID == "" ||
		request.CorrelationID == "" {
		t.Fatalf("mapped request=%+v", request)
	}
}

func TestPublisherAdapterWaitsForExactTerminalReceiptBeforeAck49(t *testing.T) {
	command := certificatePublicationCommand47()
	rollout := edgedeployment.Rollout{
		ID: uuid.New(), ConfigurationScopeID: command.TenantScopeID, ConfigVersionID: uuid.New(),
		Revision: 4, CreatedAt: time.Now(), QueuedAt: time.Now(),
	}
	tests := []struct {
		name    string
		receipt edgedeployment.CertificatePublicationReceipt
		err     error
		outcome certificateasset.PublicationOutcome
		code    string
	}{
		{name: "queued", receipt: terminalReceipt47(rollout, edgedeployment.CertificatePublicationReceiptPending), outcome: certificateasset.PublicationRetry, code: "publication_pending"},
		{name: "terminal failed", receipt: terminalReceipt47(rollout, edgedeployment.CertificatePublicationReceiptFailed), outcome: certificateasset.PublicationPermanent, code: "publication_terminal_failed"},
		{name: "receipt unavailable", err: edgedeployment.ErrUnavailable, outcome: certificateasset.PublicationRetry, code: "publication_unavailable"},
		{name: "wrong config", receipt: func() edgedeployment.CertificatePublicationReceipt {
			value := terminalReceipt47(rollout, edgedeployment.CertificatePublicationReceiptSucceeded)
			value.ConfigVersionID = uuid.New()
			return value
		}(), outcome: certificateasset.PublicationPermanent, code: "publication_contract_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &publicationAdapterService47{
				publishResult: edgedeployment.CreateRolloutResult{Rollout: rollout},
				receipt:       test.receipt, receiptErr: test.err,
			}
			adapter, err := NewPublisherAdapter(service, publicationTargetResolver47{policy: edgeautopublish.CertificateTargetPolicy{
				PolicyRevision: 1, NodeIDs: []uuid.UUID{uuid.New()},
				RequiredCapabilities: edgeautopublish.CertificatePublicationCapabilities(),
				ActivationTimeout:    time.Second, ObservationWindow: time.Second,
				RequiredConsecutiveSuccesses: 1, Deadline: time.Now().Add(time.Minute),
			}})
			if err != nil {
				t.Fatal(err)
			}
			result, publishErr := adapter.Publish(t.Context(), command)
			if publishErr != nil || result.Outcome != test.outcome || result.FailureCode != test.code ||
				result.PublicationID != uuid.Nil || service.receiptCalls != 1 {
				t.Fatalf("result=%+v err=%v receipt_calls=%d", result, publishErr, service.receiptCalls)
			}
		})
	}
}

func TestPublicationServiceReceiptResolverPreservesActorAndRolloutFence49(t *testing.T) {
	command := certificatePublicationCommand47()
	request := (&PublisherAdapter{}).publicationRequest(command, edgeautopublish.CertificateTargetPolicy{})
	rollout := edgedeployment.Rollout{
		ID: uuid.New(), ConfigurationScopeID: command.TenantScopeID,
		ConfigVersionID: uuid.New(), Revision: 9,
	}
	want := terminalReceipt47(rollout, edgedeployment.CertificatePublicationReceiptSucceeded)
	deployments := &publicationReceiptDeploymentStore49{receipt: want}
	service := &PublicationService{deployments: deployments}
	got, err := service.ResolvePublicationReceipt(t.Context(), request, rollout)
	if err != nil || got != want {
		t.Fatalf("receipt=%+v err=%v", got, err)
	}
	seen := deployments.request
	if seen.Actor.UserID != command.ActorUserID || seen.Actor.ScopeID != command.ActorScopeID ||
		seen.Actor.SessionID != command.ActorSessionID || seen.ConfigurationScopeID != command.TenantScopeID ||
		seen.ActorReference.UserRevision != command.ActorUserRevision ||
		seen.ActorReference.TargetTenantID != command.TargetTenantID ||
		seen.ActorReference.TargetTenantRevision != command.TargetTenantRevision ||
		seen.RolloutID != rollout.ID || seen.ConfigVersionID != rollout.ConfigVersionID ||
		seen.RolloutRevision != rollout.Revision {
		t.Fatalf("receipt fence=%+v", seen)
	}
}

func TestPublisherAdapterClassifiesActorDriftAndDependencyFailureWithoutLeaks47(t *testing.T) {
	command := certificatePublicationCommand47()
	for _, test := range []struct {
		name string
		err  error
		want certificateasset.PublicationOutcome
		code string
	}{
		{name: "actor", err: edgedeployment.ErrUnauthenticated, want: certificateasset.PublicationPermanent, code: "actor_unauthenticated"},
		{name: "conflict", err: edgedeployment.ErrIdempotencyConflict, want: certificateasset.PublicationPermanent, code: "publication_conflict"},
		{name: "unavailable", err: edgedeployment.ErrUnavailable, want: certificateasset.PublicationRetry, code: "publication_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &publicationAdapterService47{publishErr: test.err}
			adapter, err := NewPublisherAdapter(service, publicationTargetResolver47{policy: edgeautopublish.CertificateTargetPolicy{
				PolicyRevision: 1, NodeIDs: []uuid.UUID{uuid.New()},
				RequiredCapabilities: edgeautopublish.CertificatePublicationCapabilities(),
				ActivationTimeout:    time.Second, ObservationWindow: time.Second,
				RequiredConsecutiveSuccesses: 1, Deadline: time.Now().Add(time.Minute),
			}})
			if err != nil {
				t.Fatal(err)
			}
			result, publishErr := adapter.Publish(t.Context(), command)
			if publishErr != nil || result.Outcome != test.want || result.FailureCode != test.code {
				t.Fatalf("result=%+v err=%v", result, publishErr)
			}
		})
	}
}

func TestPublisherAdapterUnpublishUsesHistoricalSourceWithoutCurrentPolicy48(t *testing.T) {
	command := certificatePublicationCommand47()
	command.Operation = "unpublish"
	command.Deadline = time.Now().Add(time.Minute)
	rolloutID, configID := uuid.New(), uuid.New()
	service := &publicationAdapterService47{unpublishSource: certificateUnpublishSource{
		RolloutID: uuid.New(), Revision: 1, NodeIDs: []uuid.UUID{uuid.New()},
	}, unpublishResult: LifecycleResult{Rollout: edgedeployment.Rollout{
		ID: rolloutID, ConfigurationScopeID: command.TenantScopeID, ConfigVersionID: configID,
		Revision: 2, CreatedAt: time.Now(), QueuedAt: time.Now(),
	}}, receipt: edgedeployment.CertificatePublicationReceipt{
		RolloutID: rolloutID, ConfigurationScopeID: command.TenantScopeID, ConfigVersionID: configID,
		RolloutRevision: 2, State: edgedeployment.CertificatePublicationReceiptSucceeded,
		Total: 1, Succeeded: 1,
	}}
	adapter, err := NewPublisherAdapter(service, publicationTargetResolver47{err: errors.New("automatic policy disabled")})
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Publish(t.Context(), command)
	if err != nil || result.Outcome != certificateasset.PublicationAck || service.unpublishRequest == nil {
		t.Fatalf("unpublish result=%+v err=%v request=%+v", result, err, service.unpublishRequest)
	}
	request := service.unpublishRequest.PublicationRequest
	if request.AssetID != command.AssetID || request.VersionID != command.VersionID ||
		request.BindingRevision != command.BindingRevision || !request.Deadline.Equal(command.Deadline) {
		t.Fatalf("unpublish request lost frozen identity=%+v command=%+v", request, command)
	}
}

func terminalReceipt47(
	rollout edgedeployment.Rollout,
	state edgedeployment.CertificatePublicationReceiptState,
) edgedeployment.CertificatePublicationReceipt {
	receipt := edgedeployment.CertificatePublicationReceipt{
		RolloutID: rollout.ID, ConfigurationScopeID: rollout.ConfigurationScopeID,
		ConfigVersionID: rollout.ConfigVersionID, RolloutRevision: rollout.Revision,
		State: state, Total: 1,
	}
	switch state {
	case edgedeployment.CertificatePublicationReceiptSucceeded:
		receipt.Succeeded = 1
	case edgedeployment.CertificatePublicationReceiptFailed:
		receipt.Failed = 1
	default:
		receipt.Pending = 1
	}
	return receipt
}

func certificatePublicationCommand47() certificateasset.CertificatePublicationCommandV1 {
	tenantScopeID := uuid.New()
	return certificateasset.CertificatePublicationCommandV1{
		Schema:        certificateasset.CertificatePublicationSchemaV1,
		TenantScopeID: tenantScopeID, SiteID: uuid.New(), AssetID: uuid.New(), VersionID: uuid.New(),
		BindingRevision: 3, Operation: "publish", Default: true, RequestID: "request-47",
		ActorScopeID: tenantScopeID, ActorUserID: uuid.New(), ActorSessionID: uuid.New(),
		ActorScopeKind: certificateasset.ScopeTenant, ActorUserRevision: 7,
		TargetTenantID: uuid.New(), TargetTenantRevision: 11,
		IdempotencyKey: "certificate.publication/" + tenantScopeID.String() + "/placeholder/3",
		CreatedAt:      time.Now().UTC(),
	}
}

// demo-fill 11-01: an unbind after a publication that never reached a node
// retried "edge deployment not found" to permanent_failed. Nothing on the
// nodes completes it at once, without a rollout; a source that cannot be
// read right now still retries.
func TestPublisherAdapterCompletesUnpublishOfNeverPublishedCertificate(t *testing.T) {
	command := certificatePublicationCommand47()
	command.Operation = "unpublish"
	service := &publicationAdapterService47{unpublishSourceErr: errCertificateNeverPublished}
	adapter, err := NewPublisherAdapter(service, publicationTargetResolver47{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Publish(t.Context(), command)
	if err != nil || result.Outcome != certificateasset.PublicationAck ||
		result.NoopReason != certificateasset.PublicationNoopNeverPublished || result.RolloutID != uuid.Nil ||
		result.PublicationID != uuid.Nil || service.unpublishRequest != nil || service.receiptCalls != 0 {
		t.Fatalf("never-published unpublish = %+v, %v (unpublish request %v)", result, err, service.unpublishRequest)
	}

	for _, transient := range []error{edgedeployment.ErrUnavailable, edgedeployment.ErrNotFound, errors.New("connection reset")} {
		service := &publicationAdapterService47{unpublishSourceErr: transient}
		adapter, err := NewPublisherAdapter(service, publicationTargetResolver47{})
		if err != nil {
			t.Fatal(err)
		}
		result, err := adapter.Publish(t.Context(), command)
		if err != nil || result.Outcome != certificateasset.PublicationRetry || result.NoopReason != "" {
			t.Fatalf("source error %v = %+v, %v; want a retry", transient, result, err)
		}
	}
}

// demo-fill 11-01: the node's certstore stage reaches the intent's failure
// code (with the node), not one generic publication_terminal_failed.
func TestPublisherAdapterKeepsNodeCertificateFailureStage(t *testing.T) {
	command := certificatePublicationCommand47()
	nodeID := uuid.New()
	configID, rolloutID := uuid.New(), uuid.New()
	rollout := edgedeployment.Rollout{
		ID: rolloutID, ConfigurationScopeID: command.TenantScopeID, ConfigVersionID: configID,
		Revision: 1, CreatedAt: time.Now(), QueuedAt: time.Now(),
	}
	for _, test := range []struct{ message, want string }{
		{"CERTIFICATE_PRECHECK_FAILED: OpenResty rejected the certificate configuration (nginx -t)", "node_certificate_precheck_failed." + nodeID.String()},
		{"CERTIFICATE_ACTIVATION_FAILED: OpenResty did not start or reload with the certificate", "node_certificate_activation_failed." + nodeID.String()},
		{"CERTIFICATE_HEALTH_FAILED: TLS handshake with the certificate failed after activation", "node_certificate_health_failed." + nodeID.String()},
		{"certificate activation failed", "publication_terminal_failed"},
		{"", "publication_terminal_failed"},
	} {
		receipt := terminalReceipt47(rollout, edgedeployment.CertificatePublicationReceiptFailed)
		receipt.FailedNodeID, receipt.FailureMessage = nodeID, test.message
		service := &publicationAdapterService47{
			publishResult: edgedeployment.CreateRolloutResult{Rollout: rollout}, receipt: receipt,
		}
		adapter, err := NewPublisherAdapter(service, publicationTargetResolver47{policy: edgeautopublish.CertificateTargetPolicy{
			NodeIDs: []uuid.UUID{nodeID}, Deadline: time.Now().Add(time.Minute),
		}})
		if err != nil {
			t.Fatal(err)
		}
		result, err := adapter.Publish(t.Context(), command)
		if err != nil || result.Outcome != certificateasset.PublicationPermanent || result.FailureCode != test.want ||
			!validStoredFailureCode(result.FailureCode) {
			t.Fatalf("node message %q → %+v, %v; want %s", test.message, result, err, test.want)
		}
	}
}
