package challengepublication

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
)

type runtimeKeyResolverStub struct {
	keys  ResolvedKeys
	err   error
	calls int
}

func (stub *runtimeKeyResolverStub) ResolveChallengeKeys(context.Context, PublicationSnapshot) (ResolvedKeys, error) {
	stub.calls++
	return stub.keys, stub.err
}

type runtimeSecretPublisherStub struct {
	result   SecretPublication
	err      error
	calls    int
	material ArtifactMaterial
}

func (stub *runtimeSecretPublisherStub) PublishChallengeSecret(_ context.Context, _ PublishRequest, material ArtifactMaterial) (SecretPublication, error) {
	stub.calls++
	stub.material = cloneMaterial(material)
	return stub.result, stub.err
}

type runtimeRolloutReaderStub struct {
	status RolloutStatus
	err    error
	calls  int
}

func (stub *runtimeRolloutReaderStub) ChallengeRolloutStatus(context.Context, StatusRequest) (RolloutStatus, error) {
	stub.calls++
	return stub.status, stub.err
}

type runtimeConfigPublisherStub struct {
	result ConfigPublication
	err    error
	calls  int
}

func (stub *runtimeConfigPublisherStub) PublishChallengeBinding(context.Context, BindingRequest) (ConfigPublication, error) {
	stub.calls++
	return stub.result, stub.err
}

func TestRuntimePublishesSecretThenRequiresHealthyRolloutBeforeBinding(t *testing.T) {
	policyID, tenantScopeID, tenantID, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	rolloutID, configVersionID := uuid.New(), uuid.New()
	keys := &runtimeKeyResolverStub{keys: ResolvedKeys{Current: ArtifactSecret{KeyID: "challenge-current", Secret: make([]byte, 32)}}}
	secrets := &runtimeSecretPublisherStub{result: SecretPublication{RolloutID: rolloutID, ConfigVersionID: configVersionID, Revision: 1}}
	rollouts := &runtimeRolloutReaderStub{status: RolloutStatus{RolloutID: rolloutID, ConfigVersionID: configVersionID,
		Revision: 1, State: StateRunning, Total: 2, Healthy: 1, Pending: 1}}
	bindings := &runtimeConfigPublisherStub{result: ConfigPublication{PublicationID: uuid.New(), Revision: 1}}
	runtime, err := NewRuntime(keys, secrets, rollouts, bindings)
	if err != nil {
		t.Fatal(err)
	}
	request := validRuntimePublishRequest(policyID, tenantScopeID, tenantID, siteID)
	publication, err := runtime.Publish(context.Background(), request)
	if err != nil || publication.RolloutID != rolloutID || keys.calls != 1 || secrets.calls != 1 {
		t.Fatalf("Publish() = (%+v, %v), key calls=%d secret calls=%d", publication, err, keys.calls, secrets.calls)
	}
	status, err := runtime.Promote(context.Background(), PromoteRequest{
		PublishRequest: request, Secret: publication,
		Readiness: NodeReadiness{Ready: request.NodeIDs[:1], Waiting: request.NodeIDs[1:]},
	})
	if !errors.Is(err, ErrRolloutNotHealthy) || status.State != StateRunning || bindings.calls != 0 {
		t.Fatalf("running Promote() = (%+v, %v), binding calls=%d", status, err, bindings.calls)
	}
	rollouts.status = RolloutStatus{RolloutID: rolloutID, ConfigVersionID: configVersionID,
		Revision: 1, State: StateHealthy, Total: 2, Healthy: 2}
	status, err = runtime.Promote(context.Background(), PromoteRequest{PublishRequest: request, Secret: publication,
		Readiness: NodeReadiness{Ready: request.NodeIDs}})
	if err != nil || status.State != StateActive || bindings.calls != 1 || status.ConfigPublication == nil {
		t.Fatalf("healthy Promote() = (%+v, %v), binding calls=%d", status, err, bindings.calls)
	}
}

func TestRuntimeFailsClosedWithoutKeysAndPublishesBoundExternalCredential(t *testing.T) {
	request := validRuntimePublishRequest(uuid.New(), uuid.New(), uuid.New(), uuid.New())
	secrets := &runtimeSecretPublisherStub{}
	runtime, err := NewRuntime(&runtimeKeyResolverStub{err: ErrKeyUnavailable}, secrets,
		&runtimeRolloutReaderStub{}, &runtimeConfigPublisherStub{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Publish(context.Background(), request); !errors.Is(err, ErrKeyUnavailable) || secrets.calls != 0 {
		t.Fatalf("missing key Publish() error=%v secret calls=%d", err, secrets.calls)
	}

	request.Policy.Mode = "external"
	request.Policy.ExternalProvider = &ExternalProviderReference{Provider: "tencent", AppReference: "appref:tencent-primary"}
	secrets.result = SecretPublication{RolloutID: uuid.New(), ConfigVersionID: uuid.New(), Revision: 1}
	runtime, err = NewRuntime(&runtimeKeyResolverStub{keys: ResolvedKeys{
		Current: ArtifactSecret{KeyID: "challenge-current", Secret: make([]byte, 32)},
		ExternalCredential: &ExternalCredentialSecret{SchemaVersion: ExternalCredentialSchemaVersion,
			Provider: "tencent", AppID: "2060000000", Secret: []byte("tencent-controlled-secret-0001"), Environment: "production"},
	}},
		secrets, &runtimeRolloutReaderStub{}, &runtimeConfigPublisherStub{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Publish(context.Background(), request); err != nil || secrets.calls != 1 ||
		len(secrets.material.ExternalCredentials) != 1 || secrets.material.ExternalCredentials[0].TenantID != request.Policy.TenantID.String() ||
		secrets.material.ExternalCredentials[0].SiteID != request.Policy.SiteID.String() ||
		secrets.material.ExternalCredentials[0].Provider != "tencent" || secrets.material.ExternalCredentials[0].AppID != "2060000000" {
		t.Fatalf("external Publish() error=%v secret calls=%d material=%+v", err, secrets.calls, secrets.material)
	}
}

func TestRuntimeFailedRolloutReportsStableBoundedCountsWithoutPublishingBinding(t *testing.T) {
	request := validRuntimePublishRequest(uuid.New(), uuid.New(), uuid.New(), uuid.New())
	secret := SecretPublication{RolloutID: uuid.New(), ConfigVersionID: uuid.New(), Revision: 1}
	rollouts := &runtimeRolloutReaderStub{status: RolloutStatus{
		RolloutID: secret.RolloutID, ConfigVersionID: secret.ConfigVersionID, Revision: secret.Revision,
		State: StateFailed, Reason: ReasonNodeApplyFailed,
		Total: 5, Healthy: 3, Failed: 2,
	}}
	bindings := &runtimeConfigPublisherStub{}
	runtime, err := NewRuntime(&runtimeKeyResolverStub{}, &runtimeSecretPublisherStub{}, rollouts, bindings)
	if err != nil {
		t.Fatal(err)
	}
	status, err := runtime.Promote(context.Background(), PromoteRequest{PublishRequest: request, Secret: secret,
		Readiness: NodeReadiness{Ready: request.NodeIDs[:1], Failed: request.NodeIDs[1:]}})
	if !errors.Is(err, ErrRolloutFailed) || status.State != StateFailed || status.Reason != ReasonNodeApplyFailed ||
		status.Total != 5 || status.Healthy != 3 || status.Failed != 2 || bindings.calls != 0 {
		t.Fatalf("failed Promote() = (%+v, %v), binding calls=%d", status, err, bindings.calls)
	}
}

func TestRuntimeStatusRejectsMalformedDurableRolloutFacts(t *testing.T) {
	rolloutID, configVersionID := uuid.New(), uuid.New()
	rollouts := &runtimeRolloutReaderStub{status: RolloutStatus{
		RolloutID: rolloutID, ConfigVersionID: configVersionID, Revision: 2,
		State: StateRunning, Reason: ReasonWaitingForNodes, Total: 2, Pending: 1, Healthy: 1,
	}}
	runtime, err := NewRuntime(&runtimeKeyResolverStub{}, &runtimeSecretPublisherStub{}, rollouts, &runtimeConfigPublisherStub{})
	if err != nil {
		t.Fatal(err)
	}
	request := StatusRequest{Actor: validRuntimePublishRequest(uuid.New(), uuid.New(), uuid.New(), uuid.New()).Actor,
		TenantScopeID: uuid.New(), RolloutID: rolloutID}
	request.Actor.UserID = uuid.New()
	status, err := runtime.Status(context.Background(), request)
	if err != nil || status.ConfigVersionID != configVersionID || status.Revision != 2 {
		t.Fatalf("Status() = (%+v, %v)", status, err)
	}
	rollouts.status.Pending = 2
	if _, err := runtime.Status(context.Background(), request); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("malformed Status() error = %v", err)
	}
}

// fix-cfgflow3: nodes that ignored the secret as an old release are counted
// apart (not failed); a rollout healthy on the rest is healthy.
func TestRuntimeStatusCountsIgnoredOldReleaseApart(t *testing.T) {
	rolloutID, configVersionID := uuid.New(), uuid.New()
	rollouts := &runtimeRolloutReaderStub{status: RolloutStatus{
		RolloutID: rolloutID, ConfigVersionID: configVersionID, Revision: 2,
		State: StateHealthy, Total: 3, Healthy: 2, Superseded: 1,
	}}
	runtime, err := NewRuntime(&runtimeKeyResolverStub{}, &runtimeSecretPublisherStub{}, rollouts, &runtimeConfigPublisherStub{})
	if err != nil {
		t.Fatal(err)
	}
	request := StatusRequest{Actor: validRuntimePublishRequest(uuid.New(), uuid.New(), uuid.New(), uuid.New()).Actor,
		TenantScopeID: uuid.New(), RolloutID: rolloutID}
	request.Actor.UserID = uuid.New()
	status, err := runtime.Status(context.Background(), request)
	if err != nil || status.Superseded != 1 || status.Failed != 0 {
		t.Fatalf("Status() = (%+v, %v)", status, err)
	}

	reader, err := NewDurableRolloutReader(rolloutSnapshotStub{snapshot: edgedeployment.RolloutSnapshot{
		ID: rolloutID, ConfigVersionID: configVersionID, Revision: 2, State: edgedeployment.RolloutStateSucceeded,
		Progress: edgedeployment.RolloutProgress{Total: 3, Succeeded: 2, Superseded: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	durable, err := reader.ChallengeRolloutStatus(context.Background(), request)
	if err != nil || durable.State != StateHealthy || durable.Healthy != 2 || durable.Superseded != 1 ||
		!validRolloutStatus(durable, rolloutID) {
		t.Fatalf("ChallengeRolloutStatus() = (%+v, %v)", durable, err)
	}
}

type rolloutSnapshotStub struct {
	snapshot edgedeployment.RolloutSnapshot
}

func (stub rolloutSnapshotStub) GetRollout(context.Context, edgedeployment.Actor, uuid.UUID, uuid.UUID) (edgedeployment.RolloutSnapshot, error) {
	return stub.snapshot, nil
}

func validRuntimePublishRequest(policyID, tenantScopeID, tenantID, siteID uuid.UUID) PublishRequest {
	return PublishRequest{Policy: PublicationSnapshot{
		PolicyID: policyID, TenantScopeID: tenantScopeID, TenantID: tenantID, SiteID: siteID,
		Host: "challenge.example.test", Revision: 7, Priority: 10, Mode: "click",
		ChallengeTTLSeconds: 60, PassTTLSeconds: 300, AttemptsPerNonce: 1,
		FailureWindowSeconds: 60, MaxFailuresPerWindow: 3, IPBinding: "exact",
		BypassRoutes: []BypassRoute{}, KeyReference: "keyref:challenge-primary",
	}, NodeIDs: []uuid.UUID{uuid.New(), uuid.New()}, IdempotencyKey: "challenge.publish.7"}
}
