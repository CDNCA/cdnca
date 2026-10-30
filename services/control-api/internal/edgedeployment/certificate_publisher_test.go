package edgedeployment

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type certificatePublisherAuthorizer47 struct{}

func (*certificatePublisherAuthorizer47) AuthorizeCertificatePublication(
	context.Context,
	pgx.Tx,
	Actor,
	uuid.UUID,
	CertificateActorReference,
) (uuid.UUID, uuid.UUID, error) {
	return uuid.New(), uuid.New(), nil
}

func TestCertificatePublisherStoreRejectsMissingAndTypedNilAuthorizer47(t *testing.T) {
	core := new(Store)
	if store, err := NewCertificatePublisherStore(core, nil); !errors.Is(err, ErrInvalidInput) || store != nil {
		t.Fatalf("nil authorizer store=%v err=%v", store, err)
	}
	var authorizer *certificatePublisherAuthorizer47
	if store, err := NewCertificatePublisherStore(core, authorizer); !errors.Is(err, ErrInvalidInput) || store != nil {
		t.Fatalf("typed nil authorizer store=%v err=%v", store, err)
	}
}

func TestCertificateActorReferenceRequiresExactNonSecretIdentity47(t *testing.T) {
	reference := CertificateActorReference{
		UserRevision: 7, TargetTenantID: uuid.New(), TargetTenantRevision: 11,
	}
	if !validCertificateActorReference(reference) {
		t.Fatal("valid certificate actor reference rejected")
	}
	for _, mutate := range []func(*CertificateActorReference){
		func(value *CertificateActorReference) { value.UserRevision = 0 },
		func(value *CertificateActorReference) { value.TargetTenantID = uuid.Nil },
		func(value *CertificateActorReference) { value.TargetTenantRevision = 0 },
	} {
		changed := reference
		mutate(&changed)
		if validCertificateActorReference(changed) {
			t.Fatalf("invalid certificate actor reference accepted: %+v", changed)
		}
	}
}

func TestCertificatePublicationReceiptRequiresTerminalHealthyAggregate49(t *testing.T) {
	rolloutID, scopeID, configID := uuid.New(), uuid.New(), uuid.New()
	base := RolloutSnapshot{
		ID: rolloutID, ConfigurationScopeID: scopeID, ConfigVersionID: configID,
		Revision: 7, State: RolloutStateRunning,
		Progress: RolloutProgress{Total: 2, Pending: 1, Succeeded: 1},
	}
	pending, err := certificatePublicationReceiptFromSnapshot(base)
	if err != nil || pending.State != CertificatePublicationReceiptPending || pending.Total != 2 ||
		pending.Pending != 1 || pending.Succeeded != 1 {
		t.Fatalf("pending receipt=%+v err=%v", pending, err)
	}

	succeededSnapshot := base
	succeededSnapshot.State = RolloutStateSucceeded
	succeededSnapshot.Progress = RolloutProgress{Total: 2, Succeeded: 2}
	succeeded, err := certificatePublicationReceiptFromSnapshot(succeededSnapshot)
	if err != nil || succeeded.State != CertificatePublicationReceiptSucceeded || succeeded.Succeeded != 2 {
		t.Fatalf("succeeded receipt=%+v err=%v", succeeded, err)
	}

	failedSnapshot := base
	failedSnapshot.State = RolloutStatePartialFailed
	failedSnapshot.Progress = RolloutProgress{Total: 2, Succeeded: 1, Failed: 1}
	failed, err := certificatePublicationReceiptFromSnapshot(failedSnapshot)
	if err != nil || failed.State != CertificatePublicationReceiptFailed || failed.Failed != 1 || failed.Succeeded != 1 {
		t.Fatalf("failed receipt=%+v err=%v", failed, err)
	}

	invalid := base
	invalid.Progress.Total = 3
	if _, err := certificatePublicationReceiptFromSnapshot(invalid); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid aggregate error=%v", err)
	}
}
