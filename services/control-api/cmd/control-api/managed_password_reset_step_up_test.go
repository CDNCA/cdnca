package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type managedPasswordResetStepUpStub struct {
	evidence mfa.Evidence
	err      error
	actor    mfa.Actor
	scopes   []uuid.UUID
	request  mfa.ConsumeStepUpRequest
}

func (stub *managedPasswordResetStepUpStub) ConsumeStepUpTxWithScopes(
	_ context.Context,
	_ pgx.Tx,
	actor mfa.Actor,
	scopes []uuid.UUID,
	request mfa.ConsumeStepUpRequest,
) (mfa.Evidence, error) {
	stub.actor = actor
	stub.scopes = append([]uuid.UUID(nil), scopes...)
	stub.request = request
	return stub.evidence, stub.err
}

func TestManagedPasswordResetStepUpAdapterMapsExactContract(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	actor := identity.ManagedPasswordResetStepUpActor{UserID: uuid.New(), ScopeID: uuid.New(), SessionID: uuid.New()}
	tenantID, proofID := uuid.New(), uuid.New()
	binding := bytes.Repeat([]byte{0x41}, 32)
	stub := &managedPasswordResetStepUpStub{evidence: mfa.Evidence{
		ProofID: proofID, ActorUserID: actor.UserID, ActorScopeID: actor.ScopeID,
		SessionID: actor.SessionID, TenantID: tenantID, Method: "totp",
		Audience:   identity.ManagedPasswordResetStepUpAudience,
		Action:     identity.ManagedPasswordResetStepUpAction,
		VerifiedAt: now, ExpiresAt: now.Add(time.Minute), UseOrdinal: 1,
		ResourceBindingDigest: append([]byte(nil), binding...),
	}}
	adapter, err := newManagedPasswordResetStepUpAdapter(stub)
	if err != nil {
		t.Fatal(err)
	}
	scopes := []uuid.UUID{actor.ScopeID, uuid.New()}
	evidence, err := adapter.ConsumeManagedPasswordResetStepUp(t.Context(), nil, actor, scopes,
		identity.ManagedPasswordResetStepUpRequest{
			Token: "proof", TenantID: tenantID,
			Audience:              identity.ManagedPasswordResetStepUpAudience,
			Action:                identity.ManagedPasswordResetStepUpAction,
			ResourceBindingDigest: binding, RequestID: "request-1", TraceID: "trace-1",
		})
	if err != nil || evidence.ProofID != proofID || evidence.ActorUserID != actor.UserID ||
		evidence.ActorScopeID != actor.ScopeID || evidence.SessionID != actor.SessionID ||
		evidence.TenantID != tenantID || evidence.Method != "totp" || evidence.UseOrdinal != 1 ||
		!bytes.Equal(evidence.ResourceBindingDigest, binding) {
		t.Fatalf("mapped evidence = (%+v, %v)", evidence, err)
	}
	if stub.actor.UserID != actor.UserID || stub.actor.ScopeID != actor.ScopeID ||
		stub.actor.SessionID != actor.SessionID || len(stub.scopes) != len(scopes) ||
		stub.request.Token != "proof" || stub.request.Context.RequestID != "request-1" ||
		stub.request.Context.TraceID != "trace-1" || !bytes.Equal(stub.request.ResourceBindingDigest, binding) {
		t.Fatalf("MFA request mapping drifted: actor=%+v scopes=%v request=%+v", stub.actor, stub.scopes, stub.request)
	}
}

func TestManagedPasswordResetStepUpAdapterFailsClosed(t *testing.T) {
	if adapter, err := newManagedPasswordResetStepUpAdapter(nil); adapter != nil ||
		!errors.Is(err, identity.ErrManagedPasswordResetUnavailable) {
		t.Fatalf("nil consumer = (%T, %v)", adapter, err)
	}
	adapter, err := newManagedPasswordResetStepUpAdapter(&managedPasswordResetStepUpStub{err: mfa.ErrUnavailable})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.BeginManagedPasswordResetAuthorityMutation(t.Context(), nil, []uuid.UUID{uuid.New()}); !errors.Is(err, identity.ErrManagedPasswordResetUnavailable) {
		t.Fatalf("nil transaction begin error = %v", err)
	}
	if _, err := adapter.ConsumeManagedPasswordResetStepUp(t.Context(), nil,
		identity.ManagedPasswordResetStepUpActor{}, nil, identity.ManagedPasswordResetStepUpRequest{}); !errors.Is(err, identity.ErrManagedPasswordResetUnavailable) {
		t.Fatalf("MFA unavailable mapping error = %v", err)
	}
}

func TestControlAPIMountsManagedPasswordResetStepUpAdapter(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"newManagedPasswordResetStepUpAdapter(mfaRuntime.StepUpConsumer())",
		"identityService.SetManagedPasswordResetStepUpConsumer(managedPasswordResetStepUp)",
	} {
		if !bytes.Contains(source, []byte(required)) {
			t.Errorf("control-api managed password reset composition missing %q", required)
		}
	}
}

var _ identity.ManagedPasswordResetStepUpConsumer = (*managedPasswordResetStepUpAdapter)(nil)
