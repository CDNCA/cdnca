package main

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/cdnca/cdnca/services/control-api/internal/mfahttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type managedPasswordResetStepUpAdapter struct {
	consumer mfahttp.StepUpConsumer
}

func newManagedPasswordResetStepUpAdapter(
	consumer mfahttp.StepUpConsumer,
) (*managedPasswordResetStepUpAdapter, error) {
	if consumer == nil {
		return nil, identity.ErrManagedPasswordResetUnavailable
	}
	return &managedPasswordResetStepUpAdapter{consumer: consumer}, nil
}

func (adapter *managedPasswordResetStepUpAdapter) BeginManagedPasswordResetAuthorityMutation(
	ctx context.Context,
	tx pgx.Tx,
	scopes []uuid.UUID,
) ([]uuid.UUID, error) {
	if adapter == nil || adapter.consumer == nil {
		return nil, identity.ErrManagedPasswordResetUnavailable
	}
	locked, err := iamstage2b.BeginAuthorityMutation(ctx, tx, iamstage2b.OperationMFAConsumeStepUp, scopes)
	if err != nil {
		return nil, identity.ErrManagedPasswordResetUnavailable
	}
	return locked, nil
}

func (adapter *managedPasswordResetStepUpAdapter) ConsumeManagedPasswordResetStepUp(
	ctx context.Context,
	tx pgx.Tx,
	actor identity.ManagedPasswordResetStepUpActor,
	scopes []uuid.UUID,
	request identity.ManagedPasswordResetStepUpRequest,
) (identity.ManagedPasswordResetStepUpEvidence, error) {
	if adapter == nil || adapter.consumer == nil {
		return identity.ManagedPasswordResetStepUpEvidence{}, identity.ErrManagedPasswordResetUnavailable
	}
	evidence, err := adapter.consumer.ConsumeStepUpTxWithScopes(ctx, tx, mfa.Actor{
		UserID: actor.UserID, ScopeID: actor.ScopeID, SessionID: actor.SessionID,
	}, scopes, mfa.ConsumeStepUpRequest{
		Token: request.Token, TenantID: request.TenantID, Audience: request.Audience, Action: request.Action,
		ResourceBindingDigest: append([]byte(nil), request.ResourceBindingDigest...),
		Context:               mfa.RequestContext{RequestID: request.RequestID, TraceID: request.TraceID},
	})
	if errors.Is(err, mfa.ErrUnavailable) {
		return identity.ManagedPasswordResetStepUpEvidence{}, identity.ErrManagedPasswordResetUnavailable
	}
	if err != nil {
		return identity.ManagedPasswordResetStepUpEvidence{}, err
	}
	return identity.ManagedPasswordResetStepUpEvidence{
		ProofID: evidence.ProofID, ActorUserID: evidence.ActorUserID, ActorScopeID: evidence.ActorScopeID,
		SessionID: evidence.SessionID, TenantID: evidence.TenantID, Method: evidence.Method,
		Audience: evidence.Audience, Action: evidence.Action, VerifiedAt: evidence.VerifiedAt,
		ExpiresAt: evidence.ExpiresAt, UseOrdinal: evidence.UseOrdinal,
		ResourceBindingDigest: append([]byte(nil), evidence.ResourceBindingDigest...),
	}, nil
}
