package challengepolicy

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrPublicationNotReady = errors.New("challenge policy is not ready for publication")

type PublicationSnapshot struct {
	PolicyID, TenantScopeID, TenantID, SiteID uuid.UUID
	Host                                      string
	Revision                                  int64
	Priority                                  int
	Mode                                      string
	MinDelaySeconds                           int
	ChallengeTTLSeconds                       int
	PassTTLSeconds                            int
	ClockSkewSeconds                          int
	AttemptsPerNonce                          int
	FailureWindowSeconds                      int
	MaxFailuresPerWindow                      int
	IPBinding                                 string
	BindUserAgent                             bool
	BypassRoutes                              []BypassRoute
	KeyReference                              string
	ExternalProvider                          *ExternalProviderReference
}

type PublicationConsumer func(context.Context, pgx.Tx, PublicationSnapshot) error

// UsePublicationSnapshot locks and authorizes the exact active revision in the
// caller's transaction so secret and configuration publication cannot observe
// different policy facts.
func (service *Service) UsePublicationSnapshot(
	ctx context.Context,
	actor Actor,
	targetScopeID, policyID uuid.UUID,
	expectedRevision int64,
	consume PublicationConsumer,
) error {
	if service == nil || service.store == nil || ctx == nil || targetScopeID == uuid.Nil || policyID == uuid.Nil ||
		expectedRevision < 1 || consume == nil {
		return ErrInvalidInput
	}
	err := pgx.BeginFunc(ctx, service.store.pool, func(tx pgx.Tx) error {
		if _, err := service.store.authorize(ctx, tx, actor, targetScopeID, PermissionManage); err != nil {
			return err
		}
		item, err := lockPolicy(ctx, tx, targetScopeID, policyID)
		if err != nil {
			return err
		}
		snapshot, err := publicationSnapshot(item, expectedRevision)
		if err != nil {
			return err
		}
		return consume(ctx, tx, snapshot)
	})
	return normalizeStoreError(err)
}

func (service *Service) ReadPublicationSnapshot(
	ctx context.Context,
	actor Actor,
	targetScopeID, policyID uuid.UUID,
	consume PublicationConsumer,
) error {
	if service == nil || service.store == nil || ctx == nil || targetScopeID == uuid.Nil || policyID == uuid.Nil ||
		consume == nil {
		return ErrInvalidInput
	}
	err := pgx.BeginFunc(ctx, service.store.pool, func(tx pgx.Tx) error {
		if _, err := service.store.authorize(ctx, tx, actor, targetScopeID, PermissionRead); err != nil {
			return err
		}
		item, err := lockPolicy(ctx, tx, targetScopeID, policyID)
		if err != nil {
			return err
		}
		snapshot, err := publicationSnapshot(item, item.Revision)
		if err != nil {
			return err
		}
		return consume(ctx, tx, snapshot)
	})
	return normalizeStoreError(err)
}

func publicationSnapshot(item storedPolicy, expectedRevision int64) (PublicationSnapshot, error) {
	if item.ID == uuid.Nil || item.TenantScopeID == uuid.Nil || item.TenantID == uuid.Nil || item.SiteID == uuid.Nil ||
		item.Revision != expectedRevision || !item.Enabled || item.Deleted || item.KeyReference == "" {
		return PublicationSnapshot{}, ErrPublicationNotReady
	}
	result := PublicationSnapshot{
		PolicyID: item.ID, TenantScopeID: item.TenantScopeID, TenantID: item.TenantID, SiteID: item.SiteID,
		Host: item.Host, Revision: item.Revision, Priority: item.Priority, Mode: item.Mode,
		MinDelaySeconds: item.MinDelaySeconds, ChallengeTTLSeconds: item.ChallengeTTLSeconds,
		PassTTLSeconds: item.PassTTLSeconds, ClockSkewSeconds: item.ClockSkewSeconds,
		AttemptsPerNonce: item.AttemptsPerNonce, FailureWindowSeconds: item.FailureWindowSeconds,
		MaxFailuresPerWindow: item.MaxFailuresPerWindow, IPBinding: item.IPBinding,
		BindUserAgent: item.BindUserAgent, BypassRoutes: append([]BypassRoute(nil), item.BypassRoutes...),
		KeyReference: item.KeyReference,
	}
	if item.External != nil {
		provider := *item.External
		result.ExternalProvider = &provider
	}
	return result, nil
}
