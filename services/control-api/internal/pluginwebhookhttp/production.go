package pluginwebhookhttp

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhookcontrol"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProductionDependencies struct {
	Pool        *pgxpool.Pool
	Identity    *identity.Service
	IAM         *iamlock.Authorizer
	Entitlement *entitlementguard.Guard
	Keyring     pluginwebhookcontrol.Keyring
	Targets     pluginwebhookcontrol.TargetValidator
}

func NewProductionHandler(dependencies ProductionDependencies) (*Handler, error) {
	if dependencies.Pool == nil || dependencies.Identity == nil || !dependencies.Identity.Configured() || dependencies.IAM == nil || !dependencies.IAM.Configured() || dependencies.Entitlement == nil || dependencies.Keyring == nil || dependencies.Targets == nil {
		return nil, pluginwebhookcontrol.ErrInvalidConfig
	}
	store, err := pluginwebhookcontrol.NewStore(dependencies.Pool, dependencies.IAM, dependencies.Entitlement, dependencies.Keyring, dependencies.Targets)
	if err != nil {
		return nil, err
	}
	return NewHandler(Dependencies{AuthenticateSession: func(ctx context.Context, raw string) (identity.AuthenticatedSession, error) {
		return dependencies.Identity.AuthenticateSession(ctx, raw)
	}, Store: store})
}
