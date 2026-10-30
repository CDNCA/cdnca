package errorpagecontrolhttp

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpageobjectstore"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagescanner"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	Enabled     bool
	ObjectStore errorpageobjectstore.Config
	Scanner     errorpagescanner.Config
}

type Dependencies struct {
	Pool             *pgxpool.Pool
	Identity         *identity.Service
	APIKeys          *apikey.Service
	IAM              *iamlock.Authorizer
	EntitlementTrust *entitlementguard.TrustStore
	Clock            errorpagecontrol.Clock
	ContentStore     errorpagecontrol.ContentStore
	Scanner          errorpagecontrol.Scanner
}

func NewRuntime(ctx context.Context, config Config, dependencies Dependencies) (*errorpagecontrol.Runtime, error) {
	if !config.Enabled {
		return errorpagecontrol.NewRuntimeHandler(errorpagecontrol.RuntimeConfig{}, errorpagecontrol.RuntimeDependencies{})
	}
	if ctx == nil || dependencies.Pool == nil || dependencies.Identity == nil || dependencies.APIKeys == nil ||
		dependencies.IAM == nil ||
		dependencies.EntitlementTrust == nil || dependencies.Clock == nil {
		return nil, errorpagecontrol.ErrInvalidStore
	}
	limits, err := errorpagecontrol.NewVerifiedLeaseLimitProvider(
		dependencies.Pool, dependencies.EntitlementTrust, dependencies.Clock,
	)
	if err != nil {
		return nil, err
	}
	objects, scanner, err := resolveAdapters(ctx, config, dependencies)
	if err != nil {
		return nil, err
	}
	return errorpagecontrol.NewRuntimeHandler(
		errorpagecontrol.RuntimeConfig{Enabled: true},
		errorpagecontrol.RuntimeDependencies{
			Pool: dependencies.Pool, Identity: dependencies.Identity, APIKeys: dependencies.APIKeys,
			IAM:          dependencies.IAM,
			ContentStore: objects, Scanner: scanner, Limits: limits,
			SlotRepublisher: edgepublish.SlotErrorPageRepublisher{},
		},
	)
}

// resolveAdapters prefers composition-root instances and only constructs the
// legacy config-based adapters when no instance was supplied.
func resolveAdapters(
	ctx context.Context,
	config Config,
	dependencies Dependencies,
) (errorpagecontrol.ContentStore, errorpagecontrol.Scanner, error) {
	scanner := dependencies.Scanner
	if scanner == nil {
		created, err := errorpagescanner.New(ctx, config.Scanner)
		if err != nil {
			return nil, nil, err
		}
		scanner = created
	}
	objects := dependencies.ContentStore
	if objects == nil {
		created, err := errorpageobjectstore.New(ctx, config.ObjectStore)
		if err != nil {
			return nil, nil, err
		}
		objects = created
	}
	return objects, scanner, nil
}
