package edgepublish

import (
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrInvalidRuntimeConfig = errors.New("invalid edge publication runtime configuration")

type RuntimeConfig struct {
	Publisher Config
}

type RuntimeDependencies struct {
	Pool   *pgxpool.Pool
	Signer ArtifactSigner
	IAM    *iamlock.Authorizer
}

type Runtime struct {
	pool        *pgxpool.Pool
	iam         *iamlock.Authorizer
	publisher   *Service
	deployments *edgedeployment.Store
}

func NewRuntime(config RuntimeConfig, dependencies RuntimeDependencies) (*Runtime, error) {
	if !runtimePoolConfigured(dependencies.Pool) || dependencies.IAM == nil || !dependencies.IAM.Configured() ||
		nilServiceDependency(dependencies.Signer) || nilServiceDependency(config.Publisher.Clock) ||
		nilServiceDependency(config.Publisher.EntitlementAuthorizer) ||
		nilServiceDependency(config.Publisher.TargetResolver) {
		return nil, ErrInvalidRuntimeConfig
	}
	deployments, err := edgedeployment.NewIAMStoreWithClock(
		dependencies.Pool,
		config.Publisher.Clock,
		dependencies.IAM,
	)
	if err != nil {
		return nil, ErrInvalidRuntimeConfig
	}
	publisher, err := NewIAMService(
		dependencies.Pool,
		deployments,
		dependencies.Signer,
		config.Publisher,
		dependencies.IAM,
	)
	if err != nil {
		return nil, ErrInvalidRuntimeConfig
	}
	return &Runtime{
		pool: dependencies.Pool, iam: dependencies.IAM,
		publisher: publisher, deployments: deployments,
	}, nil
}

func (runtime *Runtime) ConfiguredFor(pool *pgxpool.Pool, iam *iamlock.Authorizer) bool {
	return runtime != nil && runtime.pool == pool && runtime.iam == iam &&
		runtimePoolConfigured(pool) && iam != nil && iam.Configured() &&
		runtime.publisher != nil && runtime.deployments != nil
}

func (runtime *Runtime) Publisher() *Service {
	if runtime == nil {
		return nil
	}
	return runtime.publisher
}

func (runtime *Runtime) RolloutCommands() *edgedeployment.Store {
	if runtime == nil {
		return nil
	}
	return runtime.deployments
}

func runtimePoolConfigured(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	config := pool.Config()
	return config != nil && config.MaxConns > 0
}
