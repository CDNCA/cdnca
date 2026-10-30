package dashboardhttp

import (
	"github.com/cdnca/cdnca/services/control-api/internal/dashboard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProductionConfig struct {
	Reader dashboard.ProductionConfig
	HTTP   Config
}

type ProductionDependencies struct {
	Pool      *pgxpool.Pool
	Identity  *identity.Service
	IAM       *iamlock.Authorizer
	Analytics dashboard.AnalyticsReader
}

func NewProductionHandler(config ProductionConfig, dependencies ProductionDependencies) (*Handler, error) {
	if !productionDependenciesReady(dependencies) {
		return nil, dashboard.ErrInvalidConfig
	}
	reader, err := dashboard.NewProductionStore(config.Reader, dashboard.ProductionDependencies{
		Pool: dependencies.Pool, Authorizer: dependencies.IAM, Analytics: dependencies.Analytics,
	})
	if err != nil {
		return nil, err
	}
	return NewHandler(dependencies.Identity, reader, config.HTTP)
}

func productionDependenciesReady(dependencies ProductionDependencies) (ready bool) {
	if dependencies.Pool == nil || dependencies.Identity == nil || dependencies.IAM == nil ||
		!dependencies.Identity.Configured() || !dependencies.IAM.Configured() {
		return false
	}
	defer func() {
		if recover() != nil {
			ready = false
		}
	}()
	config := dependencies.Pool.Config()
	return config != nil && config.ConnConfig != nil && config.MaxConns > 0
}
