package qualitydiagnosticshttp

import (
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/qualitydiagnostics"
)

type ProductionConfig struct {
	Source  analyticslog.FinalizedAccessConfig
	Service qualitydiagnostics.RuntimeConfig
	Handler Config
}

type ProductionDependencies struct {
	Client       *analyticslog.Client
	Authenticate Authenticator
}

func NewProductionHandler(config ProductionConfig, dependencies ProductionDependencies) (*Handler, error) {
	source, err := analyticslog.NewFinalizedAccessSource(dependencies.Client, config.Source)
	if err != nil {
		return nil, err
	}
	authority, err := qualitydiagnostics.NewProductionAccessAuthority(source)
	if err != nil {
		return nil, err
	}
	service, err := qualitydiagnostics.NewRuntimeService(config.Service, qualitydiagnostics.RuntimeDependencies{Authority: authority})
	if err != nil {
		return nil, err
	}
	return NewHandler(service, dependencies.Authenticate, config.Handler)
}
