package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/l4lineswitch"
	"github.com/cdnca/cdnca/services/control-api/internal/l4lineswitchhttp"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

type l4LineSwitchRuntimeDependencies struct {
	Pool        *pgxpool.Pool
	Identity    *identity.Service
	IAM         *iamlock.Authorizer
	Deployments *edgedeployment.Store
	NATS        *nats.Conn
	Clock       func() time.Time
}

type l4LineSwitchRuntime struct {
	HandlerFactory httpapi.MountedHandlerFactory
	Reconciler     *l4lineswitch.Reconciler
}

func openL4LineSwitchRuntime(dependencies l4LineSwitchRuntimeDependencies) (l4LineSwitchRuntime, error) {
	if dependencies.Deployments == nil {
		return l4LineSwitchRuntime{}, nil
	}
	if !configuredRuntimePool(dependencies.Pool) || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.IAM == nil || !dependencies.IAM.Configured() || dependencies.NATS == nil ||
		dependencies.NATS.IsClosed() || dependencies.Clock == nil {
		return l4LineSwitchRuntime{}, errors.New("L4 line switch production dependencies are required")
	}
	store, err := l4lineswitch.NewPostgresStore(dependencies.Pool, dependencies.IAM, nil)
	if err != nil {
		return l4LineSwitchRuntime{}, err
	}
	snapshots, err := l4lineswitch.NewPostgresSnapshotResolver(dependencies.Pool, dependencies.IAM)
	if err != nil {
		return l4LineSwitchRuntime{}, err
	}
	publications, err := l4lineswitch.NewPostgresPublicationCoordinator(
		dependencies.Pool, dependencies.IAM, dependencies.Deployments, nil,
	)
	if err != nil {
		return l4LineSwitchRuntime{}, err
	}
	targets, err := l4lineswitch.NewPostgresTargetCoordinator(dependencies.Pool, dependencies.IAM, nil)
	if err != nil {
		return l4LineSwitchRuntime{}, err
	}
	plans, err := l4lineswitch.NewPostgresDrainPlanSource(dependencies.Pool, dependencies.IAM, nil)
	if err != nil {
		return l4LineSwitchRuntime{}, err
	}
	drains, err := l4lineswitch.NewJetStreamDrainCoordinator(
		dependencies.NATS, plans, l4lineswitch.DefaultJetStreamDrainConfig(), dependencies.Clock,
	)
	if err != nil {
		return l4LineSwitchRuntime{}, err
	}
	service, err := l4lineswitch.NewService(store, snapshots, publications, targets, drains, dependencies.Clock)
	if err != nil {
		return l4LineSwitchRuntime{}, err
	}
	dnsGate, err := l4lineswitch.NewPostgresDNSGate(dependencies.Pool, dependencies.IAM)
	if err != nil {
		return l4LineSwitchRuntime{}, err
	}
	service.SetDNSGate(dnsGate)
	handler, err := l4lineswitchhttp.NewHandler(service, l4lineswitchhttp.AuthenticatorFunc(func(request *http.Request) (l4lineswitch.Actor, error) {
		values := request.Header.Values("Authorization")
		if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
			return l4lineswitch.Actor{}, identity.ErrInvalidSession
		}
		raw := strings.TrimPrefix(values[0], "Bearer ")
		if raw == "" || len(raw) > 8192 || strings.ContainsAny(raw, " \t\r\n,") || values[0] != "Bearer "+raw {
			return l4lineswitch.Actor{}, identity.ErrInvalidSession
		}
		authenticated, err := dependencies.Identity.AuthenticateSession(request.Context(), raw)
		if err != nil {
			return l4lineswitch.Actor{}, err
		}
		return l4lineswitch.Actor{
			UserID: authenticated.Principal.UserID, ScopeID: authenticated.Principal.ScopeID,
			SessionID: authenticated.SessionID, ScopeKind: authenticated.Principal.ScopeKind, Credential: raw,
		}, nil
	}))
	if err != nil {
		return l4LineSwitchRuntime{}, err
	}
	reconciler, err := l4lineswitch.NewReconciler(store, service, l4lineswitch.DefaultReconcilerConfig())
	if err != nil {
		return l4LineSwitchRuntime{}, err
	}
	return l4LineSwitchRuntime{
		HandlerFactory: func() (http.Handler, error) { return handler, nil },
		Reconciler:     reconciler,
	}, nil
}
