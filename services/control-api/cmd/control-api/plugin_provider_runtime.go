package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/pluginprovider"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginproviders"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Third-party provider plugins (PA-22/PA-23): one service shared by the
// admin handler, the contract runner and the DNS / SMS / ICP / payment
// adapters. Without
// an installation identity the service has no signer: nothing can pass a
// contract, so no provider plugin is ever used.
var pluginProviderRuntime struct {
	once    sync.Once
	service *pluginproviders.Service
	err     error
	wake    chan struct{}
}

func pluginProviderService(cfg config.Config, pool *pgxpool.Pool) (*pluginproviders.Service, error) {
	pluginProviderRuntime.once.Do(func() {
		if pool == nil {
			return
		}
		service := &pluginproviders.Service{Store: pluginproviders.NewStore(pool, time.Now)}
		if cfg.ControlInstallationID != "" && cfg.ControlInstallationKeyFile != "" {
			installationID, err := uuid.Parse(cfg.ControlInstallationID)
			if err != nil || installationID.String() != cfg.ControlInstallationID {
				pluginProviderRuntime.err = errors.New("plugin providers require a canonical control installation UUID")
				return
			}
			key, err := entitlementsync.LoadPrivateKey(cfg.ControlInstallationKeyFile)
			if err != nil {
				pluginProviderRuntime.err = err
				return
			}
			if len(key) != ed25519.PrivateKeySize {
				pluginProviderRuntime.err = errors.New("plugin provider installation key is invalid")
				return
			}
			if service.Signer, err = pluginproviders.NewSigner(installationID, key); err != nil {
				pluginProviderRuntime.err = err
				return
			}
		}
		pluginProviderRuntime.service = service
		pluginProviderRuntime.wake = make(chan struct{}, 1)
		// DNS provider type plugin: chosen (verified) and written through the
		// same usability gate.
		dnsacme.SetPluginProviderClients(service)
		dnsproviderremote.SetPluginClients(service)
	})
	return pluginProviderRuntime.service, pluginProviderRuntime.err
}

// wakePluginProviderContracts asks the runner to check pending contracts
// (called after an artifact sync round changed local artifacts).
func wakePluginProviderContracts() {
	if pluginProviderRuntime.wake == nil {
		return
	}
	select {
	case pluginProviderRuntime.wake <- struct{}{}:
	default:
	}
}

// runPluginProviderContracts runs pending contracts at start, when woken
// and every interval.
func runPluginProviderContracts(ctx context.Context, service *pluginproviders.Service, interval time.Duration) {
	if service == nil || pluginProviderRuntime.wake == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		service.RunPending(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-pluginProviderRuntime.wake:
		}
	}
}

func buildPluginProviderHandlerFactory(cfg config.Config, pool *pgxpool.Pool,
	identityService *identity.Service) (httpapi.MountedHandlerFactory, error) {
	if pool == nil || identityService == nil || !identityService.Configured() {
		return nil, nil
	}
	service, err := pluginProviderService(cfg, pool)
	if err != nil || service == nil {
		return nil, err
	}
	return func() (http.Handler, error) {
		return pluginproviders.NewHandler(service, func(request *http.Request, raw string) (identity.AuthenticatedSession, error) {
			return identityService.AuthenticateSession(context.WithoutCancel(request.Context()), raw)
		})
	}, nil
}

// lazyPluginProviderClients resolves the provider plugin service when a
// plugin is used (the notification runtime opens before the plugin routes;
// pluginProviderService is built once). Without the service (no
// installation identity) no plugin is usable.
type lazyPluginProviderClients struct {
	cfg  config.Config
	pool *pgxpool.Pool
}

func (clients lazyPluginProviderClients) Client(ctx context.Context, pluginID, kind string) (*pluginprovider.Client, error) {
	if service, err := pluginProviderService(clients.cfg, clients.pool); err == nil && service != nil {
		return service.Client(ctx, pluginID, kind)
	}
	return nil, pluginproviders.ErrNotUsable
}
