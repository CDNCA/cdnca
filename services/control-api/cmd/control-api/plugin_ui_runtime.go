package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginuihttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pluginUIOrigins is the frame-src source list of the enabled ui_page
// plugins (PA-19), for the web nginx CSP lookup.
func pluginUIOrigins(pool *pgxpool.Pool) func(context.Context) (string, error) {
	store := pluginuihttp.PostgresStore{Pool: pool}
	return func(ctx context.Context) (string, error) {
		plugins, err := store.ActivePlugins(ctx)
		if err != nil {
			return "", err
		}
		return pluginuihttp.CSPOrigins(plugins), nil
	}
}

// pluginUISigner loads the installation key the proxy signs with; nil
// (proxy unavailable, pages still mount) when the installation is not
// configured.
func pluginUISigner(cfg config.Config) (*pluginuihttp.Signer, error) {
	if cfg.ControlInstallationID == "" || cfg.ControlInstallationKeyFile == "" {
		return nil, nil
	}
	installationID, err := uuid.Parse(cfg.ControlInstallationID)
	if err != nil || installationID == uuid.Nil || installationID.String() != cfg.ControlInstallationID {
		return nil, errors.New("plugin ui proxy requires a canonical control installation UUID")
	}
	key, err := entitlementsync.LoadPrivateKey(cfg.ControlInstallationKeyFile)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("plugin ui proxy installation key is invalid")
	}
	return &pluginuihttp.Signer{InstallationID: installationID, PrivateKey: key}, nil
}

func buildPluginUIHandlerFactory(cfg config.Config, pool *pgxpool.Pool, identityService *identity.Service,
	trust *entitlementguard.TrustStore) (httpapi.MountedHandlerFactory, error) {
	if pool == nil || identityService == nil || !identityService.Configured() {
		return nil, nil
	}
	signer, err := pluginUISigner(cfg)
	if err != nil {
		return nil, err
	}
	guard := entitlementguard.NewGuard(pool, time.Now, trust)
	return func() (http.Handler, error) {
		return pluginuihttp.New(pluginuihttp.Config{
			Store: pluginuihttp.PostgresStore{Pool: pool},
			Authenticate: func(request *http.Request, raw string) (identity.AuthenticatedSession, error) {
				return identityService.AuthenticateSession(context.WithoutCancel(request.Context()), raw)
			},
			Modules: func(ctx context.Context) ([]string, error) {
				var grants entitlementguard.ModuleGrants
				err := pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
					var err error
					grants, err = guard.GrantedModules(ctx, tx)
					return err
				})
				return grants.Codes, err
			},
			Sites:   pluginuihttp.PostgresSites{Pool: pool},
			Auditor: pluginuihttp.PostgresAuditor{Pool: pool, Log: audit.New(pool)},
			Signer:  signer,
		})
	}, nil
}
