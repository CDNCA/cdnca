package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfighttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const systemConfigurationRuntimeEnabledEnv = "SYSTEM_CONFIGURATION_RUNTIME_ENABLED"

type systemConfigurationRuntimeConfig struct {
	Enabled bool
}

type systemConfigurationRuntimeDependencies struct {
	Pool      *pgxpool.Pool
	Identity  *identity.Service
	Expansion systemconfig.ExpansionAuthorizer
	Publisher systemconfig.ActivationPublisher
}

// denySystemConfigurationExpansion is default-deny. The three canonical
// control-plane categories below are non-metered and never consume tenant quotas.
type denySystemConfigurationExpansion struct {
	Entitlement *entitlementguard.Guard
}

func (authorizer denySystemConfigurationExpansion) AuthorizeSystemConfigurationExpansion(
	ctx context.Context,
	tx pgx.Tx,
	check systemconfig.ExpansionCheck,
) error {
	if ctx == nil || tx == nil || check.Actor.UserID == uuid.Nil || check.Actor.ScopeID == uuid.Nil ||
		check.Actor.ScopeKind != "platform" || strings.TrimSpace(check.RequestID) == "" {
		return systemconfig.ErrEntitlementDenied
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	switch check.Category {
	case systemconfig.CategoryNginx, systemconfig.CategoryResources, systemconfig.CategoryDefaults:
		return nil
	case systemconfig.CategoryNodeMonitoring:
		if authorizer.Entitlement == nil {
			return systemconfig.ErrEntitlementDenied
		}
		_, err := authorizer.Entitlement.CheckBuiltInNodeMonitoring(ctx, tx, entitlementguard.BuiltInNodeMonitoringCheck{
			TargetScopeID: check.Actor.ScopeID, ActorScopeID: check.Actor.ScopeID, ActorUserID: check.Actor.UserID,
			ResourceType: "system_configuration", ResourceID: check.Actor.ScopeID,
			RequestID: check.RequestID, Operation: "system_configuration.node_monitoring.expand",
		})
		return err
	default:
		return systemconfig.ErrEntitlementDenied
	}
}

func loadSystemConfigurationRuntimeConfig() (systemConfigurationRuntimeConfig, error) {
	return loadSystemConfigurationRuntimeConfigFromEnv(os.Environ())
}

func loadSystemConfigurationRuntimeConfigFromEnv(environment []string) (systemConfigurationRuntimeConfig, error) {
	var value string
	found := false
	unknown := false
	for _, entry := range environment {
		name, candidate, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if name != systemConfigurationRuntimeEnabledEnv {
			unknown = unknown || strings.HasPrefix(name, "SYSTEM_CONFIGURATION_RUNTIME_")
			continue
		}
		if found {
			return systemConfigurationRuntimeConfig{}, errors.New(systemConfigurationRuntimeEnabledEnv + " must be defined exactly once")
		}
		value = candidate
		found = true
	}

	switch value {
	case "", "false":
		return systemConfigurationRuntimeConfig{}, nil
	case "true":
		if unknown {
			return systemConfigurationRuntimeConfig{}, errors.New("system configuration runtime contains unsupported environment structure")
		}
		return systemConfigurationRuntimeConfig{Enabled: true}, nil
	default:
		return systemConfigurationRuntimeConfig{}, errors.New(systemConfigurationRuntimeEnabledEnv + " must be true or false")
	}
}

func buildSystemConfigurationHandlerFactory(
	config systemConfigurationRuntimeConfig,
	dependencies systemConfigurationRuntimeDependencies,
) (httpapi.MountedHandlerFactory, error) {
	if !config.Enabled {
		return nil, nil
	}
	if dependencies.Pool == nil || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.Expansion == nil || dependencies.Publisher == nil {
		return nil, errors.New("system configuration runtime dependencies are incomplete")
	}
	return func() (http.Handler, error) {
		return NewSystemConfigurationRuntimeHandler(
			dependencies.Pool,
			dependencies.Identity,
			dependencies.Expansion,
			dependencies.Publisher,
		)
	}, nil
}

// NewSystemConfigurationRuntimeHandler is the shared httpapi integration boundary.
// A nil expansion authorizer intentionally permits only proven contraction/disable writes.
func NewSystemConfigurationRuntimeHandler(
	pool *pgxpool.Pool,
	identityService *identity.Service,
	expansion systemconfig.ExpansionAuthorizer,
	publisher systemconfig.ActivationPublisher,
) (http.Handler, error) {
	if pool == nil || identityService == nil || !identityService.Configured() || publisher == nil {
		return nil, systemconfighttp.ErrInvalidDependencies
	}
	core, err := systemconfig.NewServiceWithPublisher(pool, audit.New(pool), time.Now, publisher)
	if err != nil {
		return nil, err
	}
	manager, err := systemconfig.NewCategoryManager(core, expansion)
	if err != nil {
		return nil, err
	}
	return systemconfighttp.NewHandler(manager,
		func(request *http.Request, rawSession string) (identity.AuthenticatedSession, error) {
			session, err := identityService.AuthenticateSession(request.Context(), rawSession)
			switch {
			case err == nil:
				return session, nil
			case errors.Is(err, identity.ErrInvalidSession):
				return identity.AuthenticatedSession{}, systemconfighttp.ErrUnauthenticated
			case request.Context().Err() != nil:
				return identity.AuthenticatedSession{}, request.Context().Err()
			default:
				return identity.AuthenticatedSession{}, systemconfighttp.ErrUnavailable
			}
		}, systemconfighttp.HandlerConfig{})
}

// runBootstrapSystemConfiguration activates the project default system
// configuration on a fresh installation (see systemconfig.BootstrapDefaultActivation).
func runBootstrapSystemConfiguration(args []string) error {
	flags := flag.NewFlagSet("bootstrap-system-configuration", flag.ContinueOnError)
	username := flags.String("username", "", "platform administrator username")
	if err := flags.Parse(args); err != nil {
		return err
	}
	*username = strings.ToLower(strings.TrimSpace(*username))
	if flags.NArg() != 0 || len(*username) < 3 || len(*username) > 128 {
		return errors.New("username is required")
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	actor := systemconfig.Actor{ScopeKind: "platform"}
	err = pool.QueryRow(ctx, `
		SELECT u.id, scope.id
		FROM users u
		JOIN memberships membership ON membership.user_id=u.id AND membership.status='active'
		JOIN access_scopes scope ON scope.id=membership.scope_id AND scope.kind='platform'
		JOIN role_assignments assignment ON assignment.scope_id=scope.id AND assignment.user_id=u.id
		JOIN roles role ON role.id=assignment.role_id AND role.system_role
		JOIN role_permissions grant_row ON grant_row.role_id=role.id AND grant_row.permission_name='system_configuration.manage'
		WHERE u.username=$1 AND u.status='active'
		LIMIT 1`, *username).Scan(&actor.UserID, &actor.ScopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("platform administrator %q with system_configuration.manage was not found", *username)
	}
	if err != nil {
		return fmt.Errorf("find platform administrator: %w", err)
	}
	service, err := systemconfig.NewService(pool)
	if err != nil {
		return err
	}
	result, err := systemconfig.BootstrapDefaultActivation(ctx, service, actor)
	if err != nil {
		return fmt.Errorf("bootstrap system configuration: %w", err)
	}
	fmt.Printf("system configuration %s: revision=%d\n", result.Outcome, result.Revision)
	return nil
}
