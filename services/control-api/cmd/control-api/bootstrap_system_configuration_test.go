package main

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/jackc/pgx/v5"
)

func TestBootstrapSystemConfigurationRejectsInvalidArguments(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	for _, args := range [][]string{nil, {"--username", "ab"}, {"--username", "admin", "extra"}} {
		if err := runBootstrapSystemConfiguration(args); err == nil {
			t.Fatalf("arguments %q were accepted", args)
		}
	}
	if err := runBootstrapSystemConfiguration([]string{"--username", "admin"}); err == nil ||
		!strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("missing DATABASE_URL error = %v", err)
	}
	if err := run([]string{"bootstrap-system-configuration"}); err == nil || strings.HasPrefix(err.Error(), "usage:") {
		t.Fatalf("command is not dispatched: %v", err)
	}
}

func TestBootstrapSystemConfigurationActivatesDefaultMonitoringIdempotently(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	hash, err := identity.HashPassword("bootstrap-system-configuration-password")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := identity.NewStore(pool).BootstrapPlatformUserWithEmail(
		t.Context(), "bootstrap-config-owner", "Bootstrap Config Owner", "config@example.invalid",
		hash, "bootstrap-config-owner-create",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", bootstrapTestDatabaseURL(t, pool.Config()))
	for range 2 {
		if err := runBootstrapSystemConfiguration([]string{"--username", "bootstrap-config-owner"}); err != nil {
			t.Fatal(err)
		}
	}
	var monitoring systemconfig.MonitoringConfiguration
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var err error
		monitoring, err = systemconfig.ReadNodeMonitoringConfiguration(t.Context(), tx, owner.ScopeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if monitoring.State != "active" || monitoring.ActiveRevision == nil || *monitoring.ActiveRevision != 1 ||
		monitoring.Policy == nil || monitoring.Policy.RequestedProtocol != "tcp" {
		t.Fatalf("node monitoring after bootstrap = %#v", monitoring)
	}
	var revisions int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM system_configuration_revisions`).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if revisions != 1 {
		t.Fatalf("revisions after two runs = %d, want 1", revisions)
	}
}
