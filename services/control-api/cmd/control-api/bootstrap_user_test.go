package main

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestBootstrapDatabaseURLPreservesSchema(t *testing.T) {
	for _, test := range []struct {
		name string
		dsn  string
	}{
		{"url", "postgres://bootstrap@localhost:5433/bootstrap_test?application_name=bootstrap-test"},
		{"url-existing-schema", "postgresql://bootstrap@localhost:5433/bootstrap_test?search_path=public&application_name=bootstrap-test"},
		{"keyword", "host=localhost port=5433 user=bootstrap dbname=bootstrap_test search_path=public application_name=bootstrap-test"},
		{"socket-keyword", "host=/tmp port=5433 user=bootstrap dbname=bootstrap_test application_name=bootstrap-test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := pgxpool.ParseConfig(test.dsn)
			if err != nil {
				t.Fatal("cannot parse test database configuration")
			}
			const schema = "bootstrap_isolated_test_schema"
			config.ConnConfig.RuntimeParams["search_path"] = schema
			isolated, err := pgxpool.ParseConfig(bootstrapTestDatabaseURL(t, config))
			if err != nil {
				t.Fatal("cannot parse isolated test database configuration")
			}
			if isolated.ConnConfig.RuntimeParams["search_path"] != schema {
				t.Fatal("bootstrap connection lost its isolated schema")
			}
			if isolated.ConnConfig.Host != config.ConnConfig.Host || isolated.ConnConfig.Port != config.ConnConfig.Port ||
				isolated.ConnConfig.Database != config.ConnConfig.Database || isolated.ConnConfig.User != config.ConnConfig.User ||
				isolated.ConnConfig.RuntimeParams["application_name"] != config.ConnConfig.RuntimeParams["application_name"] {
				t.Fatal("bootstrap connection changed unrelated database configuration")
			}
		})
	}
}

func bootstrapTestDatabaseURL(t *testing.T, config *pgxpool.Config) string {
	t.Helper()
	schema := config.ConnConfig.RuntimeParams["search_path"]
	if schema == "" {
		t.Fatal("bootstrap test requires an isolated schema")
	}
	dsn := config.ConnString()
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		parsed, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("cannot parse bootstrap test database URL")
		}
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		dsn = parsed.String()
	} else {
		escaped := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(schema)
		dsn += " search_path='" + escaped + "'"
	}
	parsed, err := pgxpool.ParseConfig(dsn)
	if err != nil || parsed.ConnConfig.RuntimeParams["search_path"] != schema {
		t.Fatal("bootstrap test connection must preserve its isolated schema")
	}
	return dsn
}

func TestBootstrapExistingOwnerRequiresMatchingPassword(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	const password = "bootstrap-test-owner-password"
	hash, err := identity.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	_, err = identity.NewStore(pool).BootstrapPlatformUserWithEmail(
		t.Context(), "bootstrap-test-owner", "Bootstrap Test Owner", "bootstrap@example.invalid",
		hash, "bootstrap-test-owner-create",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", bootstrapTestDatabaseURL(t, pool.Config()))
	for _, test := range []struct {
		name     string
		password string
		conflict bool
	}{
		{name: "matching", password: password},
		{name: "mismatching", password: "different-test-password", conflict: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("BOOTSTRAP_PASSWORD", test.password)
			err := runBootstrapUser([]string{
				"--username", "bootstrap-test-owner", "--display-name", "Bootstrap Test Owner",
				"--email", "bootstrap@example.invalid", "--existing-ok",
			})
			if test.conflict {
				if !errors.Is(err, identity.ErrConflict) {
					t.Fatalf("mismatching password returned %v, want conflict", err)
				}
			} else if err != nil {
				t.Fatalf("matching password returned %v", err)
			}
		})
	}
}
