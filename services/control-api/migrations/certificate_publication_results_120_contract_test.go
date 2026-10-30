package migrations_test

import (
	"io/fs"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestCertificatePublicationResultsMigration120Contract47(t *testing.T) {
	up := certificatePublicationMigration120(t, "up")
	for _, required := range []string{
		"migration 120 requires the exact verified 119 release head",
            "2a7e7b88433941e3e9eae3567476d261efb5382d9a1dca4900e852a2dcd6b318",
            "06305ea2ffdf4260a788a475e803a037f449b5ae939449632c8967d269992b22",
		"actor_session_id uuid",
		"actor_scope_kind text",
		"actor_user_revision bigint",
		"target_tenant_id uuid",
		"target_tenant_revision bigint",
		"publication_id uuid",
		"publication_revision bigint",
		"config_version_id uuid",
		"rollout_id uuid",
		"rollout_revision bigint",
		"REFERENCES auth_sessions(id,scope_id,user_id)",
		"REFERENCES tenants(id)",
		"state='succeeded'",
		"publication_id IS NOT NULL",
		"state<>'succeeded'",
		"publication_id IS NULL",
		"deadline_at timestamptz",
		"legacy_reissue_required",
		"previous_latest.state NOT IN ('succeeded','permanent_failed')",
		"UPDATE certificate_publication_intents",
	} {
		if !strings.Contains(compactCertificatePublicationSQL120(up), compactCertificatePublicationSQL120(required)) {
			t.Errorf("migration 120 up contract missing %q", required)
		}
	}
	for _, forbidden := range []string{"raw_token", "bearer", "refresh_token", "private_key", "certificate_pem"} {
		if strings.Contains(strings.ToLower(up), forbidden) {
			t.Errorf("migration 120 persists forbidden secret field %q", forbidden)
		}
	}
	if strings.Contains(compactCertificatePublicationSQL120(up), "migration 120 cannot invent historical certificate publication actor references") {
		t.Fatal("migration 120 still rejects populated 119 intents")
	}
}

func TestCertificatePublicationResultsMigration120DownIsLossGuarded47(t *testing.T) {
	down := certificatePublicationMigration120(t, "down")
	for _, required := range []string{
		"migration 120 rollback requires the exact verified 120 head",
		"migration 120 rollback would discard certificate publication actor or result facts",
		"DROP COLUMN actor_session_id",
		"DROP COLUMN publication_id",
	} {
		if !strings.Contains(compactCertificatePublicationSQL120(down), compactCertificatePublicationSQL120(required)) {
			t.Errorf("migration 120 down contract missing %q", required)
		}
	}
}

func certificatePublicationMigration120(t *testing.T, direction string) string {
	t.Helper()
	content, err := fs.ReadFile(controlmigrations.FS, "120_certificate_publication_results."+direction+".sql")
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func compactCertificatePublicationSQL120(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
