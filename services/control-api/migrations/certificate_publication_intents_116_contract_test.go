package migrations_test

import (
	"io/fs"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestCertificatePublicationIntentMigration116Contract39(t *testing.T) {
	up := certificatePublicationMigration116(t, "up")
	for _, required := range []string{
		"migration 116 requires the exact verified 115 release head",
		"7cb3487ac88e30576b9553f587c4c0f91973899db6863ecb427eed237ce0875f",
		"008dd22e6504db2f602693abc94e14e9a094cbfa4a46f3d553c8c694325aced3",
		"ADD COLUMN binding_xact_id xid8 NOT NULL DEFAULT pg_current_xact_id()",
		"CREATE TABLE certificate_publication_intents",
		"PRIMARY KEY (tenant_scope_id,site_id,binding_revision)",
		"operation text NOT NULL CHECK (operation IN ('publish','unpublish'))",
		"publication_xact_id xid8 NOT NULL DEFAULT pg_current_xact_id()",
		"FOREIGN KEY (tenant_scope_id,site_id,binding_revision)",
		"REFERENCES certificate_site_binding_facts(tenant_scope_id,site_id,sequence)",
		"FOREIGN KEY (tenant_scope_id,asset_id,version_id)",
		"FOREIGN KEY (actor_scope_id,actor_user_id)",
		"created_at timestamptz NOT NULL DEFAULT transaction_timestamp()",
		"certificate_publication_intents_immutable_116",
		"certificate_publication_intents_no_truncate_116",
		"certificate_binding_requires_intent_116",
		"DEFERRABLE INITIALLY DEFERRED",
		"binding.binding_xact_id IS DISTINCT FROM NEW.publication_xact_id",
		"intent.publication_xact_id=NEW.binding_xact_id",
		"NEW.operation IS DISTINCT FROM (CASE binding.action WHEN 'bind' THEN 'publish' ELSE 'unpublish' END)",
		"intent.operation=(CASE NEW.action WHEN 'bind' THEN 'publish' ELSE 'unpublish' END)",
		"NEW.created_at IS DISTINCT FROM transaction_timestamp()",
	} {
		if !strings.Contains(compactCertificatePublicationSQL116(up), compactCertificatePublicationSQL116(required)) {
			t.Errorf("migration 116 up contract missing %q", required)
		}
	}
	for _, forbidden := range []string{"private_key", "ciphertext", "nonce", "certificate_pem", "key_reference"} {
		if strings.Contains(strings.ToLower(up), forbidden) {
			t.Errorf("migration 116 intent schema contains private material field %q", forbidden)
		}
	}
}

func TestCertificatePublicationIntentMigration116DownIsLossGuarded39(t *testing.T) {
	down := certificatePublicationMigration116(t, "down")
	for _, required := range []string{
		"migration 116 rollback requires the exact verified 116 head",
		"c2cc44a6432bc5816ba31e1b49749a43963b3a620b36b7625ef1df7778c153d7",
		"migration 116 rollback would discard certificate publication intents",
		"IF EXISTS (SELECT 1 FROM certificate_publication_intents)",
		"DROP TRIGGER certificate_binding_requires_intent_116",
		"DROP TABLE certificate_publication_intents",
		"DROP COLUMN binding_xact_id",
	} {
		if !strings.Contains(compactCertificatePublicationSQL116(down), compactCertificatePublicationSQL116(required)) {
			t.Errorf("migration 116 down contract missing %q", required)
		}
	}
}

func certificatePublicationMigration116(t *testing.T, direction string) string {
	t.Helper()
	content, err := fs.ReadFile(controlmigrations.FS,
		"116_certificate_publication_intents."+direction+".sql")
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func compactCertificatePublicationSQL116(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
