package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	dnsRetry155ControlUpgrade154UpSHA256   = "b3925e3c4a28ad73a9487aae6356c39dddc11291064d2f691d4d76a58ad7278a"
	dnsRetry155ControlUpgrade154DownSHA256 = "85c925f408b65ce15c79a4bab9fb81ad6d9e2e8fb0feeb99c612426cbd35070f"
)

func TestDNS02ProviderRetryStates155Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("155_dns_provider_retry_states.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("155_dns_provider_retry_states.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	normalizedUp := strings.Join(strings.Fields(up), " ")
	for _, required := range []string{
		"migration 155 requires the exact verified 154 release head",
		"version=154 AND migration_id='154_control_upgrade_systemd_repository'",
		dnsRetry155ControlUpgrade154UpSHA256, dnsRetry155ControlUpgrade154DownSHA256,
		"CREATE TABLE dns_provider_retry_states",
		"tenant_id uuid NOT NULL", "tenant_scope_id uuid NOT NULL",
		"zone_id uuid NOT NULL", "provider_id uuid NOT NULL",
		"revision bigint NOT NULL", "state jsonb NOT NULL", "updated_at timestamptz NOT NULL",
		"PRIMARY KEY(tenant_id,zone_id,provider_id)",
		"CHECK(revision>0)", "CHECK(jsonb_typeof(state)='object')",
		"CHECK((state->>'Revision')::bigint=revision)",
		"CHECK(isfinite(updated_at) AND date_trunc('microseconds',updated_at)=updated_at)",
		"access_scopes_id_tenant_unique",
		"dns_zones_scope_zone_provider_155", "UNIQUE(scope_id,id,provider_id)",
		"FOREIGN KEY(tenant_scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT",
		"FOREIGN KEY(tenant_scope_id,zone_id,provider_id) REFERENCES dns_zones(scope_id,id,provider_id) ON DELETE RESTRICT",
		"FOREIGN KEY(tenant_scope_id,provider_id) REFERENCES dns_providers(scope_id,id) ON DELETE RESTRICT",
		"guard_dns_provider_retry_state_scope_155",
		"BEFORE INSERT OR UPDATE ON dns_provider_retry_states",
		"access_scopes.kind='tenant'", "access_scopes.tenant_id=NEW.tenant_id",
		"dns_zones.scope_id=access_scopes.id", "dns_zones.id=NEW.zone_id",
		"dns_zones.provider_id=NEW.provider_id",
		"dns_providers.scope_id=access_scopes.id", "dns_providers.id=NEW.provider_id",
		"NEW.tenant_scope_id IS NOT NULL AND NEW.tenant_scope_id<>resolved_scope_id",
		"NEW.tenant_scope_id:=resolved_scope_id", "ERRCODE='P1551'",
		"REVOKE ALL ON dns_provider_retry_states FROM PUBLIC",
	} {
		if !strings.Contains(normalizedUp, strings.Join(strings.Fields(required), " ")) {
			t.Errorf("155 up missing %q", required)
		}
	}
	firstMutation := len(up)
	for _, marker := range []string{
		"ALTER TABLE dns_zones", "CREATE TABLE dns_provider_retry_states",
	} {
		if index := strings.Index(up, marker); index >= 0 && index < firstMutation {
			firstMutation = index
		}
	}
	if guard := strings.Index(up, "migration 155 requires the exact verified 154 release head"); guard < 0 || firstMutation == len(up) || guard > firstMutation {
		t.Fatal("155 predecessor guard must precede the first mutation")
	}

	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 155 rollback requires the exact verified 155 head",
		"version=155 AND migration_id='155_dns_provider_retry_states'", upSHA,
		"migration 155 rollback would discard durable DNS provider retry state",
		"EXISTS(SELECT 1 FROM dns_provider_retry_states)",
		"DROP TABLE dns_provider_retry_states",
		"DROP CONSTRAINT dns_zones_scope_zone_provider_155",
		"version=154 AND migration_id='154_control_upgrade_systemd_repository'",
		dnsRetry155ControlUpgrade154UpSHA256, dnsRetry155ControlUpgrade154DownSHA256,
	} {
		if !strings.Contains(down, required) {
			t.Errorf("155 down missing %q", required)
		}
	}
	firstRollbackMutation := len(down)
	for _, marker := range []string{
		"DROP TRIGGER", "DROP FUNCTION", "DROP TABLE dns_provider_retry_states",
		"ALTER TABLE dns_zones",
	} {
		if index := strings.Index(down, marker); index >= 0 && index < firstRollbackMutation {
			firstRollbackMutation = index
		}
	}
	if guard := strings.Index(down, "migration 155 rollback requires the exact verified 155 head"); guard < 0 || firstRollbackMutation == len(down) || guard > firstRollbackMutation {
		t.Fatal("155 rollback guard must precede the first mutation")
	}
	for _, forbidden := range []string{
		"DELETE FROM schema_migrations", "CASCADE", "TRUNCATE", "DROP SCHEMA",
		"__UP_SHA256__", "__DOWN_SHA256__", "__PREDECESSOR_UP_SHA256__", "__PREDECESSOR_DOWN_SHA256__",
	} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("155 migration contains forbidden marker %q", forbidden)
		}
	}
}
