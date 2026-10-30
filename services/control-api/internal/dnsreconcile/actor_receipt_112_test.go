package dnsreconcile

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestDNSCommandDigestBindsActorIdentity(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	siteID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	taskID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	actorA := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	actorB := uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")

	digestA, err := dnsCommandDigest(ActionCommit, tenantID, siteID, taskID, 7, actorA, nil)
	if err != nil {
		t.Fatal(err)
	}
	digestAReplay, err := dnsCommandDigest(ActionCommit, tenantID, siteID, taskID, 7, actorA, nil)
	if err != nil {
		t.Fatal(err)
	}
	digestB, err := dnsCommandDigest(ActionCommit, tenantID, siteID, taskID, 7, actorB, nil)
	if err != nil {
		t.Fatal(err)
	}
	if digestA != digestAReplay {
		t.Fatal("same actor and request must produce a deterministic digest")
	}
	if digestA == digestB {
		t.Fatal("different actors must not share a command digest")
	}
}

func TestDNSActorReceipt112MigrationContract(t *testing.T) {
	up := readActorReceipt112Migration(t, "112_dns_reconcile_actor_receipts.up.sql")
	down := readActorReceipt112Migration(t, "112_dns_reconcile_actor_receipts.down.sql")
	assertMigrationSHA112(t, "111 up", "../../migrations/111_firewall_command_outbox.up.sql", "dd1f37db9068df613adcb435ec46686b5d6a4e23593cb987ea67d1412a42d3e6")
	assertMigrationSHA112(t, "111 down", "../../migrations/111_firewall_command_outbox.down.sql", "a40154439408384a46855ec22a9c50729855f363fb45ebd3d09c18df5febf99c")
	for _, expected := range []string{
		"count(*) FROM schema_migrations) <> 111",
		"max(version) FROM schema_migrations) <> 111",
		"migration_id='111_firewall_command_outbox'",
		"checksum_sha256='dd1f37db9068df613adcb435ec46686b5d6a4e23593cb987ea67d1412a42d3e6'",
		"down_checksum_sha256='a40154439408384a46855ec22a9c50729855f363fb45ebd3d09c18df5febf99c'",
		"ALTER TABLE dns_reconcile_commit_facts",
		"ALTER TABLE dns_reconcile_cancel_facts",
		"actor_user_id uuid",
		"REFERENCES users(id) ON DELETE RESTRICT",
		"BEFORE INSERT ON dns_reconcile_commit_facts",
		"BEFORE INSERT ON dns_reconcile_cancel_facts",
		"NEW.actor_user_id IS NULL",
		"actor identity drift",
	} {
		if !strings.Contains(up, expected) {
			t.Fatalf("112 up missing %q", expected)
		}
	}
	if strings.Contains(up, "task_events") || strings.Contains(up, "audit_events") {
		t.Fatal("112 must not expand task_events or audit_events schema")
	}
	if strings.Contains(up, "__MIGRATION_") || strings.Contains(down, "__MIGRATION_") {
		t.Fatal("112 migration retains a provisional checksum placeholder")
	}
	for _, expected := range []string{
		"count(*) FROM schema_migrations) <> 112",
		"max(version) FROM schema_migrations) <> 112",
		"version=112",
		"migration_id='112_dns_reconcile_actor_receipts'",
		"checksum_sha256='",
		"migration_id='111_firewall_command_outbox'",
		"checksum_sha256='dd1f37db9068df613adcb435ec46686b5d6a4e23593cb987ea67d1412a42d3e6'",
		"down_checksum_sha256='a40154439408384a46855ec22a9c50729855f363fb45ebd3d09c18df5febf99c'",
	} {
		if !strings.Contains(down, expected) {
			t.Fatalf("112 down missing %q", expected)
		}
	}
}

func TestDNSActorReceipt112StoreContract(t *testing.T) {
	data, err := os.ReadFile("postgres_store.go")
	if err != nil {
		t.Fatal(err)
	}
	store := string(data)
	for _, expected := range []string{
		"request.ActorUserID, nil)",
		"actor_user_id,command_idempotency_key",
		"canonical.actorUserID == uuid.Nil",
		"canonicalActorUserID == uuid.Nil",
		"existingActorUserID == nil",
		"func optionalUUID(value *uuid.UUID) uuid.UUID",
		"return ErrUnavailable",
	} {
		if !strings.Contains(store, expected) {
			t.Fatalf("postgres store missing actor receipt contract %q", expected)
		}
	}
}

func readActorReceipt112Migration(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("../../migrations/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertMigrationSHA112(t *testing.T, label, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(data))
	if actual != expected {
		t.Fatalf("%s SHA=%s want %s", label, actual, expected)
	}
}
