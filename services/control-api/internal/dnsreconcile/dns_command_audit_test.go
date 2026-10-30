package dnsreconcile

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestDNSCommandAuditEventBindsActorScopeTaskAndCAS(t *testing.T) {
	scopeID, actorID, taskID := uuid.New(), uuid.New(), uuid.New()
	for _, test := range []struct {
		action Action
		want   string
	}{
		{action: ActionApply, want: "dns.reconcile.apply"},
		{action: ActionCommit, want: "dns.reconcile.commit"},
		{action: ActionCancel, want: "dns.reconcile.cancel"},
	} {
		event, err := dnsCommandAuditEvent(dnsCommandAuditInput{
			ScopeID: scopeID, ActorUserID: actorID, TaskID: taskID,
			RequestID: "dns-audit-request", Action: test.action,
			ExpectedRevision: 7, ProviderRevision: 11,
		})
		if err != nil {
			t.Fatalf("%s audit event error = %v", test.action, err)
		}
		if event.ScopeID != scopeID || event.ActorUserID == nil || *event.ActorUserID != actorID ||
			event.Action != test.want || event.ResourceType != "dns_reconcile_task" ||
			event.ResourceID != taskID.String() || event.RequestID != "dns-audit-request" ||
			event.Result != "success" {
			t.Fatalf("%s audit event = %#v", test.action, event)
		}
		if event.Payload["expected_revision"] != int64(7) || event.Payload["provider_revision"] != int64(11) ||
			event.Payload["action"] != string(test.action) {
			t.Fatalf("%s audit payload = %#v", test.action, event.Payload)
		}
		for _, forbidden := range []string{"idempotency_key", "command_digest", "traceparent", "credential", "secret"} {
			if _, found := event.Payload[forbidden]; found {
				t.Fatalf("%s audit payload exposed %q", test.action, forbidden)
			}
		}
	}
}

func TestDNSCommandAuditIsTransactionBoundAndReplaySafe(t *testing.T) {
	encoded, err := os.ReadFile("postgres_store.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(encoded)
	for _, required := range []string{
		"store.appendDNSCommandAudit(ctx, tx, dnsCommandAuditInput{",
		"Action: ActionApply",
		"Action: ActionCommit",
		"Action: ActionCancel",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("Postgres store is missing transaction-bound audit contract %q", required)
		}
	}
	if count := strings.Count(source, "store.appendDNSCommandAudit(ctx, tx, dnsCommandAuditInput{"); count != 3 {
		t.Fatalf("transaction-bound DNS command audit calls = %d, want 3", count)
	}
	for _, forbidden := range []string{
		"Payload: map[string]any{\"idempotency_key\"",
		"Payload: map[string]any{\"command_digest\"",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("DNS command audit stores sensitive command identity: %q", forbidden)
		}
	}
}
