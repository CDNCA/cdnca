package dnsproviderremotesource

import (
	"os"
	"strings"
	"testing"
)

func TestResolveUsesFrozenIssueRequestActorBeforeCredentialDecrypt(t *testing.T) {
	raw, err := os.ReadFile("source.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	resolveStart := strings.Index(source, "func (s *Source) Resolve(")
	resolveEnd := strings.Index(source, "func (s *Source) CheckCredentialFence(")
	if resolveStart < 0 || resolveEnd <= resolveStart {
		t.Fatal("locate Source.Resolve")
	}
	resolve := strings.Join(strings.Fields(source[resolveStart:resolveEnd]), " ")
	for _, required := range []string{
		"lookup.OperationID",
		"JOIN acme_issuance_operations AS operation",
		"operation.tenant_scope_id=provider.scope_id",
		"operation.operation_id=",
		"operation.actor_user_id",
		"operation.request_snapshot ->> 'TenantID'",
		"operation.request_snapshot ->> 'ScopeID'",
		"operation.request_snapshot ->> 'ProviderID'",
		"operation.request_snapshot ->> 'ZoneID'",
		"operation.request_snapshot ->> 'ActorUserID'",
		"JOIN users AS actor ON actor.id=operation.actor_user_id",
		// fix-adminall：下单人须是租户活跃成员或平台管理员（tenantaccess 统一规则）
		"actor.status,`+actorMemberSQL+`",
		"actor.status",
	} {
		if !strings.Contains(resolve, required) {
			t.Errorf("Source.Resolve lacks frozen operation authority %q", required)
		}
	}

	decrypt := strings.Index(resolve, ".Decrypt(")
	lastAuthorityCheck := strings.Index(resolve, "supportedProviderType(providerType)")
	if decrypt < 0 || lastAuthorityCheck < 0 || lastAuthorityCheck > decrypt {
		t.Fatal("operation authority and unsupported-provider checks must finish before credential decrypt")
	}
	for _, networkPrimitive := range []string{"http.", "net.Dial", "RoundTrip("} {
		if strings.Contains(resolve, networkPrimitive) {
			t.Fatalf("Source.Resolve must remain network-zero; found %q", networkPrimitive)
		}
	}
}
