package dnsproviderremotesource

import (
	"os"
	"strings"
	"testing"
)

func TestReconcileMutationAuthorityRequiresActiveProviderActor(t *testing.T) {
	raw, err := os.ReadFile("reconcile.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "func loadMutationClaimAuthority(")
	end := strings.Index(source, "func sameMutationClaimAuthority(")
	if start < 0 || end <= start {
		t.Fatal("locate reconcile mutation authority query")
	}
	authority := strings.Join(strings.Fields(source[start:end]), " ")
	for _, required := range []string{
		"JOIN users creator ON creator.id=provider.created_by_user_id AND creator.status='active'",
		// fix-adminall：创建者须是租户活跃成员或平台管理员（tenantaccess 统一规则）
		"AND `+tenantaccess.ActorOnTenantSQL(\"creator.id\", \"scope.id\")+`",
	} {
		if !strings.Contains(authority, required) {
			t.Errorf("mutation authority lacks active provider actor predicate %q", required)
		}
	}
	if calls := strings.Count(source, "loadMutationClaimAuthority(ctx, tx, mutation)"); calls != 3 {
		t.Fatalf("mutation authority calls = %d, want Acquire/Validate/Finalize", calls)
	}
}
