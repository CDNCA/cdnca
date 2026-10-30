package dnsproviderremotesource

import (
	"os"
	"strings"
	"testing"
)

func TestCredentialFenceRequiresActiveProviderActor(t *testing.T) {
	raw, err := os.ReadFile("source.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	resolveStart := strings.Index(source, "func (s *Source) Resolve(")
	fenceStart := strings.Index(source, "func (s *Source) CheckCredentialFence(")
	fenceEnd := strings.Index(source, "func (s *Source) OutstandingRemoteTXTHandles(")
	if resolveStart < 0 || fenceStart <= resolveStart || fenceEnd <= fenceStart {
		t.Fatal("locate provider resolution and credential fence")
	}
	resolve := strings.Join(strings.Fields(source[resolveStart:fenceStart]), " ")
	fence := strings.Join(strings.Fields(source[fenceStart:fenceEnd]), " ")
	for _, required := range []string{
		"provider.created_by_user_id",
		"JOIN users AS creator ON creator.id=provider.created_by_user_id",
		// fix-adminall：创建者须是租户活跃成员或平台管理员（tenantaccess 统一规则）
		"creator.status,`+creatorMemberSQL+`",
		"creator.status",
		"createdActor == uuid.Nil",
		"actorStatus != \"active\"",
		"membership != \"active\"",
	} {
		if !strings.Contains(resolve, required) {
			t.Fatalf("Resolve lacks provider actor authority %q", required)
		}
		if !strings.Contains(fence, required) {
			t.Errorf("credential fence lacks provider actor authority %q", required)
		}
	}
	if strings.Contains(fence, "credential_ciphertext") || strings.Contains(fence, ".Decrypt(") {
		t.Fatal("credential fence reads secret material")
	}
}
