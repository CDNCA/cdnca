package plugininstallation

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// fix-plugconfirm3（报告第 4 节第 4 点）：同一授权在本主控只能有一个本地目标。第一个确认的作用域
// 成为该授权的目标绑定（head 的 tenant_scope_id + 签名的 installation_id），另一个租户不能再以同一授权
// 确认出第二个 head；原目标的重放与后续操作不受影响。
func TestServiceRefusesCrossTargetConfirmation(t *testing.T) {
	store := newMemoryStore()
	verifier := &recordingVerifier{}
	service := Service{Store: store, Verifier: verifier, Now: testNow}
	tenantA, tenantB := uuid.New(), uuid.New()
	installationID, authorizationID, verificationID := uuid.New(), uuid.New(), uuid.New()
	first := testCommand(tenantA, installationID, authorizationID, verificationID)
	first.Action, first.NewPermissionsConfirmed = ActionConfirm, true
	first.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "fact-target"}}
	if _, err := service.Apply(context.Background(), first); err != nil {
		t.Fatalf("first confirm err=%v", err)
	}
	second := testCommand(tenantB, installationID, authorizationID, verificationID)
	second.Action, second.NewPermissionsConfirmed = ActionConfirm, true
	second.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "fact-target"}}
	second.IdempotencyKey, second.RequestID = "plugin-install-b", "plugin-install-request-b"
	if _, err := service.Apply(context.Background(), second); !errors.Is(err, ErrFactDenied) {
		t.Fatalf("cross-target confirm err=%v", err)
	}
	if _, found := store.installations[storeKey(tenantB, authorizationID)]; found || len(store.receipts) != 1 {
		t.Fatalf("cross-target confirm wrote heads=%v receipts=%d", store.installations, len(store.receipts))
	}
	// The bound target replays its own confirmation unchanged.
	if _, err := service.Apply(context.Background(), first); err != nil || len(store.receipts) != 1 {
		t.Fatalf("bound target replay err=%v receipts=%d", err, len(store.receipts))
	}
}

// The plugin type is part of the signed candidate and of the head: a candidate whose type disagrees with its
// resource scope is invalid, and an upgrade cannot change the type of an installed plugin.
func TestCandidateEntrypointTypeMatchesScopeAndIsImmutable(t *testing.T) {
	tenantID, installationID, authorizationID, verificationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	command := testCommand(tenantID, installationID, authorizationID, verificationID)
	command.Action, command.NewPermissionsConfirmed = ActionConfirm, true
	for _, invalid := range []string{"", EntrypointTheme, EntrypointRulePack, "wasm"} {
		candidate := command.Candidate
		candidate.EntrypointType = invalid
		if validCandidate(candidate) {
			t.Fatalf("tenant candidate with entrypoint %q accepted", invalid)
		}
	}
	platform := command.Candidate
	platform.ResourceScope, platform.EntrypointType = ResourceScopePlatform, EntrypointExternalHTTPS
	if validCandidate(platform) {
		t.Fatal("platform candidate with a tenant entrypoint accepted")
	}

	store := newMemoryStore()
	service := Service{Store: store, Verifier: &recordingVerifier{}, Now: testNow}
	command.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "fact-target"}}
	if _, err := service.Apply(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	upgrade := testCommand(tenantID, installationID, authorizationID, uuid.New())
	upgrade.Action, upgrade.IdempotencyKey, upgrade.RequestID = ActionUpgrade, "plugin-upgrade-type", "plugin-upgrade-type"
	upgrade.Candidate.Version, upgrade.Candidate.EntrypointType = "1.3.0", EntrypointUIPage
	upgrade.NewPermissionsConfirmed = true
	upgrade.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "fact-target"}}
	if _, err := service.Apply(context.Background(), upgrade); !errors.Is(err, ErrFactDenied) {
		t.Fatalf("upgrade changing the plugin type err=%v", err)
	}
}
