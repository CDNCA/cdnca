package plugininstallation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServiceLifecycleConsentLKGProtectiveActionsAndReplay(t *testing.T) {
	now := time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
	store := newMemoryStore()
	verifier := &recordingVerifier{}
	service := Service{Store: store, Verifier: verifier, Now: func() time.Time { return now }}
	tenantID, installationID, authorizationID := uuid.New(), uuid.New(), uuid.New()
	verification1, verification2 := uuid.New(), uuid.New()

	install := testCommand(tenantID, installationID, authorizationID, verification1)
	install.Action = ActionConfirm
	install.Candidate.ManifestScopes = []string{"plugin.read", "plugin.write"}
	install.Candidate.ApprovedScopes = []string{"plugin.read"}
	install.NewPermissionsConfirmed = true
	install.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "fact-install-1"}}
	result, err := service.Apply(context.Background(), install)
	if err != nil {
		t.Fatalf("confirm installation: %v", err)
	}
	if result.Installation.Status != StatusEnabled || result.Installation.Revision != 1 ||
		result.Installation.Version != "1.2.0" || result.Installation.LKGVersion != "1.2.0" ||
		len(result.Installation.ApprovedScopes) != 1 || result.Receipt.Result != ReceiptInstalled {
		t.Fatalf("unexpected install result: %+v", result)
	}

	replayed, err := service.Apply(context.Background(), install)
	if err != nil || replayed.Receipt.ID != result.Receipt.ID || len(store.receipts) != 1 {
		t.Fatalf("exact replay changed result: result=%+v err=%v receipts=%d", replayed, err, len(store.receipts))
	}
	changed := install
	changed.Candidate.Version = "1.2.1"
	if _, err := service.Apply(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error=%v", err)
	}

	upgrade := testCommand(tenantID, installationID, authorizationID, verification2)
	upgrade.Action = ActionUpgrade
	upgrade.ExpectedRevision = 1
	upgrade.IdempotencyKey = "plugin-upgrade-1"
	upgrade.RequestID = "plugin-upgrade-request-1"
	upgrade.Candidate.Version = "1.3.0"
	upgrade.Candidate.ManifestSHA256 = digest("b")
	upgrade.Candidate.ManifestScopes = []string{"plugin.read", "plugin.write"}
	upgrade.Candidate.ApprovedScopes = []string{"plugin.read", "plugin.write"}
	upgrade.Candidate.SensitiveScopes = []string{"plugin.write"}
	upgrade.Facts = []SignedRuntimeFact{
		{Scope: "plugin.read", RequestID: "fact-upgrade-read"},
		{Scope: "plugin.write", RequestID: "fact-upgrade-write"},
	}
	downgrade := upgrade
	downgrade.Candidate.Version = "1.1.0"
	downgrade.IdempotencyKey = "plugin-upgrade-downgrade"
	downgrade.RequestID = "plugin-upgrade-downgrade-request"
	downgrade.NewPermissionsConfirmed = true
	downgrade.SensitivePermissionsConfirmed = true
	if _, err := service.Apply(context.Background(), downgrade); !errors.Is(err, ErrTransitionInvalid) {
		t.Fatalf("downgrade error=%v", err)
	}
	if _, err := service.Apply(context.Background(), upgrade); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("upgrade without new/sensitive consent error=%v", err)
	}
	if len(store.receipts) != 1 || store.current(tenantID, authorizationID).Revision != 1 {
		t.Fatal("denied upgrade mutated state or audit")
	}

	upgrade.NewPermissionsConfirmed = true
	upgrade.SensitivePermissionsConfirmed = true
	upgrade.Applied = false
	upgrade.StableReasonCode = "health_check_failed"
	failed, err := service.Apply(context.Background(), upgrade)
	if err != nil {
		t.Fatalf("record failed upgrade: %v", err)
	}
	if failed.Installation.Revision != 2 || failed.Installation.Version != "1.2.0" ||
		failed.Installation.LKGVersion != "1.2.0" || failed.Receipt.Result != ReceiptUpgradeFailedLKGPreserved ||
		failed.Receipt.AttemptedVersion != "1.3.0" {
		t.Fatalf("failed upgrade did not preserve LKG: %+v", failed)
	}

	upgrade.ExpectedRevision = 2
	upgrade.IdempotencyKey = "plugin-upgrade-2"
	upgrade.RequestID = "plugin-upgrade-request-2"
	upgrade.Applied = true
	upgrade.StableReasonCode = ""
	upgraded, err := service.Apply(context.Background(), upgrade)
	if err != nil {
		t.Fatalf("successful upgrade: %v", err)
	}
	if upgraded.Installation.Revision != 3 || upgraded.Installation.Version != "1.3.0" ||
		upgraded.Installation.LKGVersion != "1.3.0" || len(upgraded.Installation.ApprovedScopes) != 2 {
		t.Fatalf("unexpected upgraded state: %+v", upgraded.Installation)
	}

	verificationCalls := verifier.calls
	disable := protectiveCommand(upgraded.Installation, ActionDisable, "operator containment", "plugin-disable-1")
	disabled, err := service.Apply(context.Background(), disable)
	if err != nil || disabled.Installation.Status != StatusDisabled || disabled.Installation.Revision != 4 {
		t.Fatalf("protective disable: result=%+v err=%v", disabled, err)
	}
	uninstall := protectiveCommand(disabled.Installation, ActionUninstall, "customer removal", "plugin-uninstall-1")
	uninstalled, err := service.Apply(context.Background(), uninstall)
	if err != nil || uninstalled.Installation.Status != StatusUninstalled || uninstalled.Installation.Revision != 5 {
		t.Fatalf("protective uninstall: result=%+v err=%v", uninstalled, err)
	}
	if verifier.calls != verificationCalls {
		t.Fatal("protective actions consulted forward trust dependencies")
	}
	if len(store.receipts) != 5 {
		t.Fatalf("receipt count=%d want=5", len(store.receipts))
	}
}

func TestServiceCrossTenantAndBindingFailClosed(t *testing.T) {
	tenantA, tenantB := uuid.New(), uuid.New()
	installationID, authorizationID := uuid.New(), uuid.New()
	store := newMemoryStore()
	service := Service{Store: store, Verifier: &recordingVerifier{}, Now: func() time.Time {
		return time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
	}}
	command := testCommand(tenantA, installationID, authorizationID, uuid.New())
	command.Action = ActionConfirm
	command.NewPermissionsConfirmed = true
	command.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "tenant-a-fact"}}
	installed, err := service.Apply(context.Background(), command)
	if err != nil {
		t.Fatalf("seed installation: %v", err)
	}

	for name, mutate := range map[string]func(*Command){
		"tenant":       func(value *Command) { value.TenantID = tenantB },
		"installation": func(value *Command) { value.InstallationID = uuid.New() },
		"manifest":     func(value *Command) { value.Candidate.ManifestSHA256 = digest("c") },
		"version":      func(value *Command) { value.Candidate.Version = "1.2.1" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := protectiveCommand(installed.Installation, ActionDisable, "containment", "binding-"+name)
			mutate(&candidate)
			if _, err := service.Apply(context.Background(), candidate); err == nil {
				t.Fatal("binding mismatch accepted")
			}
		})
	}
	if store.current(tenantA, authorizationID).Status != StatusEnabled || len(store.receipts) != 1 {
		t.Fatal("binding attacks mutated authoritative state")
	}
}

type recordingVerifier struct{ calls int }

func (verifier *recordingVerifier) VerifyCandidate(_ context.Context, _ Candidate, facts []SignedRuntimeFact) error {
	verifier.calls++
	if len(facts) == 0 {
		return ErrFactRequired
	}
	return nil
}

type memoryStore struct {
	installations map[string]Installation
	replays       map[string]Receipt
	receipts      []Receipt
}

func newMemoryStore() *memoryStore {
	return &memoryStore{installations: map[string]Installation{}, replays: map[string]Receipt{}}
}

func storeKey(tenantID, authorizationID uuid.UUID) string {
	return tenantID.String() + "/" + authorizationID.String()
}

func replayKey(tenantID uuid.UUID, idempotencyKey string) string {
	return tenantID.String() + "/" + idempotencyKey
}

func (store *memoryStore) Transact(_ context.Context, tenantID, authorizationID uuid.UUID,
	callback func(Transaction) error) error {
	tx := &memoryTransaction{store: store, key: storeKey(tenantID, authorizationID), tenantID: tenantID}
	return callback(tx)
}

func (store *memoryStore) current(tenantID, authorizationID uuid.UUID) Installation {
	return store.installations[storeKey(tenantID, authorizationID)]
}

type memoryTransaction struct {
	store    *memoryStore
	key      string
	tenantID uuid.UUID
}

func (tx *memoryTransaction) Current() (Installation, bool, error) {
	value, ok := tx.store.installations[tx.key]
	return value, ok, nil
}

func (tx *memoryTransaction) BoundElsewhere() (bool, error) {
	for key, value := range tx.store.installations {
		if key != tx.key && value.AuthorizationID.String() == tx.key[len(tx.key)-36:] {
			return true, nil
		}
	}
	return false, nil
}

func (tx *memoryTransaction) Replay(idempotencyKey string) (Receipt, bool, error) {
	value, ok := tx.store.replays[replayKey(tx.tenantID, idempotencyKey)]
	return value, ok, nil
}

func (tx *memoryTransaction) Save(value Installation, receipt Receipt) error {
	tx.store.installations[tx.key] = value
	tx.store.replays[replayKey(tx.tenantID, receipt.IdempotencyKey)] = receipt
	tx.store.receipts = append(tx.store.receipts, receipt)
	return nil
}

func testCommand(tenantID, installationID, authorizationID, verificationID uuid.UUID) Command {
	return Command{
		TenantID: tenantID, InstallationID: installationID, AuthorizationID: authorizationID,
		ExpectedRevision: 1, IdempotencyKey: "plugin-install-1", RequestID: "plugin-install-request-1", Applied: true,
		Candidate: Candidate{TenantID: tenantID, ResourceScope: ResourceScopeTenant, EntrypointType: EntrypointExternalHTTPS, InstallationID: installationID, AuthorizationID: authorizationID,
			VerificationID: verificationID, PluginID: "acme.example", Version: "1.2.0",
			ManifestSHA256: digest("a"), ConfigurationSchemaSHA256: digest("1"),
			ManifestScopes: []string{"plugin.read"}, ApprovedScopes: []string{"plugin.read"}},
	}
}

func protectiveCommand(current Installation, action, reason, key string) Command {
	return Command{TenantID: current.TenantID, InstallationID: current.InstallationID,
		AuthorizationID: current.AuthorizationID, Action: action, ExpectedRevision: current.Revision,
		IdempotencyKey: key, RequestID: key + "-request", Reason: reason,
		Candidate: Candidate{TenantID: current.TenantID, ResourceScope: ResourceScopeTenant, EntrypointType: EntrypointExternalHTTPS, InstallationID: current.InstallationID,
			AuthorizationID: current.AuthorizationID, VerificationID: current.VerificationID,
			PluginID: current.PluginID, Version: current.Version, ManifestSHA256: current.ManifestSHA256,
			ConfigurationSchemaSHA256: current.ConfigurationSchemaSHA256,
			ManifestScopes:            append([]string{}, current.ManifestScopes...), ApprovedScopes: append([]string{}, current.ApprovedScopes...)}}
}

func digest(character string) string {
	value := ""
	for range 64 {
		value += character
	}
	return value
}
