package controlupgrade

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParentGrantReceiptLogicalDigestV2(t *testing.T) {
	receipt := ParentGrantReceipt{
		ID:                  "00000000-0000-4000-8000-000000000071",
		PlanID:              "00000000-0000-4000-8000-000000000072",
		InstallationID:      "00000000-0000-4000-8000-000000000073",
		GrantID:             "00000000-0000-4000-8000-000000000074",
		RequestSchema:       parentGrantReceiptRequestSchema,
		RequestDigestSchema: 2, Status: parentGrantReceiptRejected,
		InstalledVersion: "1.2.3", ErrorCode: "health_check_failed",
		ObservedAt: time.Unix(1_800_000_001, 0).UTC(),
	}
	want := independentReceiptDigest(
		"cdnca-upgrade-grant-receipt-idempotency/v2",
		"upgrade-grant.receipt-request/v2",
		receipt.ID, receipt.InstallationID, receipt.GrantID, receipt.Status,
		receipt.InstalledVersion, receipt.ErrorCode, "1800000001",
	)
	if got, err := parentGrantReceiptLogicalDigest(receipt); err != nil || got != hex.EncodeToString(want[:]) {
		t.Fatalf("logical digest = (%q,%v), want %x", got, err, want)
	}
	changed := receipt
	changed.RequestedAt = time.Unix(1_900_000_000, 0).UTC()
	if got, err := parentGrantReceiptLogicalDigest(changed); err != nil || got != hex.EncodeToString(want[:]) {
		t.Fatalf("transport freshness changed logical digest = (%q,%v)", got, err)
	}
}

func TestLicenseReceiptTerminalMapping(t *testing.T) {
	plan := mustRolloutPlan(t)
	observed := time.Unix(1_800_000_100, 0).UTC()

	upgraded := plan
	upgraded.State, upgraded.Completion, upgraded.Revision = PlanCompleted, CompletionUpgraded, plan.Revision+1
	receipt, ok, err := terminalParentGrantReceipt(plan, upgraded, false, observed)
	if err != nil || !ok || receipt.Status != parentGrantReceiptApplied ||
		receipt.InstalledVersion != plan.TargetVersion || receipt.ErrorCode != "" || receipt.Sequence != 3 {
		t.Fatalf("upgraded receipt = (%#v,%t,%v)", receipt, ok, err)
	}

	restored := plan
	restored.State, restored.Completion, restored.Revision = PlanCompleted, CompletionRolledBack, plan.Revision+1
	restored.HealthReceipts = append(restored.HealthReceipts, PlanHealthReceipt{
		Health: PlanHealthEvent{Code: "HEALTH_FAILED"}, Event: PlanEvent{Reason: "HEALTH_FAILED"},
	}, PlanHealthReceipt{Health: PlanHealthEvent{Success: true}, Event: PlanEvent{Reason: "healthy"}})
	receipt, ok, err = terminalParentGrantReceipt(plan, restored, false, observed)
	if err != nil || !ok || receipt.Status != parentGrantReceiptRejected ||
		receipt.InstalledVersion != plan.CurrentVersion || receipt.ErrorCode != "health_check_failed" ||
		receipt.Sequence != 3 {
		t.Fatalf("automatic restore receipt = (%#v,%t,%v)", receipt, ok, err)
	}
	receipt, ok, err = terminalParentGrantReceipt(plan, restored, true, observed)
	if err != nil || !ok || receipt.Status != parentGrantReceiptRolledBack ||
		receipt.InstalledVersion != plan.CurrentVersion || receipt.ErrorCode != "" || receipt.Sequence != 4 {
		t.Fatalf("post-apply rollback receipt = (%#v,%t,%v)", receipt, ok, err)
	}

	unresolved := plan
	unresolved.State, unresolved.Completion, unresolved.Revision = PlanFailed, CompletionNone, plan.Revision+1
	if receipt, ok, err = terminalParentGrantReceipt(plan, unresolved, false, observed); err != nil || ok {
		t.Fatalf("unresolved plan emitted receipt = (%#v,%t,%v)", receipt, ok, err)
	}
}

func TestLicenseReceiptTerminalFailureMapping(t *testing.T) {
	plan := mustRolloutPlan(t)
	observed := time.Unix(1_800_000_101, 0).UTC()
	for _, test := range []struct {
		name string
		code string
		want string
	}{
		{"download", "DOWNLOAD_FAILED", "download_failed"},
		{"health", "HEALTH_FAILED", "health_check_failed"},
		{"apply", "UPGRADE_FAILED", "atomic_apply_failed"},
		{"installer rolled back", "INSTALLER_ROLLED_BACK", "atomic_apply_failed"},
		{"integrity", "ARTIFACT_INTEGRITY_FAILED", "preflight_failed"},
		{"too large", "ARTIFACT_TOO_LARGE", "preflight_failed"},
		{"disk", "INSUFFICIENT_DISK", "preflight_failed"},
		{"expired", "PLAN_EXPIRED", "preflight_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			terminal := cloneRolloutPlan(plan)
			terminal.State, terminal.Completion, terminal.Revision = PlanCompleted, CompletionRolledBack, plan.Revision+1
			terminal.HealthReceipts = append(terminal.HealthReceipts, PlanHealthReceipt{
				Health: PlanHealthEvent{Code: test.code}, Event: PlanEvent{Reason: test.code},
			})
			receipt, ok, err := terminalParentGrantReceipt(plan, terminal, false, observed)
			if err != nil || !ok || receipt.Status != parentGrantReceiptRejected ||
				receipt.ErrorCode != test.want || receipt.InstalledVersion != plan.CurrentVersion {
				t.Fatalf("terminal mapping = (%#v,%t,%v)", receipt, ok, err)
			}
		})
	}

	for _, code := range []string{
		"ROLLBACK_FAILED", "UNKNOWN_OUTCOME", "INSTALLER_OUTCOME_UNKNOWN", "INSTALLER_UNCERTAIN",
		"CONFLICTING_TERMINAL_STATE",
	} {
		t.Run("unresolved_"+strings.ToLower(code), func(t *testing.T) {
			unknown := cloneRolloutPlan(plan)
			unknown.State, unknown.Completion, unknown.Revision = PlanCompleted, CompletionRolledBack, plan.Revision+1
			unknown.HealthReceipts = append(unknown.HealthReceipts,
				PlanHealthReceipt{Health: PlanHealthEvent{Code: "INSUFFICIENT_DISK"}},
				PlanHealthReceipt{Health: PlanHealthEvent{Code: code}, Event: PlanEvent{Reason: code}},
			)
			if receipt, ok, err := terminalParentGrantReceipt(plan, unknown, false, observed); err != nil || ok {
				t.Fatalf("unresolved code %s emitted receipt = (%#v,%t,%v)", code, receipt, ok, err)
			}
		})
	}
}

func TestLicenseReceiptAgentFailureCodeParityIsExplicit(t *testing.T) {
	managerSource, err := os.ReadFile("../../../../agents/edge-agent/internal/updater/manager.go")
	if err != nil {
		t.Fatal(err)
	}
	commandStoreSource, err := os.ReadFile("../../../../agents/edge-agent/internal/updater/command_store.go")
	if err != nil {
		t.Fatal(err)
	}
	combined := string(managerSource) + string(commandStoreSource)
	for code, want := range map[string]string{
		"DOWNLOAD_FAILED":           "download_failed",
		"HEALTH_FAILED":             "health_check_failed",
		"UPGRADE_FAILED":            "atomic_apply_failed",
		"INSTALLER_ROLLED_BACK":     "atomic_apply_failed",
		"ARTIFACT_INTEGRITY_FAILED": "preflight_failed",
		"ARTIFACT_TOO_LARGE":        "preflight_failed",
		"INSUFFICIENT_DISK":         "preflight_failed",
		"PLAN_EXPIRED":              "preflight_failed",
	} {
		if !strings.Contains(combined, `"`+code+`"`) {
			t.Fatalf("Agent no longer emits reviewed definitive code %s", code)
		}
		if got, definitive := terminalParentGrantReceiptError(RolloutPlan{HealthReceipts: []PlanHealthReceipt{{
			Health: PlanHealthEvent{Code: code},
		}}}); !definitive || got != want {
			t.Errorf("Agent code %s mapped to (%q,%t), want (%q,true)", code, got, definitive, want)
		}
	}
	for _, code := range []string{"ROLLBACK_FAILED", "INSTALLER_UNCERTAIN"} {
		if !strings.Contains(combined, `"`+code+`"`) {
			t.Fatalf("Agent no longer emits reviewed unresolved code %s", code)
		}
		if got, definitive := terminalParentGrantReceiptError(RolloutPlan{HealthReceipts: []PlanHealthReceipt{{
			Health: PlanHealthEvent{Code: code},
		}}}); definitive || got != "" {
			t.Errorf("unresolved Agent code %s mapped to (%q,%t)", code, got, definitive)
		}
	}
	if got, definitive := terminalParentGrantReceiptError(RolloutPlan{HealthReceipts: []PlanHealthReceipt{{
		Health: PlanHealthEvent{Code: "INSTALLER_OUTCOME_UNKNOWN"},
	}}}); definitive || got != "" {
		t.Errorf("legacy unresolved contract code mapped to (%q,%t)", got, definitive)
	}
}

func TestLicenseReceiptDispatcherKeepsHTTPOutsideStoreAndNeverExhaustsRetries(t *testing.T) {
	now := time.Unix(1_800_000_200, 0).UTC()
	receipt := ParentGrantReceipt{ID: "00000000-0000-4000-8000-000000000081",
		PlanID:         "00000000-0000-4000-8000-000000000082",
		InstallationID: "00000000-0000-4000-8000-000000000083",
		GrantID:        "00000000-0000-4000-8000-000000000084",
		RequestSchema:  parentGrantReceiptRequestSchema, RequestDigestSchema: 2,
		Sequence: 1, Status: parentGrantReceiptFetched, InstalledVersion: "1.2.3", ObservedAt: now}
	digest, err := parentGrantReceiptLogicalDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.LogicalDigest = digest
	store := &fakeLicenseReceiptStore{claims: []ParentGrantReceiptClaim{{Receipt: receipt,
		ClaimToken: "00000000-0000-4000-8000-000000000085", AttemptCount: 10_000}}}
	client := &fakeParentGrantReceiptClient{record: func(context.Context, ParentGrantReceipt) (ParentGrantReceiptResponse, error) {
		if store.inStore {
			t.Fatal("License HTTP ran while the store operation was active")
		}
		return ParentGrantReceiptResponse{}, ErrLicenseReceiptRetryable
	}}
	dispatcher, err := NewLicenseReceiptDispatcher(store, client, LicenseReceiptDispatcherConfig{
		WorkerID: "receipt-worker", ClaimLease: time.Minute, ClaimBatch: 8, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if count, err := dispatcher.DispatchOnce(t.Context()); err != nil || count != 1 {
		t.Fatalf("dispatch = (%d,%v)", count, err)
	}
	if len(store.settlements) != 1 || store.settlements[0].Disposition != ParentGrantReceiptRetryable ||
		store.settlements[0].AvailableAt.Sub(now) != 30*time.Second {
		t.Fatalf("retry settlement = %#v", store.settlements)
	}
}

func TestLicenseReceiptDispatcherPermanentlyFailsAndReportsStickyReadiness(t *testing.T) {
	now := time.Unix(1_800_000_300, 0).UTC()
	receipt := ParentGrantReceipt{ID: "00000000-0000-4000-8000-0000000000a1",
		PlanID:         "00000000-0000-4000-8000-0000000000a2",
		InstallationID: "00000000-0000-4000-8000-0000000000a3",
		GrantID:        "00000000-0000-4000-8000-0000000000a4",
		RequestSchema:  parentGrantReceiptRequestSchema, RequestDigestSchema: 2,
		Sequence: 1, Status: parentGrantReceiptFetched, InstalledVersion: "1.2.3", ObservedAt: now}
	digest, err := parentGrantReceiptLogicalDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.LogicalDigest = digest
	store := &fakeLicenseReceiptStore{claims: []ParentGrantReceiptClaim{{Receipt: receipt,
		ClaimToken: "00000000-0000-4000-8000-0000000000a5", AttemptCount: 1}}}
	client := &fakeParentGrantReceiptClient{record: func(context.Context, ParentGrantReceipt) (ParentGrantReceiptResponse, error) {
		return ParentGrantReceiptResponse{}, ErrLicenseReceiptPermanent
	}}
	dispatcher, err := NewLicenseReceiptDispatcher(store, client, LicenseReceiptDispatcherConfig{
		WorkerID: "receipt-worker", ClaimLease: time.Minute, ClaimBatch: 1, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if count, err := dispatcher.DispatchOnce(t.Context()); err != nil || count != 1 {
		t.Fatalf("dispatch = (%d,%v)", count, err)
	}
	if len(store.settlements) != 1 || store.settlements[0].Disposition != ParentGrantReceiptFailed {
		t.Fatalf("permanent settlement = %#v", store.settlements)
	}
	store.failed = true
	if failed, err := dispatcher.HasFailed(t.Context()); err != nil || !failed {
		t.Fatalf("sticky failure = (%t,%v)", failed, err)
	}
}

func TestLicenseReceiptAtomicEnqueueHooksRemainInsideOwningTransactions(t *testing.T) {
	createSource, err := os.ReadFile("create_store.go")
	if err != nil {
		t.Fatal(err)
	}
	storeSource, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	create := string(createSource)
	if !strings.Contains(create, "SET state='consumed',plan_id=$2,updated_at=date_trunc('second',clock_timestamp())") ||
		!strings.Contains(create, "insertInitialParentGrantReceiptsTx(ctx, tx") {
		t.Fatal("create transaction does not atomically consume the intent and enqueue fetched/verified receipts")
	}
	store := string(storeSource)
	if !strings.Contains(store, "insertTerminalParentGrantReceiptTx(ctx, tx, locked.Plan, mutation.Plan") {
		t.Fatal("rollout transaction does not atomically enqueue the terminal License receipt")
	}
}

func independentReceiptDigest(fields ...string) [sha256.Size]byte {
	hash := sha256.New()
	var length [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(field))
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

type fakeLicenseReceiptStore struct {
	claims      []ParentGrantReceiptClaim
	settlements []ParentGrantReceiptSettlement
	inStore     bool
	failed      bool
}

func (store *fakeLicenseReceiptStore) ClaimParentGrantReceipts(context.Context, string, time.Time,
	time.Duration, int) ([]ParentGrantReceiptClaim, error) {
	store.inStore = true
	defer func() { store.inStore = false }()
	return append([]ParentGrantReceiptClaim(nil), store.claims...), nil
}

func (store *fakeLicenseReceiptStore) SettleParentGrantReceipt(_ context.Context,
	settlement ParentGrantReceiptSettlement) error {
	store.inStore = true
	defer func() { store.inStore = false }()
	store.settlements = append(store.settlements, settlement)
	return nil
}

func (store *fakeLicenseReceiptStore) HasFailedParentGrantReceipt(context.Context) (bool, error) {
	return store.failed, nil
}

type fakeParentGrantReceiptClient struct {
	record func(context.Context, ParentGrantReceipt) (ParentGrantReceiptResponse, error)
}

func (client *fakeParentGrantReceiptClient) RecordParentGrantReceipt(ctx context.Context,
	receipt ParentGrantReceipt) (ParentGrantReceiptResponse, error) {
	if client.record == nil {
		return ParentGrantReceiptResponse{}, errors.New("unexpected receipt call")
	}
	return client.record(ctx, receipt)
}
