package entitlementguard

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// a plugin stopped on this controller takes its
// feature code out of the grant here (every read the guard answers:
// ReadValidFeatures, GrantedModules, CheckFeature/CheckModule); enabling it
// again restores the grant. Both writes are idempotent by key, audited, and
// only take plugin codes. The community edition grants its modules without a
// lease, and pack.* only once bought, so the lease below adds nothing.
func TestLocalDisableSubtractsFromLeaseGrant(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	fixture.install(t, fixture.moduleLease(1, "module.probe.dnspup", "pack.selfwaf"), fixture.now)
	var notified [][]string
	// The change hook runs in the write's transaction (the system republication of edgeautopublish in production).
	store := NewLocalDisableStore(fixture.pool, func() time.Time { return fixture.now },
		func(_ context.Context, tx pgx.Tx, codes []string) error {
			if tx == nil {
				t.Error("change hook without the write transaction")
			}
			notified = append(notified, codes)
			return nil
		})
	actor := LocalDisableActor{UserID: fixture.actorUser, ScopeID: fixture.actorScope, IP: "203.0.113.9"}

	features := func() map[string]bool {
		tx := fixture.begin(t)
		defer tx.Rollback(t.Context())
		granted, err := fixture.guard().ReadValidFeatures(t.Context(), tx)
		if err != nil {
			t.Fatal(err)
		}
		return granted
	}
	if got := features(); !got["module.probe.dnspup"] || !got["module.icp"] {
		t.Fatalf("features before = %v", got)
	}

	disabled, err := store.Disable(t.Context(), actor, "key-1", LocalDisableInput{PluginID: "io.cdnca.probe-dnspup",
		FeatureCode: "module.probe.dnspup"})
	if err != nil || !disabled.Disabled || disabled.FeatureCode != "module.probe.dnspup" || disabled.DisabledBy == nil ||
		*disabled.DisabledBy != fixture.actorUser || disabled.DisabledAt == nil {
		t.Fatalf("Disable() = %+v, %v", disabled, err)
	}
	if got := features(); got["module.probe.dnspup"] || !got[FeatureExtensionsWebhooks] || !got["module.icp"] {
		t.Fatalf("features after disable = %v", got)
	}
	want := slices.DeleteFunc(communityModuleCodes(), func(code string) bool { return code == "module.probe.dnspup" })
	if grants := fixture.grantedModules(t); grants.Has("module.probe.dnspup") || !reflect.DeepEqual(grants.Codes, want) {
		t.Fatalf("GrantedModules(disabled) = %+v, want %v", grants, want)
	}
	if err := fixture.checkModule(t, "module.probe.dnspup", "disabled"); !errors.Is(err, ErrFeatureDenied) {
		t.Fatalf("CheckModule(disabled) error = %v, want ErrFeatureDenied", err)
	}
	// AuthorizeModule (the module routes' and workers' gate) commits the denial with its reason.
	if err := fixture.guard().AuthorizeModule(t.Context(), fixture.pool, ModuleCheck{
		TargetScopeID: fixture.targetScope, ActorScopeID: fixture.actorScope, ActorUserID: fixture.actorUser,
		ResourceType: "module_probe", ResourceID: fixture.resourceID, RequestID: "module-disabled-commit",
		Operation: "module_probe.use", Module: "module.probe.dnspup",
	}); !errors.Is(err, ErrFeatureDenied) {
		t.Fatalf("AuthorizeModule(disabled) error = %v", err)
	}
	var reason string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT payload->>'reason' FROM audit_events
		WHERE action='entitlement.guard.reject' AND request_id='module-disabled-commit'`).Scan(&reason); err != nil || reason != ReasonLocallyDisabled {
		t.Fatalf("reject audit reason = %q, %v", reason, err)
	}
	// The stop asks for no reason: the audit names the plugin and its code only.
	var auditPayload string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT payload::text FROM audit_events
		WHERE action=$1 AND request_id='plugin-local-key-1'`, LocalDisableAction).Scan(&auditPayload); err != nil ||
		strings.Contains(auditPayload, `"reason"`) || !strings.Contains(auditPayload, `"feature_code": "module.probe.dnspup"`) {
		t.Fatalf("disable audit payload = %s, %v", auditPayload, err)
	}
	// Same key, same body: the same answer, nothing written twice.
	if again, err := store.Disable(t.Context(), actor, "key-1", LocalDisableInput{PluginID: "io.cdnca.probe-dnspup",
		FeatureCode: "module.probe.dnspup"}); err != nil || !reflect.DeepEqual(again, disabled) {
		t.Fatalf("Disable(replay) = %+v, %v", again, err)
	}
	if _, err := store.Disable(t.Context(), actor, "key-1", LocalDisableInput{PluginID: "io.cdnca.selfwaf",
		FeatureCode: "pack.selfwaf"}); !errors.Is(err, ErrLocalDisableIdempotency) {
		t.Fatalf("Disable(same key, other body) error = %v", err)
	}
	// A new key on an already stopped plugin keeps the first stop.
	if again, err := store.Disable(t.Context(), actor, "key-2", LocalDisableInput{PluginID: "io.cdnca.probe-dnspup",
		FeatureCode: "module.probe.dnspup"}); err != nil || !again.Disabled || again.DisabledBy == nil ||
		*again.DisabledBy != *disabled.DisabledBy || again.DisabledAt == nil || !again.DisabledAt.Equal(*disabled.DisabledAt) {
		t.Fatalf("Disable(already stopped) = %+v, %v", again, err)
	}
	for _, input := range []LocalDisableInput{
		{PluginID: "io.cdnca.sites", FeatureCode: FeatureSitesManage},    // not a plugin code
		{PluginID: "io.cdnca.other", FeatureCode: "module.probe.dnspup"}, // code held by another plugin
		{PluginID: "Bad ID", FeatureCode: "pack.selfwaf"},                // plugin id
	} {
		if _, err := store.Disable(t.Context(), actor, "key-"+uuid.NewString(), input); !errors.Is(err, ErrLocalDisableInvalid) {
			t.Errorf("Disable(%+v) error = %v, want ErrLocalDisableInvalid", input, err)
		}
	}
	list, err := store.List(t.Context())
	if err != nil || len(list) != 1 || list[0].PluginID != "io.cdnca.probe-dnspup" {
		t.Fatalf("List() = %+v, %v", list, err)
	}

	enabled, err := store.Enable(t.Context(), actor, "key-3", "io.cdnca.probe-dnspup")
	if err != nil || enabled.Disabled || enabled.FeatureCode != "module.probe.dnspup" {
		t.Fatalf("Enable() = %+v, %v", enabled, err)
	}
	if got := features(); !got["module.probe.dnspup"] {
		t.Fatalf("features after enable = %v", got)
	}
	if err := fixture.checkModule(t, "module.probe.dnspup", "enabled"); err != nil {
		t.Fatalf("CheckModule(enabled) error = %v", err)
	}
	// Enabling a plugin that is not stopped answers its state and changes nothing.
	if again, err := store.Enable(t.Context(), actor, "key-4", "io.cdnca.probe-dnspup"); err != nil || again.Disabled {
		t.Fatalf("Enable(not stopped) = %+v, %v", again, err)
	}
	var actions []string
	rows, err := fixture.pool.Query(t.Context(), `SELECT action FROM audit_events WHERE action LIKE 'plugin.local.%'
		AND resource_id='io.cdnca.probe-dnspup' ORDER BY occurred_at,stream_position`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, action)
	}
	if !reflect.DeepEqual(actions, []string{LocalDisableAction, LocalEnableAction}) {
		t.Fatalf("audits = %v", actions)
	}
	if !reflect.DeepEqual(notified, [][]string{{"module.probe.dnspup"}, {"module.probe.dnspup"}}) {
		t.Fatalf("changed callbacks = %v", notified)
	}
}
