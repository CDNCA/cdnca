package entitlementguard

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

func TestBuiltInNodeMonitoringRequiresVerifiedLicense(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	lease := integrationLease(fixture.now, 1) // No monitoring feature and no node quota.
	encoded := fixture.install(t, lease, fixture.now)
	check := builtinMonitoringCheck(fixture, "valid")
	tx := fixture.begin(t)
	defer tx.Rollback(context.Background())
	decision, err := fixture.guard().CheckBuiltInNodeMonitoring(t.Context(), tx, check)
	if err != nil {
		t.Fatalf("valid license without monitoring feature: %v", err)
	}
	if decision.Feature != "builtin.node_monitoring" || decision.Quota != "" || decision.Current != 0 || decision.Limit != 0 ||
		decision.TargetScopeID != check.TargetScopeID || decision.ActorScopeID != check.ActorScopeID ||
		decision.ActorUserID != check.ActorUserID || decision.ResourceID != check.ResourceID ||
		decision.ResourceType != check.ResourceType || decision.Operation != check.Operation || decision.RequestID != check.RequestID ||
		decision.LeaseSerial != 1 || decision.LeaseSHA256 != sha256.Sum256(encoded) ||
		decision.RevocationRevision != 1 || decision.RevocationSHA256 == ([32]byte{}) ||
		decision.RevocationKeyID != fixture.signer.id || !decision.EvaluatedAt.Equal(fixture.now) ||
		!decision.ExpiresAt.Equal(time.Unix(lease.ExpiresAt, 0)) {
		t.Fatalf("built-in decision = %#v", decision)
	}
	for _, feature := range []string{"builtin.node_monitoring", FeatureNodesManage} {
		paid := FeatureCheck{TargetScopeID: check.TargetScopeID, ActorScopeID: check.ActorScopeID,
			ActorUserID: check.ActorUserID, ResourceType: check.ResourceType, ResourceID: check.ResourceID,
			RequestID: "ordinary-" + feature, Operation: check.Operation, Feature: feature}
		if _, err := fixture.guard().CheckFeature(t.Context(), tx, paid); !errors.Is(err, ErrFeatureDenied) {
			t.Fatalf("ordinary CheckFeature(%s) bypassed membership: %v", feature, err)
		}
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*entitlement.Lease)
		fault  string
		query  string
		clock  time.Duration
		want   error
		reason string
	}{
		{name: "missing cache", query: `UPDATE control_installation_entitlement SET current_serial=NULL,last_status='uninstalled'`, want: ErrUnavailable, reason: "lease_unavailable"},
		{name: "missing trust", want: ErrUnavailable, reason: "trust_anchor_unavailable"},
		{name: "invalid envelope", query: `UPDATE entitlement_cached_leases SET signed_lease='{}'`, want: ErrInvalid, reason: "invalid_envelope"},
		{name: "invalid signature", want: ErrInvalid, reason: "invalid_signature"},
		{name: "wrong installation", mutate: func(lease *entitlement.Lease) { lease.InstallationID = uuid.NewString() }, want: ErrInvalid, reason: "installation_mismatch"},
		{name: "wrong signed serial", mutate: func(lease *entitlement.Lease) { lease.Serial++ }, want: ErrInvalid, reason: "lease_serial_mismatch"},
		{name: "wrong audience", mutate: func(lease *entitlement.Lease) { lease.Audience = "another-audience" }, want: ErrInvalid, reason: "audience_mismatch"},
		{name: "not yet valid", mutate: func(lease *entitlement.Lease) {
			lease.NotBefore = fixture.now.Add(entitlement.VerifierClockSkew + time.Second).Unix()
		}, want: ErrStateDenied, reason: "not_yet_valid"},
		{name: "expired", mutate: func(lease *entitlement.Lease) {
			lease.ExpiresAt = fixture.now.Add(-time.Second).Unix()
			lease.GraceUntil = fixture.now.Unix()
		}, want: ErrStateDenied, reason: "lease_expired"},
		{name: "cached revoked", query: `UPDATE entitlement_cached_leases SET status='revoked'`, want: ErrStateDenied, reason: "lease_revoked"},
		{name: "missing revocation", fault: `ALTER TABLE control_entitlement_revocation_lkg DISABLE TRIGGER control_entitlement_revocation_lkg_guard_084`, query: `DELETE FROM control_entitlement_revocation_lkg`, want: ErrRevocationUnavailable, reason: "revocation_state_unavailable"},
		{name: "invalid revocation", fault: `ALTER TABLE control_entitlement_revocation_lkg DISABLE TRIGGER control_entitlement_revocation_lkg_guard_084`, query: `UPDATE control_entitlement_revocation_lkg SET artifact='{}'`, want: ErrRevocationInvalid, reason: "revocation_state_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := fixture.begin(t)
			defer tx.Rollback(context.Background())
			// Corrupt-state injection is confined to this random schema and rolled
			// back with its named trigger change; production guards stay enabled.
			if test.fault != "" {
				if _, err := tx.Exec(t.Context(), test.fault); err != nil {
					t.Fatal(err)
				}
			}
			if test.query != "" {
				if _, err := tx.Exec(t.Context(), test.query); err != nil {
					t.Fatal(err)
				}
			}
			if test.mutate != nil || test.name == "invalid signature" {
				changed := lease
				if test.mutate != nil {
					test.mutate(&changed)
				}
				signed := signIntegrationLease(t, changed, fixture.signer)
				if test.name == "invalid signature" {
					signed.Signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				}
				raw, err := json.Marshal(signed)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(t.Context(), `UPDATE entitlement_cached_leases SET signed_lease=$1`, raw); err != nil {
					t.Fatal(err)
				}
			}
			trust := fixture.trust
			if test.name == "missing trust" {
				trust = nil
			}
			guard := NewGuard(fixture.pool, func() time.Time { return fixture.now.Add(test.clock) }, trust)
			check := builtinMonitoringCheck(fixture, test.name)
			if _, err := guard.CheckBuiltInNodeMonitoring(t.Context(), tx, check); !errors.Is(err, test.want) || !IsDenial(err) {
				t.Fatalf("built-in check = %v, want %v", err, test.want)
			}
			var feature, quota, reason, actorScope, targetScope, operation string
			if err := tx.QueryRow(t.Context(), `SELECT payload->>'feature',payload->>'quota',payload->>'reason',
				payload->>'actor_scope_id',payload->>'target_scope_id',payload->>'operation'
				FROM audit_events WHERE request_id=$1 AND action='entitlement.guard.reject' AND result='denied'`,
				check.RequestID).Scan(&feature, &quota, &reason, &actorScope, &targetScope, &operation); err != nil {
				t.Fatal(err)
			}
			if feature != "builtin.node_monitoring" || quota != "" || reason != test.reason ||
				actorScope != check.ActorScopeID.String() || targetScope != check.TargetScopeID.String() || operation != check.Operation {
				t.Fatalf("denial audit = %q %q %q %q %q %q", feature, quota, reason, actorScope, targetScope, operation)
			}
			if err := tx.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			var audits int
			var lastStatus string
			if err := fixture.pool.QueryRow(t.Context(), `SELECT last_status,
				(SELECT count(*) FROM audit_events WHERE request_id=$1)
				FROM control_installation_entitlement WHERE singleton`, check.RequestID).Scan(&lastStatus, &audits); err != nil {
				t.Fatal(err)
			}
			if lastStatus != "valid" || audits != 0 {
				t.Fatalf("rollback left status=%q audits=%d", lastStatus, audits)
			}
		})
	}
	t.Run("signed revocation overrides valid cached status", func(t *testing.T) {
		acceptIntegrationRevocation(t, fixture.pool, fixture.trust, fixture.signer,
			fixture.now, fixture.now.Add(-time.Minute), 2, []uint64{1})
		tx := fixture.begin(t)
		defer tx.Rollback(context.Background())
		// Inject a stale decomposed status while retaining the real signed LKG.
		if _, err := tx.Exec(t.Context(), `ALTER TABLE entitlement_cached_leases DISABLE TRIGGER entitlement_cached_leases_revocation_guard_084`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `UPDATE entitlement_cached_leases SET status='valid'`); err != nil {
			t.Fatal(err)
		}
		check := builtinMonitoringCheck(fixture, "signed-revoked")
		if _, err := fixture.guard().CheckBuiltInNodeMonitoring(t.Context(), tx, check); !errors.Is(err, ErrStateDenied) {
			t.Fatalf("signed revoked check = %v", err)
		}
		var reason string
		var revision int
		if err := tx.QueryRow(t.Context(), `SELECT payload->>'reason',(payload->>'revocation_revision')::int
			FROM audit_events WHERE request_id=$1`, check.RequestID).Scan(&reason, &revision); err != nil {
			t.Fatal(err)
		}
		if reason != "lease_revoked" || revision != 2 {
			t.Fatalf("signed revocation audit reason=%q revision=%d", reason, revision)
		}
	})
}

func TestBuiltInNodeMonitoringWaiterUsesPostLockClock(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	lease := integrationLease(fixture.now, 1)
	lease.ExpiresAt, lease.GraceUntil = fixture.now.Add(time.Second).Unix(), fixture.now.Add(2*time.Second).Unix()
	fixture.install(t, lease, fixture.now)
	holder := fixture.begin(t)
	defer holder.Rollback(context.Background())
	if _, err := holder.Exec(t.Context(), `SELECT singleton FROM control_installation_entitlement WHERE singleton FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	waiter := fixture.begin(t)
	defer waiter.Rollback(context.Background())
	var waiterPID int
	if err := waiter.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&waiterPID); err != nil {
		t.Fatal(err)
	}
	var released atomic.Bool
	var clockCalls atomic.Int32
	guard := NewGuard(fixture.pool, func() time.Time {
		clockCalls.Add(1)
		if released.Load() {
			return fixture.now.Add(3 * time.Second)
		}
		return fixture.now
	}, fixture.trust)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	check := builtinMonitoringCheck(fixture, "post-lock-clock")
	go func() {
		_, err := guard.CheckBuiltInNodeMonitoring(ctx, waiter, check)
		done <- err
	}()
	waitForEntitlementBlock(t, fixture.pool, waiterPID)
	if clockCalls.Load() != 0 {
		t.Fatal("clock sampled before acquiring entitlement lock")
	}
	released.Store(true)
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrStateDenied) {
		joined = true
		t.Fatalf("post-lock check = %v, want expired denial", err)
	}
	joined = true
	var reason, evaluatedAt string
	if err := waiter.QueryRow(t.Context(), `SELECT payload->>'reason',payload->>'evaluated_at'
		FROM audit_events WHERE request_id=$1`, check.RequestID).Scan(&reason, &evaluatedAt); err != nil {
		t.Fatal(err)
	}
	if reason != "lease_expired" || evaluatedAt != fixture.now.Add(3*time.Second).UTC().Format(time.RFC3339Nano) {
		t.Fatalf("post-lock audit reason=%q evaluatedAt=%q", reason, evaluatedAt)
	}
}

func TestBuiltInNodeMonitoringInvalidInput(t *testing.T) {
	if _, err := NewGuard(nil, nil, nil).CheckBuiltInNodeMonitoring(t.Context(), nil, BuiltInNodeMonitoringCheck{}); err == nil {
		t.Fatal("missing transaction and audit context accepted")
	}
}

func builtinMonitoringCheck(fixture webhookFeatureFixture, suffix string) BuiltInNodeMonitoringCheck {
	return BuiltInNodeMonitoringCheck{
		TargetScopeID: fixture.actorScope, ActorScopeID: fixture.actorScope, ActorUserID: fixture.actorUser,
		ResourceType: "system_configuration", ResourceID: fixture.actorScope,
		RequestID: "builtin-monitoring-" + suffix, Operation: "system_configuration.node_monitoring.expand",
	}
}
