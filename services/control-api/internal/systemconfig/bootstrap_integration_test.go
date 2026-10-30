package systemconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func readMonitoring(t *testing.T, fixture systemConfigFixture) MonitoringConfiguration {
	t.Helper()
	var result MonitoringConfiguration
	if err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		var err error
		result, err = ReadNodeMonitoringConfiguration(context.Background(), tx, fixture.platform.ScopeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func countAudit(t *testing.T, fixture systemConfigFixture, action string) int {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action=$2 AND resource_type='system_configuration_revision'`,
		fixture.platform.ScopeID, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestBootstrapDefaultActivationActivatesProjectDefaultsOnce(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	ctx := context.Background()
	if got := readMonitoring(t, fixture); got.State != "unconfigured" {
		t.Fatalf("fresh monitoring state = %#v", got)
	}

	result, err := BootstrapDefaultActivation(ctx, fixture.service, fixture.platform)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != BootstrapActivated || result.Revision != 1 {
		t.Fatalf("bootstrap result = %#v", result)
	}
	monitoring := readMonitoring(t, fixture)
	if monitoring.State != "active" || monitoring.ActiveRevision == nil || *monitoring.ActiveRevision != 1 ||
		monitoring.Policy == nil || !monitoring.Policy.Enabled || monitoring.Policy.RequestedProtocol != "tcp" {
		t.Fatalf("activated monitoring = %#v", monitoring)
	}
	active, err := fixture.service.GetActive(ctx, fixture.platform)
	if err != nil {
		t.Fatal(err)
	}
	_, _, defaultHash, err := CanonicalSnapshot(ProjectBootstrapConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	if active.SnapshotSHA256 != defaultHash {
		t.Fatalf("active snapshot = %s, want project defaults %s", active.SnapshotSHA256, defaultHash)
	}
	for _, action := range []string{operationCreateDraft, operationPreflight, operationActivate} {
		if got := countAudit(t, fixture, action); got != 1 {
			t.Fatalf("audit %s count = %d, want 1", action, got)
		}
	}

	again, err := BootstrapDefaultActivation(ctx, fixture.service, fixture.platform)
	if err != nil {
		t.Fatal(err)
	}
	if again.Outcome != BootstrapAlreadyActive || again.Revision != 1 {
		t.Fatalf("rerun result = %#v", again)
	}
	if countRows(t, fixture.pool, "system_configuration_revisions") != 1 || countAudit(t, fixture, operationActivate) != 1 {
		t.Fatal("rerun changed configuration facts")
	}
}

func TestBootstrapDefaultActivationNeverOverwritesOperatorConfiguration(t *testing.T) {
	t.Run("existing active revision", func(t *testing.T) {
		fixture := newSystemConfigFixture(t)
		ctx := context.Background()
		configuration := ProjectBootstrapConfiguration()
		configuration.Nginx.WorkerConnections = 2048
		draft, err := fixture.service.CreateDraft(ctx, fixture.platform, createDraftRequest(0, "operator-draft", configuration))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.service.RecordPreflight(ctx, fixture.platform, passingPreflight(1, draft.SnapshotSHA256, "operator-preflight")); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.service.Activate(ctx, fixture.platform, ActivateRequest{
			Revision: 1, ExpectedActiveRevision: 0, IdempotencyKey: "operator-activate", RequestID: "operator-activate",
		}); err != nil {
			t.Fatal(err)
		}
		result, err := BootstrapDefaultActivation(ctx, fixture.service, fixture.platform)
		if err != nil || result.Outcome != BootstrapAlreadyActive || result.Revision != 1 {
			t.Fatalf("bootstrap over active operator revision = %#v, %v", result, err)
		}
		active, err := fixture.service.GetActive(ctx, fixture.platform)
		if err != nil || active.SnapshotSHA256 != draft.SnapshotSHA256 || countRows(t, fixture.pool, "system_configuration_revisions") != 1 {
			t.Fatalf("operator revision changed: %#v %v", active, err)
		}
	})

	t.Run("unactivated operator draft", func(t *testing.T) {
		fixture := newSystemConfigFixture(t)
		ctx := context.Background()
		if _, err := fixture.service.CreateDraft(ctx, fixture.platform, createDraftRequest(0, "operator-draft", ProjectBootstrapConfiguration())); err != nil {
			t.Fatal(err)
		}
		_, err := BootstrapDefaultActivation(ctx, fixture.service, fixture.platform)
		if !errors.Is(err, ErrBootstrapNotFresh) {
			t.Fatalf("bootstrap over operator draft error = %v, want ErrBootstrapNotFresh", err)
		}
		if countRows(t, fixture.pool, "system_configuration_revisions") != 1 || countStatus(t, fixture.pool, StatusDraft) != 1 {
			t.Fatal("operator draft was modified")
		}
	})

	t.Run("enrolled node requires edge publication", func(t *testing.T) {
		fixture := newSystemConfigFixture(t)
		ctx := context.Background()
		if _, err := fixture.pool.Exec(ctx, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			VALUES($1,$2,'edge','active',$3,1)`, uuid.New(), fixture.platform.ScopeID, fixture.platform.UserID); err != nil {
			t.Fatal(err)
		}
		_, err := BootstrapDefaultActivation(ctx, fixture.service, fixture.platform)
		if !errors.Is(err, ErrBootstrapNotFresh) {
			t.Fatalf("bootstrap with enrolled node error = %v, want ErrBootstrapNotFresh", err)
		}
		if countRows(t, fixture.pool, "system_configuration_revisions") != 0 {
			t.Fatal("bootstrap wrote a revision despite an enrolled node")
		}
	})
}

func TestBootstrapDefaultActivationResumesAfterInterruptedRun(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	ctx := context.Background()
	// Simulate a run that stopped after the draft step: the same deterministic
	// idempotency key must be replayed instead of being reported as foreign.
	interrupted, err := NewServiceWithDependencies(fixture.pool, failingAfterDraftAuditor{delegate: audit.New(fixture.pool)}, fixture.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BootstrapDefaultActivation(ctx, interrupted, fixture.platform); !errors.Is(err, errInjectedAudit) {
		t.Fatalf("interrupted bootstrap error = %v", err)
	}
	if streamHead(t, fixture.pool) != 1 || countStatus(t, fixture.pool, StatusDraft) != 1 {
		t.Fatal("interrupted bootstrap did not leave its draft")
	}
	result, err := BootstrapDefaultActivation(ctx, fixture.service, fixture.platform)
	if err != nil || result.Outcome != BootstrapActivated || result.Revision != 1 {
		t.Fatalf("resumed bootstrap = %#v, %v", result, err)
	}
	if countRows(t, fixture.pool, "system_configuration_revisions") != 1 || countStatus(t, fixture.pool, StatusActive) != 1 {
		t.Fatal("resumed bootstrap did not activate the original draft")
	}
}

type failingAfterDraftAuditor struct{ delegate AuditAppender }

func (auditor failingAfterDraftAuditor) Append(ctx context.Context, tx pgx.Tx, event audit.Event) error {
	if event.Action != operationCreateDraft {
		return errInjectedAudit
	}
	return auditor.delegate.Append(ctx, tx, event)
}
