package systemconfig

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestReadNodeMonitoringConfiguration(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	read := func(tx pgx.Tx) MonitoringConfiguration {
		t.Helper()
		value, err := ReadNodeMonitoringConfiguration(t.Context(), tx, fixture.platform.ScopeID)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	begin := func() pgx.Tx {
		t.Helper()
		tx, err := fixture.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		return tx
	}
	tx := begin()
	if got := read(tx); !reflect.DeepEqual(got, MonitoringConfiguration{State: "unconfigured"}) {
		t.Fatalf("implicit configuration: %+v", got)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	var streams int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM system_configuration_streams`).Scan(&streams); err != nil || streams != 0 {
		t.Fatalf("read created a stream: %d %v", streams, err)
	}
	draft, err := fixture.service.CreateDraft(t.Context(), fixture.platform, createDraftRequest(0, "monitor-read-draft", ProjectBootstrapConfiguration()))
	if err != nil {
		t.Fatal(err)
	}
	tx = begin()
	if got := read(tx); got.State != "not_activated" || got.HeadRevision != draft.Revision || got.ActiveRevision != nil || got.Policy != nil || got.ActivatedAt != nil {
		t.Fatalf("draft was promoted: %+v", got)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.RecordPreflight(t.Context(), fixture.platform, passingPreflight(draft.Revision, draft.SnapshotSHA256, "monitor-read-preflight")); err != nil {
		t.Fatal(err)
	}
	active, err := fixture.service.Activate(t.Context(), fixture.platform, ActivateRequest{Revision: draft.Revision, IdempotencyKey: "monitor-read-activate", RequestID: "monitor-read-activate"})
	if err != nil {
		t.Fatal(err)
	}
	tx = begin()
	want := read(tx)
	if want.State != "active" || want.ActiveRevision == nil || *want.ActiveRevision != active.Revision || !want.ActivatedAt.Equal(active.StateChangedAt) || !want.Policy.Enabled || want.Policy.RequestedProtocol != "tcp" || want.Policy.RequestedPort != nil {
		t.Fatalf("active legacy policy: %+v", want)
	}
	configuration := ProjectBootstrapConfiguration()
	monitoring := EffectiveNodeMonitoring(configuration.NodeMonitoring)
	enabled, port := false, uint16(81)
	monitoring.MonitorEnabled, monitoring.Protocol, monitoring.MonitorPort = &enabled, "http", &port
	configuration.NodeMonitoring = &monitoring
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	next, err := fixture.service.CreateDraft(ctx, fixture.platform, createDraftRequest(active.Revision, "monitor-read-next", configuration))
	if err != nil {
		t.Fatalf("read-only snapshot blocked writer: %v", err)
	}
	if got := read(tx); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot changed within transaction: %+v", got)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	tx = begin()
	got := read(tx)
	if got.HeadRevision != next.Revision || got.ActiveRevision == nil || *got.ActiveRevision != active.Revision || !reflect.DeepEqual(got.Policy, want.Policy) {
		t.Fatalf("head draft replaced active policy: %+v", got)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.RecordPreflight(t.Context(), fixture.platform, passingPreflight(next.Revision, next.SnapshotSHA256, "monitor-read-next-preflight")); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Activate(t.Context(), fixture.platform, ActivateRequest{Revision: next.Revision, ExpectedActiveRevision: active.Revision, IdempotencyKey: "monitor-read-next-activate", RequestID: "monitor-read-next-activate"}); err != nil {
		t.Fatal(err)
	}
	tx = begin()
	got = read(tx)
	if got.Policy.Enabled || got.Policy.RequestedProtocol != "http" || got.Policy.RequestedPort == nil || *got.Policy.RequestedPort != 81 {
		t.Fatalf("explicit active request lost: %+v", got)
	}
}

func TestReadNodeMonitoringConfigurationCorruption(t *testing.T) {
	scope, one := uuid.New(), int64(1)
	for _, mutation := range []string{"missing revision", "unknown schema", "invalid snapshot", "wrong hash", "wrong scope", "wrong revision", "wrong status", "zero activation", "unsafe head", "unsafe active", "active above head"} {
		t.Run(mutation, func(t *testing.T) {
			head, active := one, one
			if mutation == "unsafe head" {
				head = 1 << 53
			}
			if mutation == "unsafe active" {
				head, active = 1<<53, 1<<53
			}
			if mutation == "active above head" {
				active = 2
			}
			row := effectiveResourceRow(func(dest ...any) error {
				if mutation == "missing revision" {
					return pgx.ErrNoRows
				}
				if err := monitoringReadRevisionRow(t, scope, one, StatusActive).Scan(dest...); err != nil {
					return err
				}
				switch mutation {
				case "unknown schema":
					*dest[3].(*string) = "unknown/v9"
				case "invalid snapshot":
					*dest[4].(*[]byte) = []byte(`{}`)
				case "wrong hash":
					(*dest[5].(*[]byte))[0] ^= 1
				case "wrong scope":
					*dest[0].(*uuid.UUID) = uuid.New()
				case "wrong revision":
					*dest[1].(*int64) = 2
				case "wrong status":
					*dest[2].(*string) = StatusDraft
				case "zero activation":
					*dest[9].(*time.Time) = time.Time{}
				}
				return nil
			})
			got, err := ReadNodeMonitoringConfiguration(t.Context(), monitoringReadFixture(&head, &active, row), scope)
			if err == nil || !reflect.DeepEqual(got, MonitoringConfiguration{}) {
				t.Fatalf("corruption accepted: %+v %v", got, err)
			}
		})
	}
	// An invalid unactivated head is unavailable, never the same as no configuration.
	if _, err := ReadNodeMonitoringConfiguration(t.Context(), monitoringReadFixture(&one, nil, invalidEffectiveResourceRevisionRow(scope, one)), scope); err == nil {
		t.Fatal("corrupt draft silently ignored")
	}
	for _, row := range []pgx.Row{
		effectiveResourceRow(func(...any) error { return pgx.ErrNoRows }),
		effectiveResourceRow(func(...any) error { return errors.New("injected unavailable read") }),
		effectiveResourceRow(func(dest ...any) error { *dest[0].(*string) = "tenant"; return nil }),
	} {
		if _, err := ReadNodeMonitoringConfiguration(t.Context(), &effectiveResourceTxStub{rows: []pgx.Row{row}}, scope); err == nil {
			t.Fatal("invalid platform scope/read accepted")
		}
	}
	zero, safeMaximum := int64(0), int64(1<<53-1)
	if got, err := ReadNodeMonitoringConfiguration(t.Context(), monitoringReadFixture(&zero, nil), scope); err != nil || !reflect.DeepEqual(got, MonitoringConfiguration{State: "unconfigured"}) {
		t.Fatalf("zero head changed bootstrap semantics: %+v %v", got, err)
	}
	if got, err := ReadNodeMonitoringConfiguration(t.Context(), monitoringReadFixture(&safeMaximum, &safeMaximum, monitoringReadRevisionRow(t, scope, safeMaximum, StatusActive)), scope); err != nil || got.HeadRevision != safeMaximum {
		t.Fatalf("safe integer boundary rejected: %+v %v", got, err)
	}
	if _, err := ReadNodeMonitoringConfiguration(t.Context(), nil, scope); !errors.Is(err, ErrInvalidStore) {
		t.Fatal(err)
	}
	if _, err := ReadNodeMonitoringConfiguration(nil, &effectiveResourceTxStub{}, scope); !errors.Is(err, ErrInvalidStore) {
		t.Fatal(err)
	}
}

func TestMonitoringPolicyDefaults(t *testing.T) {
	value := EffectiveNodeMonitoring(nil)
	got := monitoringPolicyFromActive(value)
	if !got.Enabled || got.RequestedProtocol != "tcp" || got.RequestedPort != nil || got.ProbeIntervalMS != 10000 || got.ProbeTimeoutMS != 3000 || got.FailureThreshold != 3 || got.RecoveryThreshold != 3 {
		t.Fatalf("legacy defaults: %+v", got)
	}
	custom, monitor, disabled := uint16(8080), uint16(443), false
	value.PortMode, value.CustomPort, value.MonitorEnabled, value.Protocol = PortModeCustom, &custom, &disabled, "ping"
	got = monitoringPolicyFromActive(value)
	if got.Enabled || got.RequestedProtocol != "ping" || got.RequestedPort == nil || *got.RequestedPort != custom {
		t.Fatal("explicit request lost")
	}
	value.MonitorPort = &monitor
	if got := monitoringPolicyFromActive(value); got.RequestedPort == nil || *got.RequestedPort != monitor {
		t.Fatal("monitor_port did not take precedence")
	}
}

func monitoringReadFixture(head, active *int64, rows ...pgx.Row) *effectiveResourceTxStub {
	return &effectiveResourceTxStub{rows: append([]pgx.Row{effectiveResourceRow(func(dest ...any) error {
		*dest[0].(*string), *dest[1].(**uuid.UUID) = "platform", nil
		*dest[2].(**int64), *dest[3].(**int64) = head, active
		return nil
	})}, rows...)}
}

func monitoringReadRevisionRow(t *testing.T, scope uuid.UUID, revision int64, status string) pgx.Row {
	t.Helper()
	_, raw, _, err := CanonicalSnapshot(ProjectBootstrapConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return effectiveResourceRow(func(dest ...any) error {
		if err := invalidEffectiveResourceRevisionRow(scope, revision).Scan(dest...); err != nil {
			return err
		}
		*dest[2].(*string), *dest[4].(*[]byte), *dest[5].(*[]byte) = status, raw, digest[:]
		return nil
	})
}
