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

func TestLoadEffectivePlatformResourcesUsesActiveRevision(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	configuration := ProjectBootstrapConfiguration()
	configuration.Resources.MaxDomainsPerSite = 37
	active := activateEffectiveResourceConfiguration(t, fixture, configuration, "effective-active")

	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	result, err := LoadEffectivePlatformResources(t.Context(), tx, EffectiveResourceTarget{})
	if err != nil {
		t.Fatal(err)
	}
	if result.PlatformScopeID != fixture.platform.ScopeID || result.Revision != active.Revision ||
		result.SnapshotSHA256 != active.SnapshotSHA256 || result.Resources.MaxDomainsPerSite != 37 ||
		len(result.Resources.Overrides) != 0 {
		t.Fatalf("unexpected active resources: %#v", result)
	}
}

func TestLoadEffectivePlatformResourcesIgnoresUnactivatedHead(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	configuration := ProjectBootstrapConfiguration()
	configuration.Resources.MaxDomainsPerSite = 37
	if _, err := fixture.service.CreateDraft(t.Context(), fixture.platform, CreateDraftRequest{
		ExpectedHeadRevision: 0, Configuration: configuration,
		IdempotencyKey: "effective-draft", RequestID: "effective-draft",
	}); err != nil {
		t.Fatal(err)
	}

	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	result, err := LoadEffectivePlatformResources(t.Context(), tx, EffectiveResourceTarget{})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, _, snapshotHash, err := CanonicalSnapshot(ProjectBootstrapConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != 0 || result.SnapshotSHA256 != snapshotHash ||
		!reflect.DeepEqual(result.Resources, bootstrap.Resources) {
		t.Fatalf("unactivated head became authoritative: %#v", result)
	}
}

func TestLoadEffectivePlatformResourcesReadsBootstrapFromCallingTransaction(t *testing.T) {
	pool := isolatedSystemConfigPool(t)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	platformScopeID := uuid.New()
	if _, err := tx.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`,
		platformScopeID); err != nil {
		t.Fatal(err)
	}

	result, err := LoadEffectivePlatformResources(t.Context(), tx, EffectiveResourceTarget{})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, _, snapshotHash, err := CanonicalSnapshot(ProjectBootstrapConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	if result.PlatformScopeID != platformScopeID || result.Revision != 0 ||
		result.SnapshotSHA256 != snapshotHash || !reflect.DeepEqual(result.Resources, bootstrap.Resources) {
		t.Fatalf("unexpected transaction-visible bootstrap: %#v", result)
	}

	outside, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outside.Rollback(context.Background()) }()
	if _, err := LoadEffectivePlatformResources(t.Context(), outside, EffectiveResourceTarget{}); !errors.Is(err, ErrPlatformResourcesUnavailable) {
		t.Fatalf("uncommitted platform scope leaked outside transaction: %v", err)
	}
}

func TestLoadEffectivePlatformResourcesRejectsMissingPlatform(t *testing.T) {
	pool := isolatedSystemConfigPool(t)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	result, err := LoadEffectivePlatformResources(t.Context(), tx, EffectiveResourceTarget{})
	if !errors.Is(err, ErrPlatformResourcesUnavailable) || !reflect.DeepEqual(result, EffectivePlatformResources{}) {
		t.Fatalf("result=%#v error=%v", result, err)
	}
}

func TestLoadEffectivePlatformResourcesFailsClosed(t *testing.T) {
	platformScopeID := uuid.New()
	activeRevision := int64(1)
	readFailure := errors.New("database read failed")
	tests := []struct {
		name   string
		tx     pgx.Tx
		target EffectiveResourceTarget
		want   error
	}{
		{name: "nil transaction", want: ErrPlatformResourcesUnavailable},
		{name: "invalid target", tx: &effectiveResourceTxStub{},
			target: EffectiveResourceTarget{RegionID: " bad"}, want: ErrPlatformResourcesInvalid},
		{name: "platform read failure", tx: &effectiveResourceTxStub{rows: []pgx.Row{
			effectiveResourceRow(func(...any) error { return readFailure }),
		}}, want: ErrPlatformResourcesUnavailable},
		{name: "missing active revision", tx: &effectiveResourceTxStub{rows: []pgx.Row{
			effectivePlatformResourceRow(platformScopeID, &activeRevision),
			effectiveResourceRow(func(...any) error { return pgx.ErrNoRows }),
		}}, want: ErrPlatformResourcesUnavailable},
		{name: "invalid active snapshot", tx: &effectiveResourceTxStub{rows: []pgx.Row{
			effectivePlatformResourceRow(platformScopeID, &activeRevision),
			invalidEffectiveResourceRevisionRow(platformScopeID, activeRevision),
		}}, want: ErrPlatformResourcesInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := LoadEffectivePlatformResources(t.Context(), test.tx, test.target)
			if !errors.Is(err, test.want) || !reflect.DeepEqual(result, EffectivePlatformResources{}) {
				t.Fatalf("result=%#v error=%v want=%v", result, err, test.want)
			}
		})
	}
}

func activateEffectiveResourceConfiguration(
	t *testing.T,
	fixture systemConfigFixture,
	configuration Configuration,
	key string,
) Revision {
	t.Helper()
	draft, err := fixture.service.CreateDraft(t.Context(), fixture.platform, CreateDraftRequest{
		ExpectedHeadRevision: 0, Configuration: configuration,
		IdempotencyKey: key + "-draft", RequestID: key + "-draft",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.RecordPreflight(t.Context(), fixture.platform, RecordPreflightRequest{
		Revision: draft.Revision, ExpectedStatus: StatusDraft, SnapshotSHA256: draft.SnapshotSHA256,
		Checks: passingChecks(), IdempotencyKey: key + "-preflight", RequestID: key + "-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	active, err := fixture.service.Activate(t.Context(), fixture.platform, ActivateRequest{
		Revision: draft.Revision, ExpectedActiveRevision: 0,
		IdempotencyKey: key + "-activate", RequestID: key + "-activate",
	})
	if err != nil {
		t.Fatal(err)
	}
	return active
}

type effectiveResourceTxStub struct {
	pgx.Tx
	rows []pgx.Row
}

func (stub *effectiveResourceTxStub) QueryRow(context.Context, string, ...any) pgx.Row {
	if len(stub.rows) == 0 {
		return effectiveResourceRow(func(...any) error { return errors.New("unexpected query") })
	}
	row := stub.rows[0]
	stub.rows = stub.rows[1:]
	return row
}

type effectiveResourceRow func(...any) error

func (row effectiveResourceRow) Scan(destinations ...any) error {
	return row(destinations...)
}

func effectivePlatformResourceRow(platformScopeID uuid.UUID, activeRevision *int64) pgx.Row {
	return effectiveResourceRow(func(destinations ...any) error {
		*destinations[0].(*uuid.UUID) = platformScopeID
		if activeRevision == nil {
			*destinations[1].(**int64) = nil
		} else {
			revision := *activeRevision
			*destinations[1].(**int64) = &revision
		}
		return nil
	})
}

func invalidEffectiveResourceRevisionRow(platformScopeID uuid.UUID, revision int64) pgx.Row {
	return effectiveResourceRow(func(destinations ...any) error {
		now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
		snapshot := []byte(`{}`)
		digest := sha256.Sum256(snapshot)
		*destinations[0].(*uuid.UUID) = platformScopeID
		*destinations[1].(*int64) = revision
		*destinations[2].(*string) = StatusActive
		*destinations[3].(*string) = canonicalSchema
		*destinations[4].(*[]byte) = snapshot
		*destinations[5].(*[]byte) = digest[:]
		*destinations[6].(**int64) = nil
		*destinations[7].(*uuid.UUID) = uuid.New()
		*destinations[8].(*time.Time) = now
		*destinations[9].(*time.Time) = now
		return nil
	})
}
