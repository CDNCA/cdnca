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

func TestLoadActiveNodeMonitoring(t *testing.T) {
	t.Run("no implicit bootstrap activation", func(t *testing.T) {
		pool := isolatedSystemConfigPool(t)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		document, activatedAt, err := LoadActiveNodeMonitoring(t.Context(), tx)
		if err != nil || !reflect.DeepEqual(document, CategoryDocument{}) || !activatedAt.IsZero() {
			t.Fatalf("missing platform produced active monitoring: %#v %v %v", document, activatedAt, err)
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, uuid.New()); err != nil {
			t.Fatal(err)
		}
		document, activatedAt, err = LoadActiveNodeMonitoring(t.Context(), tx)
		if err != nil || !reflect.DeepEqual(document, CategoryDocument{}) || !activatedAt.IsZero() {
			t.Fatalf("missing stream produced active monitoring: %#v %v %v", document, activatedAt, err)
		}
	})
	t.Run("unactivated head is not published", func(t *testing.T) {
		fixture := newSystemConfigFixture(t)
		if _, err := fixture.service.CreateDraft(t.Context(), fixture.platform,
			createDraftRequest(0, "monitoring-draft", ProjectBootstrapConfiguration())); err != nil {
			t.Fatal(err)
		}
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		document, activatedAt, err := LoadActiveNodeMonitoring(t.Context(), tx)
		if err != nil || !reflect.DeepEqual(document, CategoryDocument{}) || !activatedAt.IsZero() {
			t.Fatalf("draft produced active monitoring: %#v %v %v", document, activatedAt, err)
		}
	})
	t.Run("active snapshot remains locked through command insertion", func(t *testing.T) {
		fixture := newSystemConfigFixture(t)
		active := activateEffectiveResourceConfiguration(t, fixture, ProjectBootstrapConfiguration(), "monitoring-active")
		fixture.clock.Set(active.StateChangedAt.Add(time.Second))
		draft, err := fixture.service.CreateDraft(t.Context(), fixture.platform,
			createDraftRequest(active.Revision, "monitoring-next-draft", ProjectBootstrapConfiguration()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.service.RecordPreflight(t.Context(), fixture.platform,
			passingPreflight(draft.Revision, draft.SnapshotSHA256, "monitoring-next-preflight")); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		tx, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		var blockerPID int32
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
			t.Fatal(err)
		}
		document, activatedAt, err := LoadActiveNodeMonitoring(ctx, tx)
		if err != nil || document.ActiveRevision != active.Revision || document.HeadRevision != active.Revision ||
			document.SnapshotSHA256 != active.SnapshotSHA256 || !activatedAt.Equal(active.StateChangedAt) ||
			!reflect.DeepEqual(document.Value, EffectiveNodeMonitoring(active.Configuration.NodeMonitoring)) {
			t.Fatalf("active snapshot differs from original activation: %#v %v %v", document, activatedAt, err)
		}
		completed := make(chan error, 1)
		go func() {
			_, err := fixture.service.Activate(ctx, fixture.platform, ActivateRequest{
				Revision: draft.Revision, ExpectedActiveRevision: active.Revision,
				IdempotencyKey: "monitoring-next-activate", RequestID: "monitoring-next-activate",
			})
			completed <- err
		}()
		blocked := false
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			if err := fixture.pool.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))
			)`, blockerPID).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break
			}
			select {
			case err := <-completed:
				t.Fatalf("activation escaped the held snapshot lock: %v", err)
			case <-time.After(10 * time.Millisecond):
			}
		}
		if !blocked {
			t.Fatal("did not observe activation blocked on the snapshot transaction")
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-completed; err != nil {
			t.Fatal(err)
		}
		next, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = next.Rollback(context.Background()) }()
		document, activatedAt, err = LoadActiveNodeMonitoring(ctx, next)
		if err != nil || document.ActiveRevision != draft.Revision || !activatedAt.Equal(fixture.clock.Now()) {
			t.Fatalf("next reconciliation did not observe the committed activation: %#v %v %v", document, activatedAt, err)
		}
	})
	t.Run("invalid persisted facts fail closed", func(t *testing.T) {
		platformID := uuid.New()
		for _, mutation := range []string{"read failure", "negative revision", "missing revision", "invalid canonical snapshot",
			"snapshot digest mismatch", "non-active status", "missing activation time"} {
			t.Run(mutation, func(t *testing.T) {
				rows := []pgx.Row{effectiveResourceRow(func(destinations ...any) error {
					*destinations[0].(*uuid.UUID) = platformID
					return nil
				}), effectiveResourceRow(func(destinations ...any) error {
					if mutation == "read failure" {
						return errors.New("injected database read failure")
					}
					revision := int64(1)
					if mutation == "negative revision" {
						revision = -1
					}
					*destinations[0].(**int64) = &revision
					return nil
				})}
				if mutation == "missing revision" {
					rows = append(rows, effectiveResourceRow(func(...any) error { return pgx.ErrNoRows }))
				} else {
					rows = append(rows, effectiveResourceRow(func(destinations ...any) error {
						if err := invalidEffectiveResourceRevisionRow(platformID, 1).Scan(destinations...); err != nil {
							return err
						}
						if mutation != "invalid canonical snapshot" {
							_, snapshot, _, err := CanonicalSnapshot(ProjectBootstrapConfiguration())
							if err != nil {
								return err
							}
							digest := sha256.Sum256(snapshot)
							*destinations[4].(*[]byte) = snapshot
							*destinations[5].(*[]byte) = digest[:]
							if mutation == "snapshot digest mismatch" {
								digest[0] ^= 1
							}
							if mutation == "non-active status" {
								*destinations[2].(*string) = StatusDraft
							}
							if mutation == "missing activation time" {
								*destinations[9].(*time.Time) = time.Time{}
							}
						}
						return nil
					}))
				}
				document, activatedAt, err := LoadActiveNodeMonitoring(t.Context(), &effectiveResourceTxStub{rows: rows})
				if err == nil || !reflect.DeepEqual(document, CategoryDocument{}) || !activatedAt.IsZero() {
					t.Fatalf("invalid active fact accepted: %#v %v %v", document, activatedAt, err)
				}
			})
		}
		if _, _, err := LoadActiveNodeMonitoring(t.Context(), nil); !errors.Is(err, ErrInvalidStore) {
			t.Fatalf("nil transaction error = %v", err)
		}
		if _, _, err := LoadActiveNodeMonitoring(nil, &effectiveResourceTxStub{}); !errors.Is(err, ErrInvalidStore) {
			t.Fatalf("nil context error = %v", err)
		}
	})
}
