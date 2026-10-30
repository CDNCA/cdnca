package jobstate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestVoluntaryYieldTxUsesExactClaimFence(t *testing.T) {
	tx := &voluntaryYieldTx{rows: []int64{1, 1, 1}}
	input := validVoluntaryYieldInput()
	if err := VoluntaryYieldTx(t.Context(), tx, input); err != nil {
		t.Fatal(err)
	}
	if len(tx.queries) != 3 {
		t.Fatalf("VoluntaryYieldTx() statements=%d, want 3", len(tx.queries))
	}
	for _, required := range []string{
		"INSERT INTO background_job_yield_facts_115",
		"UPDATE background_jobs job",
		"UPDATE background_job_attempts attempt",
		"tenant_id=$2", "job_id=$3", "attempt=$5", "lease_id=$6", "worker_id=$7",
		"lease_expires_at>$8", "state='running'",
		"job.attempt<job.max_attempts",
	} {
		if !strings.Contains(strings.Join(tx.queries, "\n"), required) {
			t.Fatalf("VoluntaryYieldTx SQL missing exact fence %q", required)
		}
	}
	if !strings.Contains(tx.queries[1], "state='queued'") || !strings.Contains(tx.queries[1], "claimable_at=$9") ||
		!strings.Contains(tx.queries[2], "state='deferred'") {
		t.Fatalf("VoluntaryYieldTx SQL does not yield directly to queued/deferred: %#v", tx.queries)
	}
}

func TestVoluntaryYieldTxFailsClosedAtEveryMutation(t *testing.T) {
	for step := 1; step <= 3; step++ {
		t.Run(string(rune('0'+step)), func(t *testing.T) {
			tx := &voluntaryYieldTx{rows: []int64{1, 1, 1}, failAt: step}
			err := VoluntaryYieldTx(t.Context(), tx, validVoluntaryYieldInput())
			if err == nil || len(tx.queries) != step {
				t.Fatalf("VoluntaryYieldTx() error=%v statements=%d, want failure at %d", err, len(tx.queries), step)
			}
		})
	}
	for step := 1; step <= 3; step++ {
		t.Run("lost-"+string(rune('0'+step)), func(t *testing.T) {
			rows := []int64{1, 1, 1}
			rows[step-1] = 0
			tx := &voluntaryYieldTx{rows: rows}
			err := VoluntaryYieldTx(t.Context(), tx, validVoluntaryYieldInput())
			if !errors.Is(err, ErrClaimLost) || len(tx.queries) != step {
				t.Fatalf("VoluntaryYieldTx() error=%v statements=%d, want claim loss at %d", err, len(tx.queries), step)
			}
		})
	}
}

func TestVoluntaryYieldTxRejectsInvalidOrCancelledInputWithoutWrites(t *testing.T) {
	for _, test := range []struct {
		name  string
		input VoluntaryYieldInput
	}{
		{name: "empty", input: VoluntaryYieldInput{}},
		{name: "past not before", input: func() VoluntaryYieldInput {
			input := validVoluntaryYieldInput()
			input.NotBefore = input.YieldedAt
			return input
		}()},
		{name: "oversize", input: func() VoluntaryYieldInput {
			input := validVoluntaryYieldInput()
			input.NotBefore = input.YieldedAt.Add(time.Hour + time.Microsecond)
			return input
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := &voluntaryYieldTx{rows: []int64{1, 1, 1}}
			if err := VoluntaryYieldTx(t.Context(), tx, test.input); !errors.Is(err, ErrInvalidRequest) || len(tx.queries) != 0 {
				t.Fatalf("VoluntaryYieldTx() error=%v statements=%d", err, len(tx.queries))
			}
		})
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	tx := &voluntaryYieldTx{rows: []int64{1, 1, 1}}
	if err := VoluntaryYieldTx(cancelled, tx, validVoluntaryYieldInput()); !errors.Is(err, context.Canceled) || len(tx.queries) != 0 {
		t.Fatalf("cancelled VoluntaryYieldTx() error=%v statements=%d", err, len(tx.queries))
	}
}

func validVoluntaryYieldInput() VoluntaryYieldInput {
	yieldedAt := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	return VoluntaryYieldInput{
		TenantID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		JobID:    uuid.MustParse("22222222-2222-2222-2222-222222222222"), Kind: "dns_reconcile",
		Attempt: 3, LeaseID: uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		WorkerID: "dns-worker-1", YieldedAt: yieldedAt, NotBefore: yieldedAt.Add(37 * time.Second),
	}
}

type voluntaryYieldTx struct {
	queries []string
	rows    []int64
	failAt  int
}

func (tx *voluntaryYieldTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	tx.queries = append(tx.queries, sql)
	step := len(tx.queries)
	if step == tx.failAt {
		return pgconn.CommandTag{}, errors.New("injected statement failure")
	}
	rows := int64(1)
	if step <= len(tx.rows) {
		rows = tx.rows[step-1]
	}
	return pgconn.NewCommandTag("UPDATE " + string(rune('0'+rows))), nil
}

func (*voluntaryYieldTx) Begin(context.Context) (pgx.Tx, error) { panic("unexpected Begin") }
func (*voluntaryYieldTx) Commit(context.Context) error          { panic("unexpected Commit") }
func (*voluntaryYieldTx) Rollback(context.Context) error        { panic("unexpected Rollback") }
func (*voluntaryYieldTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	panic("unexpected CopyFrom")
}
func (*voluntaryYieldTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	panic("unexpected SendBatch")
}
func (*voluntaryYieldTx) LargeObjects() pgx.LargeObjects { panic("unexpected LargeObjects") }
func (*voluntaryYieldTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	panic("unexpected Prepare")
}
func (*voluntaryYieldTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	panic("unexpected Query")
}
func (*voluntaryYieldTx) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected QueryRow")
}
func (*voluntaryYieldTx) Conn() *pgx.Conn { return nil }

var _ pgx.Tx = (*voluntaryYieldTx)(nil)
