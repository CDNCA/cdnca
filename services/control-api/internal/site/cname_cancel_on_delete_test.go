package site

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// cancelTestTx answers only the in-flight CNAME job query.
type cancelTestTx struct {
	pgx.Tx
	jobs  [][2]uuid.UUID
	query string
	args  []any
	execs []string
	eargs [][]any
}

func (tx *cancelTestTx) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	tx.execs, tx.eargs = append(tx.execs, query), append(tx.eargs, args)
	return pgconn.CommandTag{}, nil
}

func (tx *cancelTestTx) Query(_ context.Context, query string, args ...any) (pgx.Rows, error) {
	tx.query, tx.args = query, args
	return &cancelTestRows{jobs: tx.jobs, index: -1}, nil
}

type cancelTestRows struct {
	pgx.Rows
	jobs  [][2]uuid.UUID
	index int
}

func (rows *cancelTestRows) Next() bool                                   { rows.index++; return rows.index < len(rows.jobs) }
func (rows *cancelTestRows) Close()                                       {}
func (rows *cancelTestRows) Err() error                                   { return nil }
func (rows *cancelTestRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (rows *cancelTestRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *cancelTestRows) Scan(dest ...any) error {
	*dest[0].(*uuid.UUID), *dest[1].(*uuid.UUID) = rows.jobs[rows.index][0], rows.jobs[rows.index][1]
	return nil
}

// retest-n1 step 4: deleting a site cancels every queued/running CNAME
// intent and allocation job of that site in the delete transaction; a job
// that settled meanwhile (invalid transition) does not fail the delete.
func TestSiteDeleteCancelsInFlightCNAMEJobs(t *testing.T) {
	tenantID, scopeID, siteID := uuid.New(), uuid.New(), uuid.New()
	intentJob, allocationJob, settledJob := uuid.New(), uuid.New(), uuid.New()
	tx := &cancelTestTx{jobs: [][2]uuid.UUID{{tenantID, intentJob}, {tenantID, allocationJob}, {tenantID, settledJob}}}
	now := time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)
	var cancelled []uuid.UUID
	actor := Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: "tenant"}
	err := cancelSiteCNAMEJobs(context.Background(), tx, actor, "delete-request", scopeID, siteID, now,
		func(_ context.Context, _ pgx.Tx, gotActor Actor, requestID string, gotTenant, jobID uuid.UUID, at time.Time) error {
			if gotActor != actor || requestID != "delete-request" || gotTenant != tenantID || !at.Equal(now) {
				t.Fatalf("cancel(%s, %s, %s)", gotTenant, jobID, at)
			}
			if jobID == settledJob {
				return jobstate.ErrInvalidTransition
			}
			cancelled = append(cancelled, jobID)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(cancelled) != 2 || cancelled[0] != intentJob || cancelled[1] != allocationJob {
		t.Fatalf("cancelled = %v", cancelled)
	}
	if len(tx.args) != 2 || tx.args[0] != scopeID || tx.args[1] != siteID {
		t.Fatalf("query args = %v", tx.args)
	}
	for _, required := range []string{"job.state IN ('queued','running')", "job.kind='dns.cname.intent'",
		"cname_allocation_intents", "job.kind='dns.cname.allocation'", "cname_allocation_targets",
		"site_id=$2", "FOR UPDATE OF job"} {
		if !strings.Contains(tx.query, required) {
			t.Errorf("in-flight CNAME job query missing %q", required)
		}
	}
	// n12b: the site's own CNAME owners are retired in the same transaction.
	if len(tx.execs) != 1 || !strings.Contains(tx.execs[0], "INSERT INTO cname_record_retirements") ||
		!strings.Contains(tx.execs[0], "allocation.mode='site'") || tx.eargs[0][0] != scopeID || tx.eargs[0][1] != siteID {
		t.Fatalf("retirement exec = %v %v", tx.execs, tx.eargs)
	}
}

func TestSiteDeleteCNAMEJobCancelFailureAbortsDelete(t *testing.T) {
	tx := &cancelTestTx{jobs: [][2]uuid.UUID{{uuid.New(), uuid.New()}}}
	boom := errors.New("lock lost")
	err := cancelSiteCNAMEJobs(context.Background(), tx, Actor{}, "r", uuid.New(), uuid.New(), time.Now(),
		func(context.Context, pgx.Tx, Actor, string, uuid.UUID, uuid.UUID, time.Time) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}
