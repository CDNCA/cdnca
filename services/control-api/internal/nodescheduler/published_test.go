package nodescheduler

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type publishedRow struct {
	endpointID uuid.UUID
	published  bool
}

type publishedRows struct {
	items []publishedRow
	index int
}

func (rows *publishedRows) Next() bool                                   { rows.index++; return rows.index <= len(rows.items) }
func (rows *publishedRows) Close()                                       {}
func (rows *publishedRows) Err() error                                   { return nil }
func (rows *publishedRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (rows *publishedRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *publishedRows) Values() ([]any, error)                       { return nil, nil }
func (rows *publishedRows) RawValues() [][]byte                          { return nil }
func (rows *publishedRows) Conn() *pgx.Conn                              { return nil }
func (rows *publishedRows) Scan(dest ...any) error {
	item := rows.items[rows.index-1]
	*dest[0].(*uuid.UUID) = item.endpointID
	*dest[1].(*bool) = item.published
	return nil
}

type publishedQuerier struct {
	rows  []publishedRow
	err   error
	sql   string
	args  []any
	calls int
}

func (querier *publishedQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return nil }
func (querier *publishedQuerier) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	querier.calls++
	querier.sql, querier.args = sql, args
	if querier.err != nil {
		return nil, querier.err
	}
	return &publishedRows{items: querier.rows}, nil
}

func TestAttachPublishedReadsMigration501View(t *testing.T) {
	scopeID, groupID := uuid.New(), uuid.New()
	primary, standby, missing := uuid.New(), uuid.New(), uuid.New()
	group := LineGroupRevision{
		TenantScopeID: scopeID, GroupID: groupID, Revision: 4,
		Endpoints: []Endpoint{{ID: primary}, {ID: standby}, {ID: missing}},
	}
	querier := &publishedQuerier{rows: []publishedRow{{primary, true}, {standby, false}, {uuid.New(), true}}}
	if err := attachPublished(context.Background(), querier, &group); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(querier.sql, "FROM node_line_endpoint_published") ||
		!strings.Contains(querier.sql, "config_revision=$3") {
		t.Fatalf("sql = %s", querier.sql)
	}
	if len(querier.args) != 3 || querier.args[0] != scopeID || querier.args[1] != groupID || querier.args[2] != int64(4) {
		t.Fatalf("args = %#v", querier.args)
	}
	got := group.Endpoints
	if got[0].Published == nil || !*got[0].Published || got[1].Published == nil || *got[1].Published ||
		got[2].Published != nil {
		t.Fatalf("published = %v %v %v", got[0].Published, got[1].Published, got[2].Published)
	}
}

func TestAttachPublishedSkipsEmptyGroupAndWrapsErrors(t *testing.T) {
	querier := &publishedQuerier{err: errors.New("boom")}
	if err := attachPublished(context.Background(), querier, &LineGroupRevision{}); err != nil || querier.calls != 0 {
		t.Fatalf("empty group err=%v calls=%d", err, querier.calls)
	}
	group := LineGroupRevision{Endpoints: []Endpoint{{ID: uuid.New()}}}
	err := attachPublished(context.Background(), querier, &group)
	if err == nil || !strings.Contains(err.Error(), "node line endpoint publication") {
		t.Fatalf("err = %v", err)
	}
}
