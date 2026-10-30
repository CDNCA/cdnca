// Package pgxscript is a test-only pgx.Tx: each statement is answered by the
// first unused step whose fragment occurs in the SQL, so a producer's
// transaction body runs without PostgreSQL. Savepoints are the same Tx.
package pgxscript

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Step answers one statement containing Match: Rows for Query (or the first
// row for QueryRow); NoRows makes QueryRow return pgx.ErrNoRows.
type Step struct {
	Match  string
	Rows   [][]any
	NoRows bool
}

type Tx struct {
	pgx.Tx
	mu    sync.Mutex
	steps []Step
	used  []bool
	Execs []string
}

func New(steps ...Step) *Tx { return &Tx{steps: steps, used: make([]bool, len(steps))} }

func (tx *Tx) take(sql string) (Step, error) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	for i, step := range tx.steps {
		if !tx.used[i] && strings.Contains(sql, step.Match) {
			tx.used[i] = true
			return step, nil
		}
	}
	return Step{}, fmt.Errorf("pgxscript: unexpected statement %q", strings.Join(strings.Fields(sql), " "))
}

// Unused lists the fragments of steps no statement consumed.
func (tx *Tx) Unused() []string {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	var out []string
	for i, step := range tx.steps {
		if !tx.used[i] {
			out = append(out, step.Match)
		}
	}
	return out
}

func (tx *Tx) Begin(context.Context) (pgx.Tx, error) { return tx, nil }
func (tx *Tx) Commit(context.Context) error          { return nil }
func (tx *Tx) Rollback(context.Context) error        { return nil }

func (tx *Tx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	tx.mu.Lock()
	tx.Execs = append(tx.Execs, sql)
	tx.mu.Unlock()
	return pgconn.NewCommandTag("OK 1"), nil
}

func (tx *Tx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	step, err := tx.take(sql)
	if err != nil {
		return row{err: err}
	}
	if step.NoRows || len(step.Rows) == 0 {
		return row{err: pgx.ErrNoRows}
	}
	return row{values: step.Rows[0]}
}

func (tx *Tx) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	step, err := tx.take(sql)
	if err != nil {
		return nil, err
	}
	return &rows{values: step.Rows, index: -1}, nil
}

type row struct {
	values []any
	err    error
}

func (r row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	return assign(r.values, dest)
}

type rows struct {
	values [][]any
	index  int
}

func (r *rows) Close()                                       {}
func (r *rows) Err() error                                   { return nil }
func (r *rows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("SELECT") }
func (r *rows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *rows) Next() bool                                   { r.index++; return r.index < len(r.values) }
func (r *rows) Scan(dest ...any) error                       { return assign(r.values[r.index], dest) }
func (r *rows) Values() ([]any, error)                       { return r.values[r.index], nil }
func (r *rows) RawValues() [][]byte                          { return nil }
func (r *rows) Conn() *pgx.Conn                              { return nil }

func assign(values []any, dest []any) error {
	if len(values) != len(dest) {
		return fmt.Errorf("pgxscript: %d values for %d destinations", len(values), len(dest))
	}
	for i, value := range values {
		target := reflect.ValueOf(dest[i])
		if target.Kind() != reflect.Pointer || target.IsNil() {
			return errors.New("pgxscript: destination is not a pointer")
		}
		if value == nil {
			target.Elem().SetZero()
			continue
		}
		source := reflect.ValueOf(value)
		if !source.Type().AssignableTo(target.Elem().Type()) {
			return fmt.Errorf("pgxscript: value %d is %s, destination %s", i, source.Type(), target.Elem().Type())
		}
		target.Elem().Set(source)
	}
	return nil
}
