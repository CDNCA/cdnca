package firewallactioncontrol

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type firewallActionSourceRevisionTxStub struct {
	query string
	args  []any
	tag   pgconn.CommandTag
	err   error
}

func (stub *firewallActionSourceRevisionTxStub) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	stub.query = query
	stub.args = args
	return stub.tag, stub.err
}

func TestAdvanceFirewallActionSourceRevisionIsAtomicAndExact(t *testing.T) {
	scopeID := uuid.New()
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	stub := &firewallActionSourceRevisionTxStub{tag: pgconn.NewCommandTag("UPDATE 1")}
	if err := advanceFirewallActionSourceRevision(t.Context(), stub, scopeID, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stub.query, "source_revision=source_revision+1") || len(stub.args) != 2 ||
		stub.args[0] != scopeID || stub.args[1] != now {
		t.Fatalf("source revision update = %q args=%v", stub.query, stub.args)
	}

	stub = &firewallActionSourceRevisionTxStub{tag: pgconn.NewCommandTag("UPDATE 0")}
	if err := advanceFirewallActionSourceRevision(t.Context(), stub, scopeID, now); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing scope error = %v", err)
	}
	want := errors.New("database unavailable")
	stub = &firewallActionSourceRevisionTxStub{err: want}
	if err := advanceFirewallActionSourceRevision(t.Context(), stub, scopeID, now); !errors.Is(err, want) {
		t.Fatalf("database error = %v", err)
	}
}
