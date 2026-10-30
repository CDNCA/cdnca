package marketruntime

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/google/uuid"
)

type fakeHolds struct {
	snapshot marketclient.SupplyHolds
	err      error
}

func (f fakeHolds) SupplyHolds(context.Context) (marketclient.SupplyHolds, error) {
	return f.snapshot, f.err
}

type recordingApplier struct {
	calls []map[string]marketsupply.Hold
}

func (r *recordingApplier) RefreshLimits(_ context.Context, holds map[string]marketsupply.Hold) (int, error) {
	r.calls = append(r.calls, holds)
	return 0, nil
}

// An unreachable market still re-splits node shares but keeps the holds
// (nil map); a snapshot is keyed like the grants.
func TestRefreshHoldsKeepsLastHoldsWhenMarketUnreachable(t *testing.T) {
	path, pool := []uuid.UUID{uuid.New()}, uuid.NewString()
	applier := &recordingApplier{}
	r := New(Config{StateDir: t.TempDir()}, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.id.MemberID = uuid.New()
	r.WithHolds(fakeHolds{err: errors.New("down")}, applier, 0)
	if err := r.refreshHolds(context.Background()); err != nil || len(applier.calls) != 1 || applier.calls[0] != nil {
		t.Fatalf("unreachable: %v %+v", err, applier.calls)
	}
	r.WithHolds(fakeHolds{snapshot: marketclient.SupplyHolds{Revision: 9, Items: []marketclient.SupplyHold{
		{SubscriptionPath: path, NodePoolRef: pool, Action: "stop", Revision: 9}}}}, applier, 0)
	if err := r.refreshHolds(context.Background()); err != nil || len(applier.calls) != 2 {
		t.Fatal(err)
	}
	got := applier.calls[1]
	if h, ok := got[marketsupply.HoldKey(path, pool)]; len(got) != 1 || !ok || h.Action != "stop" || h.Revision != 9 {
		t.Fatalf("snapshot %+v", got)
	}
}
