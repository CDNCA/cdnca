package marketruntime

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/usage"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/google/uuid"
)

type fakeUsageSource struct {
	targets []marketsupply.UsageTarget
	windows [][2]time.Time
}

func (f *fakeUsageSource) UsageTargets(context.Context) ([]marketsupply.UsageTarget, error) { return f.targets, nil }
func (f *fakeUsageSource) TrafficBuckets(_ context.Context, _, _ uuid.UUID, start, end time.Time) ([]usage.Item, error) {
	f.windows = append(f.windows, [2]time.Time{start, end})
	return []usage.Item{{BucketStart: start.Unix(), BytesOut: 100, Requests: 2}}, nil
}

type fakeReporter struct {
	reports []usage.Report
	fail    int
}

func (f *fakeReporter) ReportUsage(_ context.Context, _ marketclient.Identity, r usage.Report) (marketclient.UsageResult, error) {
	if f.fail > 0 {
		f.fail--
		f.reports = append(f.reports, r)
		return marketclient.UsageResult{}, errors.New("market unreachable")
	}
	f.reports = append(f.reports, r)
	return marketclient.UsageResult{Accepted: len(r.Items)}, nil
}

func TestUsageReportsEachWindowOnceAndRetriesWithTheSameID(t *testing.T) {
	grant, sub := uuid.New(), uuid.New()
	since := time.Now().UTC().Add(-90 * time.Minute)
	source := &fakeUsageSource{targets: []marketsupply.UsageTarget{{GrantID: grant, TenantScopeID: uuid.New(), SubscriptionID: sub, Since: since}}}
	reporter := &fakeReporter{fail: 1}
	r := New(Config{StateDir: t.TempDir()}, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithUsage(source, reporter, time.Minute)
	r.id = marketclient.Identity{MemberID: uuid.New()}

	if err := r.reportUsage(t.Context()); err == nil {
		t.Fatal("market failure must surface")
	}
	if err := r.reportUsage(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(reporter.reports) != 2 || reporter.reports[0].ReportID != reporter.reports[1].ReportID {
		t.Fatalf("a retry must reuse the report ID: %+v", reporter.reports)
	}
	first := source.windows[0]
	if !first[0].Equal(since.Truncate(usageBucket)) || first[1].After(time.Now().UTC().Add(-usageSettle)) ||
		reporter.reports[1].Items[0].GrantID != grant {
		t.Fatalf("window %v, item %+v", first, reporter.reports[1].Items[0])
	}
	// Nothing new has settled: the cursor keeps the window from being sent again.
	before := len(reporter.reports)
	if err := r.reportUsage(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(reporter.reports) != before {
		t.Fatalf("already reported window sent again: %d reports", len(reporter.reports))
	}
	// A restart reads the cursor back.
	again := New(Config{StateDir: r.cfg.StateDir}, nil, nil, nil, r.log).WithUsage(source, reporter, time.Minute)
	again.id = r.id
	if err := again.reportUsage(t.Context()); err != nil || len(reporter.reports) != before {
		t.Fatalf("restart re-sent: %d %v", len(reporter.reports), err)
	}
}

func TestUsageSkippedBeforeRegistration(t *testing.T) {
	reporter := &fakeReporter{}
	r := New(Config{StateDir: t.TempDir()}, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithUsage(&fakeUsageSource{targets: []marketsupply.UsageTarget{{GrantID: uuid.New(), SubscriptionID: uuid.New(), Since: time.Now().Add(-time.Hour)}}}, reporter, time.Minute)
	if err := r.reportUsage(t.Context()); err != nil || len(reporter.reports) != 0 {
		t.Fatalf("reported before registration: %v %d", err, len(reporter.reports))
	}
}
