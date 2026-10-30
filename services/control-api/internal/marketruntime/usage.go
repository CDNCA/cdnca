package marketruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/usage"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/google/uuid"
)

const (
	usageStateFile = "market-usage-cursor.json"
	usageBucket    = usage.BucketSeconds * time.Second
	// usageSettle leaves late access events time to land before a bucket is
	// reported; the market keeps the first report of a bucket and bills it
	// 15 minutes after it closes.
	usageSettle   = 10 * time.Minute
	usageLookback = 7 * 24 * time.Hour
	usageMaxSpan  = 24 * time.Hour
)

// UsageSource lists the grants to meter and their local 5-minute traffic.
type UsageSource interface {
	UsageTargets(ctx context.Context) ([]marketsupply.UsageTarget, error)
	TrafficBuckets(ctx context.Context, tenantScopeID, subscriptionID uuid.UUID, start, end time.Time) ([]usage.Item, error)
}

// UsageReporter submits signed usage reports.
type UsageReporter interface {
	ReportUsage(ctx context.Context, self marketclient.Identity, report usage.Report) (marketclient.UsageResult, error)
}

// WithUsage turns on leaf usage reporting every interval.
func (r *Runtime) WithUsage(source UsageSource, reporter UsageReporter, every time.Duration) *Runtime {
	if every <= 0 {
		every = 5 * time.Minute
	}
	r.usageSource, r.usageReporter, r.usageEvery = source, reporter, every
	return r
}

func (r *Runtime) usageLoop(ctx context.Context) {
	for {
		if err := r.reportUsage(ctx); err != nil && ctx.Err() == nil {
			r.log.Warn("market usage report failed", "err", err)
		}
		if !sleep(ctx, r.usageEvery) {
			return
		}
	}
}

// reportUsage sends every closed, settled bucket once per grant. The cursor
// moves only after the market answered; a report retried after a lost
// response carries the same report ID, so the market drops the replay.
func (r *Runtime) reportUsage(ctx context.Context) error {
	self := r.identity()
	if self.MemberID == uuid.Nil {
		return nil
	}
	targets, err := r.usageSource.UsageTargets(ctx)
	if err != nil {
		return err
	}
	cursor, err := r.loadUsageCursor()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	end := now.Add(-usageSettle).Truncate(usageBucket)
	var errs []error
	for _, target := range targets {
		key := target.SubscriptionID.String()
		start := now.Add(-usageLookback).Truncate(usageBucket)
		if since := target.Since.UTC().Truncate(usageBucket); since.After(start) {
			start = since
		}
		if done, ok := cursor[key]; ok && done.After(start) {
			start = done
		}
		for start.Before(end) {
			stop := start.Add(usageMaxSpan)
			if stop.After(end) {
				stop = end
			}
			items, err := r.usageSource.TrafficBuckets(ctx, target.TenantScopeID, target.SubscriptionID, start, stop)
			if err != nil {
				errs = append(errs, err)
				break
			}
			if len(items) > 0 {
				for i := range items {
					items[i].GrantID = target.GrantID
				}
				id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("cdnca-market-usage/"+self.MemberID.String()+"/"+key+"/"+
					strconv.FormatInt(start.Unix(), 10)+"/"+strconv.FormatInt(stop.Unix(), 10)))
				result, err := r.usageReporter.ReportUsage(ctx, self, usage.Report{Schema: usage.SchemaV2, ReportID: id, LeafMemberID: self.MemberID,
					CreatedAt: now.Unix(), Items: items})
				if err != nil {
					errs = append(errs, err)
					break
				}
				if result.Rejected > 0 || result.Conflicts > 0 {
					r.log.Warn("market usage partly refused", "subscription", key, "rejected", result.Rejected,
						"conflicts", result.Conflicts)
				}
			}
			cursor[key] = stop
			if err := r.saveUsageCursor(cursor); err != nil {
				return err
			}
			start = stop
		}
	}
	return errors.Join(errs...)
}

func (r *Runtime) loadUsageCursor() (map[string]time.Time, error) {
	cursor := map[string]time.Time{}
	raw, err := os.ReadFile(filepath.Join(r.cfg.StateDir, usageStateFile))
	if errors.Is(err, os.ErrNotExist) {
		return cursor, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &cursor); err != nil {
		// A corrupt cursor only costs re-sending reports the market dedupes.
		return map[string]time.Time{}, nil
	}
	return cursor, nil
}

func (r *Runtime) saveUsageCursor(cursor map[string]time.Time) error {
	if err := os.MkdirAll(r.cfg.StateDir, 0o700); err != nil {
		return err
	}
	raw, _ := json.Marshal(cursor)
	tmp := filepath.Join(r.cfg.StateDir, usageStateFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(r.cfg.StateDir, usageStateFile))
}
