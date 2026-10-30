package entitlementusage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type fakeTraffic struct {
	from, to time.Time
	exclude  bool
	value    uint64
	err      error
}

func (traffic *fakeTraffic) InstallationTrafficBytes(_ context.Context, from, to time.Time, exclude bool) (uint64, error) {
	traffic.from, traffic.to, traffic.exclude = from, to, exclude
	return traffic.value, traffic.err
}

func TestMonthStartIsTheUTCCalendarMonth(t *testing.T) {
	shanghai := time.FixedZone("CST", 8*3600)
	// 北京时间 11-01 03:00 仍是 UTC 10 月。
	if got := MonthStart(time.Date(2026, 11, 1, 3, 0, 0, 0, shanghai)); !got.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("month start=%v", got)
	}
}

// 没有 ClickHouse（分析查询未开）或查询失败：整轮不出值、不伪造 0，且不碰数据库。
func TestCollectRefusesWithoutTraffic(t *testing.T) {
	pool := &pgxpool.Pool{} // never used: the traffic check comes first
	channels := func() int { return 3 }
	if _, _, err := (Collector{Pool: pool, ReleaseChannels: channels}).Collect(context.Background()); !errors.Is(err, ErrTrafficUnavailable) {
		t.Fatalf("nil traffic err=%v", err)
	}
	failing := &fakeTraffic{err: errors.New("clickhouse down")}
	if _, _, err := (Collector{Pool: pool, Traffic: failing, ReleaseChannels: channels,
		Now: func() time.Time { return time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC) }}).Collect(context.Background()); !errors.Is(err, ErrTrafficUnavailable) {
		t.Fatalf("failing traffic err=%v", err)
	}
	if !failing.from.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) || !failing.to.Equal(time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("window=[%v,%v)", failing.from, failing.to)
	}
	blockedErr := Collector{Pool: pool, Traffic: &fakeTraffic{}, ReleaseChannels: channels,
		ExcludeBlocked: func(context.Context) (bool, error) { return false, errors.New("pg down") }}
	if _, _, err := blockedErr.Collect(context.Background()); !errors.Is(err, ErrTrafficUnavailable) {
		t.Fatalf("exclude switch err=%v", err)
	}
}
