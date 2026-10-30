package sitetrafficlimit

import (
	"strings"
	"testing"
	"time"
)

func ptr(value int64) *int64 { return &value }

func TestDecidePicksTheReachedCap(t *testing.T) {
	day := time.Date(2026, 10, 18, 16, 0, 0, 0, time.UTC)
	month := time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)
	since := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	setting := Setting{DailyBytes: ptr(100), MonthlyBytes: ptr(1000), TotalBytes: ptr(5000)}
	for name, test := range map[string]struct {
		daily, monthly, total uint64
		want                  string
		start                 time.Time
	}{
		"within":        {daily: 99, monthly: 999, total: 4999, want: ""},
		"daily":         {daily: 100, monthly: 500, total: 600, want: "daily", start: day},
		"monthly first": {daily: 150, monthly: 1000, total: 1200, want: "monthly", start: month},
		"total first":   {daily: 150, monthly: 1500, total: 5000, want: "total", start: since},
	} {
		period, start := Decide(setting, test.daily, test.monthly, test.total, day, month, &since)
		if period != test.want || !start.Equal(test.start) {
			t.Errorf("%s: Decide = %q %s, want %q %s", name, period, start, test.want, test.start)
		}
	}
	if period, _ := Decide(Setting{DailyBytes: ptr(1)}, 0, 10, 10, day, month, nil); period != "" {
		t.Fatalf("an uncapped period decided %q", period)
	}
}

func TestPeriodStartsFollowTheSiteZone(t *testing.T) {
	shanghai, _ := time.LoadLocation("Asia/Shanghai")
	at := time.Date(2026, 10, 31, 17, 30, 0, 0, time.UTC) // 2026-11-01 01:30 in Shanghai
	day, month := PeriodStarts(at, shanghai)
	if !day.Equal(time.Date(2026, 10, 31, 16, 0, 0, 0, time.UTC)) || !month.Equal(time.Date(2026, 10, 31, 16, 0, 0, 0, time.UTC)) {
		t.Fatalf("PeriodStarts = %s %s", day, month)
	}
	day, month = PeriodStarts(at, time.UTC)
	if !day.Equal(time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)) || !month.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("PeriodStarts UTC = %s %s", day, month)
	}
}

func TestNormalizeSetting(t *testing.T) {
	valid := Setting{Enabled: true, DailyBytes: ptr(1 << 30), TimeZone: ""}
	if err := NormalizeSetting(&valid); err != nil || valid.TimeZone != "Asia/Shanghai" {
		t.Fatalf("valid setting: %v %q", err, valid.TimeZone)
	}
	disabled := Setting{TimeZone: "UTC"}
	if err := NormalizeSetting(&disabled); err != nil {
		t.Fatalf("a disabled limit without caps is valid: %v", err)
	}
	for name, setting := range map[string]Setting{
		"enabled without caps": {Enabled: true, TimeZone: "UTC"},
		"zero cap":             {Enabled: true, DailyBytes: ptr(0), TimeZone: "UTC"},
		"huge cap":             {Enabled: true, TotalBytes: ptr(MaxLimitBytes + 1), TimeZone: "UTC"},
		"bad zone":             {Enabled: true, DailyBytes: ptr(1), TimeZone: "Mars/Olympus"},
		"local zone":           {Enabled: true, DailyBytes: ptr(1), TimeZone: "Local"},
		"page too large":       {Enabled: true, DailyBytes: ptr(1), TimeZone: "UTC", NoticeHTML: strings.Repeat("x", 64<<10+1)},
		"page NUL":             {Enabled: true, DailyBytes: ptr(1), TimeZone: "UTC", NoticeHTML: "a\x00b"},
	} {
		if err := NormalizeSetting(&setting); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
