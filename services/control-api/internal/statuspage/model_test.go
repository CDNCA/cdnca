package statuspage

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLineGroupStatus(t *testing.T) {
	for _, tc := range []struct {
		total, available int
		want             string
	}{
		{0, 0, StatusOutage}, {5, 0, StatusOutage}, {5, 3, StatusDegraded}, {5, 4, StatusOperational},
		{10, 7, StatusDegraded}, {10, 8, StatusOperational}, {1, 1, StatusOperational},
	} {
		if got := lineGroupStatus(tc.total, tc.available); got != tc.want {
			t.Errorf("lineGroupStatus(%d,%d)=%s want %s", tc.total, tc.available, got, tc.want)
		}
	}
}

func TestWorstAndDay(t *testing.T) {
	if got := worst(StatusMaintenance, StatusDegraded, StatusOperational); got != StatusDegraded {
		t.Fatalf("worst=%s", got)
	}
	if got := worst(); got != StatusOperational {
		t.Fatalf("worst()=%s", got)
	}
	if dayStatus(5, 1, 0) != StatusOutage || dayStatus(5, 0, 9) != StatusDegraded || dayStatus(0, 0, 9) != StatusMaintenance ||
		dayStatus(0, 0, 0) != StatusOperational {
		t.Fatal("dayStatus order")
	}
}

func TestUptimeExcludesMaintenance(t *testing.T) {
	if uptime(0, 0, 0) != nil || uptime(60, 0, 60) != nil {
		t.Fatal("no counted minutes must be nil")
	}
	if got := *uptime(1440, 72, 0); got != 0.95 {
		t.Fatalf("uptime=%v", got)
	}
	if got := *uptime(1440, 70, 40); got != 0.95 {
		t.Fatalf("uptime without maintenance=%v", got)
	}
}

func TestSeriesFillsNinetyDays(t *testing.T) {
	id := uuid.New()
	now := time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)
	h := history{id: {"2026-11-10": {sampled: 480, outage: 48}, "2026-11-09": {sampled: 1440, degraded: 10}}}
	days, total := h.series(id, now)
	if len(days) != HistoryDays || days[0].Day != "2026-08-13" || days[89].Day != "2026-11-10" {
		t.Fatalf("days %d %s..%s", len(days), days[0].Day, days[len(days)-1].Day)
	}
	if days[89].Status != StatusOutage || days[88].Status != StatusDegraded || days[0].Status != "no_data" || days[0].Uptime != nil {
		t.Fatalf("statuses %+v %+v %+v", days[89], days[88], days[0])
	}
	if total == nil || *total != 1-48.0/1920 {
		t.Fatalf("total=%v", total)
	}
}

func TestValidText(t *testing.T) {
	if !validText("控制台 API", 1, 64, false) || validText(" x", 1, 64, false) || validText("", 1, 64, false) ||
		validText("a\nb", 0, 10, false) || !validText("a\nb", 0, 10, true) || validText("a\tb", 0, 10, true) {
		t.Fatal("validText")
	}
}
