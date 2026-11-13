package statuspage

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLineGroupStatus(t *testing.T) {
	for _, tc := range []struct {
		total, available int
		want             string
	}{
		{0, 0, StatusUnconfigured}, {5, 0, StatusOutage}, {5, 3, StatusDegraded}, {5, 4, StatusOperational},
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
	h := history{id: {"2026-11-10": {sampled: 480, outage: 48}, "2026-11-09": {sampled: 1440, degraded: 1}}}
	days, total := h.series([]uuid.UUID{id}, now, nil)
	if len(days) != HistoryDays || days[0].Day != "2026-08-13" || days[89].Day != "2026-11-10" {
		t.Fatalf("days %d %s..%s", len(days), days[0].Day, days[len(days)-1].Day)
	}
	if days[89].Status != StatusOutage || days[88].Status != StatusOperational || days[0].Status != "no_data" || days[0].Uptime != nil {
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

// A day is coloured by uptime tiers, and a day without samples is no_data, never an outage.
func TestDayTier(t *testing.T) {
	for _, tc := range []struct {
		row  dayRow
		want string
	}{
		{dayRow{}, "no_data"},
		{dayRow{sampled: 1440}, StatusOperational},
		{dayRow{sampled: 1440, outage: 1}, StatusOperational},
		{dayRow{sampled: 1440, outage: 3}, StatusDegraded},
		{dayRow{sampled: 1440, degraded: 30}, StatusDegraded},
		{dayRow{sampled: 1440, outage: 15}, StatusOutage},
		{dayRow{sampled: 60, maintenance: 60}, StatusMaintenance},
		{dayRow{sampled: 1440, maintenance: 20}, StatusMaintenance},
	} {
		if got := dayTier(tc.row); got != tc.want {
			t.Errorf("dayTier(%+v)=%s want %s", tc.row, got, tc.want)
		}
	}
}

func TestRatioAndShareStatus(t *testing.T) {
	if ratioStatus(0, 0) != StatusUnconfigured || ratioStatus(3, 0) != StatusOutage || ratioStatus(5, 3) != StatusDegraded ||
		ratioStatus(5, 4) != StatusOperational {
		t.Fatal("ratioStatus")
	}
	if shareStatus(0, 0) != StatusUnconfigured || shareStatus(10, 0) != StatusOperational || shareStatus(10, 4) != StatusDegraded ||
		shareStatus(10, 5) != StatusOutage {
		t.Fatal("shareStatus")
	}
}

func TestPageStatus(t *testing.T) {
	if pageStatus(false, nil) != StatusOperational || pageStatus(true, nil) != StatusUnconfigured ||
		pageStatus(true, []string{StatusOperational, StatusDegraded}) != StatusDegraded {
		t.Fatal("pageStatus")
	}
}

func TestMergeTakesWorstChildPerKind(t *testing.T) {
	got := dayRow{sampled: 1440, outage: 5}.merge(dayRow{sampled: 600, outage: 20, degraded: 3})
	if got != (dayRow{sampled: 1440, outage: 20, degraded: 3}) {
		t.Fatalf("merge=%+v", got)
	}
}

func TestBuildPublicGroupsAndHidden(t *testing.T) {
	now := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	group, other := AdminGroup{ID: uuid.New(), Name: "节点"}, AdminGroup{ID: uuid.New(), Name: "空组"}
	a := AdminComponent{ID: uuid.New(), Name: "网关", GroupID: &group.ID, Status: StatusOperational}
	b := AdminComponent{ID: uuid.New(), Name: "在线率", GroupID: &group.ID, Status: StatusUnconfigured}
	hidden := AdminComponent{ID: uuid.New(), Name: "隐藏", Hidden: true, Status: StatusOutage}
	alone := AdminComponent{ID: uuid.New(), Name: "独立", Status: StatusDegraded}
	built := buildPublic([]AdminGroup{group, other}, []AdminComponent{a, b, hidden, alone}, history{}, nil, now)
	if len(built.components) != 4 || built.components[0].Mode != "group" || built.components[1].Parent != built.components[0].Key {
		t.Fatalf("components %+v", built.components)
	}
	if built.components[0].Status != StatusOperational {
		t.Fatalf("group status %s: an unconfigured child must not lower it", built.components[0].Status)
	}
	if _, found := built.visible[hidden.ID]; found {
		t.Fatal("hidden component is visible")
	}
	if _, found := built.visible[other.ID]; found {
		t.Fatal("empty group is visible")
	}
	if len(built.statuses) != 2 {
		t.Fatalf("statuses %v", built.statuses)
	}
}

func TestEventsSplitByDay(t *testing.T) {
	id := uuid.New()
	start := time.Date(2026, 11, 12, 22, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 13, 1, 0, 0, 0, time.UTC)
	item := Incident{ID: uuid.New(), Kind: KindIncident, Title: "x", Impact: StatusOutage, ComponentIDs: []uuid.UUID{id}, StartedAt: start, ResolvedAt: &end}
	events := eventsFor([]uuid.UUID{id}, []Incident{item}, end)
	day1 := events(time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC))
	day2 := events(time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC))
	if len(day1) != 1 || day1[0].Minutes != 120 || len(day2) != 1 || day2[0].Minutes != 60 {
		t.Fatalf("day1=%+v day2=%+v", day1, day2)
	}
	if events(time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)) != nil {
		t.Fatal("event on a day it did not touch")
	}
}

func TestFailureReason(t *testing.T) {
	if failureReason(context.DeadlineExceeded) != "timeout" || failureReason(syscall.ECONNREFUSED) != "connection refused" ||
		failureReason(errors.New("x")) != "request failed" {
		t.Fatal("failureReason")
	}
}
