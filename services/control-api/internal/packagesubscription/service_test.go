package packagesubscription

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/google/uuid"
)

func TestLoadIANAZoneRejectsProcessLocalAndUnstableOffsets(t *testing.T) {
	for _, name := range []string{"UTC", "Asia/Shanghai", "America/New_York"} {
		location, err := loadIANAZone(name)
		if err != nil || location.String() != name {
			t.Fatalf("loadIANAZone(%q) = (%v, %v)", name, location, err)
		}
	}
	for _, name := range []string{"", "Local", "CST", "+08:00", "UTC+08:00", "Mars/Olympus", "../UTC"} {
		if _, err := loadIANAZone(name); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("loadIANAZone(%q) error = %v, want %v", name, err, ErrInvalidInput)
		}
	}
}

func TestEvaluateBlocksOnlyNewCapacityAndProducesTypedStatusIntents(t *testing.T) {
	location := mustZone(t, "America/New_York")
	start := time.Date(2026, time.March, 7, 12, 0, 0, 0, location)
	end := time.Date(2026, time.April, 7, 12, 0, 0, 0, location)
	subscription := evaluationSubscription(start, end)

	evaluation, err := Evaluate(time.Date(2026, time.March, 8, 11, 0, 0, 0, location), subscription, Usage{
		Sites: 3, Domains: 5, Nodes: 1, OtherTrafficBytes: 100, TCPTrafficBytes: 100,
	}, packageperiod.ServiceState{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(evaluation.BlockedResources) != 1 || evaluation.BlockedResources[0] != ResourceSites ||
		len(evaluation.Warnings) != 1 || evaluation.Intent != nil || evaluation.BilledTraffic != 210 {
		t.Fatalf("capacity evaluation = %#v", evaluation)
	}

	overTraffic, err := Evaluate(time.Date(2026, time.March, 8, 11, 0, 0, 0, location), subscription, Usage{
		Sites: 2, Domains: 5, Nodes: 1, TCPTrafficBytes: 910,
	}, packageperiod.ServiceState{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if overTraffic.BilledTraffic != 1001 || overTraffic.Intent == nil ||
		overTraffic.Intent.Action != TaskActionSuspend || overTraffic.Intent.Reason != TaskReasonTrafficExceeded ||
		overTraffic.Intent.DesiredEnabled {
		t.Fatalf("traffic evaluation = %#v", overTraffic)
	}

	expired, err := Evaluate(end, subscription, Usage{}, packageperiod.ServiceState{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if expired.Intent == nil || expired.Intent.Action != TaskActionSuspend || expired.Intent.Reason != TaskReasonExpired {
		t.Fatalf("expiry evaluation = %#v", expired)
	}
}

func TestEvaluateRejectsInvalidQuotaSentinels(t *testing.T) {
	location := mustZone(t, "UTC")
	start := time.Date(2026, time.July, 1, 0, 0, 0, 0, location)
	end := start.AddDate(0, 1, 0)
	base := evaluationSubscription(start, end)
	for _, test := range []struct {
		name   string
		mutate func(*QuotaSnapshot)
	}{
		{name: "sites", mutate: func(quota *QuotaSnapshot) { quota.Sites = -2 }},
		{name: "domains", mutate: func(quota *QuotaSnapshot) { quota.Domains = -2 }},
		{name: "nodes", mutate: func(quota *QuotaSnapshot) { quota.Nodes = -2 }},
		{name: "traffic", mutate: func(quota *QuotaSnapshot) { quota.TrafficBytes = -2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			subscription := base
			test.mutate(&subscription.Quotas)
			if _, err := Evaluate(start.Add(time.Hour), subscription, Usage{}, packageperiod.ServiceState{Enabled: true}); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Evaluate() error = %v, want %v", err, ErrInvalidInput)
			}
		})
	}
}

func TestEvaluateRecoversAtNewCycleBoundary(t *testing.T) {
	location := mustZone(t, "America/New_York")
	start := time.Date(2026, time.March, 7, 12, 0, 0, 0, location)
	end := time.Date(2026, time.April, 7, 12, 0, 0, 0, location)
	subscription := evaluationSubscription(start, end)
	endCopy := subscription.Period.EndsAt
	validity, err := packageperiod.NewValidity(start, location, packageperiod.Terms{EndAt: &endCopy})
	if err != nil {
		t.Fatal(err)
	}
	firstAt := time.Date(2026, time.March, 8, 11, 59, 0, 0, location)
	first, err := packageperiod.CurrentCycle(subscription.ID.String(), validity, subscription.Period.CyclePolicy, firstAt)
	if err != nil {
		t.Fatal(err)
	}
	if first.EndsAt().Sub(first.StartsAt()) != 23*time.Hour {
		t.Fatalf("DST daily cycle = [%s,%s), want 23h", first.StartsAt(), first.EndsAt())
	}
	current := packageperiod.ServiceState{Reason: packageperiod.SuspensionQuota, ResetKey: first.ResetKey()}
	recovered, err := Evaluate(time.Date(2026, time.March, 8, 12, 0, 0, 0, location), subscription, Usage{}, current)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Intent == nil || recovered.Intent.Action != TaskActionRecover ||
		recovered.Intent.Reason != TaskReasonNewCycle || !recovered.Intent.DesiredEnabled ||
		recovered.Intent.ResetKey != recovered.ResetKey {
		t.Fatalf("recovery evaluation = %#v", recovered)
	}
}

func TestEvaluateUsesExactTrafficQuotaAndResetsAtNextCycle(t *testing.T) {
	location := mustZone(t, "UTC")
	start := time.Date(2026, time.July, 1, 0, 0, 0, 0, location)
	end := start.AddDate(0, 0, 2)
	subscription := evaluationSubscription(start, end)
	subscription.Period.TimeZone = "UTC"
	subscription.Period.TrafficFactor = RationalSnapshot{Numerator: 1, Denominator: 1}
	subscription.Quotas.TrafficBytes = 100

	exact, err := Evaluate(start.Add(time.Hour), subscription, Usage{TCPTrafficBytes: 100},
		packageperiod.ServiceState{Enabled: true})
	if err != nil || exact.BilledTraffic != 100 || exact.Intent != nil {
		t.Fatalf("exact quota evaluation = (%#v, %v)", exact, err)
	}
	over, err := Evaluate(start.Add(time.Hour), subscription, Usage{TCPTrafficBytes: 101},
		packageperiod.ServiceState{Enabled: true})
	if err != nil || over.BilledTraffic != 101 || over.Intent == nil ||
		over.Intent.Reason != TaskReasonTrafficExceeded || over.ResetKey == "" {
		t.Fatalf("over quota evaluation = (%#v, %v)", over, err)
	}
	recovered, err := Evaluate(start.AddDate(0, 0, 1), subscription, Usage{}, packageperiod.ServiceState{
		Reason: packageperiod.SuspensionQuota, ResetKey: over.ResetKey,
	})
	if err != nil || recovered.Intent == nil || recovered.Intent.Reason != TaskReasonNewCycle ||
		!recovered.Intent.DesiredEnabled || recovered.ResetKey == over.ResetKey {
		t.Fatalf("next-cycle reset evaluation = (%#v, %v)", recovered, err)
	}

	subscription.Period.TrafficFactor = RationalSnapshot{Numerator: 11, Denominator: 10}
	subscription.Quotas.TrafficBytes = 110
	weighted, err := Evaluate(start.Add(time.Hour), subscription, Usage{TCPTrafficBytes: 100},
		packageperiod.ServiceState{Enabled: true})
	if err != nil || weighted.BilledTraffic != 110 || weighted.Intent != nil {
		t.Fatalf("1.1 exact quota evaluation = (%#v, %v)", weighted, err)
	}
}

func evaluationSubscription(start, end time.Time) Subscription {
	return Subscription{
		ID:            uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		TenantScopeID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		Quotas:        QuotaSnapshot{Sites: 2, Domains: 5, Nodes: 1, TrafficBytes: 1000},
		Period: PeriodSnapshot{
			StartsAt: start.UTC(), EndsAt: end.UTC(), TimeZone: "America/New_York",
			CyclePolicy:   packageperiod.CyclePolicy{Kind: packageperiod.CycleDaily},
			TrafficFactor: RationalSnapshot{Numerator: 11, Denominator: 10},
		},
		LifecycleStatus: LifecycleActive,
	}
}

func mustZone(t *testing.T, name string) *time.Location {
	t.Helper()
	location, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return location
}
