package packageperiod

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestTrafficFactorUsesExactCeilingRounding(t *testing.T) {
	one, err := NewTrafficFactor(10, 10)
	if err != nil {
		t.Fatal(err)
	}
	if one.Numerator() != 1 || one.Denominator() != 1 {
		t.Fatalf("reduced 1.0 factor = %d/%d", one.Numerator(), one.Denominator())
	}
	if got, err := one.Apply(math.MaxUint64); err != nil || got != math.MaxUint64 {
		t.Fatalf("1.0 Apply(MaxUint64) = (%d, %v)", got, err)
	}

	onePointOne, err := NewTrafficFactor(11, 10)
	if err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[uint64]uint64{0: 0, 1: 2, 10: 11, 11: 13, 100: 110} {
		got, applyErr := onePointOne.Apply(raw)
		if applyErr != nil || got != want {
			t.Errorf("1.1 Apply(%d) = (%d, %v), want (%d, nil)", raw, got, applyErr, want)
		}
	}
}

func TestTrafficFactorRejectsInvalidAndOverflow(t *testing.T) {
	for _, values := range [][2]uint64{
		{0, 1},
		{1, 0},
		{0, 0},
		{MaxTrafficFactorComponent + 1, 1},
		{1, MaxTrafficFactorComponent + 1},
		{MaxTrafficMultiplier + 1, 1},
	} {
		if _, err := NewTrafficFactor(values[0], values[1]); !errors.Is(err, ErrInvalidFactor) {
			t.Fatalf("NewTrafficFactor(%d, %d) error = %v, want %v",
				values[0], values[1], err, ErrInvalidFactor)
		}
	}
	factor, err := NewTrafficFactor(11, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factor.Apply(math.MaxUint64); !errors.Is(err, ErrTrafficOverflow) {
		t.Fatalf("Apply(MaxUint64) error = %v, want %v", err, ErrTrafficOverflow)
	}
}

func TestTrafficFactorReducesBeforeOperationalLimits(t *testing.T) {
	factor, err := NewTrafficFactor(1_100_000, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if factor.Numerator() != 11 || factor.Denominator() != 10 {
		t.Fatalf("reduced factor = %d/%d, want 11/10", factor.Numerator(), factor.Denominator())
	}
	maxReduced, err := NewTrafficFactor(math.MaxUint64, math.MaxUint64)
	if err != nil || maxReduced.Numerator() != 1 || maxReduced.Denominator() != 1 {
		t.Fatalf("max reduced factor = %d/%d, %v", maxReduced.Numerator(), maxReduced.Denominator(), err)
	}
}

func TestCycleSnapshotFreezesTrafficConfiguration(t *testing.T) {
	location := mustLocation(t, "UTC")
	start := time.Date(2026, time.July, 1, 0, 0, 0, 0, location)
	validity := mustCustomValidity(t, start, start.AddDate(0, 2, 0), location)
	cycle, err := CurrentCycle("subscription-snapshot", validity, CyclePolicy{Kind: CycleMonthly}, start)
	if err != nil {
		t.Fatal(err)
	}
	factorV1, _ := NewTrafficFactor(1, 1)
	settled, err := NewCycleSnapshot(cycle, factorV1, "billing-config-v1")
	if err != nil {
		t.Fatal(err)
	}

	factorV2, _ := NewTrafficFactor(11, 10)
	resolved, err := ResolveCycleSnapshot(cycle, factorV2, "billing-config-v2", &settled)
	if err != nil {
		t.Fatal(err)
	}
	oldAmount, oldErr := settled.BillTCP(101)
	resolvedAmount, resolvedErr := resolved.BillTCP(101)
	if oldErr != nil || resolvedErr != nil || oldAmount != 101 || resolvedAmount != 101 {
		t.Fatalf("same-cycle billing = old (%d, %v), resolved (%d, %v)",
			oldAmount, oldErr, resolvedAmount, resolvedErr)
	}
	if resolved != settled || resolved.ConfigRevision() != "billing-config-v1" ||
		resolved.TrafficFactor() != factorV1 {
		t.Fatalf("same-cycle snapshot changed: %#v", resolved)
	}

	nextCycle, err := CurrentCycle("subscription-snapshot", validity, CyclePolicy{Kind: CycleMonthly},
		start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	next, err := ResolveCycleSnapshot(nextCycle, factorV2, "billing-config-v2", &settled)
	if err != nil {
		t.Fatal(err)
	}
	nextAmount, nextErr := next.BillTCP(101)
	if nextErr != nil || nextAmount != 112 || next.ConfigRevision() != "billing-config-v2" ||
		next.ResetKey() == settled.ResetKey() {
		t.Fatalf("next-cycle snapshot = amount (%d, %v), snapshot %#v", nextAmount, nextErr, next)
	}
}
