package autodefense

import "testing"

// TestLimits (fix-adplatwire): the snapshot limits are part 1 only, within
// the platform settings' bounds, and survive Split / Assemble.
func TestLimits(t *testing.T) {
	bad := []func(*Limits){
		func(l *Limits) { l.MaxSites = 0 },
		func(l *Limits) { l.MaxSites = MaxSites + 1 },
		func(l *Limits) { l.BanL3PerMinute = 0 },
		func(l *Limits) { l.BanL4PerMinute = MaxBansPerMinute + 1 },
		func(l *Limits) { l.CircuitResumeMinutes = 0 },
		func(l *Limits) { l.CircuitResumeMinutes = MaxResumeMinutes + 1 },
		func(l *Limits) { l.CircuitManualAfterBreaks = 0 },
		func(l *Limits) { l.CircuitManualAfterBreaks = MaxManualAfterBreaks + 1 },
	}
	for index, mutate := range bad {
		limits := DefaultLimits()
		mutate(&limits)
		snapshot := testSnapshot()
		snapshot.Canonical()
		snapshot.Limits = &limits
		if snapshot.Validate() == nil {
			t.Errorf("case %d %+v accepted", index, limits)
		}
	}
	snapshot := testSnapshot()
	snapshot.Canonical()
	snapshot.Limits = &Limits{MaxSites: 7, BanL3PerMinute: 3, BanL4PerMinute: 2, CircuitResumeMinutes: 5, CircuitManualAfterBreaks: 3}
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
	second := snapshot
	second.Part, second.Parts = 2, 2
	if second.Validate() == nil {
		t.Error("limits on part 2 accepted")
	}
	parts, err := Split(snapshot, "k1")
	if err != nil {
		t.Fatal(err)
	}
	whole, err := Assemble(parts)
	if err != nil || whole.Limits == nil || *whole.Limits != *snapshot.Limits {
		t.Fatalf("assembled limits %+v: %v", whole.Limits, err)
	}
	if DefaultLimits() != (Limits{MaxSites: 10000, BanL3PerMinute: 5000, BanL4PerMinute: 2000, CircuitResumeMinutes: 30,
		CircuitManualAfterBreaks: 2}) {
		t.Error("defaults")
	}
}
