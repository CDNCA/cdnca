package originfailover

import "testing"

func TestObserveDebounce(t *testing.T) {
	state := ProbeState{}
	for index := 1; index <= FailThreshold; index++ {
		state = Observe(state, false, true)
		want := StatusUnknown
		if index == FailThreshold {
			want = StatusUnhealthy
		}
		if state.Status != want {
			t.Fatalf("after %d failures: %s, want %s", index, state.Status, want)
		}
	}
	if state = Observe(state, true, false); state.Status != StatusUnhealthy || state.Failures != FailThreshold {
		t.Fatalf("a non-vote changed the state: %+v", state)
	}
	state = Observe(state, true, true)
	if state.Status != StatusUnhealthy {
		t.Fatalf("one success recovered: %+v", state)
	}
	if state = Observe(state, true, true); state.Status != StatusHealthy {
		t.Fatalf("two successes did not recover: %+v", state)
	}
}

func TestLevelStatusesAndOverall(t *testing.T) {
	levels := LevelStatuses([]LevelOrigin{
		{Level: 1, Status: StatusUnhealthy}, {Level: 0, Status: StatusUnhealthy}, {Level: 0, Status: StatusHealthy},
		{Level: 2, Status: StatusUnknown}, {Level: 2, Status: StatusUnhealthy},
	})
	want := []LevelStatus{{0, StatusHealthy}, {1, StatusUnhealthy}, {2, StatusUnknown}}
	if len(levels) != len(want) {
		t.Fatalf("levels %+v", levels)
	}
	for index := range want {
		if levels[index] != want[index] {
			t.Fatalf("levels %+v, want %+v", levels, want)
		}
	}
	for name, test := range map[string]struct {
		levels []LevelStatus
		want   string
	}{
		"any healthy":  {[]LevelStatus{{0, StatusUnhealthy}, {1, StatusHealthy}}, StatusHealthy},
		"all down":     {[]LevelStatus{{0, StatusUnhealthy}, {1, StatusUnhealthy}}, StatusUnhealthy},
		"down+unknown": {[]LevelStatus{{0, StatusUnhealthy}, {1, StatusUnknown}}, StatusUnknown},
		"no level":     {nil, StatusUnhealthy},
	} {
		if got := Overall(test.levels); got != test.want {
			t.Errorf("%s: %s, want %s", name, got, test.want)
		}
	}
}

func TestDecide(t *testing.T) {
	h, u, k := StatusHealthy, StatusUnhealthy, StatusUnknown
	levels := func(statuses ...string) []LevelStatus {
		result := make([]LevelStatus, len(statuses))
		for index, status := range statuses {
			result[index] = LevelStatus{Level: index, Status: status}
		}
		return result
	}
	for name, test := range map[string]struct {
		levels        []LevelStatus
		active        int
		manual        bool
		target        int
		reason        string
		failbackReady bool
		allDown       bool
	}{
		"primary healthy stays":           {levels(h, h), 0, false, 0, "", false, false},
		"primary unknown stays":           {levels(k, h), 0, false, 0, "", false, false},
		"primary down -> backup 1":        {levels(u, h, h), 0, false, 1, "level_down", false, false},
		"backup 1 down -> backup 2":       {levels(u, u, h), 1, false, 2, "level_down", false, false},
		"skip a down level":               {levels(u, u, h), 0, false, 2, "level_down", false, false},
		"prefer healthy over unknown":     {levels(u, k, h), 0, false, 2, "level_down", false, false},
		"unknown when none healthy":       {levels(u, k, u), 0, false, 1, "level_down", false, false},
		"all down keeps the level":        {levels(u, u, u), 2, false, 2, "", false, true},
		"all down from primary":           {levels(u, u), 0, false, 0, "", false, true},
		"auto failback to primary":        {levels(h, u, h), 2, false, 0, "recovered", false, false},
		"auto failback to best":           {levels(u, h, h), 2, false, 1, "recovered", false, false},
		"manual keeps, ready":             {levels(h, h), 1, true, 1, "", true, false},
		"manual still fails over further": {levels(h, u, h), 1, true, 2, "level_down", true, false},
		"manual nothing recovered":        {levels(u, h), 1, true, 1, "", false, false},
	} {
		got := Decide(test.levels, test.active, test.manual)
		if got.Target != test.target || got.Reason != test.reason || got.FailbackReady != test.failbackReady ||
			got.AllDown != test.allDown {
			t.Errorf("%s: %+v", name, got)
		}
	}
	// The active level lost its origins (the pool was edited).
	if got := Decide([]LevelStatus{{0, h}}, 3, false); got.Target != 0 {
		t.Errorf("gone level: %+v", got)
	}
	if got := FailbackTarget(levels(u, h, h), 2); got != 1 {
		t.Errorf("failback target %d", got)
	}
	if got := FailbackTarget(levels(u, u, h), 2); got != -1 {
		t.Errorf("failback target %d", got)
	}
}
