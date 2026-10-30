// Package originfailover probes every origin of a site's pool and moves the
// pool's active origin level: when every origin of the
// active level is down, to the next level that is not; when a higher level
// recovers, back to it at once (failback auto) or only on the user's switch
// back (failback manual, which raises a "can switch back" alert instead).
// The edge (cdnca_origin.lua) starts selecting at the active level, so a
// level change is a site republication.
package originfailover

import "slices"

const (
	StatusHealthy   = "healthy"
	StatusUnhealthy = "unhealthy"
	StatusUnknown   = "unknown"

	// FailThreshold consecutive failed probes make an origin unhealthy,
	// RecoverThreshold consecutive successes healthy again (the debounce).
	FailThreshold    = 3
	RecoverThreshold = 2
)

// ProbeState is one origin's debounced probe state.
type ProbeState struct {
	Status    string
	Failures  int
	Successes int
}

// Observe folds one probe outcome into state. voted=false (the origin
// could not be probed: no prober, blocked address) keeps the state.
func Observe(state ProbeState, ok, voted bool) ProbeState {
	if state.Status == "" {
		state.Status = StatusUnknown
	}
	if !voted {
		return state
	}
	if ok {
		state.Successes, state.Failures = state.Successes+1, 0
		if state.Successes >= RecoverThreshold {
			state.Status = StatusHealthy
		}
		return state
	}
	state.Failures, state.Successes = state.Failures+1, 0
	if state.Failures >= FailThreshold {
		state.Status = StatusUnhealthy
	}
	return state
}

// LevelOrigin is one enabled origin's level and status.
type LevelOrigin struct {
	Level  int
	Status string
}

// LevelStatuses: a level is healthy when any of its enabled origins is,
// unhealthy when all are, otherwise unknown. Levels without an enabled
// origin are absent. Sorted by level.
func LevelStatuses(origins []LevelOrigin) []LevelStatus {
	byLevel := map[int][]string{}
	for _, origin := range origins {
		byLevel[origin.Level] = append(byLevel[origin.Level], origin.Status)
	}
	levels := make([]int, 0, len(byLevel))
	for level := range byLevel {
		levels = append(levels, level)
	}
	slices.Sort(levels)
	result := make([]LevelStatus, 0, len(levels))
	for _, level := range levels {
		statuses := byLevel[level]
		status := StatusUnknown
		switch {
		case slices.Contains(statuses, StatusHealthy):
			status = StatusHealthy
		case !slices.ContainsFunc(statuses, func(value string) bool { return value != StatusUnhealthy }):
			status = StatusUnhealthy
		}
		result = append(result, LevelStatus{Level: level, Status: status})
	}
	return result
}

// Overall: healthy while any level is healthy, unhealthy when every level
// is (or there is none), otherwise unknown.
func Overall(levels []LevelStatus) string {
	if len(levels) == 0 {
		return StatusUnhealthy
	}
	unhealthy := 0
	for _, level := range levels {
		switch level.Status {
		case StatusHealthy:
			return StatusHealthy
		case StatusUnhealthy:
			unhealthy++
		}
	}
	if unhealthy == len(levels) {
		return StatusUnhealthy
	}
	return StatusUnknown
}

// Decision is what one probe round asks of a pool.
type Decision struct {
	// Target is the active level after the round (== active: no switch).
	Target int
	// Reason of a switch: "level_down" (the active level is down),
	// "recovered" (auto failback to a healthy higher level).
	Reason string
	// FailbackReady: manual mode, a level above the active one is healthy.
	FailbackReady bool
	// AllDown: every level is unhealthy (the active level is kept).
	AllDown bool
}

// Decide applies the failover rules to a pool whose active level is active.
// Only a confirmed state moves the pool: an unknown level is never left
// and never switched to while a confirmed one exists.
func Decide(levels []LevelStatus, active int, manual bool) Decision {
	decision := Decision{Target: active}
	if len(levels) == 0 {
		return decision
	}
	status := map[int]string{}
	for _, level := range levels {
		status[level.Level] = level.Status
	}
	// The best healthy level above (numerically below) the active one.
	higher := -1
	for _, level := range levels {
		if level.Level < active && level.Status == StatusHealthy {
			higher = level.Level
			break
		}
	}
	if higher >= 0 {
		if manual {
			decision.FailbackReady = true
		} else {
			decision.Target, decision.Reason = higher, "recovered"
			return decision
		}
	}
	current, known := status[active]
	if known && current != StatusUnhealthy {
		return decision
	}
	if !known && !slices.ContainsFunc(levels, func(level LevelStatus) bool { return level.Level > active }) {
		// The active level lost its origins (the pool was edited): back to
		// the first level.
		decision.Target, decision.Reason = levels[0].Level, "level_down"
		return decision
	}
	// The active level is down (or gone): the next level that is healthy,
	// else the next that is not confirmed down.
	next := -1
	for _, want := range []string{StatusHealthy, StatusUnknown} {
		for _, level := range levels {
			if level.Level > active && level.Status == want {
				next = level.Level
				break
			}
		}
		if next >= 0 {
			break
		}
	}
	if next < 0 {
		decision.AllDown = Overall(levels) == StatusUnhealthy
		return decision
	}
	decision.Target, decision.Reason = next, "level_down"
	return decision
}

// FailbackTarget: the level a manual switch back moves to (the lowest
// healthy level below active), or -1.
func FailbackTarget(levels []LevelStatus, active int) int {
	for _, level := range levels {
		if level.Level < active && level.Status == StatusHealthy {
			return level.Level
		}
	}
	return -1
}
