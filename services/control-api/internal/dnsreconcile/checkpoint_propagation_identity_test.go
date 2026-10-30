package dnsreconcile

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

func TestValidateResultAdvancePreservesPropagationIdentity(t *testing.T) {
	for _, phase := range []checkpointTestPhase{checkpointTestApply, checkpointTestCommit} {
		for _, drift := range []struct {
			name   string
			mutate func(*dnscheck.PropagationAttempt)
		}{
			{name: "number", mutate: func(item *dnscheck.PropagationAttempt) { item.Number++ }},
			{name: "checked at", mutate: func(item *dnscheck.PropagationAttempt) { item.CheckedAt = item.CheckedAt.Add(time.Second) }},
			{name: "status", mutate: func(item *dnscheck.PropagationAttempt) { item.Status = dnscheck.ClassificationHealthy }},
			{name: "consecutive healthy", mutate: func(item *dnscheck.PropagationAttempt) { item.ConsecutiveHealthy++ }},
			{name: "dependency unavailable", mutate: func(item *dnscheck.PropagationAttempt) { item.DependencyUnavailable = true }},
		} {
			t.Run(string(phase)+"/history field/"+drift.name, func(t *testing.T) {
				current := propagationIdentityResult()
				next := cloneCheckpointIdentityResult(current)
				drift.mutate(&next.Propagation[0])
				requireResultAdvance(t, current, next, phase, false)
			})
		}

		t.Run(string(phase)+"/history deletion", func(t *testing.T) {
			current := propagationIdentityResult()
			next := cloneCheckpointIdentityResult(current)
			next.Propagation = next.Propagation[:1]
			requireResultAdvance(t, current, next, phase, false)
		})

		t.Run(string(phase)+"/history reorder", func(t *testing.T) {
			current := propagationIdentityResult()
			next := cloneCheckpointIdentityResult(current)
			next.Propagation[0], next.Propagation[1] = next.Propagation[1], next.Propagation[0]
			requireResultAdvance(t, current, next, phase, false)
		})

		t.Run(string(phase)+"/single matching attempt", func(t *testing.T) {
			current := propagationIdentityResult()
			next := cloneCheckpointIdentityResult(current)
			checkedAt := current.Propagation[len(current.Propagation)-1].CheckedAt.Add(time.Minute)
			next.Propagation = append(next.Propagation, dnscheck.PropagationAttempt{
				Number: 3, CheckedAt: checkedAt, Status: dnscheck.ClassificationHealthy,
				ConsecutiveHealthy: 1,
			})
			next.LastCheck = &dnscheck.CheckResult{
				Status: dnscheck.ClassificationHealthy, Compliant: true, CheckedAt: checkedAt,
			}
			requireResultAdvance(t, current, next, phase, phase == checkpointTestApply)
		})
	}

	t.Run("commit allows fresh last check without propagation append", func(t *testing.T) {
		current := propagationIdentityResult()
		next := cloneCheckpointIdentityResult(current)
		next.LastCheck.Status = dnscheck.ClassificationHealthy
		next.LastCheck.CheckedAt = next.LastCheck.CheckedAt.Add(time.Minute)
		requireResultAdvance(t, current, next, checkpointTestCommit, true)
	})
}

func propagationIdentityResult() dnscheck.ReconcileResult {
	result := checkpointIdentityResult()
	first := time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC)
	second := first.Add(time.Minute)
	result.Propagation = []dnscheck.PropagationAttempt{
		{Number: 1, CheckedAt: first, Status: dnscheck.ClassificationPublicPropagating},
		{Number: 2, CheckedAt: second, Status: dnscheck.ClassificationPublicPropagating},
	}
	result.LastCheck = &dnscheck.CheckResult{Status: dnscheck.ClassificationPublicPropagating, CheckedAt: second}
	return result
}
