package edgestatus

import "testing"

func TestApplyStateGraph(t *testing.T) {
	allowed := [][2]string{
		{"queued", "delivered"}, {"delivered", "staged"}, {"staged", "prechecked"},
		{"prechecked", "activated"}, {"activated", "healthy"}, {"activated", "reverting"},
		{"reverting", "reverted"}, {"reverting", "rollback_failed"},
		{"delivered", "failed"}, {"staged", "failed"}, {"prechecked", "failed"},
	}
	for _, edge := range allowed {
		if !validAdvance("apply", edge[0], edge[1]) {
			t.Fatalf("apply transition %s -> %s rejected", edge[0], edge[1])
		}
	}
	rejected := [][2]string{
		{"queued", "staged"}, {"delivered", "prechecked"}, {"prechecked", "healthy"},
		{"activated", "failed"}, {"healthy", "reverting"}, {"reverting", "failed"},
	}
	for _, edge := range rejected {
		if validAdvance("apply", edge[0], edge[1]) {
			t.Fatalf("apply transition %s -> %s accepted", edge[0], edge[1])
		}
	}
}

func TestExplicitRollbackStateGraph(t *testing.T) {
	allowed := [][2]string{
		{"queued", "delivered"}, {"delivered", "staged"}, {"staged", "prechecked"},
		{"prechecked", "reverting"}, {"reverting", "reverted"}, {"reverting", "rollback_failed"},
		{"delivered", "failed"}, {"staged", "failed"}, {"prechecked", "failed"}, {"reverting", "failed"},
	}
	for _, edge := range allowed {
		if !validAdvance("rollback", edge[0], edge[1]) {
			t.Fatalf("rollback transition %s -> %s rejected", edge[0], edge[1])
		}
	}
	if validAdvance("rollback", "prechecked", "activated") || validAdvance("rollback", "reverted", "failed") {
		t.Fatal("explicit rollback accepted an invalid transition")
	}
}

func TestAgentQueueStateGraph(t *testing.T) {
	for _, action := range []string{"apply", "rollback"} {
		for _, edge := range [][2]string{
			{"delivered", "agent_queued"}, {"agent_queued", "started"}, {"agent_queued", "failed"},
			{"started", "staged"}, {"started", "failed"},
		} {
			if !validAdvance(action, edge[0], edge[1]) {
				t.Fatalf("%s transition %s -> %s rejected", action, edge[0], edge[1])
			}
		}
		for _, edge := range [][2]string{
			{"queued", "agent_queued"}, {"agent_queued", "staged"}, {"started", "prechecked"},
			{"agent_queued", "agent_queued"}, {"started", "agent_queued"}, {"staged", "started"},
		} {
			if validAdvance(action, edge[0], edge[1]) {
				t.Fatalf("%s transition %s -> %s accepted", action, edge[0], edge[1])
			}
		}
	}
}
