package nodescheduler

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestValidateTopologyGraphRejectsSelfCycleAndL2ToL2(t *testing.T) {
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	tests := []struct {
		name     string
		graph    map[uuid.UUID]map[uuid.UUID]struct{}
		indegree map[uuid.UUID]int
		wantErr  bool
	}{
		{name: "two_level_dag", graph: map[uuid.UUID]map[uuid.UUID]struct{}{a: {b: {}, c: {}}},
			indegree: map[uuid.UUID]int{b: 1, c: 1}},
		{name: "self", graph: map[uuid.UUID]map[uuid.UUID]struct{}{a: {a: {}}},
			indegree: map[uuid.UUID]int{a: 1}, wantErr: true},
		{name: "l2_to_l2", graph: map[uuid.UUID]map[uuid.UUID]struct{}{a: {b: {}}, b: {c: {}}},
			indegree: map[uuid.UUID]int{b: 1, c: 1}, wantErr: true},
		{name: "cycle", graph: map[uuid.UUID]map[uuid.UUID]struct{}{a: {b: {}}, b: {a: {}}},
			indegree: map[uuid.UUID]int{a: 1, b: 1}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateTopologyGraph(test.graph, test.indegree)
			if errors.Is(err, ErrTopologyCycle) != test.wantErr {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
