package edgepublish

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// A target lacking a pack is refused (the first named with what it lacks,
// the rest listed); the refusal is held and classified like the other
// readiness refusals, so the system republication leaves the node out and
// an applied set republishes.
func TestRulePackTargetsRefuseNodesWithoutThePacks(t *testing.T) {
	ready, first, second := uuid.New(), uuid.New(), uuid.New()
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	applied := map[uuid.UUID]map[string]bool{ready: {a: true, b: true}, first: {a: true}}
	if err := rulePackTargetsError([]uuid.UUID{ready}, []string{a, b}, applied); err != nil {
		t.Fatalf("ready node refused: %v", err)
	}
	err := rulePackTargetsError([]uuid.UUID{ready, first, second}, []string{a, b}, applied)
	var refusal *RulePackUnavailableError
	if !errors.As(err, &refusal) || refusal.NodeID != first || !slices.Equal(refusal.SHA256, []string{b}) ||
		!slices.Equal(refusal.OtherNodeIDs, []uuid.UUID{second}) || !errors.Is(err, ErrTargetIneligible) {
		t.Fatalf("refusal = %#v", err)
	}
	wrapped := fmt.Errorf("publish: %w", err)
	nodes, facts, held := heldRefusal(wrapped)
	if !held || !slices.Equal(nodes, []uuid.UUID{first, second}) || facts["rule_packs"] == nil {
		t.Fatalf("held = %v %v %v", nodes, facts, held)
	}
	item, ok := systemRefusalOf(wrapped)
	if !ok || item.NodeID != first || !slices.Equal(item.RulePacks, []string{b}) {
		t.Fatalf("system refusal = %+v %v", item, ok)
	}
	var again *RulePackUnavailableError
	if all := refusedAllError([]systemRefusal{item, {NodeID: second, RulePacks: []string{a}}}); !errors.As(all, &again) ||
		again.NodeID != first || !slices.Equal(again.OtherNodeIDs, []uuid.UUID{second}) {
		t.Fatalf("refused all = %#v", all)
	}
	if rulePackTargetsError([]uuid.UUID{first}, nil, applied) != nil {
		t.Fatal("a release without packs refused")
	}
}

// sa-rulepack-wait: the refusal carries every pack the release needs, not
// only the first node's missing ones, so a waiting security activation is
// resumed only when each target node holds them all.
func TestRulePackRefusalCarriesEveryRequiredPack(t *testing.T) {
	first, second := uuid.New(), uuid.New()
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	applied := map[uuid.UUID]map[string]bool{first: {a: true}, second: {b: true}}
	var refusal *RulePackUnavailableError
	if err := rulePackTargetsError([]uuid.UUID{first, second}, []string{a, b}, applied); !errors.As(err, &refusal) ||
		!slices.Equal(refusal.SHA256, []string{b}) || !slices.Equal(refusal.Required, []string{a, b}) || refusal.AutoResume {
		t.Fatalf("refusal = %#v", err)
	}
}
