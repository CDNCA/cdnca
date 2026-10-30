package edgepublish

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestChallengePolicyTargetsFromSiteRuntime(t *testing.T) {
	const policyID = "01990000-0000-7000-8000-000000000005"
	want := []challengePolicyTarget{{SiteID: "b", Domain: "b.example", PolicyID: policyID, PolicyVersion: 7}}
	challenge := &edgeconfig.ListenerChallenge{TenantID: policyID, PolicyID: policyID, PolicyVersion: 7}
	document := siteRuntimeV2Document{Sites: []siteRuntimeV2Site{
		{ID: "b", Domains: []string{"b.example"}, Listeners: []siteRuntimeV2Listener{
			{Port: 80, Security: &edgeconfig.ListenerSecurity{Challenge: challenge}},
			{Port: 443, Security: &edgeconfig.ListenerSecurity{Challenge: challenge}},
		}},
		{ID: "a", Domains: []string{"a.example"}, Listeners: []siteRuntimeV2Listener{{Port: 80}}},
	}}
	canonical, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := siteRuntimeV2ChallengePolicyTargets(canonical)
	if err != nil || len(v2) != 1 || v2[0] != want[0] {
		t.Fatalf("v2 targets = %+v, %v", v2, err)
	}
	if _, err := siteRuntimeV2ChallengePolicyTargets([]byte("{")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad document: %v", err)
	}
}

// A missing JS challenge policy is held like a
// missing capability: every named node is refused, the audit names the policy.
func TestHeldRefusalCoversCapabilityAndChallengeRefusals(t *testing.T) {
	first, second, third := uuid.New(), uuid.New(), uuid.New()
	refused, facts, ok := heldRefusal(fmt.Errorf("publish: %w", &ChallengePolicyUnavailableError{NodeID: first,
		SiteID: "site-1", Domain: "a.example.com", PolicyID: "policy-1", PolicyVersion: 4,
		OtherNodeIDs: []uuid.UUID{second}}))
	challenge, _ := facts["challenge"].(map[string]any)
	if !ok || !slices.Equal(refused, []uuid.UUID{first, second}) || challenge["policy_id"] != "policy-1" ||
		challenge["site_id"] != "site-1" || challenge["policy_version"] != uint64(4) {
		t.Fatalf("challenge refusal = %v %v %v", refused, facts, ok)
	}
	refused, facts, ok = heldRefusal(&TargetCapabilityError{NodeID: third, Feature: "L4 port ranges",
		Capability: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, Required: 9})
	if !ok || !slices.Equal(refused, []uuid.UUID{third}) || facts["capability"] != "CAPABILITY_NAME_TCP_PROXY" ||
		facts["required"] != uint32(9) {
		t.Fatalf("capability refusal = %v %v %v", refused, facts, ok)
	}
	if _, _, ok := heldRefusal(ErrTargetIneligible); ok {
		t.Fatal("a plain ineligible target is held")
	}
}

func TestChallengePolicyUnavailableErrorNamesNodeAndSite(t *testing.T) {
	node, other := uuid.MustParse("01990000-0000-7000-8000-0000000000a1"), uuid.MustParse("01990000-0000-7000-8000-0000000000a2")
	err := error(&ChallengePolicyUnavailableError{NodeID: node, SiteID: "site-1", Domain: "www.example.com",
		PolicyID: "policy-1", PolicyVersion: 3, OtherNodeIDs: []uuid.UUID{other}})
	if !errors.Is(err, ErrTargetIneligible) {
		t.Fatal("does not unwrap to ErrTargetIneligible")
	}
	for _, want := range []string{node.String(), "www.example.com", "site-1", "policy-1 version 3", "JS 挑战策略", other.String()} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%q missing %q", err.Error(), want)
		}
	}
}
