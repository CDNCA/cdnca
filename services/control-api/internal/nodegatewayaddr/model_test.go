package nodegatewayaddr

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestCreateRequestNormalize(t *testing.T) {
	request, err := CreateRequest{Address: " gateway.cdnca.com:9443 ", TargetKind: TargetAll}.Normalize()
	if err != nil || request.ServerName != "gateway.cdnca.com" || request.Address != "gateway.cdnca.com:9443" {
		t.Fatalf("default server name: %+v %v", request, err)
	}
	request, err = CreateRequest{Address: "203.0.113.9:9443", ServerName: "gateway.cdnca.com", TargetKind: TargetRegion, Region: "hk"}.Normalize()
	if err != nil || request.ServerName != "gateway.cdnca.com" {
		t.Fatalf("explicit sni: %+v %v", request, err)
	}
	id := uuid.New()
	for name, bad := range map[string]CreateRequest{
		"no port":          {Address: "gateway.cdnca.com", TargetKind: TargetAll},
		"bad port":         {Address: "gateway.cdnca.com:70000", TargetKind: TargetAll},
		"bad sni":          {Address: "gateway.cdnca.com:443", ServerName: "a b", TargetKind: TargetAll},
		"unknown target":   {Address: "gateway.cdnca.com:443", TargetKind: "some"},
		"region missing":   {Address: "gateway.cdnca.com:443", TargetKind: TargetRegion},
		"all with nodes":   {Address: "gateway.cdnca.com:443", TargetKind: TargetAll, NodeIDs: []uuid.UUID{id}},
		"nodes empty":      {Address: "gateway.cdnca.com:443", TargetKind: TargetNodes},
		"nodes duplicated": {Address: "gateway.cdnca.com:443", TargetKind: TargetNodes, NodeIDs: []uuid.UUID{id, id}},
		"nil node":         {Address: "gateway.cdnca.com:443", TargetKind: TargetNodes, NodeIDs: []uuid.UUID{uuid.Nil}},
	} {
		if _, err := bad.Normalize(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}

func TestNextStateNeverMovesBackFromFinal(t *testing.T) {
	cases := []struct {
		current, reported, code string
		want, wantCode          string
		ok                      bool
	}{
		{StateDelivered, StateProbing, "", StateProbing, "", true},
		{StatePending, StateProbing, "", StateProbing, "", true},
		{StateProbing, StateProbing, "", StateProbing, "", false},
		{StateProbing, StateSwitched, "", StateSwitched, "", true},
		{StateProbing, StateFailed, "dial_failed", StateFailed, "dial_failed", true},
		{StateDelivered, StateFailed, "not_supported", StateFailed, "not_supported", true},
		{StateProbing, StateFailed, "", StateProbing, "", false},
		{StateProbing, StateFailed, "Bad", StateProbing, "", false},
		{StateSwitched, StateProbing, "", StateSwitched, "", false},
		{StateFailed, StateSwitched, "", StateFailed, "", false},
		{StateSuperseded, StateSwitched, "", StateSuperseded, "", false},
		{StateDelivered, "unknown", "", StateDelivered, "", false},
	}
	for _, c := range cases {
		state, code, ok := nextState(c.current, c.reported, c.code)
		if state != c.want || code != c.wantCode || ok != c.ok {
			t.Fatalf("%s + %s/%s = %s/%s/%v", c.current, c.reported, c.code, state, code, ok)
		}
	}
}

func TestStateCountsComplete(t *testing.T) {
	var counts StateCounts
	for _, state := range []string{StateSwitched, StateSuperseded} {
		counts.Count(state)
	}
	if !counts.Complete() {
		t.Fatal("switched + superseded should be complete")
	}
	counts.Count(StateDelivered)
	if counts.Complete() || counts.Pending != 1 {
		t.Fatal("delivered counts as pending")
	}
}

func TestStepUpBindingCoversRequest(t *testing.T) {
	a, _ := CreateRequest{Address: "gateway.cdnca.com:443", TargetKind: TargetAll}.Normalize()
	b := a
	b.Address = "gateway.cdnca.com:444"
	if StepUpBinding(a) == StepUpBinding(b) {
		t.Fatal("binding ignores the address")
	}
	c := a
	c.TargetKind, c.Region = TargetRegion, "hk"
	if StepUpBinding(a) == StepUpBinding(c) {
		t.Fatal("binding ignores the target")
	}
	d1 := CreateRequest{Address: "g.cdnca.com:443", ServerName: "g.cdnca.com", TargetKind: TargetNodes, NodeIDs: []uuid.UUID{uuid.MustParse("00000000-0000-4000-8000-000000000001"), uuid.MustParse("00000000-0000-4000-8000-000000000002")}}
	d2 := d1
	d2.NodeIDs = []uuid.UUID{d1.NodeIDs[1], d1.NodeIDs[0]}
	if StepUpBinding(d1) != StepUpBinding(d2) {
		t.Fatal("binding depends on node order")
	}
}
