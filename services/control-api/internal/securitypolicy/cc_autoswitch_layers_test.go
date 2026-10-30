package securitypolicy

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// fix-fwregion: the auto switch a platform node runs is its node override,
// else its region's, else the platform global one; a tenant's own node
// (not listed as a platform node) only ever runs the global one.
func TestResolveAutoSwitchLayers(t *testing.T) {
	global := CCSystemAutoSwitch{Enable: true, QPSTotal: 1000, QPS5xx: 50, Rule: "10003", Seconds: 300}
	regional := CCSystemAutoSwitch{Enable: true, QPSTotal: 200, Rule: "10004", Seconds: 600}
	off := CCSystemAutoSwitch{Enable: false}
	east, west, lone := uuid.MustParse("00000000-0000-0000-0000-00000000000a"),
		uuid.MustParse("00000000-0000-0000-0000-00000000000b"), uuid.MustParse("00000000-0000-0000-0000-00000000000c")
	nodes := []PlatformNode{{ID: west, Region: "west"}, {ID: east, Region: "east"}, {ID: lone, Region: ""}}

	t.Run("inherit", func(t *testing.T) {
		got := ResolveAutoSwitchLayers(global, nil, nil, nodes)
		want := []NodeAutoSwitch{{NodeID: east, Source: AutoSwitchSourceGlobal, Value: global},
			{NodeID: west, Source: AutoSwitchSourceGlobal, Value: global},
			{NodeID: lone, Source: AutoSwitchSourceGlobal, Value: global}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v\nwant %+v", got, want)
		}
	})
	t.Run("node over region over global", func(t *testing.T) {
		got := ResolveAutoSwitchLayers(global, map[string]CCSystemAutoSwitch{"east": regional, "west": regional},
			map[uuid.UUID]CCSystemAutoSwitch{west: off}, nodes)
		want := []NodeAutoSwitch{{NodeID: east, Source: AutoSwitchSourceRegion, Value: regional},
			{NodeID: west, Source: AutoSwitchSourceNode, Value: off},
			{NodeID: lone, Source: AutoSwitchSourceGlobal, Value: global}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v\nwant %+v", got, want)
		}
	})
	t.Run("deleted override falls back", func(t *testing.T) {
		got := ResolveAutoSwitchLayers(global, map[string]CCSystemAutoSwitch{"east": regional}, map[uuid.UUID]CCSystemAutoSwitch{}, nodes)
		if got[1].NodeID != west || got[1].Source != AutoSwitchSourceGlobal || got[1].Value != global {
			t.Fatalf("west without overrides = %+v", got[1])
		}
		if got[0].Source != AutoSwitchSourceRegion {
			t.Fatalf("east = %+v", got[0])
		}
	})
	t.Run("override of a node that is not a platform node is ignored", func(t *testing.T) {
		tenantNode := uuid.New()
		got := ResolveAutoSwitchLayers(global, nil, map[uuid.UUID]CCSystemAutoSwitch{tenantNode: off}, nodes)
		for _, item := range got {
			if item.NodeID == tenantNode || item.Source != AutoSwitchSourceGlobal {
				t.Fatalf("unexpected %+v", item)
			}
		}
	})
}

func TestNodeAutoSwitchOverridesOnlyDifferences(t *testing.T) {
	global := CCSystemAutoSwitch{Enable: true, QPSTotal: 1000, Rule: "10003", Seconds: 300}
	a, b := uuid.MustParse("00000000-0000-0000-0000-000000000001"), uuid.MustParse("00000000-0000-0000-0000-000000000002")
	same := []NodeAutoSwitch{{NodeID: a, Source: AutoSwitchSourceRegion, Value: global},
		{NodeID: b, Source: AutoSwitchSourceNode, Value: CCSystemAutoSwitch{Enable: false}}}
	got := NodeAutoSwitchOverrides(global, same)
	if len(got) != 1 || got[0].NodeID != b {
		t.Fatalf("an override equal to the global value is no override: %+v", got)
	}
}

func TestDecodeCCSystemAutoSwitchLayers(t *testing.T) {
	platformGlobal := []byte(`{"cc_enable":true}`)
	tenantGlobal := []byte(`{"auto_switch":{"enable":true,"qps_50x":0,"qps_total":500,"rule":"10003","seconds":0}}`)
	value, err := autoSwitchGlobal(platformGlobal, tenantGlobal)
	if err != nil || value != (CCSystemAutoSwitch{Enable: true, QPSTotal: 500, Rule: "10003"}) {
		t.Fatalf("platform without auto_switch takes the license default: %+v %v", value, err)
	}
	value, err = autoSwitchGlobal([]byte(`{"auto_switch":{"enable":false,"qps_50x":0,"qps_total":0,"rule":"","seconds":0}}`), tenantGlobal)
	if err != nil || value.Enable {
		t.Fatalf("a set platform value wins: %+v %v", value, err)
	}
	value, err = autoSwitchGlobal(nil, nil)
	if err != nil || value != (CCSystemAutoSwitch{}) {
		t.Fatalf("nothing set is off: %+v %v", value, err)
	}
	if _, set, err := autoSwitchOverride([]byte(`{"waf_enable":true}`)); err != nil || set {
		t.Fatalf("an override without auto_switch inherits: %v %v", set, err)
	}
}
