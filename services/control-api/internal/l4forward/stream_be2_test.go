package l4forward

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// A stream's own CNAME / line (migration 491) decides which nodes get it and
// where its CNAME points; the node runtime it renders is the same as without
// them (no new runtime field, tcp/udp capability unchanged).
func TestStreamOverridesLeaveRuntimeSpecUnchanged(t *testing.T) {
	base := Forward{ID: uuid.New(), ScopeID: uuid.New(), Revision: 3, Protocol: ProtocolTCP, ListenAddress: "*",
		ListenPort: 24201, UpstreamAddress: "192.0.2.90", UpstreamPort: 80, ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000}
	plain, err := json.Marshal(runtimeSpec(base))
	if err != nil {
		t.Fatal(err)
	}
	domain, mode, group, backup, region := "stream.example", "package", uuid.New(), uuid.New(), uuid.New()
	base.Overrides = Overrides{CNAMEDomain: &domain, CNAMEMode: &mode, RegionID: &region, NodeGroupID: &group, BackupNodeGroupID: &backup}
	overridden, err := json.Marshal(runtimeSpec(base))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != string(overridden) {
		t.Fatalf("runtime changed by overrides:\n%s\n%s", plain, overridden)
	}
	// The API shape: overrides always present, null when following the site.
	encoded, _ := json.Marshal(Forward{})
	var wire map[string]any
	_ = json.Unmarshal(encoded, &wire)
	overrides, ok := wire["overrides"].(map[string]any)
	if !ok || len(overrides) != 5 || overrides["node_group_id"] != nil || overrides["cname_mode"] != nil {
		t.Fatalf("overrides wire = %v", wire["overrides"])
	}
}

func TestValidBatchActionValue(t *testing.T) {
	id := uuid.New()
	other := uuid.New()
	text := func(value string) *string { return &value }
	for _, test := range []struct {
		name    string
		request BatchActionRequest
		ok      bool
	}{
		{"status", BatchActionRequest{Action: BatchActionSetStatus, AdminStatus: AdminStatusLocked}, true},
		{"status with domain", BatchActionRequest{Action: BatchActionSetStatus, AdminStatus: AdminStatusLocked, CNAMEDomain: text("a.example")}, false},
		{"domain", BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: text(" CDN.Example ")}, true},
		{"domain clear", BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: text("")}, true},
		{"domain bad", BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: text("no_dot")}, false},
		{"domain missing", BatchActionRequest{Action: BatchActionCNAMEDomain}, false},
		{"mode", BatchActionRequest{Action: BatchActionCNAMEMode, CNAMEMode: text("site")}, true},
		{"mode clear", BatchActionRequest{Action: BatchActionCNAMEMode, CNAMEMode: text("")}, true},
		{"mode bad", BatchActionRequest{Action: BatchActionCNAMEMode, CNAMEMode: text("node")}, false},
		{"line", BatchActionRequest{Action: BatchActionLineGroup, NodeGroupID: &id, BackupNodeGroupID: &other}, true},
		{"line clear", BatchActionRequest{Action: BatchActionLineGroup}, true},
		{"backup only", BatchActionRequest{Action: BatchActionLineGroup, BackupNodeGroupID: &other}, false},
		{"backup same", BatchActionRequest{Action: BatchActionLineGroup, NodeGroupID: &id, BackupNodeGroupID: &id}, false},
		{"line with mode", BatchActionRequest{Action: BatchActionLineGroup, NodeGroupID: &id, CNAMEMode: text("site")}, false},
		{"unknown", BatchActionRequest{Action: "delete"}, false},
	} {
		request := test.request
		if got := validBatchActionValue(&request); got != test.ok {
			t.Errorf("%s: valid = %v want %v", test.name, got, test.ok)
		}
	}
	request := BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: text(" CDN.Example ")}
	if validBatchActionValue(&request); *request.CNAMEDomain != "cdn.example" {
		t.Fatalf("domain normalized to %q", *request.CNAMEDomain)
	}
}
