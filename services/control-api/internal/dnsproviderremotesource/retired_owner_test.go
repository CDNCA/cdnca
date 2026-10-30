package dnsproviderremotesource

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
)

// n12b: retiring an owner deletes only what the system wrote under exactly
// that name; a customer's own record under it, or a sibling name, is kept.
func TestRetiredOwnerDeletesOnlySystemWrittenValues(t *testing.T) {
	owner := cnameallocation.RetiredOwner{Owner: "abc123.cdn.example.com",
		A: []string{"192.0.2.20"}, AAAA: []string{"2001:db8::20"}, CNAME: []string{"edge.Market.example.net"}}
	records := []dnsproviderremote.ZoneRecord{
		{ID: "a1", Name: "abc123.cdn.example.com.", Type: dnscheck.RecordA, Value: "192.0.2.20", TTL: 300},
		{ID: "a2", Name: "ABC123.cdn.example.com", Type: dnscheck.RecordAAAA, Value: "2001:db8::20", TTL: 300},
		{ID: "c1", Name: "abc123.cdn.example.com.", Type: dnscheck.RecordCNAME, Value: "edge.market.example.net.", TTL: 300},
		{ID: "u1", Name: "abc123.cdn.example.com.", Type: dnscheck.RecordA, Value: "198.51.100.7", TTL: 600},
		{ID: "s1", Name: "x.abc123.cdn.example.com.", Type: dnscheck.RecordA, Value: "192.0.2.20", TTL: 300},
		{ID: "s2", Name: "abc1234.cdn.example.com.", Type: dnscheck.RecordA, Value: "192.0.2.20", TTL: 300},
	}
	operations := RetiredOwnerDeletes(records, "abc123.cdn.example.com.", owner)
	deleted, kept := map[string]bool{}, map[string]bool{}
	for _, operation := range operations {
		if operation.Action == dnscheck.ProviderDelete {
			deleted[operation.RecordID] = true
		} else {
			kept[operation.RecordID] = true
		}
	}
	if len(deleted) != 3 || !deleted["a1"] || !deleted["a2"] || !deleted["c1"] {
		t.Fatalf("deleted = %v, want a1 a2 c1", deleted)
	}
	if len(kept) != 1 || !kept["u1"] {
		t.Fatalf("kept = %v, want only the customer's own u1 (siblings are not this owner)", kept)
	}
	if empty := RetiredOwnerDeletes(records, "abc123.cdn.example.com.", cnameallocation.RetiredOwner{}); len(empty) != 4 {
		t.Fatalf("no written values: %d operations, want 4 kept", len(empty))
	} else {
		for _, operation := range empty {
			if operation.Action == dnscheck.ProviderDelete {
				t.Fatalf("deleted %s without a system-written value", operation.RecordID)
			}
		}
	}
}
