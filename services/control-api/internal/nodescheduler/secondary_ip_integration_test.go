//go:build integration

package nodescheduler

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

// TestEndpointAddressMustBelongToNode:
// a node-bound endpoint may use the node's primary IPv4/IPv6 or a secondary
// IP from its management settings, and nothing else.
func TestEndpointAddressMustBelongToNode(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := t.Context()
	nodeID := uuid.New()
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,
		ipv4,ipv6) VALUES($1,$2,'secondary-ip node','active',$3,1,'192.0.2.50','2001:db8::50')`,
		nodeID, fixture.actor.ScopeID, fixture.actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE nodes SET management_settings=jsonb_set(management_settings,
		'{secondary_ips}','["198.51.100.7","2001:db8::77"]') WHERE id=$1`, nodeID); err != nil {
		t.Fatal(err)
	}
	endpoint := func(address string) Endpoint {
		value := testEndpoint(address, 443, 0, 1)
		value.NodeID = nodeID
		return value
	}
	request := PutGroupRequest{GroupID: uuid.New(), Name: "secondary ip", Endpoints: []Endpoint{
		endpoint("192.0.2.50"), endpoint("198.51.100.7"), endpoint("2001:db8::77"), testEndpoint("203.0.113.9", 443, 0, 1),
	}, IdempotencyKey: "secondary-ip-ok", RequestID: "secondary-ip-ok"}
	created, err := fixture.service.PutGroup(ctx, fixture.actor, request)
	if err != nil || len(created.Group.Endpoints) != 4 {
		t.Fatalf("secondary IP endpoints: %#v %v", created, err)
	}
	bad := request
	bad.ExpectedRevision, bad.IdempotencyKey, bad.RequestID = 1, "secondary-ip-bad", "secondary-ip-bad"
	bad.Endpoints = append([]Endpoint(nil), request.Endpoints...)
	bad.Endpoints = append(bad.Endpoints, endpoint("198.51.100.8"))
	if _, err := fixture.service.PutGroup(ctx, fixture.actor, bad); !errors.Is(err, ErrEndpointAddressNotOnNode) {
		t.Fatalf("foreign address on node: %v, want ErrEndpointAddressNotOnNode", err)
	}
	var revision int64
	if err := fixture.pool.QueryRow(ctx, `SELECT current_revision FROM node_line_groups WHERE id=$1`,
		request.GroupID).Scan(&revision); err != nil || revision != 1 {
		t.Fatalf("rejected write moved the group: revision=%d err=%v", revision, err)
	}
	var published int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM node_line_endpoint_published
		WHERE line_group_id=$1 AND config_revision=1 AND published AND host(address)='198.51.100.7'`,
		request.GroupID).Scan(&published); err != nil || published != 1 {
		t.Fatalf("secondary IP not published to DNS: %d %v", published, err)
	}
}
