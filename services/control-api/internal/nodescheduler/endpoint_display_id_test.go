package nodescheduler

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEndpointDisplayIDIsNotConfiguration(t *testing.T) {
	request := PutGroupRequest{GroupID: uuid.New(), Name: "display-id", IdempotencyKey: "display-id-test", RequestID: "display-id-test",
		Endpoints: []Endpoint{{ID: uuid.New(), NodeID: uuid.New(), Address: "192.0.2.1", Port: 443, Weight: 1, Enabled: true}}}
	before, err := normalizePutRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Endpoints[0].DisplayID = "999"
	after, err := normalizePutRequest(request)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("display metadata changed canonical configuration or request: %v", err)
	}
}

func TestEndpointDisplayIDDoesNotChangePlan(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	endpoint := testEndpoint("192.0.2.1", 443, 0, 1)
	endpoint.Health.Status, endpoint.Health.LastReceivedAt = HealthHealthy, &now
	group := LineGroupRevision{TenantScopeID: uuid.New(), GroupID: uuid.New(), Revision: 1,
		Policy: DefaultHealthPolicy(), Endpoints: []Endpoint{endpoint}}
	before, err := BuildPlan(group, Selector{}, now)
	if err != nil {
		t.Fatal(err)
	}
	group.Endpoints[0].DisplayID = "42"
	after, err := BuildPlan(group, Selector{}, now)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("display metadata changed scheduling plan or digest: %v", err)
	}
	if group.Endpoints[0].DisplayID != "42" {
		t.Fatal("plan normalization mutated the stored/read model")
	}
}
