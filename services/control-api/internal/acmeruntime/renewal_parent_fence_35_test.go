package acmeruntime

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRenewalParentAuthorityAllowsOnlyLiveSameScopeParent35(t *testing.T) {
	parentID := uuid.New()
	active := "active"
	renewalDue := "renewal_due"
	revoked := "revoked"
	failed := "failed"
	for _, test := range []struct {
		name         string
		renewalOf    *uuid.UUID
		parentStatus *string
		want         bool
	}{
		{name: "initial order", want: true},
		{name: "active parent", renewalOf: &parentID, parentStatus: &active, want: true},
		{name: "renewal due parent", renewalOf: &parentID, parentStatus: &renewalDue, want: true},
		{name: "same scope parent missing", renewalOf: &parentID},
		{name: "revoked parent", renewalOf: &parentID, parentStatus: &revoked},
		{name: "failed parent", renewalOf: &parentID, parentStatus: &failed},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := renewalParentAuthorityAllows(test.renewalOf, test.parentStatus); got != test.want {
				t.Fatalf("renewalParentAuthorityAllows(%v,%v) = %t, want %t",
					test.renewalOf, test.parentStatus, got, test.want)
			}
		})
	}
}

func TestBuildRequestFencesRenewalParentBeforeSideEffects35(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	raw, err := os.ReadFile(strings.TrimSuffix(file, "renewal_parent_fence_35_test.go") + "dispatcher.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "func (d *Dispatcher) buildRequest")
	end := strings.Index(source, "type managedZone struct")
	if start < 0 || end <= start {
		t.Fatal("isolate Dispatcher.buildRequest")
	}
	buildRequest := source[start:end]
	for _, required := range []string{
		"certificate_order.renewal_of_order_id",
		"SELECT status FROM certificate_orders",
		"WHERE scope_id=$1 AND id=$2 FOR SHARE",
		"lease.ScopeID, *renewalOfOrderID",
		"renewalParentAuthorityAllows(renewalOfOrderID, parentStatus)",
		"codedError(\"acme_order_state_invalid\", ErrConflict)",
	} {
		if !strings.Contains(buildRequest, required) {
			t.Errorf("buildRequest missing renewal parent fence %q", required)
		}
	}
	authority := strings.Index(buildRequest, "renewalParentAuthorityAllows(renewalOfOrderID, parentStatus)")
	ensureKey := strings.Index(buildRequest, "d.keys.ensureKey")
	statusMutation := strings.Index(buildRequest, "UPDATE certificate_orders SET")
	if authority < 0 || ensureKey < 0 || statusMutation < 0 || authority > ensureKey || authority > statusMutation {
		t.Fatalf("renewal authority order authority=%d ensure_key=%d status_mutation=%d",
			authority, ensureKey, statusMutation)
	}
}
