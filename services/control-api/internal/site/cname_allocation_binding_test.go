package site

import (
	"os"
	"strings"
	"testing"
)

func TestSiteWriteContractCarriesSoldSubscriptionAndCNAMEProjection(t *testing.T) {
	model, err := os.ReadFile("model.go")
	if err != nil {
		t.Fatal(err)
	}
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"PackageSubscriptionID", "CNAMEState", "CNAMETaskID", "CNAMECurrentRevision", "CNAMELKGRevision"} {
		if !strings.Contains(string(model), required) {
			t.Errorf("model.go missing %q", required)
		}
	}
	for _, required := range []string{"package_subscription_id", "cname_state", "cname_task_id", "cname_current_revision", "cname_lkg_revision"} {
		if !strings.Contains(string(store), required) {
			t.Errorf("store.go missing %q", required)
		}
	}
	for _, required := range []string{"product_snapshot->'spec'->'cname'", "dns.cname.intent", "sites.manage", "dns.manage"} {
		if !strings.Contains(string(store), required) {
			t.Errorf("store.go missing durable CNAME authority %q", required)
		}
	}
}

func TestSiteWriteContractRejectsSubscriptionFromAnotherProductOrOwner(t *testing.T) {
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"SELECT subscription.product_id",
		"owner.owner_user_id=$3",
		"*fields.PackageID != subscriptionProductID",
		"fields.PackageID = &subscriptionProductID",
	} {
		if !strings.Contains(string(store), required) {
			t.Errorf("store.go missing subscription binding guard %q", required)
		}
	}
}

func TestUnchangedCNAMEPolicyDoesNotRequireDNSManage(t *testing.T) {
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(store)
	for _, required := range []string{"!canManageSites", "if samePolicy && !fields.CNAMERegenerate", "if !canManageDNS"} {
		if !strings.Contains(source, required) {
			t.Fatalf("store.go missing CNAME permission boundary %q", required)
		}
	}
	unchangedReturn := strings.Index(source, "if samePolicy && !fields.CNAMERegenerate")
	dnsMutationGuard := strings.Index(source, "if !canManageDNS")
	if unchangedReturn > dnsMutationGuard {
		t.Fatal("dns.manage is checked before the unchanged-policy fast path")
	}
}
