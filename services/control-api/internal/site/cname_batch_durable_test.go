package site

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestCNAMEBatchRegenerationPlansOnlyFailedDurableBindings(t *testing.T) {
	packageID, subscriptionID := uuid.New(), uuid.New()
	mode, domain, hostname := "site", "example.test", "fixed"
	failed := Site{
		ID: uuid.New(), PackageID: &packageID, PackageSubscriptionID: &subscriptionID,
		CNAMEMode: &mode, CNAMEDomain: &domain, CNAMEHostname: &hostname,
		CNAMEState: stringPointer("failed"), Revision: 9,
	}
	fields, code := batchCNAMERegenerationFields(failed)
	if code != "" || fields.PackageID == nil || *fields.PackageID != packageID ||
		fields.PackageSubscriptionID == nil || *fields.PackageSubscriptionID != subscriptionID ||
		fields.CNAMEMode != mode || fields.CNAMEDomain != domain || fields.CNAMEHostname != hostname ||
		!fields.CNAMERegenerate {
		t.Fatalf("failed CNAME regeneration plan = (%+v,%q)", fields, code)
	}

	for _, test := range []struct {
		name string
		site Site
		code string
	}{
		{name: "pending", site: func() Site { value := failed; value.CNAMEState = stringPointer("pending"); return value }(), code: "cname_not_failed"},
		{name: "done", site: func() Site { value := failed; value.CNAMEState = stringPointer("done"); return value }(), code: "cname_not_failed"},
		// fix-nopkg (533): a site without a package has a per-site CNAME too.
		{name: "no package", site: func() Site {
			value := failed
			value.PackageSubscriptionID, value.PackageID = nil, nil
			return value
		}(), code: ""},
		{name: "missing policy", site: func() Site { value := failed; value.CNAMEMode = nil; return value }(), code: "cname_not_configured"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, got := batchCNAMERegenerationFields(test.site); got != test.code {
				t.Fatalf("code = %q, want %q", got, test.code)
			}
		})
	}
}

func TestCNAMEBatchRegenerationUsesStablePerSiteIntentIdentity(t *testing.T) {
	siteID := uuid.New()
	first := cnameBatchIntentKey("batch-key", siteID)
	if first == "" || first != cnameBatchIntentKey("batch-key", siteID) {
		t.Fatalf("intent key is not stable: %q", first)
	}
	if first == cnameBatchIntentKey("batch-key", uuid.New()) ||
		first == cnameBatchIntentKey("other-batch", siteID) {
		t.Fatal("intent key is not bound to both batch and site")
	}
}

func TestCNAMEBatchActionPersistsIntentAndReturnsPendingTaskIdentity(t *testing.T) {
	if !validBatchAction(BatchActionRegenerateCNAME) {
		t.Fatal("regenerate_cname is not accepted by the site batch contract")
	}
	raw, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Join(strings.Fields(string(raw)), " ")
	for _, required := range []string{
		"request.Action == BatchActionRegenerateCNAME",
		"prepareCNAMEWriteIntent",
		"insertCNAMEIntentJob",
		"insertCNAMEIntentFact",
		"cname_state='pending'",
		"cname_task_id=$",
		"itemResult.Status = \"queued\"",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("site batch store lacks durable CNAME contract %q", required)
		}
	}
	if strings.Contains(source, "request.Action == BatchActionRegenerateCNAME { itemResult.Status = \"done\"") {
		t.Fatal("enqueue path reports DNS completion")
	}
}

func stringPointer(value string) *string { return &value }
