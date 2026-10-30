package edgepublish

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSITE14StatusRecoveryCandidateRequiresExactAuthority(t *testing.T) {
	tenantID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7201")
	siteID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7202")
	row := siteStatusRecoveryCandidateRow{
		scopeTenantID: tenantID,
		jobTenantID:   tenantID,
		jobID:         uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7203"),
		jobState:      "queued",
		subject:       "site/status-recovery/" + siteID.String() + "/renewal/17/41",
		itemID:        siteID.String(),
		itemState:     "pending",
		siteID:        siteID,
		siteRevision:  17,
		siteStatus:    "package_expired",
	}
	candidate, ok := validateSiteStatusRecoveryCandidate(row, 41)
	if !ok || candidate.siteID != siteID || candidate.jobID != row.jobID ||
		candidate.siteRevision != 17 || candidate.edgeSourceRevision != 41 || candidate.trigger != "renewal" {
		t.Fatalf("candidate=%+v ok=%t", candidate, ok)
	}

	tests := []struct {
		name   string
		mutate func(*siteStatusRecoveryCandidateRow)
	}{
		{name: "cross tenant", mutate: func(value *siteStatusRecoveryCandidateRow) { value.jobTenantID = uuid.New() }},
		{name: "terminal job", mutate: func(value *siteStatusRecoveryCandidateRow) { value.jobState = "succeeded" }},
		{name: "terminal item", mutate: func(value *siteStatusRecoveryCandidateRow) { value.itemState = "succeeded" }},
		{name: "wrong item", mutate: func(value *siteStatusRecoveryCandidateRow) { value.itemID = uuid.NewString() }},
		{name: "wrong subject site", mutate: func(value *siteStatusRecoveryCandidateRow) {
			value.subject = "site/status-recovery/" + uuid.NewString() + "/renewal/17/41"
		}},
		{name: "stale site revision", mutate: func(value *siteStatusRecoveryCandidateRow) { value.siteRevision = 18 }},
		{name: "wrong edge revision", mutate: func(value *siteStatusRecoveryCandidateRow) {
			value.subject = "site/status-recovery/" + siteID.String() + "/renewal/17/40"
		}},
		{name: "trigger status mismatch", mutate: func(value *siteStatusRecoveryCandidateRow) { value.siteStatus = "traffic_exceeded" }},
		{name: "unlock does not bypass status", mutate: func(value *siteStatusRecoveryCandidateRow) {
			value.subject = "site/status-recovery/" + siteID.String() + "/unlock/17/41"
		}},
		{name: "noncanonical revision", mutate: func(value *siteStatusRecoveryCandidateRow) {
			value.subject = "site/status-recovery/" + siteID.String() + "/renewal/017/41"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := row
			test.mutate(&value)
			if got, ok := validateSiteStatusRecoveryCandidate(value, 41); ok {
				t.Fatalf("candidate=%+v unexpectedly accepted", got)
			}
		})
	}
}

func TestSITE14RecoveryCandidatePreservesSecurityChallengeCaptureAndPackageFacts(t *testing.T) {
	read := func(name string) string {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(content)
	}
	service := read("service.go")
	store := read("store.go")
	v2 := read("site_runtime_v2.go")
	capture := read("site_capture_policy.go")
	for _, fragment := range []string{
		"loadSiteStatusRecoveryCandidates(ctx, tx, scopeID, sourceRevision)",
		"loadSiteFacts(ctx, tx, scopeID, recoverySiteIDs)",
		"loadPackageSubscriptionFacts(ctx, tx, scopeID, recoverySiteIDs)",
		"loadSiteCapturePolicyFacts(ctx, tx, scopeID)",
	} {
		if !strings.Contains(v2, fragment) {
			t.Fatalf("site-runtime-v2 compiler missing recovery fact path %q", fragment)
		}
	}
	if count := strings.Count(store, "site.id=ANY($2::uuid[])"); count != 3 {
		t.Fatalf("site/security/challenge recovery predicates=%d want 3", count)
	}
	if count := strings.Count(service, "site.id=ANY($2::uuid[])"); count != 1 {
		t.Fatalf("package recovery predicates=%d want 1", count)
	}
	for _, fragment := range []string{"active_policy_version", "runtime_snapshot_sha256", "active_binding_revision"} {
		if !strings.Contains(store, fragment) {
			t.Fatalf("recovery LKG fact path missing %q", fragment)
		}
	}
	if strings.Contains(capture, "package_expired") || strings.Contains(capture, "traffic_exceeded") {
		t.Fatal("capture fact loader unexpectedly filters recovery status")
	}
}

func TestSITE14StatusRecoveryCandidateQueryBindsScopeJobItemAndSite(t *testing.T) {
	for _, fragment := range []string{
		"JOIN access_scopes", "scope.tenant_id=job.tenant_id", "job.kind='site.status_recovery'",
		"job.state IN ('queued','running')", "item.tenant_id=job.tenant_id", "item.job_id=job.id",
		"item.item_id=site.id::text", "item.state='pending'", "site.scope_id=$1",
		"site.status IN ('package_expired','traffic_exceeded')",
	} {
		if !strings.Contains(siteStatusRecoveryCandidateQuery, fragment) {
			t.Fatalf("candidate query missing %q", fragment)
		}
	}
}
