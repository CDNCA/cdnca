//go:build integration

package httppolicycontrol

import (
	"context"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// A policy with header variables, allow_duplicate and rule
// conditions is stored (migration 490), read back and published unchanged.
func TestHTTPPolicyHeaderVariablesAndConditionsStored(t *testing.T) {
	fixture := newIntegrationFixture(t, allowTestGate())
	config := validTestConfig()
	config.RequestHeaders = []HeaderAction{
		{Kind: HeaderAdd, Name: "x-forwarded-country", Values: []string{"$country"}, AllowDuplicate: true},
		{Kind: HeaderSet, Name: "x-client", Values: []string{"$remote_addr|$tls_fp"}},
	}
	condition := []edgeconfig.RuleCondition{{Source: edgeconfig.RuleConditionUserAgent, Pattern: "iPhone|Android"}}
	config.Rewrites[0].Conditions = condition
	config.Redirects[0].Conditions = []edgeconfig.RuleCondition{{Source: edgeconfig.RuleConditionHeader, Name: "X-Beta", Pattern: "^1$"}}
	created, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: true, Config: config, WriteMetadata: testMetadata("extras"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := fixture.service.Get(context.Background(), fixture.ownerA, fixture.tenantA, created.Policy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.RequestHeaders[1].AllowDuplicate || got.RequestHeaders[0].Values[0] != "$remote_addr|$tls_fp" ||
		len(got.Rewrites[0].Conditions) != 1 || got.Redirects[0].Conditions[0].Name != "x-beta" {
		t.Fatalf("read back %+v", got)
	}
	preview, err := fixture.service.PublicationPreview(context.Background(), fixture.ownerA, fixture.tenantA)
	if err != nil {
		t.Fatal(err)
	}
	site := preview.Snapshot.Sites[0]
	if !site.RequestHeaders[1].AllowDuplicate || len(site.Rewrites[0].Conditions) != 1 {
		t.Fatalf("published %+v", site)
	}
	config.RequestHeaders[0].Values = []string{"$unknown"}
	if _, err := fixture.service.Update(context.Background(), fixture.ownerA, UpdateRequest{
		TargetScopeID: fixture.tenantA, ID: created.Policy.ID, ExpectedRevision: got.Revision, Config: config,
		WriteMetadata: testMetadata("extras-bad"),
	}); err == nil || !strings.Contains(err.Error(), "validation") {
		t.Fatalf("unknown variable update err=%v", err)
	}
}
