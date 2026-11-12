package site

import (
	"regexp"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
)

var randomLabelPattern = regexp.MustCompile(`^[a-z0-9]{8}\.cdn\.cdnca\.com$`)

// Site mode: the site's own name, taken names, the line
// group prefix, unchanged existing CNAMEs and a regenerate after a rename.
func TestCNAMECustomLabelSiteMode(t *testing.T) {
	f := newCNAMELabelFixture(t)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := f.pool.Exec(t.Context(), query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}

	// A site allocated before any name or prefix exists keeps its random CNAME.
	legacy := f.createSite(t, "legacy.example.com")
	if state, code := f.runIntent(t, *legacy.CNAMETaskID); state != "succeeded" {
		t.Fatalf("legacy intent state=%s code=%s", state, code)
	}
	legacyHost, legacyExplicit := f.claimHostname(t, legacy.ID)
	if !randomLabelPattern.MatchString(legacyHost) || legacyExplicit {
		t.Fatalf("legacy hostname %q explicit=%v", legacyHost, legacyExplicit)
	}

	t.Run("site name becomes the label", func(t *testing.T) {
		site := f.createSite(t, "shop.example.com")
		exec(`UPDATE sites SET cname_custom_label='shop' WHERE scope_id=$1 AND id=$2`, f.tenant.scopeID, site.ID)
		if state, code := f.runIntent(t, *site.CNAMETaskID); state != "succeeded" {
			t.Fatalf("intent state=%s code=%s", state, code)
		}
		if host, explicit := f.claimHostname(t, site.ID); host != "shop.cdn.cdnca.com" || explicit {
			t.Fatalf("hostname %q explicit=%v", host, explicit)
		}
	})

	t.Run("a taken name fails with cname_label_taken", func(t *testing.T) {
		site := f.createSite(t, "other.example.com")
		exec(`UPDATE sites SET cname_custom_label='shop' WHERE scope_id=$1 AND id=$2`, f.tenant.scopeID, site.ID)
		if state, code := f.runIntent(t, *site.CNAMETaskID); state != "failed" || code != cnameallocation.CodeLabelTaken {
			t.Fatalf("intent state=%s code=%s, want failed %s", state, code, cnameallocation.CodeLabelTaken)
		}
	})

	t.Run("line group prefix shapes new CNAMEs and leaves existing ones", func(t *testing.T) {
		f.setLabel(t, "line_group", f.platformGroup, "gd")
		if host, _ := f.claimHostname(t, legacy.ID); host != legacyHost {
			t.Fatalf("existing CNAME changed from %q to %q", legacyHost, host)
		}
		site := f.createSite(t, "prefixed.example.com")
		if state, code := f.runIntent(t, *site.CNAMETaskID); state != "succeeded" {
			t.Fatalf("intent state=%s code=%s", state, code)
		}
		host, explicit := f.claimHostname(t, site.ID)
		label := strings.TrimSuffix(host, ".cdn.cdnca.com")
		if explicit || !strings.HasPrefix(label, "gd-") || len(label) != len("gd-")+cnameallocation.LabelLength {
			t.Fatalf("hostname %q explicit=%v", host, explicit)
		}
		// The site's own name still wins over the line group prefix.
		named := f.createSite(t, "named.example.com")
		exec(`UPDATE sites SET cname_custom_label='named' WHERE scope_id=$1 AND id=$2`, f.tenant.scopeID, named.ID)
		if state, code := f.runIntent(t, *named.CNAMETaskID); state != "succeeded" {
			t.Fatalf("intent state=%s code=%s", state, code)
		}
		if host, _ := f.claimHostname(t, named.ID); host != "named.cdn.cdnca.com" {
			t.Fatalf("named hostname %q", host)
		}
	})

	t.Run("renaming then regenerating re-allocates to the new name", func(t *testing.T) {
		site := f.createSite(t, "rename.example.com")
		if state, code := f.runIntent(t, *site.CNAMETaskID); state != "succeeded" {
			t.Fatalf("intent state=%s code=%s", state, code)
		}
		before, _ := f.claimHostname(t, site.ID)
		exec(`UPDATE sites SET cname_custom_label='renamed' WHERE scope_id=$1 AND id=$2`, f.tenant.scopeID, site.ID)
		current, err := f.service.Get(t.Context(), f.owner, site.ID)
		if err != nil {
			t.Fatal(err)
		}
		updated, err := f.service.Update(t.Context(), f.owner, UpdateRequest{ID: site.ID, ExpectedRevision: current.Revision,
			Fields: SiteFields{Domains: current.Domains, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
				Enabled: false, Status: StatusDisabled, CNAMERegenerate: true},
			IdempotencyKey: "cname-label-regen", RequestID: "cname-label-regen"})
		if err != nil || updated.Site.CNAMETaskID == nil || *updated.Site.CNAMETaskID == *current.CNAMETaskID {
			t.Fatalf("regenerate: task=%v err=%v", updated.Site.CNAMETaskID, err)
		}
		if state, code := f.runIntent(t, *updated.Site.CNAMETaskID); state != "succeeded" {
			t.Fatalf("regenerate intent state=%s code=%s", state, code)
		}
		if after, _ := f.claimHostname(t, site.ID); after != "renamed.cdn.cdnca.com" || after == before {
			t.Fatalf("hostname %q (before %q)", after, before)
		}
	})
}
