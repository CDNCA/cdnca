package site

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
)

// the administrator API of the store. A platform session
// renames, a tenant session is refused, a taken name is refused, and a prefix
// change re-allocates only on the explicit regenerate.
func TestCNAMELabelAdminStore(t *testing.T) {
	f := newCNAMELabelFixture(t)
	legacy := f.createSite(t, "old.example.com")
	if state, code := f.runIntent(t, *legacy.CNAMETaskID); state != "succeeded" {
		t.Fatalf("intent state=%s code=%s", state, code)
	}
	f.completeAllocation(t, legacy.ID)
	oldHost, _ := f.claimHostname(t, legacy.ID)

	t.Run("a tenant session is refused", func(t *testing.T) {
		_, err := f.store.SetCNAMELabel(t.Context(), f.owner, CNAMELabelRequest{Kind: CNAMELabelSite, SubjectID: legacy.ID, Label: "mine", RequestID: "cl-tenant"})
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("invalid and reserved names", func(t *testing.T) {
		for label, want := range map[string]error{"WWW": cnameallocation.ErrLabelReserved, "www": cnameallocation.ErrLabelReserved, "a_b": cnameallocation.ErrLabelInvalid} {
			_, err := f.store.SetCNAMELabel(t.Context(), f.admin(), CNAMELabelRequest{Kind: CNAMELabelSite, SubjectID: legacy.ID, Label: label, RequestID: "cl-bad"})
			if !errors.Is(err, want) {
				t.Fatalf("%q: %v, want %v", label, err, want)
			}
		}
		if host, _ := f.claimHostname(t, legacy.ID); host != oldHost {
			t.Fatalf("a refused name changed the CNAME to %q", host)
		}
	})

	t.Run("renaming re-allocates the CNAME of the site", func(t *testing.T) {
		result, err := f.store.SetCNAMELabel(t.Context(), f.admin(), CNAMELabelRequest{Kind: CNAMELabelSite, SubjectID: legacy.ID, Label: "Brand", RequestID: "cl-rename"})
		if err != nil || result.Label != "brand" || result.Regenerated != 1 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		current, err := f.service.Get(t.Context(), f.owner, legacy.ID)
		if err != nil || current.CNAMETaskID == nil {
			t.Fatalf("site: %v", err)
		}
		if state, code := f.runIntent(t, *current.CNAMETaskID); state != "succeeded" {
			t.Fatalf("regenerate intent state=%s code=%s", state, code)
		}
		if host, explicit := f.claimHostname(t, legacy.ID); host != "brand.cdn.cdnca.com" || explicit {
			t.Fatalf("hostname %q explicit=%v (was %q)", host, explicit, oldHost)
		}
		var retired int
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM cname_record_retirements`).Scan(&retired); err != nil || retired == 0 {
			t.Fatalf("old record retirements = %d err=%v", retired, err)
		}
	})

	t.Run("a taken name is refused", func(t *testing.T) {
		other := f.createSite(t, "other2.example.com")
		_, err := f.store.SetCNAMELabel(t.Context(), f.admin(), CNAMELabelRequest{Kind: CNAMELabelSite, SubjectID: other.ID, Label: "brand", RequestID: "cl-taken"})
		if !errors.Is(err, cnameallocation.ErrLabelTaken) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a prefix changes nothing until the explicit regenerate", func(t *testing.T) {
		site := f.createSite(t, "prefixed2.example.com")
		if state, code := f.runIntent(t, *site.CNAMETaskID); state != "succeeded" {
			t.Fatalf("intent state=%s code=%s", state, code)
		}
		f.completeAllocation(t, site.ID)
		before, _ := f.claimHostname(t, site.ID)
		if _, err := f.store.SetCNAMELabel(t.Context(), f.admin(), CNAMELabelRequest{Kind: CNAMELabelLineGroup, SubjectID: f.platformGroup, Label: "gd", RequestID: "cl-prefix"}); err != nil {
			t.Fatal(err)
		}
		if host, _ := f.claimHostname(t, site.ID); host != before {
			t.Fatalf("existing CNAME changed to %q", host)
		}
		count, err := f.store.CountPrefixAffected(t.Context(), f.admin(), CNAMELabelLineGroup, f.platformGroup)
		if err != nil || count < 1 {
			t.Fatalf("affected = %d err=%v", count, err)
		}
		if _, err := f.store.CountPrefixAffected(t.Context(), f.owner, CNAMELabelLineGroup, f.platformGroup); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("tenant count err = %v", err)
		}
		n, err := f.store.RegeneratePrefix(t.Context(), f.admin(), CNAMELabelLineGroup, f.platformGroup, "cl-regen")
		if err != nil || n != count {
			t.Fatalf("regenerated %d, want %d: %v", n, count, err)
		}
		current, _ := f.service.Get(t.Context(), f.owner, site.ID)
		if state, code := f.runIntent(t, *current.CNAMETaskID); state != "succeeded" {
			t.Fatalf("regenerate intent state=%s code=%s", state, code)
		}
		host, _ := f.claimHostname(t, site.ID)
		if !strings.HasPrefix(host, "gd-") || host == before {
			t.Fatalf("hostname %q (was %q)", host, before)
		}
		// The site that has its own name is not an affected one.
		if host, _ := f.claimHostname(t, legacy.ID); host != "brand.cdn.cdnca.com" {
			t.Fatalf("named site changed to %q", host)
		}
	})
}
