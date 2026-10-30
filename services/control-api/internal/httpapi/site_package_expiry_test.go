package httpapi

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

// site-backend6 item 1: the site detail carries the package period end and,
// once it passed, the whole days since ("已过期 N 天").
func TestSiteDetailPackageExpiry(t *testing.T) {
	now := time.Date(2026, 10, 22, 18, 41, 9, 0, time.UTC)
	ends := time.Date(2026, 5, 3, 8, 10, 37, 0, time.UTC)
	for _, test := range []struct {
		name      string
		expiresAt *time.Time
		wantAt    any
		wantDays  any
		wantLeft  any
	}{
		{"no subscription", nil, nil, nil, nil},
		{"expired 172 days", &ends, "2026-05-03T08:10:37Z", float64(172), float64(0)},
		{"still valid", ptrTime(now.Add(48 * time.Hour)), now.Add(48 * time.Hour).Format(time.RFC3339), float64(0), float64(2)},
		{"passed less than a day ago", ptrTime(now.Add(-time.Hour)), now.Add(-time.Hour).Format(time.RFC3339), float64(0), float64(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := site.Site{Revision: 1, PackageExpiresAt: test.expiresAt}
			raw, err := json.Marshal(siteDetailAt(item, now))
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatal(err)
			}
			if body["package_expires_at"] != test.wantAt || body["package_expired_days"] != test.wantDays {
				t.Fatalf("package_expires_at=%v package_expired_days=%v, want %v %v",
					body["package_expires_at"], body["package_expired_days"], test.wantAt, test.wantDays)
			}
			if body["package_remaining_days"] != test.wantLeft {
				t.Fatalf("package_remaining_days=%v, want %v", body["package_remaining_days"], test.wantLeft)
			}
			if _, inBasic := body["basic"].(map[string]any)["package_expires_at"]; inBasic {
				t.Fatal("the expiry must stay out of basic (PATCH echoes basic with unknown fields refused)")
			}
		})
	}
}

func ptrTime(value time.Time) *time.Time { return &value }
