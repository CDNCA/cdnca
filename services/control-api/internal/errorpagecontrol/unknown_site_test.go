package errorpagecontrol

import "testing"

// The domain mismatch page (global unknown_site) answers
// with 403, 404, 410 or 421, one status per rule.
func TestUnknownSiteStatusRange(t *testing.T) {
	for _, status := range []int{403, 404, 410, 421} {
		if !categoryAllowsRange(CategoryUnknownSite, status, status) {
			t.Errorf("unknown_site %d refused", status)
		}
	}
	for _, statusRange := range [][2]int{{400, 400}, {500, 500}, {403, 404}, {421, 421 + 1}} {
		if categoryAllowsRange(CategoryUnknownSite, statusRange[0], statusRange[1]) {
			t.Errorf("unknown_site %v accepted", statusRange)
		}
	}
}
