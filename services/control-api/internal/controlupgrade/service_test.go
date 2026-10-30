package controlupgrade

import "testing"

func TestValidCanonicalVersion(t *testing.T) {
	for _, version := range []string{"0.0.0", "1.4.0", "2.0.0-rc.1"} {
		if !validCanonicalVersion(version) {
			t.Errorf("validCanonicalVersion(%q) = false", version)
		}
	}
	for _, version := range []string{"", "v1.4.0", "1.4", "01.4.0", "1.4.0+build", " 1.4.0"} {
		if validCanonicalVersion(version) {
			t.Errorf("validCanonicalVersion(%q) = true", version)
		}
	}
}
