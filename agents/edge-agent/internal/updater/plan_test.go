package updater

import "testing"

func TestSemanticVersionPrereleaseOrdering(t *testing.T) {
	ordered := []string{
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
	}
	for index := 0; index < len(ordered)-1; index++ {
		left, leftErr := parseVersion(ordered[index])
		right, rightErr := parseVersion(ordered[index+1])
		if leftErr != nil || rightErr != nil || compareVersion(left, right) >= 0 {
			t.Fatalf("version order %q < %q failed: %v, %v", ordered[index], ordered[index+1], leftErr, rightErr)
		}
	}
	for _, invalid := range []string{"1.0.0-", "1.0.0-alpha..1", "1.0.0-01", "1.0.0+build"} {
		if _, err := parseVersion(invalid); err == nil {
			t.Fatalf("invalid version %q accepted", invalid)
		}
	}
}
