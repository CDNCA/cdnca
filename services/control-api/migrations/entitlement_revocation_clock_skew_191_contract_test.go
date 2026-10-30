package migrations

import (
	"strings"
	"testing"
)

func TestEntitlementRevocationClockSkew191Contract(t *testing.T) {
	up, err := FS.ReadFile("191_entitlement_revocation_clock_skew.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("191_entitlement_revocation_clock_skew.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{"up": string(up), "down": string(down)} {
		if !strings.Contains(source, "interval '2 seconds'") {
			t.Fatalf("%s migration does not define the bounded clock-skew window", name)
		}
		if !strings.Contains(source, "GREATEST(physical_now, NEW.issued_at)") {
			t.Fatalf("%s migration does not preserve accepted_at >= issued_at", name)
		}
		if !strings.Contains(source, "guard_control_entitlement_revocation_lkg_084()") {
			t.Fatalf("%s migration does not target the protected revocation trigger", name)
		}
	}
	if strings.Contains(string(up), "DROP TABLE control_entitlement_revocation_lkg") ||
		strings.Contains(string(down), "DROP TABLE control_entitlement_revocation_lkg") {
		t.Fatal("revocation clock-skew migration must not drop the protected LKG")
	}
}
