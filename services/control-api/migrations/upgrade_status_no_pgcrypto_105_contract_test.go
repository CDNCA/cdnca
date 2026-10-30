package migrations

import (
	"os"
	"strings"
	"testing"
)

// No control plane installs pgcrypto, so a digest() call fails at runtime and
// the status validator's WHEN OTHERS turns every v2 healthy/rolled_back receipt
// into 'invalid upgrade status json'. 1.0.35 is the first release, so 105
// itself uses the built-in sha256().
func TestUpgradeStatusValidator105UsesBuiltInSHA256(t *testing.T) {
	body, err := os.ReadFile("105_upgrade_canary_active_probe_lkg.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := string(body)
	if strings.Contains(up, "digest(") {
		t.Error("105 up calls pgcrypto digest()")
	}
	if !strings.Contains(up, "encode(sha256(convert_to(evidence_canonical,'UTF8')),'hex')") {
		t.Error("105 up does not hash active probe evidence with built-in sha256()")
	}
}
