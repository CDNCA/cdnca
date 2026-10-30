package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestSecurityCustomRuleReportState283Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
		forbidden []string
	}{
		{"283_security_custom_rule_report_state.up.sql", "fcd817b0bdf2157651205b47d94aa83027a1d3c5bd6dd158067d60d700f0a079", []string{
			"(SELECT count(*) FROM schema_migrations) <> 282", "282_security_rule_catalog_consumer",
			"6809951208c23bd51918e881e6c355231403a88ccfb2bf9f4f9b5e61faf4c99b",
			"60e6b9c785c603df1df0cd2d95584e1697d15c3a62f16335ac0d9a1016ca00c6",
			"ERRCODE='P2830'", "CREATE TABLE security_custom_rule_report_state",
		}, []string{"enabled boolean", "opt_out"}},
		{"283_security_custom_rule_report_state.down.sql", "4163b07aacb95be5707172b137e23998aec5c2676a5557b85ab52997e34d8280", []string{
			"(SELECT count(*) FROM schema_migrations) <> 283", "283_security_custom_rule_report_state",
			"DROP TABLE security_custom_rule_report_state",
		}, nil},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
		// The upload is mandatory: the sender state must not grow a switch.
		for _, forbidden := range script.forbidden {
			if strings.Contains(string(raw), forbidden) {
				t.Errorf("%s must not contain %q", script.name, forbidden)
			}
		}
	}
}
