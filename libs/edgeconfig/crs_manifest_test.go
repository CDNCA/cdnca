package edgeconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// TestDeriveCRSManifestFromCatalogRuleText: the manifest comes from the
// catalog's CRS rule package text (no manifest is pinned in the binary).
func TestDeriveCRSManifestFromCatalogRuleText(t *testing.T) {
	text := testCRSRuleText()
	manifest, err := DeriveCRSManifest(text)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "4.30.0" || manifest.SetupVersion() != "4300" || len(manifest.Rules) != 286 {
		t.Fatalf("manifest version %s setup %s rules %d", manifest.Version, manifest.SetupVersion(), len(manifest.Rules))
	}
	if rule, ok := manifest.Rule(942100); !ok || rule.Phase != 2 || rule.Paranoia != 1 || rule.File != "REQUEST-942-APPLICATION-ATTACK-SQLI.conf" {
		t.Fatalf("942100 = %+v %v", rule, ok)
	}
	for _, file := range manifest.Files {
		sum := sha256.Sum256(text.Files[file.Name])
		if file.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s digest", file.Name)
		}
	}
	unversioned := &CRSRuleText{Files: text.Files}
	if derived, err := DeriveCRSManifest(unversioned); err != nil || derived.Version != "4.30.0" {
		t.Fatalf("version from ver: tags = %v %v", derived, err)
	}
	for name, mutate := range map[string]func(map[string][]byte){
		"no license":   func(files map[string][]byte) { delete(files, CRSLicenseFile) },
		"no notice":    func(files map[string][]byte) { delete(files, CRSNoticeFile) },
		"unknown file": func(files map[string][]byte) { files["evil.lua"] = []byte("x") },
		"unused data":  func(files map[string][]byte) { files["unused-list.data"] = []byte("x\n") },
		"missing data": func(files map[string][]byte) { delete(files, "unix-shell.data") },
		"no base":      func(files map[string][]byte) { delete(files, "REQUEST-905-COMMON-EXCEPTIONS.conf") },
		"mixed versions": func(files map[string][]byte) {
			files["REQUEST-913-SCANNER-DETECTION.conf"] = bytes.ReplaceAll(files["REQUEST-913-SCANNER-DETECTION.conf"], []byte("OWASP_CRS/4.30.0"), []byte("OWASP_CRS/4.31.0"))
		},
		"duplicate rule": func(files map[string][]byte) {
			files["REQUEST-999-COPY-SQLI.conf"] = files["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]
		},
		"empty rule file": func(files map[string][]byte) { files["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] = nil },
		"engine directive": func(files map[string][]byte) {
			files["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] = append(append([]byte(nil), files["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]...), []byte("SecRuleEngine Off\n")...)
		},
		"include": func(files map[string][]byte) {
			files["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] = append(append([]byte(nil), files["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]...), []byte("  Include /etc/passwd\n")...)
		},
	} {
		files := make(map[string][]byte, len(text.Files))
		for key, value := range text.Files {
			files[key] = value
		}
		mutate(files)
		if _, err := DeriveCRSManifest(&CRSRuleText{Files: files}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if _, err := DeriveCRSManifest(&CRSRuleText{Version: "4.29.0", Files: text.Files}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("declared version mismatch: %v", err)
	}
}

func TestParseCRSRulesAttributesChainScoreToStartingRule(t *testing.T) {
	content := []byte(`SecRule ARGS "@rx a" \
    "id:942130,\
    phase:2,\
    block,\
    setvar:'tx.942130_matched_var_name=%{matched_var_name}',\
    chain"
    SecRule TX:1 "@streq %{TX.2}" \
        "t:none,\
        setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
        setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"

# comment mentioning chain"
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:942014,phase:2,pass,nolog,skipAfter:END"
SecRule ARGS "@detectSQLi" \
    "id:942100,\
    phase:2,\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}'"
`)
	rules, err := ParseCRSRules("REQUEST-942-APPLICATION-ATTACK-SQLI.conf", content)
	if err != nil {
		t.Fatal(err)
	}
	want := []CRSRule{
		{ID: 942100, File: "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", Phase: 2, Paranoia: 1, Severity: "warning"},
		{ID: 942130, File: "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", Phase: 2, Paranoia: 2, Severity: "critical"},
	}
	if len(rules) != len(want) || rules[0] != want[0] || rules[1] != want[1] {
		t.Fatalf("rules = %+v", rules)
	}
}

func TestCRSManifestCoversCatalogClasses(t *testing.T) {
	manifest, err := DeriveCRSManifest(testCRSRuleText())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, rule := range manifest.Rules {
		counts[rule.File[:11]]++
	}
	for _, prefix := range []string{"REQUEST-920", "REQUEST-922", "REQUEST-930", "REQUEST-931", "REQUEST-932",
		"REQUEST-933", "REQUEST-934", "REQUEST-941", "REQUEST-942", "REQUEST-944"} {
		if counts[prefix] == 0 {
			t.Fatalf("no scoring rules for %s: %v", prefix, counts)
		}
	}
}
