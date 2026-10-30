package main

import (
	"os"
	"regexp"
	"testing"
)

func TestAPIKeySecurityProductionComposition(t *testing.T) {
	for path, keyring := range map[string]string{
		"main.go":                   `cfg\.APIKeyPepperKeyring`,
		"analytics_logs_runtime.go": `apiKeyPepper`,
	} {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		verifier := regexp.MustCompile(`apikeycredential\.NewVerifierWithKeyring\(\s*` + keyring + `,\s*time\.Now,\s*apikeycredential\.NewPostgresDenialRecorder\(\s*pool,\s*time\.Now\s*\),\s*\)`)
		if !verifier.Match(source) {
			t.Errorf("%s does not compose the API key verifier with the durable denial recorder", path)
		}
	}

	mainSource, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for field, expression := range map[string]string{
		"APIKeyTrustedProxyCIDRs": "cfg.APIKeyTrustedProxyCIDRs",
		"APIKeyMaxProxyHops":      "cfg.APIKeyMaxProxyHops",
	} {
		pattern := regexp.MustCompile(field + `:\s*` + regexp.QuoteMeta(expression) + `,`)
		if !pattern.Match(mainSource) {
			t.Errorf("main.go does not pass %s to httpapi.Config", field)
		}
	}
}
