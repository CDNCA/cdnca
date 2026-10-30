package main

import (
	"os"
	"strings"
	"testing"
)

func TestACMEHelmWiresProductionRuntimeConfiguration(t *testing.T) {
	documents := map[string][]string{
		"../../../../infra/helm/cdnca/values.yaml": {
			"  acme:\n    enabled: false", "publicationCursorActiveKeyID:", "runtimeSecret:",
			"dnsHandleVerifyOnlyKeys:", "publicationCursorKeys:",
		},
		"../../../../infra/helm/cdnca/values.schema.json": {
			`"acmeRuntime"`, `"directoryURL"`, `"contacts"`, `"dnsHandleActiveKey"`,
			`"publicationCursorActiveKeyID"`, `"publicationCursorKeys"`,
		},
		"../../../../infra/helm/cdnca/templates/control-api.yaml": {
			"- name: ACME_RUNTIME_ENABLED", "- name: CERTIFICATE_PUBLICATION_CURSOR_ACTIVE_KEY_ID",
			"- name: CERTIFICATE_PUBLICATION_CURSOR_KEYS_JSON", "- name: ACME_DIRECTORY_URL", "- name: ACME_CONTACTS",
			"- name: ACME_WRAPPING_KEY_BASE64", "- name: ACME_DNS_HANDLE_ACTIVE_KEY_BASE64",
			"- name: ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON", "optional: true",
		},
		"../../../../infra/helm/cdnca/templates/validation.yaml": {
			"controlApi.acme requires controlApi", "controlApi.acme.directoryURL must be one HTTPS URL",
			"controlApi.acme requires explicit controlExternalEgress CIDRs and port 443",
		},
	}
	for path, required := range documents {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range required {
			if !strings.Contains(string(raw), text) {
				t.Errorf("%s missing %q", path, text)
			}
		}
	}
}
