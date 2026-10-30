package main

import (
	"io"
	"strings"
	"testing"
)

func TestPluginWebhookAttestationKeyCommandRejectsBadUsageAndMissingKeys(t *testing.T) {
	for _, args := range [][]string{nil, {"rotate", "extra"}, {"install"}} {
		if err := runPluginWebhookAttestationKey(args, io.Discard); err == nil || err.Error() != pluginWebhookAttestationKeyUsage {
			t.Fatalf("%v: %v", args, err)
		}
	}
	t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_KEY_ID", "")
	t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE", "")
	if err := runPluginWebhookAttestationKey([]string{"status"}, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "PLUGIN_WEBHOOK_ATTESTATION_KEY_ID") {
		t.Fatalf("missing key: %v", err)
	}
}
