package edgeconfig

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func telemetryCaptureSpec() Spec {
	spec := validSpec()
	spec.ConfigRevision = 7
	spec.TenantID = "11111111-1111-4111-8111-111111111111"
	spec.Sites[0].ID = "33333333-3333-4333-8333-333333333333"
	return spec
}

func telemetryMultiPortSpec() Spec {
	spec := telemetryCaptureSpec()
	spec.Sites[0].TelemetryCapture = TelemetryCapturePolicy{
		SchemaVersion: 1, Enabled: true, RequestHeaderAllowlist: []string{"X-First-Listener"},
	}
	second := spec.Sites[0]
	second.ListenPort++
	second.TelemetryCapture = TelemetryCapturePolicy{
		SchemaVersion: 1, Enabled: true, RequestBodyFieldAllowlist: []string{"clientSecret"},
	}
	spec.Sites = append(spec.Sites, second)
	return spec
}

func assertInvalidTelemetryManifestMutation(t *testing.T, original map[string]any, mutate func(map[string]any)) {
	t.Helper()
	content, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	mutate(document)
	content, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTelemetryIdentityManifest(content); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("ParseTelemetryIdentityManifest() error = %v, want ErrInvalidConfig; document=%s", err, content)
	}
}

func nginxLineContaining(t *testing.T, config, marker string) string {
	t.Helper()
	for _, line := range strings.Split(config, "\n") {
		if strings.Contains(line, marker) {
			return line
		}
	}
	t.Fatalf("generated config is missing line containing %q", marker)
	return ""
}
