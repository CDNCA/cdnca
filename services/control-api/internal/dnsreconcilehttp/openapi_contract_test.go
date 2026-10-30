package dnsreconcilehttp

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenAPIFragmentMatchesRuntimeSurface(t *testing.T) {
	fragmentPath := filepath.Join("..", "..", "..", "..", "api", "control-dns-reconcile.openapi.yaml")
	encoded, err := os.ReadFile(fragmentPath)
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(encoded)
	for _, required := range []string{
		"openapi: 3.1.0",
		"/v1/sites/{site_id}/dns-reconcile/dry-run:",
		"/v1/sites/{site_id}/dns-reconcile/apply:",
		"/v1/sites/{site_id}/dns-reconcile/tasks/{task_id}:",
		"/v1/sites/{site_id}/dns-reconcile/tasks/{task_id}/commit:",
		"/v1/sites/{site_id}/dns-reconcile/tasks/{task_id}/cancel:",
		"/internal/v1/dns/reconcile/tasks/{task_id}/provider-reports:",
		"x-required-permissions: [dns.read]",
		"x-required-permissions: [dns.manage]",
		"security: [{bearerAuth: []}]",
		"security: [{workloadAuth: []}]",
		"additionalProperties: false",
		"required_consecutive:",
		"X-Report-Accepted",
		"required: [client_request_id, job_attempt, lease_id, status, error_class, error_code, sequence]",
		"job_attempt: {type: integer, format: int64, minimum: 1, maximum: 4294967295}",
		"lease_id: {type: string, format: uuid}",
		"provider_request_id: {type: string, minLength: 1, maxLength: 256, pattern: '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'}",
		"provider_record_id: {type: string, minLength: 1, maxLength: 256, pattern: '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'}",
		"required: [provider_request_id, provider_record_id, provider_revision]",
		"status: {const: succeeded}",
		"status: {const: transient_failed}",
		"error_class: {type: string, enum: [transient, timeout]}",
		"error_code: {type: string, minLength: 1, maxLength: 128, pattern: '^[a-z][a-z0-9._-]{0,127}$'}",
		"retry_after_seconds: {type: integer, format: int64, minimum: 0, maximum: 3600}",
		"retry_after_seconds: {type: integer, format: int64, minimum: 1, maximum: 3600}",
		"required: [number, checked_at, status, consecutive_healthy, dependency_unavailable]",
		"dependency_unavailable: {type: boolean}",
		"'409': {$ref: '#/components/responses/CancelConflict'}",
		"dns_reconcile_operation_in_flight",
	} {
		if !strings.Contains(fragment, required) {
			t.Fatalf("OpenAPI fragment is missing %q", required)
		}
	}
	if strings.Contains(fragment, "/v1/sites/{site_id}/dns-reconcile/tasks:\n") {
		t.Fatal("OpenAPI fragment still exposes the rejected legacy apply route")
	}
	if count := strings.Count(fragment, "- $ref: '#/components/parameters/MutationIdempotencyKey'"); count != 4 {
		t.Fatalf("mutation Idempotency-Key declarations = %d, want 4", count)
	}
	if count := strings.Count(fragment, "- $ref: '#/components/parameters/IfMatchRevision'"); count != 4 {
		t.Fatalf("mutation If-Match declarations = %d, want 4", count)
	}
	if strings.Contains(fragment, "cdncaApiKey") {
		t.Fatal("tenant API keys must not be accepted by this Bearer-session-only fragment")
	}
	providerReportStart := strings.Index(fragment, "    ProviderReport:\n")
	taskStart := strings.Index(fragment, "    Task:\n")
	if providerReportStart < 0 || taskStart <= providerReportStart {
		t.Fatal("ProviderReport schema boundary is missing")
	}
	providerReport := fragment[providerReportStart:taskStart]
	if !strings.Contains(providerReport,
		"status: {type: string, enum: [transient_failed, permanent_failed, revision_conflict, cancelled]}") {
		t.Fatal("failure receipt identity branch is missing")
	}
	if count := strings.Count(providerReport, "- required: [provider_request_id]"); count != 1 {
		t.Fatalf("provider_request_id prohibition count=%d, want running-only prohibition", count)
	}
	for _, field := range []string{"provider_record_id", "provider_revision"} {
		if count := strings.Count(providerReport, "- required: ["+field+"]"); count != 2 {
			t.Fatalf("%s prohibition count=%d, want running and failure prohibitions", field, count)
		}
	}
	if count := strings.Count(providerReport, "retry_after_seconds: {maximum: 0}"); count != 3 {
		t.Fatalf("zero retry constraint count=%d, want running, succeeded, and non-transient branches", count)
	}
	recordIDSchema := "record_id: {type: string, minLength: 1, maxLength: 256, pattern: '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'}"
	if count := strings.Count(fragment, "\n        "+recordIDSchema); count != 2 {
		t.Fatalf("public record_id schema count=%d, want 2", count)
	}
	providerRecordIDSchema := "provider_record_id: {type: string, minLength: 1, maxLength: 256, pattern: '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'}"
	if count := strings.Count(fragment, "\n        "+providerRecordIDSchema); count != 2 {
		t.Fatalf("public provider_record_id schema count=%d, want 2", count)
	}
}

func TestOpenAPIFragmentBundlesWithRedocly(t *testing.T) {
	if _, err := exec.LookPath("pnpm"); err != nil {
		t.Skip("pnpm is unavailable")
	}
	fragmentPath, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "api", "control-dns-reconcile.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "dns-reconcile-bundle.yaml")
	command := exec.Command("pnpm", "--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle",
		fragmentPath, "--output", bundlePath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("redocly bundle failed: %v\n%s", err, output)
	}
}
