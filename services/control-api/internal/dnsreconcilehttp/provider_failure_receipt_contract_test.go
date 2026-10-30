package dnsreconcilehttp

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

func TestProviderFailureReceiptHTTPContract(t *testing.T) {
	tenantID, siteID, taskID := uuid.New(), uuid.New(), uuid.New()
	leaseID := uuid.New()
	path := "/internal/v1/dns/reconcile/tasks/" + taskID.String() + "/provider-reports"

	newHandler := func(t *testing.T, domain *fakeDomain) http.Handler {
		t.Helper()
		dependencies := validDependencies(domain)
		dependencies.Workloads = workloadAuthenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) {
			return WorkloadPrincipal{WorkloadID: "provider-worker-a", TenantID: tenantID, SiteID: siteID}, nil
		})
		return newTestHandler(t, dependencies)
	}
	encode := func(t *testing.T, body map[string]any) string {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	failureBody := func(status, errorClass, errorCode string) map[string]any {
		return map[string]any{
			"client_request_id": "operation-1", "provider_request_id": "provider-request-1",
			"job_attempt": 3, "lease_id": leaseID,
			"status": status, "error_class": errorClass, "error_code": errorCode, "sequence": 2,
		}
	}

	for _, test := range []struct {
		name      string
		body      map[string]any
		wantRetry time.Duration
	}{
		{name: "transient receipt with retry", body: func() map[string]any {
			body := failureBody("transient_failed", "transient", "provider_rate_limited")
			body["retry_after_seconds"] = 17
			return body
		}(), wantRetry: 17 * time.Second},
		{name: "timeout receipt with retry", body: func() map[string]any {
			body := failureBody("transient_failed", "timeout", "provider_timeout")
			body["retry_after_seconds"] = 3600
			return body
		}(), wantRetry: time.Hour},
		{name: "permanent receipt", body: failureBody("permanent_failed", "permanent", "provider_rejected")},
		{name: "permanent receipt with explicit zero retry", body: func() map[string]any {
			body := failureBody("permanent_failed", "permanent", "provider_rejected")
			body["retry_after_seconds"] = 0
			return body
		}()},
		{name: "revision conflict receipt", body: failureBody("revision_conflict", "revision_conflict", "provider_revision_changed")},
		{name: "cancelled receipt", body: failureBody("cancelled", "cancelled", "provider_cancelled")},
	} {
		t.Run("accepted/"+test.name, func(t *testing.T) {
			domain := &fakeDomain{}
			response := serveWithHeaders(newHandler(t, domain), http.MethodPost, path,
				encode(t, test.body), nil, mutationHeaders())
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body)
			}
			if len(domain.reports) != 1 {
				t.Fatalf("reports=%d, want 1", len(domain.reports))
			}
			report := domain.reports[0].Report
			if report.ProviderRequestID != "provider-request-1" || report.ProviderRecordID != "" ||
				report.ProviderRevision != 0 || report.RetryAfter != test.wantRetry {
				t.Fatalf("mapped report=%#v, want failure receipt with retry %s", report, test.wantRetry)
			}
		})
	}

	for _, test := range []struct {
		name string
		body map[string]any
	}{
		{name: "running with provider request receipt", body: failureBody("running", "", "")},
		{name: "running with retry", body: map[string]any{
			"client_request_id": "operation-1", "status": "running", "error_class": "", "error_code": "",
			"job_attempt": 3, "lease_id": leaseID,
			"retry_after_seconds": 1, "sequence": 2,
		}},
		{name: "succeeded with retry", body: map[string]any{
			"client_request_id": "operation-1", "provider_request_id": "provider-request-1",
			"job_attempt": 3, "lease_id": leaseID,
			"provider_record_id": "record-1", "provider_revision": 8, "status": "succeeded",
			"error_class": "", "error_code": "", "retry_after_seconds": 1, "sequence": 2,
		}},
		{name: "permanent failure with retry", body: func() map[string]any {
			body := failureBody("permanent_failed", "permanent", "provider_rejected")
			body["retry_after_seconds"] = 1
			return body
		}()},
		{name: "transient failure with negative retry", body: func() map[string]any {
			body := failureBody("transient_failed", "transient", "provider_busy")
			body["retry_after_seconds"] = -1
			return body
		}()},
		{name: "transient failure with excessive retry", body: func() map[string]any {
			body := failureBody("transient_failed", "timeout", "provider_timeout")
			body["retry_after_seconds"] = 3601
			return body
		}()},
		{name: "failed receipt with provider record", body: func() map[string]any {
			body := failureBody("transient_failed", "transient", "provider_busy")
			body["provider_record_id"] = "record-1"
			return body
		}()},
		{name: "failed receipt with provider revision", body: func() map[string]any {
			body := failureBody("revision_conflict", "revision_conflict", "provider_revision_changed")
			body["provider_revision"] = 8
			return body
		}()},
	} {
		t.Run("rejected/"+test.name, func(t *testing.T) {
			domain := &fakeDomain{}
			response := serveWithHeaders(newHandler(t, domain), http.MethodPost, path,
				encode(t, test.body), nil, mutationHeaders())
			assertError(t, response, http.StatusBadRequest, "dns_reconcile_invalid_request")
			if len(domain.reports) != 0 {
				t.Fatalf("domain received %d invalid reports", len(domain.reports))
			}
		})
	}

	task := sampleTask(tenantID, siteID)
	task.Result.Operations = []dnscheck.OperationResult{{
		SourceSequence: 1, ClientRequestID: "operation-1", ProviderRequestID: "provider-request-1",
		Status: dnscheck.OperationTransientFailed, Attempts: 1, RetryAfter: 45 * time.Second,
		ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_rate_limited", ReportSequence: 2,
	}}
	task.Result.DeferredDeletes = []dnscheck.OperationResult{{SourceSequence: 2, Status: dnscheck.OperationPlanned}}
	task.Result.Propagation = []dnscheck.PropagationAttempt{{
		Number: 1, CheckedAt: time.Now().UTC(), Status: dnscheck.ClassificationResolverFailure,
		DependencyUnavailable: true,
	}}
	encodedTask, err := json.Marshal(taskViewOf(task))
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result struct {
			Operations []struct {
				RetryAfterSeconds int64 `json:"retry_after_seconds"`
			} `json:"operations"`
			Propagation []struct {
				DependencyUnavailable bool `json:"dependency_unavailable"`
			} `json:"propagation"`
		} `json:"result"`
	}
	if err := json.Unmarshal(encodedTask, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Result.Operations) != 1 || response.Result.Operations[0].RetryAfterSeconds != 45 {
		t.Fatalf("operation response=%s, want retry_after_seconds=45", encodedTask)
	}
	if len(response.Result.Propagation) != 1 || !response.Result.Propagation[0].DependencyUnavailable {
		t.Fatalf("propagation response=%s, want dependency_unavailable=true", encodedTask)
	}
	if count := strings.Count(string(encodedTask), `"retry_after_seconds"`); count != 1 {
		t.Fatalf("retry_after_seconds count=%d in %s, want only the positive retry hint", count, encodedTask)
	}

	fragmentPath := filepath.Join("..", "..", "..", "..", "api", "control-dns-reconcile.openapi.yaml")
	fragmentBytes, err := os.ReadFile(fragmentPath)
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(fragmentBytes)
	for _, required := range []string{
		"retry_after_seconds: {type: integer, format: int64, minimum: 0, maximum: 3600}",
		"required: [number, checked_at, status, consecutive_healthy, dependency_unavailable]",
		"dependency_unavailable: {type: boolean}",
	} {
		if !strings.Contains(fragment, required) {
			t.Fatalf("OpenAPI fragment is missing %q", required)
		}
	}
}
