package dnsreconcilehttp

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/google/uuid"
)

func TestResponsesRejectNestedScopeDrift(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	foreignTenantID := uuid.MustParse("99999999-9999-4999-8999-999999999999")
	siteID, taskID, zoneID := uuid.New(), uuid.New(), uuid.New()
	const foreignFact = "foreign-record.example.net"

	newDomain := func() *scopeDriftDomain {
		result := dnscheck.ReconcileResult{
			TenantID: tenantID, SiteID: siteID, ZoneID: zoneID, Status: dnscheck.TaskApplying,
			Plan: dnscheck.RepairPlan{TenantID: tenantID, SiteID: siteID, ZoneID: zoneID},
		}
		return &scopeDriftDomain{
			dryRun: result,
			task: dnsreconcile.Task{
				ID: taskID, TenantID: tenantID, SiteID: siteID, Revision: 7,
				Prepared: dnscheck.PreparedReconcile{Request: dnscheck.CheckRequest{
					TenantID: tenantID, SiteID: siteID,
					Provider: dnscheck.ProviderSnapshot{TenantID: tenantID, SiteID: siteID, ZoneID: zoneID},
				}},
				Result: result,
			},
		}
	}
	newHandler := func(t *testing.T, domain *scopeDriftDomain) http.Handler {
		t.Helper()
		dependencies := validDependencies(domain)
		dependencies.Workloads = workloadAuthenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) {
			return WorkloadPrincipal{WorkloadID: "provider-worker-a", TenantID: tenantID, SiteID: siteID}, nil
		})
		return newTestHandler(t, dependencies)
	}

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		headers    http.Header
		authority  []string
		wantStatus int
		mutate     func(*scopeDriftDomain)
	}{
		{
			name: "dry-run repair plan", method: http.MethodPost,
			path: "/v1/sites/" + siteID.String() + "/dns-reconcile/dry-run",
			body: validCheckBody(uuid.Nil), headers: readHeaders(), authority: []string{"Bearer session-a"},
			wantStatus: http.StatusServiceUnavailable,
			mutate: func(domain *scopeDriftDomain) {
				domain.dryRun.Plan.TenantID = foreignTenantID
				domain.dryRun.Plan.Operations = []dnscheck.ProviderOperation{{Name: foreignFact}}
			},
		},
		{
			name: "get prepared request", method: http.MethodGet,
			path:    "/v1/sites/" + siteID.String() + "/dns-reconcile/tasks/" + taskID.String(),
			headers: readHeaders(), authority: []string{"Bearer session-a"}, wantStatus: http.StatusNotFound,
			mutate: func(domain *scopeDriftDomain) {
				domain.task.Prepared.Request.TenantID = foreignTenantID
				domain.task.Prepared.Request.Provider.Records = []dnscheck.ProviderRecord{{RecordID: "record-1", Name: foreignFact}}
			},
		},
		{
			name: "apply result plan", method: http.MethodPost,
			path: "/v1/sites/" + siteID.String() + "/dns-reconcile/apply",
			body: validCheckBody(uuid.Nil), headers: mutationHeaders(), authority: []string{"Bearer session-a"},
			wantStatus: http.StatusServiceUnavailable,
			mutate: func(domain *scopeDriftDomain) {
				domain.task.Result.Plan.TenantID = foreignTenantID
				domain.task.Result.Plan.Operations = []dnscheck.ProviderOperation{{Name: foreignFact}}
			},
		},
		{
			name: "commit last check", method: http.MethodPost,
			path: "/v1/sites/" + siteID.String() + "/dns-reconcile/tasks/" + taskID.String() + "/commit",
			body: `{}`, headers: mutationHeaders(), authority: []string{"Bearer session-a"},
			wantStatus: http.StatusServiceUnavailable,
			mutate: func(domain *scopeDriftDomain) {
				domain.task.Result.LastCheck = &dnscheck.CheckResult{
					TenantID: foreignTenantID, SiteID: siteID, Name: foreignFact,
				}
			},
		},
		{
			name: "provider report prepared request", method: http.MethodPost,
			path:    "/internal/v1/dns/reconcile/tasks/" + taskID.String() + "/provider-reports",
			body:    `{"client_request_id":"operation-1","job_attempt":3,"lease_id":"33333333-3333-4333-8333-333333333333","provider_request_id":"provider-1","provider_record_id":"record-1","provider_revision":8,"status":"succeeded","error_class":"","error_code":"","sequence":2}`,
			headers: mutationHeaders(), wantStatus: http.StatusServiceUnavailable,
			mutate: func(domain *scopeDriftDomain) {
				domain.task.Prepared.Request.Provider.TenantID = foreignTenantID
				domain.task.Prepared.Request.Provider.Records = []dnscheck.ProviderRecord{{RecordID: "record-1", Name: foreignFact}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain := newDomain()
			test.mutate(domain)
			response := serveWithHeaders(newHandler(t, domain), test.method, test.path, test.body, test.authority, test.headers)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.wantStatus, response.Body)
			}
			if strings.Contains(response.Body.String(), foreignFact) || strings.Contains(response.Body.String(), foreignTenantID.String()) {
				t.Fatalf("response leaked foreign nested facts: %s", response.Body)
			}
		})
	}
}

type scopeDriftDomain struct {
	dryRun dnscheck.ReconcileResult
	task   dnsreconcile.Task
}

func (domain *scopeDriftDomain) DryRun(context.Context, dnsreconcile.DryRunRequest) (dnscheck.ReconcileResult, error) {
	return domain.dryRun, nil
}

func (domain *scopeDriftDomain) Apply(context.Context, dnsreconcile.ApplyRequest) (dnsreconcile.Task, error) {
	return domain.task, nil
}

func (domain *scopeDriftDomain) Get(context.Context, uuid.UUID, uuid.UUID) (dnsreconcile.Task, error) {
	return domain.task, nil
}

func (domain *scopeDriftDomain) Commit(context.Context, dnsreconcile.CommitRequest) (dnsreconcile.Task, error) {
	return domain.task, nil
}

func (domain *scopeDriftDomain) Cancel(context.Context, dnsreconcile.CancelRequest) (dnsreconcile.Task, error) {
	return domain.task, nil
}

func (domain *scopeDriftDomain) RecordProviderReport(context.Context, dnsreconcile.ProviderReportRequest) (dnsreconcile.ReportResult, error) {
	return dnsreconcile.ReportResult{Task: domain.task, Accepted: true}, nil
}
