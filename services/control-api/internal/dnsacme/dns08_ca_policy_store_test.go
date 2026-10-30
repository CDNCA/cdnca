package dnsacme

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
)

var _ acmeworker.CAPolicyFactStore = (*Store)(nil)

func TestDNS08CAPolicyStoreFailsClosedWithoutPostgres(t *testing.T) {
	request := acmeworker.IssueRequest{
		TenantID: uuid.New(), ScopeID: uuid.New(), OperationID: uuid.NewString(),
		Domains: []string{"example.test"},
	}
	_, err := (*Store)(nil).LoadCAPolicyFacts(t.Context(), request, []acmeworker.CAPolicyCandidate{{
		DirectoryURL: "https://ca.example/directory", AccountKeyRef: "account/ca",
	}}, time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC), time.Hour, 24*time.Hour)
	if err == nil {
		t.Fatal("LoadCAPolicyFacts() succeeded without a PostgreSQL store")
	}
}

func TestDNS08CAPolicyStoreUsesImmutableOperationAndLatestRetryFacts(t *testing.T) {
	body, err := os.ReadFile("ca_policy_store.go")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Join(strings.Fields(string(body)), " ")
	for _, contract := range []string{
		"FROM acme_issuance_operations", "tenant_scope_id=$1 AND operation_id=$2",
		"request_snapshot -> 'Domains'", "acme_issuance_operation_events",
		"ORDER BY revision DESC LIMIT 1", "failure_code='acme_rate_limited'",
		"next_reconcile_at", "created_at >= $3", "created_at >= $4",
	} {
		if !strings.Contains(source, contract) {
			t.Errorf("ca policy store missing %q", contract)
		}
	}
}

type dns08NoopIssuer struct{}

func (dns08NoopIssuer) Issue(context.Context, acmeworker.IssueRequest) (acmeworker.IssueResult, error) {
	return acmeworker.IssueResult{}, nil
}
