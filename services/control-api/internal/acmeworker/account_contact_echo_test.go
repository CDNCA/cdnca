package acmeworker

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// B-D1: Let's Encrypt no longer echoes "contact" in the new-account
// response. The account registration must keep the contacts this worker
// submitted (048 stores contacts NOT NULL) instead of the CA's empty echo,
// and the order must go on to publish the HTTP-01 token.
func TestWorkerKeepsSubmittedContactsWhenCADoesNotEchoThem(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{omitAccountContact: true})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, records, records, &memoryCertificates{items: map[string]IssuedCertificate{}}, nil)
	accounts := worker.deps.Accounts.(*memoryAccounts)
	request := validIssueRequest(ChallengeHTTP01, "no-contact-echo.example.test")

	if _, err := worker.Issue(context.Background(), request); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if !accounts.found || accounts.account.URI != protocol.accountURI ||
		accounts.account.Contact == nil || !slices.Equal(accounts.account.Contact, request.Contacts) {
		t.Fatalf("saved account = %+v found=%t, want contacts %v", accounts.account, accounts.found, request.Contacts)
	}
	records.mu.Lock()
	published := len(records.published)
	records.mu.Unlock()
	if published == 0 {
		t.Fatal("HTTP-01 token was never published")
	}
}

// B-D1: failure() used to drop its cause, so a database rejection reached
// the dispatcher as a bare acme_account_unavailable. The detail names the
// SQLSTATE and column but never the row values PostgreSQL puts in Detail.
func TestFailureDetailReportsCauseWithoutRowValues(t *testing.T) {
	err := failure(CodeAccountUnavailable, &pgconn.PgError{
		Code: "23502", TableName: "acme_account_registration_facts", ColumnName: "contacts",
		Message: `null value in column "contacts" violates not-null constraint`,
		Detail:  "Failing row contains (mailto:secret@example.test)",
	})
	detail := FailureDetail(err)
	if err.Error() != string(CodeAccountUnavailable) ||
		!strings.Contains(detail, "sqlstate=23502") || !strings.Contains(detail, "column=contacts") ||
		strings.Contains(detail, "secret@") {
		t.Fatalf("Error() = %q, FailureDetail() = %q", err.Error(), detail)
	}
	if detail := FailureDetail(failure(CodeAccountUnavailable, errors.New("https://user:pw@host/x"))); detail != "cause_type=*errors.errorString" {
		t.Fatalf("free-form cause detail = %q", detail)
	}
	if detail := FailureDetail(failure(CodeAccountUnavailable, nil)); detail != "" {
		t.Fatalf("no cause detail = %q", detail)
	}
}
