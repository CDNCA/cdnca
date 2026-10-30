package acmeworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type terminalCleanupStore36 struct {
	OperationStore
	claims      []TerminalChallengeCleanupLease
	claimErrors []error
	fenceErr    error
	completeErr []error
	claimCalls  int
	fenceCalls  int
	completions int
}

func (store *terminalCleanupStore36) ClaimTerminalChallengeCleanup(
	context.Context,
) (TerminalChallengeCleanupLease, bool, error) {
	index := store.claimCalls
	store.claimCalls++
	if index < len(store.claimErrors) && store.claimErrors[index] != nil {
		return TerminalChallengeCleanupLease{}, false, store.claimErrors[index]
	}
	if index >= len(store.claims) {
		return TerminalChallengeCleanupLease{}, false, nil
	}
	return store.claims[index], true, nil
}

func (store *terminalCleanupStore36) FenceTerminalChallengeCleanup(
	context.Context,
	TerminalChallengeCleanupLease,
) error {
	store.fenceCalls++
	return store.fenceErr
}

func (store *terminalCleanupStore36) CompleteTerminalChallengeCleanup(
	_ context.Context,
	_ TerminalChallengeCleanupLease,
) error {
	index := store.completions
	store.completions++
	if index < len(store.completeErr) {
		return store.completeErr[index]
	}
	return nil
}

type terminalHTTPProvider36 struct {
	deletes   []ChallengeIdentity
	deleteErr []error
	publishes int
}

func (provider *terminalHTTPProvider36) Publish(context.Context, ChallengeIdentity) error {
	provider.publishes++
	return nil
}

func (provider *terminalHTTPProvider36) Delete(_ context.Context, challenge ChallengeIdentity) error {
	provider.deletes = append(provider.deletes, challenge)
	index := len(provider.deletes) - 1
	if index < len(provider.deleteErr) {
		return provider.deleteErr[index]
	}
	return nil
}

type terminalDNSProvider36 struct {
	deletes   []ChallengeIdentity
	presents  int
	observes  int
	deleteErr error
}

func (provider *terminalDNSProvider36) PresentTXT(context.Context, ChallengeIdentity) (RemoteTXTHandle, error) {
	provider.presents++
	return RemoteTXTHandle{}, nil
}

func (provider *terminalDNSProvider36) ObserveTXT(context.Context, ChallengeIdentity) error {
	provider.observes++
	return nil
}

func (provider *terminalDNSProvider36) DeleteTXT(_ context.Context, challenge ChallengeIdentity) error {
	provider.deletes = append(provider.deletes, challenge)
	return provider.deleteErr
}

func TestTerminalCleanupWorkerRequiresExplicitStore36(t *testing.T) {
	worker := &Worker{config: DefaultConfig("https://acme.example/directory"), deps: Dependencies{
		Operations: &struct{ OperationStore }{},
	}}
	if err := worker.TerminalCleanupReady(); ErrorCodeOf(err) != CodeChallengeUnavailable {
		t.Fatalf("TerminalCleanupReady() error=%v", err)
	}
	if found, err := worker.CleanupTerminalChallengeOnce(t.Context()); found || ErrorCodeOf(err) != CodeChallengeUnavailable {
		t.Fatalf("CleanupTerminalChallengeOnce()=(%v,%v)", found, err)
	}
}

func TestTerminalCleanupWorkerDeletesOnlyFrozenPublishedArtifact36(t *testing.T) {
	for _, challengeType := range []ChallengeType{ChallengeHTTP01, ChallengeDNS01} {
		t.Run(string(challengeType), func(t *testing.T) {
			lease := terminalCleanupLease36(challengeType)
			store := &terminalCleanupStore36{claims: []TerminalChallengeCleanupLease{lease}}
			httpProvider := &terminalHTTPProvider36{}
			dnsProvider := &terminalDNSProvider36{}
			worker := terminalCleanupWorker36(store, httpProvider, dnsProvider)
			if err := worker.TerminalCleanupReady(); err != nil {
				t.Fatal(err)
			}
			found, err := worker.CleanupTerminalChallengeOnce(t.Context())
			if err != nil || !found {
				t.Fatalf("CleanupTerminalChallengeOnce()=(%v,%v)", found, err)
			}
			if store.claimCalls != 1 || store.fenceCalls != 1 || store.completions != 1 {
				t.Fatalf("store calls claim=%d fence=%d complete=%d", store.claimCalls, store.fenceCalls, store.completions)
			}
			if challengeType == ChallengeHTTP01 {
				if httpProvider.publishes != 0 || len(httpProvider.deletes) != 1 || dnsProvider.presents != 0 || len(dnsProvider.deletes) != 0 {
					t.Fatalf("HTTP provider publish=%d deletes=%d DNS present=%d deletes=%d", httpProvider.publishes, len(httpProvider.deletes), dnsProvider.presents, len(dnsProvider.deletes))
				}
			} else if dnsProvider.presents != 0 || dnsProvider.observes != 0 || len(dnsProvider.deletes) != 1 || len(httpProvider.deletes) != 0 {
				t.Fatalf("DNS present=%d observe=%d deletes=%d HTTP deletes=%d", dnsProvider.presents, dnsProvider.observes, len(dnsProvider.deletes), len(httpProvider.deletes))
			}
		})
	}
}

func TestTerminalCleanupWorkerFencesBeforeDeleteAndKeepsUnknownUncleaned36(t *testing.T) {
	lease := terminalCleanupLease36(ChallengeHTTP01)
	fenceFailure := failure(CodeLeaseLost, nil)
	store := &terminalCleanupStore36{claims: []TerminalChallengeCleanupLease{lease}, fenceErr: fenceFailure}
	httpProvider := &terminalHTTPProvider36{}
	worker := terminalCleanupWorker36(store, httpProvider, &terminalDNSProvider36{})
	if found, err := worker.CleanupTerminalChallengeOnce(t.Context()); !found || !errors.Is(err, fenceFailure) {
		t.Fatalf("fenced cleanup=(%v,%v)", found, err)
	}
	if len(httpProvider.deletes) != 0 || store.completions != 0 {
		t.Fatalf("fenced cleanup deletes=%d completions=%d", len(httpProvider.deletes), store.completions)
	}

	unknown := errors.New("remote delete outcome unknown")
	store.fenceErr = nil
	store.claims = append(store.claims, lease)
	httpProvider.deleteErr = []error{unknown}
	if found, err := worker.CleanupTerminalChallengeOnce(t.Context()); !found || ErrorCodeOf(err) != CodeChallengeCleanupFailed {
		t.Fatalf("unknown cleanup=(%v,%v)", found, err)
	}
	if len(httpProvider.deletes) != 1 || store.completions != 0 {
		t.Fatalf("unknown cleanup deletes=%d completions=%d", len(httpProvider.deletes), store.completions)
	}
}

func TestTerminalCleanupWorkerResponseLossRetriesAbsentIdempotently36(t *testing.T) {
	first := terminalCleanupLease36(ChallengeHTTP01)
	second := first
	second.Token = uuid.New()
	second.Revision++
	second.ExpiresAt = second.ExpiresAt.Add(time.Minute)
	store := &terminalCleanupStore36{
		claims:      []TerminalChallengeCleanupLease{first, second},
		completeErr: []error{failure(CodeOperationStoreFailed, nil), nil},
	}
	httpProvider := &terminalHTTPProvider36{}
	worker := terminalCleanupWorker36(store, httpProvider, &terminalDNSProvider36{})
	if found, err := worker.CleanupTerminalChallengeOnce(t.Context()); !found || ErrorCodeOf(err) != CodeOperationStoreFailed {
		t.Fatalf("first cleanup=(%v,%v)", found, err)
	}
	if found, err := worker.CleanupTerminalChallengeOnce(t.Context()); !found || err != nil {
		t.Fatalf("absent replay cleanup=(%v,%v)", found, err)
	}
	if len(httpProvider.deletes) != 2 || store.completions != 2 {
		t.Fatalf("response-loss deletes=%d completions=%d", len(httpProvider.deletes), store.completions)
	}
}

func TestTerminalCleanupWorkerRejectsForeignFrozenIdentity36(t *testing.T) {
	base := terminalCleanupLease36(ChallengeDNS01)
	for _, test := range []struct {
		name   string
		mutate func(*TerminalChallengeCleanupLease)
	}{
		{name: "attempt", mutate: func(lease *TerminalChallengeCleanupLease) { lease.Challenge.AttemptID = uuid.New() }},
		{name: "provider", mutate: func(lease *TerminalChallengeCleanupLease) { lease.Challenge.TXTHandle.ProviderRef = uuid.NewString() }},
		{name: "record", mutate: func(lease *TerminalChallengeCleanupLease) { lease.Challenge.TXTHandle.RecordRef += "-foreign" }},
		{name: "digest", mutate: func(lease *TerminalChallengeCleanupLease) { lease.ChallengeSHA256[0] ^= 0xff }},
		{name: "operation", mutate: func(lease *TerminalChallengeCleanupLease) { lease.Challenge.OperationID = uuid.NewString() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := base
			test.mutate(&lease)
			store := &terminalCleanupStore36{claims: []TerminalChallengeCleanupLease{lease}}
			dnsProvider := &terminalDNSProvider36{}
			worker := terminalCleanupWorker36(store, &terminalHTTPProvider36{}, dnsProvider)
			if found, err := worker.CleanupTerminalChallengeOnce(t.Context()); !found || ErrorCodeOf(err) != CodeOperationConflict {
				t.Fatalf("foreign cleanup=(%v,%v)", found, err)
			}
			if store.fenceCalls != 0 || store.completions != 0 || len(dnsProvider.deletes) != 0 {
				t.Fatalf("foreign cleanup fence=%d complete=%d deletes=%d", store.fenceCalls, store.completions, len(dnsProvider.deletes))
			}
		})
	}
}

func TestTerminalCleanupPGContractUsesTerminalAuthorityAndDatabaseLease36(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "pgstore.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"func (s *PGOperationStore) ClaimTerminalChallengeCleanup",
		"func (s *PGOperationStore) FenceTerminalChallengeCleanup",
		"func (s *PGOperationStore) CompleteTerminalChallengeCleanup",
		"statement_timestamp()",
		"FOR UPDATE OF operation,attempt SKIP LOCKED",
		"certificate_order.status IN ('failed','revoked')",
		"renewal_parent.status IN ('failed','revoked')",
		"latest_operation.status <> 'active'",
		"terminalChallengeCleanupLeaseDuration",
		"latest_challenge.state IN ('published','cleanup_claimed')",
		"certificate.challenge.terminal_cleanup",
		"'cleaned'",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("terminal cleanup PG contract missing %q", required)
		}
	}
	start := strings.Index(text, "func (s *PGOperationStore) Recoverable")
	end := strings.Index(text, "func hasACMEBinding048")
	if start < 0 || end <= start {
		t.Fatal("isolate Recoverable")
	}
	if !strings.Contains(text[start:end], "certificate_order.status IN ('pending','validating','issuing','issued')") {
		t.Fatal("terminal cleanup changed issuance Recoverable authority")
	}
}

func terminalCleanupWorker36(
	store *terminalCleanupStore36,
	httpProvider *terminalHTTPProvider36,
	dnsProvider *terminalDNSProvider36,
) *Worker {
	return &Worker{
		config: DefaultConfig("https://acme.example/directory"),
		deps:   Dependencies{Operations: store, HTTP01: httpProvider, DNS01: dnsProvider},
	}
}

func terminalCleanupLease36(challengeType ChallengeType) TerminalChallengeCleanupLease {
	scopeID := uuid.New()
	orderID := uuid.New()
	request := IssueRequest{
		TenantID: scopeID, ScopeID: scopeID, OperationID: orderID.String(), CertificateOrderID: orderID,
		ActorUserID: uuid.New(), DirectoryURL: "https://acme.example/directory",
		AccountKeyRef: "account-key", CertificateKeyRef: "certificate-key",
		Contacts: []string{"mailto:ops@example.test"}, AcceptTerms: true,
		Domains: []string{"example.test"}, ChallengeType: challengeType,
	}
	challenge := ChallengeIdentity{
		TenantID: scopeID, ScopeID: scopeID, OperationID: orderID.String(), AttemptID: uuid.New(),
		AuthorizationURL: "https://acme.example/authz/1", ChallengeURL: "https://acme.example/challenge/1",
		ChallengeType: challengeType, Identifier: "example.test", RecordName: "example.test",
		Token: "terminal-cleanup-token", ExactValue: "terminal-cleanup-value",
	}
	if challengeType == ChallengeDNS01 {
		providerID := uuid.New()
		request.ProviderID = providerID
		request.ZoneID = uuid.New()
		request.ProviderRef = providerID.String()
		challenge.ProviderID = request.ProviderID
		challenge.ZoneID = request.ZoneID
		challenge.ProviderRef = request.ProviderRef
		challenge.RecordName = "_acme-challenge.example.test."
		challenge.TXTHandle = RemoteTXTHandle{ProviderRef: request.ProviderRef, RecordRef: "remote-record-1"}
	}
	lease := TerminalChallengeCleanupLease{
		Token: uuid.New(), Revision: 3, ExpiresAt: time.Now().UTC().Add(time.Minute),
		Request: request, RequestDigest: issueRequestDigest(request), Challenge: challenge,
	}
	lease.ChallengeSHA256 = terminalChallengeCleanupDigest(challenge)
	return lease
}
