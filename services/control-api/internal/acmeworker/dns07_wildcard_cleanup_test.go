package acmeworker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDNS07WildcardOwnersAndSuccessfulCleanup(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{}
	operations := newMemoryOperations()
	worker := newTestWorker(t, protocol, nil, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	worker.deps.Operations = operations
	worker.config.MaxConcurrentAuthorizations = 1
	request := validIssueRequest(ChallengeDNS01,
		"example.test", "*.example.test", "*.deep.example.test")

	if _, err := worker.Issue(t.Context(), request); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	records.mu.Lock()
	identities := append([]ChallengeIdentity(nil), records.identities...)
	deleted := append([]string(nil), records.deleted...)
	records.mu.Unlock()
	if len(identities) != 3 || len(deleted) != 3 {
		t.Fatalf("published identities=%d deletes=%v", len(identities), deleted)
	}
	wantOwners := map[string]int{
		"_acme-challenge.example.test.":      2,
		"_acme-challenge.deep.example.test.": 1,
	}
	handles := make(map[string]struct{}, len(deleted))
	for index, identity := range identities {
		wantOwners[identity.RecordName]--
		wantDelete := identity.ProviderRef + "|record/" + identity.AttemptID.String() + "|" + identity.ExactValue
		if deleted[index] != wantDelete {
			t.Fatalf("delete[%d]=%q want=%q", index, deleted[index], wantDelete)
		}
		handles[identity.AttemptID.String()] = struct{}{}
	}
	if wantOwners["_acme-challenge.example.test."] != 0 ||
		wantOwners["_acme-challenge.deep.example.test."] != 0 || len(handles) != 3 {
		t.Fatalf("owner counts=%v unique handles=%d", wantOwners, len(handles))
	}
	operations.mu.Lock()
	item := operations.items[operationKey(request.ScopeID, request.OperationID)]
	for attemptID, state := range item.states {
		if state != "cleaned" {
			operations.mu.Unlock()
			t.Fatalf("challenge %s state=%q", attemptID, state)
		}
	}
	operations.mu.Unlock()
}

func TestDNS07WildcardCleanupAcrossFailureCancellationAndRestart(t *testing.T) {
	t.Run("propagation failure", func(t *testing.T) {
		protocol := newProtocolServer(t, testNow, protocolOptions{})
		records := &challengeRecords{waitError: errors.New("resolver unavailable")}
		worker := newTestWorker(t, protocol, nil, records,
			&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)

		_, err := worker.Issue(t.Context(), validIssueRequest(ChallengeDNS01, "*.example.test"))
		if ErrorCodeOf(err) != CodeChallengePropagationFailed {
			t.Fatalf("Issue() error=%v", err)
		}
		assertDNS07ExactDelete(t, records)
	})

	t.Run("cancellation", func(t *testing.T) {
		protocol := newProtocolServer(t, testNow, protocolOptions{})
		ctx, cancel := context.WithCancel(t.Context())
		records := &challengeRecords{onObserve: func(ChallengeIdentity) { cancel() }}
		worker := newTestWorker(t, protocol, nil, records,
			&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)

		_, err := worker.Issue(ctx, validIssueRequest(ChallengeDNS01, "*.deep.example.test"))
		if !errors.Is(err, context.Canceled) || ErrorCodeOf(err) != CodeCancelled {
			t.Fatalf("Issue() error=%v code=%s", err, ErrorCodeOf(err))
		}
		assertDNS07ExactDelete(t, records)
	})

	t.Run("cleanup retry after restart", func(t *testing.T) {
		protocol := newProtocolServer(t, testNow, protocolOptions{})
		records := &challengeRecords{deleteError: errors.New("provider unavailable")}
		operations := newMemoryOperations()
		worker := newTestWorker(t, protocol, nil, records,
			&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
		worker.deps.Operations = operations
		now := testNow
		worker.config.Clock = func() time.Time { return now }
		request := validIssueRequest(ChallengeDNS01, "*.example.test")

		if _, err := worker.Issue(t.Context(), request); ErrorCodeOf(err) != CodeChallengeCleanupFailed {
			t.Fatalf("first Issue() error=%v", err)
		}
		records.deleteError = nil
		now = now.Add(worker.config.RetryDelay + time.Second)
		if _, err := worker.Issue(t.Context(), request); err != nil {
			t.Fatalf("resumed Issue() error=%v", err)
		}
		assertDNS07ExactDelete(t, records)
		operations.mu.Lock()
		item := operations.items[operationKey(request.ScopeID, request.OperationID)]
		for attemptID, state := range item.states {
			if state != "cleaned" {
				operations.mu.Unlock()
				t.Fatalf("challenge %s state=%q", attemptID, state)
			}
		}
		operations.mu.Unlock()
	})
}

func TestDNS07CleanupRejectsCrossTenantIdentityBeforeProviderMutation(t *testing.T) {
	records := &challengeRecords{}
	request := validIssueRequest(ChallengeDNS01, "*.example.test")
	lease := OperationLease{
		TenantID: request.TenantID, ScopeID: request.ScopeID, OperationID: request.OperationID, Request: request,
	}
	challenge := ChallengeIdentity{
		TenantID: uuid.New(), ScopeID: request.ScopeID, ProviderID: request.ProviderID, ZoneID: request.ZoneID,
		OperationID: request.OperationID, ProviderRef: request.ProviderRef, ChallengeType: ChallengeDNS01,
		AttemptID: uuid.New(), RecordName: "_acme-challenge.example.test.", ExactValue: "value",
		TXTHandle: RemoteTXTHandle{ProviderRef: request.ProviderRef, RecordRef: "record/foreign"},
	}
	worker := &Worker{
		config: Config{Clock: func() time.Time { return testNow }, CleanupTimeout: time.Second},
		deps:   Dependencies{DNS01: records, Operations: newMemoryOperations()},
	}

	if err := worker.cleanupChallenge(t.Context(), lease, challenge); ErrorCodeOf(err) != CodeOperationConflict {
		t.Fatalf("cleanupChallenge() error=%v", err)
	}
	if len(records.deleted) != 0 {
		t.Fatalf("cross-tenant deletes=%v", records.deleted)
	}
}

func assertDNS07ExactDelete(t *testing.T, records *challengeRecords) {
	t.Helper()
	records.mu.Lock()
	defer records.mu.Unlock()
	if len(records.identities) != 1 || len(records.deleted) < 1 {
		t.Fatalf("identities=%+v deletes=%v", records.identities, records.deleted)
	}
	identity := records.identities[0]
	want := identity.ProviderRef + "|record/" + identity.AttemptID.String() + "|" + identity.ExactValue
	for _, deleted := range records.deleted {
		if deleted != want || strings.TrimSpace(identity.RecordName) == "" {
			t.Fatalf("delete=%q want=%q identity=%+v", deleted, want, identity)
		}
	}
}
