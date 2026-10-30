package acmeworker

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/acme"
)

var testNow = time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)

type memorySigners struct {
	keys map[string]crypto.Signer
	err  error
}

func (s *memorySigners) Signer(_ context.Context, keyRef string) (crypto.Signer, error) {
	if s.err != nil {
		return nil, s.err
	}
	signer := s.keys[keyRef]
	if signer == nil {
		return nil, errors.New("key absent")
	}
	return signer, nil
}

type memoryAccounts struct {
	mu      sync.Mutex
	account AccountRegistration
	found   bool
}

func (s *memoryAccounts) LoadAccount(context.Context, string, string) (AccountRegistration, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.account, s.found, nil
}

func (s *memoryAccounts) SaveAccount(_ context.Context, _, _ string, account AccountRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.account = account
	s.found = true
	return nil
}

type memoryCertificates struct {
	mu         sync.Mutex
	items      map[string]IssuedCertificate
	saveCalls  int
	saveLeases []OperationLease
	onSave     func()
}

func (s *memoryCertificates) Load(_ context.Context, scopeID uuid.UUID, operationID string) (IssuedCertificate, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	certificate, found := s.items[scopeID.String()+"/"+operationID]
	return cloneCertificate(certificate), found, nil
}

func (s *memoryCertificates) Save(_ context.Context, lease OperationLease, certificate IssuedCertificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveCalls++
	s.saveLeases = append(s.saveLeases, lease)
	if s.onSave != nil {
		s.onSave()
	}
	key := lease.ScopeID.String() + "/" + lease.OperationID
	if existing, found := s.items[key]; found && existing.LeafFingerprint != certificate.LeafFingerprint {
		return errors.New("operation conflict")
	}
	s.items[key] = cloneCertificate(certificate)
	return nil
}

type challengeRecords struct {
	mu            sync.Mutex
	published     []string
	deleted       []string
	waited        []string
	presentError  error
	presentHandle *RemoteTXTHandle
	waitError     error
	deleteError   error
	onPublish     func()
	onObserve     func(ChallengeIdentity)
	onDeleteTXT   func(ChallengeIdentity)
	identities    []ChallengeIdentity
}

type recoverableChallengeRecords struct {
	*challengeRecords
	recoverHandle RemoteTXTHandle
	recoverFound  bool
	recoverError  error
	recovered     []ChallengeIdentity
}

func (r *recoverableChallengeRecords) RecoverTXT(_ context.Context, challenge ChallengeIdentity) (RemoteTXTHandle, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recovered = append(r.recovered, challenge)
	return r.recoverHandle, r.recoverFound, r.recoverError
}

func (r *challengeRecords) Publish(_ context.Context, challenge ChallengeIdentity) error {
	r.mu.Lock()
	r.published = append(r.published, challenge.RecordName+"|"+challenge.Token+"|"+challenge.ExactValue)
	r.identities = append(r.identities, challenge)
	onPublish := r.onPublish
	r.mu.Unlock()
	if onPublish != nil {
		onPublish()
	}
	return nil
}

func (r *challengeRecords) PresentTXT(_ context.Context, challenge ChallengeIdentity) (RemoteTXTHandle, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.published = append(r.published, challenge.RecordName+"|"+challenge.ExactValue)
	r.identities = append(r.identities, challenge)
	handle := RemoteTXTHandle{}
	if r.presentHandle != nil {
		handle = *r.presentHandle
	} else {
		handle = RemoteTXTHandle{
			ProviderRef: challenge.ProviderRef,
			RecordRef:   "record/" + challenge.AttemptID.String(),
		}
	}
	return handle, r.presentError
}

func (r *challengeRecords) ObserveTXT(_ context.Context, challenge ChallengeIdentity) error {
	r.mu.Lock()
	r.waited = append(r.waited, challenge.TXTHandle.ProviderRef+"|"+challenge.TXTHandle.RecordRef+"|"+challenge.ExactValue)
	onObserve := r.onObserve
	err := r.waitError
	r.mu.Unlock()
	if onObserve != nil {
		onObserve(challenge)
	}
	return err
}

func (r *challengeRecords) Delete(_ context.Context, challenge ChallengeIdentity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleted = append(r.deleted, challenge.RecordName+"|"+challenge.ExactValue)
	return r.deleteError
}

func (r *challengeRecords) DeleteTXT(_ context.Context, challenge ChallengeIdentity) error {
	r.mu.Lock()
	r.deleted = append(r.deleted, challenge.TXTHandle.ProviderRef+"|"+challenge.TXTHandle.RecordRef+"|"+challenge.ExactValue)
	onDelete := r.onDeleteTXT
	err := r.deleteError
	r.mu.Unlock()
	if onDelete != nil {
		onDelete(challenge)
	}
	return err
}

type memoryOperation struct {
	request       IssueRequest
	digest        string
	lease         OperationLease
	nextReconcile time.Time
	challenges    map[uuid.UUID]ChallengeIdentity
	states        map[uuid.UUID]string
	cleanupTokens map[uuid.UUID]uuid.UUID
}

type memoryOperations struct {
	mu            sync.Mutex
	items         map[string]*memoryOperation
	beforeAdvance func(string)
	afterAdvance  func(string)
	beforeMark    func(string)
	afterMark     func(string)
	markError     error
}

type memoryCleanupClaim struct {
	store     *memoryOperations
	item      *memoryOperation
	lease     OperationLease
	challenge ChallengeIdentity
	closed    bool
}

func newMemoryOperations() *memoryOperations {
	return &memoryOperations{items: make(map[string]*memoryOperation)}
}

func operationKey(scopeID uuid.UUID, operationID string) string {
	return scopeID.String() + "/" + operationID
}

func (s *memoryOperations) Claim(_ context.Context, request IssueRequest, digest string, now, leaseUntil time.Time) (OperationClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := operationKey(request.ScopeID, request.OperationID)
	item := s.items[key]
	if item == nil {
		token := uuid.New()
		lease := OperationLease{
			TenantID: request.TenantID, ScopeID: request.ScopeID, OperationID: request.OperationID, Token: token,
			ExpiresAt: leaseUntil, Revision: 1, Request: request, Digest: digest,
			State: OperationState{Phase: PhaseClaimed, Status: OperationActive},
		}
		s.items[key] = &memoryOperation{request: request, digest: digest, lease: lease,
			challenges: make(map[uuid.UUID]ChallengeIdentity), states: make(map[uuid.UUID]string),
			cleanupTokens: make(map[uuid.UUID]uuid.UUID)}
		return OperationClaim{State: OperationClaimed, Lease: lease}, nil
	}
	if item.digest != digest {
		return OperationClaim{}, failure(CodeOperationConflict, nil)
	}
	switch item.lease.State.Status {
	case OperationCompleted:
		return OperationClaim{State: OperationDone, Lease: item.lease}, nil
	case OperationFailed:
		return OperationClaim{State: OperationTerminal, Lease: item.lease}, nil
	case OperationActive:
		if item.lease.ExpiresAt.After(now) {
			return OperationClaim{State: OperationBusy, Lease: item.lease}, nil
		}
	case OperationRetryWait:
		if item.nextReconcile.After(now) {
			return OperationClaim{State: OperationBusy, Lease: item.lease}, nil
		}
	}
	item.lease.Token = uuid.New()
	item.lease.ExpiresAt = leaseUntil
	item.lease.Revision++
	item.lease.State.Status = OperationActive
	item.lease.State.FailureCode = ""
	return OperationClaim{State: OperationClaimed, Lease: item.lease}, nil
}

func (s *memoryOperations) Advance(_ context.Context, lease OperationLease, eventType string, next OperationState, now time.Time) (OperationLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.fenced(lease, now)
	if err != nil {
		return OperationLease{}, err
	}
	if phaseRank(next.Phase) < phaseRank(item.lease.State.Phase) {
		return OperationLease{}, failure(CodeOperationConflict, nil)
	}
	if s.beforeAdvance != nil {
		s.beforeAdvance(eventType)
	}
	item.lease.Revision++
	item.lease.State = cloneOperationState(next)
	if next.Status == OperationCompleted || next.Status == OperationFailed {
		item.lease.Token = uuid.Nil
		item.lease.ExpiresAt = time.Time{}
	}
	if s.afterAdvance != nil {
		s.afterAdvance(eventType)
	}
	return item.lease, nil
}

func (s *memoryOperations) Release(_ context.Context, lease OperationLease, code ErrorCode, retry bool, now, retryAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.fenced(lease, now)
	if err != nil {
		return err
	}
	item.lease.Revision++
	item.lease.Token = uuid.Nil
	item.lease.ExpiresAt = time.Time{}
	item.lease.State.FailureCode = code
	item.lease.State.Status = OperationFailed
	if retry {
		item.lease.State.Status = OperationRetryWait
		item.nextReconcile = retryAt
	}
	return nil
}

func (s *memoryOperations) PrepareChallenge(_ context.Context, lease OperationLease, challenge ChallengeIdentity, now time.Time) (ChallengeIdentity, error) {
	if challenge.ZeroMatchCleanupClaimed {
		return ChallengeIdentity{}, failure(CodeOperationConflict, nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.fenced(lease, now)
	if err != nil {
		return ChallengeIdentity{}, err
	}
	challenge.TenantID = lease.TenantID
	challenge.ScopeID = lease.ScopeID
	challenge.OperationID = lease.OperationID
	challenge.AttemptID = uuid.New()
	item.challenges[challenge.AttemptID] = challenge
	item.states[challenge.AttemptID] = "intent"
	return challenge, nil
}

func (s *memoryOperations) MarkChallenge(_ context.Context, lease OperationLease, challenge ChallengeIdentity, state string, now time.Time) error {
	if state != "published" || challenge.ZeroMatchCleanupClaimed {
		return failure(CodeInvalidInput, nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.fenced(lease, now)
	if err != nil {
		return err
	}
	stored, found := item.challenges[challenge.AttemptID]
	if !found {
		return failure(CodeOperationStoreFailed, nil)
	}
	if challenge.ChallengeType == ChallengeDNS01 {
		if err := validateRemoteTXTHandle(challenge.TXTHandle, challenge.ProviderRef); err != nil {
			return failure(CodeInvalidInput, err)
		}
	} else if challenge.TXTHandle != (RemoteTXTHandle{}) {
		return failure(CodeInvalidInput, nil)
	}
	withoutHandle := challenge
	withoutHandle.TXTHandle = RemoteTXTHandle{}
	if storedState := item.states[challenge.AttemptID]; storedState == state {
		if stored != challenge {
			return failure(CodeOperationConflict, nil)
		}
		return nil
	}
	if stored != withoutHandle {
		return failure(CodeOperationConflict, nil)
	}
	if s.markError != nil {
		return s.markError
	}
	if s.beforeMark != nil {
		s.beforeMark(state)
	}
	item.challenges[challenge.AttemptID] = challenge
	item.states[challenge.AttemptID] = state
	if s.afterMark != nil {
		s.afterMark(state)
	}
	return nil
}

func (s *memoryOperations) ClaimChallengeCleanup(_ context.Context, lease OperationLease, challenge ChallengeIdentity, now time.Time) (ChallengeCleanupClaim, error) {
	if challenge.ZeroMatchCleanupClaimed {
		return nil, failure(CodeOperationConflict, nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.fenced(lease, now)
	if err != nil {
		return nil, err
	}
	previousState, found := item.states[challenge.AttemptID]
	if !found || previousState == "cleaned" || item.challenges[challenge.AttemptID] != challenge {
		return nil, failure(CodeOperationStoreFailed, nil)
	}
	if previousState == "cleanup_claimed" && item.cleanupTokens[challenge.AttemptID] == lease.Token {
		return nil, &Error{Code: CodeChallengeCleanupFailed, Temporary: true}
	}
	item.states[challenge.AttemptID] = "cleanup_claimed"
	item.cleanupTokens[challenge.AttemptID] = lease.Token
	return &memoryCleanupClaim{
		store: s, item: item, lease: lease, challenge: challenge,
	}, nil
}

func (c *memoryCleanupClaim) Complete(_ context.Context, now time.Time) error {
	if c.closed {
		return failure(CodeOperationConflict, nil)
	}
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.item.lease.Token != c.lease.Token || c.item.lease.Revision != c.lease.Revision ||
		c.item.lease.State.Status != OperationActive || !c.item.lease.ExpiresAt.After(now) {
		return failure(CodeLeaseLost, nil)
	}
	attemptID := c.challenge.AttemptID
	if c.item.challenges[attemptID] != c.challenge || c.item.states[attemptID] != "cleanup_claimed" ||
		c.item.cleanupTokens[attemptID] != c.lease.Token {
		return failure(CodeOperationConflict, nil)
	}
	if c.store.beforeMark != nil {
		c.store.beforeMark("cleaned")
	}
	c.item.states[attemptID] = "cleaned"
	if c.store.afterMark != nil {
		c.store.afterMark("cleaned")
	}
	c.closed = true
	return nil
}

func (c *memoryCleanupClaim) Abort(context.Context) error {
	c.closed = true
	return nil
}

func (s *memoryOperations) OutstandingChallenges(_ context.Context, lease OperationLease, now time.Time) ([]ChallengeIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.fenced(lease, now)
	if err != nil {
		return nil, err
	}
	var result []ChallengeIdentity
	for id, challenge := range item.challenges {
		if item.states[id] != "cleaned" {
			challenge.ZeroMatchCleanupClaimed = challenge.ChallengeType == ChallengeDNS01 &&
				challenge.TXTHandle == (RemoteTXTHandle{}) && item.states[id] == "cleanup_claimed"
			result = append(result, challenge)
		}
	}
	return result, nil
}

func (s *memoryOperations) Recoverable(_ context.Context, now time.Time, limit int) ([]IssueRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []IssueRequest
	for _, item := range s.items {
		if len(result) == limit {
			break
		}
		if item.lease.State.Status == OperationActive && !item.lease.ExpiresAt.After(now) ||
			item.lease.State.Status == OperationRetryWait && !item.nextReconcile.After(now) {
			result = append(result, item.request)
		}
	}
	return result, nil
}

func (s *memoryOperations) fenced(lease OperationLease, now time.Time) (*memoryOperation, error) {
	item := s.items[operationKey(lease.ScopeID, lease.OperationID)]
	if item == nil || item.lease.Token != lease.Token || item.lease.Revision != lease.Revision ||
		item.lease.State.Status != OperationActive || !item.lease.ExpiresAt.After(now) {
		return nil, failure(CodeLeaseLost, nil)
	}
	return item, nil
}

func TestIssueRFC8555RetriesBadNonceAnd429ThenParsesProcessingChain(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{
		badNonceCount: 1, rateLimitCount: 1, finalizeProcessing: true,
	})
	records := &challengeRecords{}
	certificates := &memoryCertificates{items: make(map[string]IssuedCertificate)}
	worker := newTestWorker(t, protocol, records, records, certificates, nil)
	request := validIssueRequest(ChallengeHTTP01, "www.example.test", "api.example.test")

	result, err := worker.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if protocol.newOrderAttempts != 3 {
		t.Fatalf("new-order attempts = %d, want badNonce + 429 + success", protocol.newOrderAttempts)
	}
	if protocol.postFinalizePolls != 1 {
		t.Fatalf("post-finalize processing polls = %d, want 1", protocol.postFinalizePolls)
	}
	if len(result.Authorizations) != 2 || len(result.Certificate.ChainDER) != 2 ||
		result.Certificate.LeafFingerprint == "" || result.Certificate.NotAfter != testNow.Add(90*24*time.Hour) ||
		result.Certificate.CertificateKeyRef != request.CertificateKeyRef ||
		!strings.HasPrefix(result.Certificate.PublicKeySPKISHA256, "sha256:") {
		t.Fatalf("unexpected issue result: %+v", result)
	}
	for _, authorization := range result.Authorizations {
		if authorization.Status != "valid" || authorization.Identifier == "" || authorization.ErrorCode != "" {
			t.Fatalf("authorization progress = %+v", authorization)
		}
	}
	if len(records.published) != 2 || len(records.deleted) != 2 {
		t.Fatalf("HTTP challenge lifecycle publish=%v delete=%v", records.published, records.deleted)
	}

	replayed, err := worker.Issue(context.Background(), request)
	if err != nil || !replayed.Reused || protocol.newOrderAttempts != 3 || certificates.saveCalls != 1 {
		t.Fatalf("replayed issue = %+v, error=%v, attempts=%d saves=%d", replayed, err, protocol.newOrderAttempts, certificates.saveCalls)
	}
	conflict := request
	conflict.Domains = []string{"other.example.test"}
	if _, err := worker.Issue(context.Background(), conflict); ErrorCodeOf(err) != CodeOperationConflict || protocol.newOrderAttempts != 3 {
		t.Fatalf("operation replay conflict error=%v attempts=%d", err, protocol.newOrderAttempts)
	}
}

func TestNewRejectsMissingOperationStore(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	worker := newTestWorker(t, protocol, &challengeRecords{}, &challengeRecords{},
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	dependencies := worker.deps
	dependencies.Operations = nil
	if _, err := New(worker.config, dependencies); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("New() error = %v", err)
	}
}

func TestNewRequiresCleanupLeaseSafetyMargin(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	worker := newTestWorker(t, protocol, &challengeRecords{}, &challengeRecords{},
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	config := worker.config
	config.LeaseDuration = config.OrderTimeout + config.CleanupTimeout + 5*time.Second - time.Nanosecond
	if _, err := New(config, worker.deps); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("New() undersized cleanup lease error = %v", err)
	}
	config.LeaseDuration += time.Nanosecond
	if _, err := New(config, worker.deps); err != nil {
		t.Fatalf("New() exact cleanup lease margin error = %v", err)
	}
}

func TestValidateNewOrderRejectsMissingIdentifiers(t *testing.T) {
	order := &acme.Order{
		URI:         "https://ca.example/order/1",
		FinalizeURL: "https://ca.example/finalize/1",
		AuthzURLs:   []string{"https://ca.example/authz/1"},
	}
	if err := validateNewOrder(order, []string{"example.test"}); err == nil {
		t.Fatal("validateNewOrder() accepted an empty identifier list")
	}
}

func TestConcurrentSameOperationCreatesOneOrder(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	entered := make(chan struct{})
	resume := make(chan struct{})
	var once sync.Once
	records := &challengeRecords{onPublish: func() {
		once.Do(func() { close(entered) })
		<-resume
	}}
	worker := newTestWorker(t, protocol, records, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	request := validIssueRequest(ChallengeHTTP01, "concurrent.example.test")
	firstDone := make(chan error, 1)
	go func() {
		_, err := worker.Issue(context.Background(), request)
		firstDone <- err
	}()
	<-entered
	if _, err := worker.Issue(context.Background(), request); ErrorCodeOf(err) != CodeOperationBusy {
		t.Fatalf("concurrent Issue() error = %v", err)
	}
	close(resume)
	if err := <-firstDone; err != nil {
		t.Fatalf("winning Issue() error = %v", err)
	}
	if protocol.newOrderAttempts != 1 {
		t.Fatalf("new order attempts = %d, want 1", protocol.newOrderAttempts)
	}
}

func TestCrashAfterAccountRegistrationUsesExistingAccount(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, records, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	operations := newMemoryOperations()
	operations.beforeAdvance = panicOnEvent("account_registered")
	worker.deps.Operations = operations
	worker.config.MaxConcurrentAuthorizations = 1
	now := testNow
	worker.config.Clock = func() time.Time { return now }
	request := validIssueRequest(ChallengeHTTP01, "account-crash.example.test")
	executeUntilCrash(t, worker, request)
	operations.beforeAdvance = nil
	now = now.Add(worker.config.LeaseDuration + time.Second)
	if _, err := worker.Issue(context.Background(), request); err != nil {
		t.Fatalf("takeover Issue() error = %v", err)
	}
	if protocol.newAccountAttempts != 1 || protocol.newOrderAttempts != 1 {
		t.Fatalf("account attempts=%d order attempts=%d", protocol.newAccountAttempts, protocol.newOrderAttempts)
	}
}

func TestCrashAfterNewOrderResponseFailsClosedWithoutSecondOrder(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, records, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	operations := newMemoryOperations()
	operations.beforeAdvance = panicOnEvent("order_created")
	worker.deps.Operations = operations
	worker.config.MaxConcurrentAuthorizations = 1
	now := testNow
	worker.config.Clock = func() time.Time { return now }
	request := validIssueRequest(ChallengeHTTP01, "order-crash.example.test")
	executeUntilCrash(t, worker, request)
	operations.beforeAdvance = nil
	now = now.Add(worker.config.LeaseDuration + time.Second)
	if _, err := worker.Issue(context.Background(), request); ErrorCodeOf(err) != CodeOrderUncertain {
		t.Fatalf("takeover Issue() error = %v", err)
	}
	if protocol.newOrderAttempts != 1 {
		t.Fatalf("new order attempts = %d, want fail-closed 1", protocol.newOrderAttempts)
	}
}

func TestCrashAfterChallengePublishTakeoverCleansPersistedAttempt(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{onPublish: func() { panic("simulated process crash") }}
	worker := newTestWorker(t, protocol, records, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	operations := newMemoryOperations()
	worker.deps.Operations = operations
	worker.config.MaxConcurrentAuthorizations = 1
	now := testNow
	worker.config.Clock = func() time.Time { return now }
	request := validIssueRequest(ChallengeHTTP01, "publish-crash.example.test")
	executeUntilCrash(t, worker, request)
	records.onPublish = nil
	now = now.Add(worker.config.LeaseDuration + time.Second)
	if _, err := worker.Issue(context.Background(), request); err != nil {
		t.Fatalf("takeover Issue() error = %v", err)
	}
	wantDelete := records.identities[0].RecordName + "|" + records.identities[0].ExactValue
	if protocol.newOrderAttempts != 1 || len(records.deleted) != 2 || records.deleted[0] != wantDelete {
		t.Fatalf("orders=%d published=%v deleted=%v", protocol.newOrderAttempts, records.published, records.deleted)
	}
}

func TestCrashAfterAuthorizationCleanupTakeoverDeletesAtLeastOnce(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, records, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	operations := newMemoryOperations()
	operations.beforeMark = func(state string) {
		if state == "cleaned" {
			panic("simulated process crash")
		}
	}
	worker.deps.Operations = operations
	worker.config.MaxConcurrentAuthorizations = 1
	now := testNow
	worker.config.Clock = func() time.Time { return now }
	request := validIssueRequest(ChallengeHTTP01, "authz-crash.example.test")
	executeUntilCrash(t, worker, request)
	operations.beforeMark = nil
	now = now.Add(worker.config.LeaseDuration + time.Second)
	if _, err := worker.Issue(context.Background(), request); err != nil {
		t.Fatalf("takeover Issue() error = %v", err)
	}
	if protocol.newOrderAttempts != 1 || len(records.deleted) != 2 || records.deleted[0] != records.deleted[1] {
		t.Fatalf("orders=%d deletes=%v", protocol.newOrderAttempts, records.deleted)
	}
}

func TestDNSCrashAfterDeleteBeforeCleanupCASRetriesExactRecord(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, nil, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	operations := newMemoryOperations()
	operations.beforeMark = func(state string) {
		if state == "cleaned" {
			panic("simulated process crash after DeleteTXT")
		}
	}
	worker.deps.Operations = operations
	worker.config.MaxConcurrentAuthorizations = 1
	now := testNow
	worker.config.Clock = func() time.Time { return now }
	request := validIssueRequest(ChallengeDNS01, "dns-cleanup-crash.example.test")

	executeUntilCrash(t, worker, request)
	operations.beforeMark = nil
	now = now.Add(worker.config.LeaseDuration + time.Second)
	if _, err := worker.Issue(t.Context(), request); err != nil {
		t.Fatalf("takeover Issue() error = %v", err)
	}
	if len(records.deleted) != 2 || records.deleted[0] != records.deleted[1] ||
		!strings.Contains(records.deleted[0], "|record/") {
		t.Fatalf("DeleteTXT calls = %v", records.deleted)
	}
}

func TestCrashAfterFinalizeBeforeSaveFetchesExistingCertificate(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{finalizeProcessing: true})
	records := &challengeRecords{}
	certificates := &memoryCertificates{items: make(map[string]IssuedCertificate)}
	certificates.onSave = func() { panic("simulated process crash") }
	worker := newTestWorker(t, protocol, records, records, certificates, nil)
	operations := newMemoryOperations()
	worker.deps.Operations = operations
	now := testNow
	worker.config.Clock = func() time.Time { return now }
	request := validIssueRequest(ChallengeHTTP01, "finalize-crash.example.test")
	executeUntilCrash(t, worker, request)
	certificates.onSave = nil
	now = now.Add(worker.config.LeaseDuration + time.Second)
	if _, err := worker.Issue(context.Background(), request); err != nil {
		t.Fatalf("takeover Issue() error = %v", err)
	}
	if protocol.newOrderAttempts != 1 || certificates.saveCalls != 2 {
		t.Fatalf("orders=%d saves=%d", protocol.newOrderAttempts, certificates.saveCalls)
	}
}

func TestCrashAfterCertificateSaveReplaysIdempotentSave(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{}
	certificates := &memoryCertificates{items: make(map[string]IssuedCertificate)}
	worker := newTestWorker(t, protocol, records, records, certificates, nil)
	operations := newMemoryOperations()
	operations.beforeAdvance = panicOnEvent("certificate_saved")
	worker.deps.Operations = operations
	now := testNow
	worker.config.Clock = func() time.Time { return now }
	request := validIssueRequest(ChallengeHTTP01, "save-crash.example.test")
	executeUntilCrash(t, worker, request)
	operations.beforeAdvance = nil
	now = now.Add(worker.config.LeaseDuration + time.Second)
	if _, err := worker.Issue(context.Background(), request); err != nil {
		t.Fatalf("takeover Issue() error = %v", err)
	}
	if protocol.newOrderAttempts != 1 || certificates.saveCalls != 2 {
		t.Fatalf("orders=%d saves=%d", protocol.newOrderAttempts, certificates.saveCalls)
	}
}

func TestIssueDNS01TracksWildcardAndApexSeparately(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, nil, records, &memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)

	result, err := worker.Issue(context.Background(), validIssueRequest(ChallengeDNS01, "example.test", "*.example.test"))
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if len(result.Authorizations) != 2 || !slices.ContainsFunc(result.Authorizations, func(item AuthorizationProgress) bool {
		return item.Identifier == "example.test" && item.Wildcard
	}) {
		t.Fatalf("authorization progress = %+v", result.Authorizations)
	}
	if len(records.published) != 2 || len(records.waited) != 2 || len(records.deleted) != 2 {
		t.Fatalf("DNS challenge lifecycle publish=%v wait=%v delete=%v", records.published, records.waited, records.deleted)
	}
	for _, call := range records.published {
		if !strings.HasPrefix(call, "_acme-challenge.example.test.|") {
			t.Fatalf("unexpected DNS owner: %s", call)
		}
	}
	publishedValues := make(map[string]struct{}, len(records.published))
	deletedValues := make(map[string]struct{}, len(records.deleted))
	deletedHandles := make(map[string]struct{}, len(records.deleted))
	for _, call := range records.published {
		publishedValues[call[strings.LastIndex(call, "|")+1:]] = struct{}{}
	}
	for _, call := range records.deleted {
		lastSeparator := strings.LastIndex(call, "|")
		deletedValues[call[lastSeparator+1:]] = struct{}{}
		deletedHandles[call[:lastSeparator]] = struct{}{}
	}
	if len(publishedValues) != 2 || len(deletedHandles) != 2 || !mapsEqual(publishedValues, deletedValues) {
		t.Fatalf("exact DNS cleanup mismatch publish=%v delete=%v", records.published, records.deleted)
	}
	for _, identity := range records.identities {
		if identity.TenantID == uuid.Nil || identity.OperationID == "" || identity.AttemptID == uuid.Nil ||
			identity.ProviderRef == "" || identity.AuthorizationURL == "" || identity.ChallengeURL == "" ||
			identity.RecordName == "" || identity.ExactValue == "" {
			t.Fatalf("incomplete challenge identity: %+v", identity)
		}
	}
}

func TestIssueRejectsAuthorizationOutsideFrozenRequestBeforeProvider(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{authzIdentifier: "unrelated.test"})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, records, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)

	_, err := worker.Issue(context.Background(), validIssueRequest(ChallengeHTTP01, "example.test"))
	if ErrorCodeOf(err) != CodeAuthorizationInvalid {
		t.Fatalf("Issue() error = %v", err)
	}
	if len(records.published) != 0 || len(records.waited) != 0 || len(records.deleted) != 0 {
		t.Fatalf("provider calls publish=%v wait=%v delete=%v", records.published, records.waited, records.deleted)
	}
}

func TestIssueInvalidAuthorizationIsStableAndCleansUp(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{invalidAuth: true})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, records, records, &memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)

	result, err := worker.Issue(context.Background(), validIssueRequest(ChallengeHTTP01, "bad.example.test"))
	if ErrorCodeOf(err) != CodeAuthorizationInvalid || len(records.deleted) != 1 ||
		len(result.Authorizations) != 1 || result.Authorizations[0].ErrorCode != CodeAuthorizationInvalid {
		t.Fatalf("result=%+v error=%v deletes=%v", result, err, records.deleted)
	}
}

func TestIssueCancellationStillDeletesPublishedToken(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{pendingAuth: true})
	records := &challengeRecords{}
	ctx, cancel := context.WithCancel(context.Background())
	records.onPublish = cancel
	worker := newTestWorker(t, protocol, records, records, &memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)

	_, err := worker.Issue(ctx, validIssueRequest(ChallengeHTTP01, "cancel.example.test"))
	if !errors.Is(err, context.Canceled) || ErrorCodeOf(err) != CodeCancelled || len(records.deleted) != 1 {
		t.Fatalf("error=%v code=%s deletes=%v", err, ErrorCodeOf(err), records.deleted)
	}
}

func TestIssueCleanupFailureStopsBeforeFinalize(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{deleteError: errors.New("delete denied")}
	worker := newTestWorker(t, protocol, records, records, &memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)

	result, err := worker.Issue(context.Background(), validIssueRequest(ChallengeHTTP01, "cleanup.example.test"))
	if ErrorCodeOf(err) != CodeChallengeCleanupFailed || protocol.finalized ||
		result.Authorizations[0].CleanupErrorCode != CodeChallengeCleanupFailed {
		t.Fatalf("result=%+v error=%v finalized=%t", result, err, protocol.finalized)
	}
}

func TestTerminalAuthorizationCleanupFailureRemainsRecoverable(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{invalidAuth: true})
	records := &challengeRecords{deleteError: errors.New("provider cleanup unavailable")}
	operations := newMemoryOperations()
	worker := newTestWorker(t, protocol, records, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	worker.deps.Operations = operations
	now := testNow
	worker.config.Clock = func() time.Time { return now }
	request := validIssueRequest(ChallengeHTTP01, "terminal-cleanup.example.test")

	result, err := worker.Issue(t.Context(), request)
	if ErrorCodeOf(err) != CodeAuthorizationInvalid || len(result.Authorizations) != 1 ||
		result.Authorizations[0].ErrorCode != CodeAuthorizationInvalid ||
		result.Authorizations[0].CleanupErrorCode != CodeChallengeCleanupFailed {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	assertCleanupRetryOperation(t, operations, request, err, CodeAuthorizationInvalid)

	records.deleteError = nil
	now = now.Add(worker.config.RetryDelay + time.Second)
	_, err = worker.Issue(t.Context(), request)
	if ErrorCodeOf(err) != CodeAuthorizationInvalid {
		t.Fatalf("terminal retry error=%v", err)
	}
	operations.mu.Lock()
	item := operations.items[operationKey(request.ScopeID, request.OperationID)]
	operations.mu.Unlock()
	if item == nil || item.lease.State.Status != OperationFailed ||
		item.lease.State.FailureCode != CodeAuthorizationInvalid {
		t.Fatalf("terminal operation=%+v", item)
	}
}

func TestDNSChallengeFailuresStillAttemptExactCleanup(t *testing.T) {
	for _, test := range []struct {
		name       string
		presentErr error
		waitErr    error
		wantCode   ErrorCode
	}{
		{name: "present may have partially succeeded", presentErr: errors.New("provider timeout"), wantCode: CodeChallengePublishFailed},
		{name: "propagation observation failed", waitErr: errors.New("resolver timeout"), wantCode: CodeChallengePropagationFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newProtocolServer(t, testNow, protocolOptions{})
			records := &challengeRecords{presentError: test.presentErr, waitError: test.waitErr}
			worker := newTestWorker(t, protocol, nil, records,
				&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)

			_, err := worker.Issue(context.Background(), validIssueRequest(ChallengeDNS01, "failure.example.test"))
			if ErrorCodeOf(err) != test.wantCode || len(records.deleted) != 1 || protocol.finalized {
				t.Fatalf("error=%v delete=%v finalized=%t", err, records.deleted, protocol.finalized)
			}
		})
	}
}

func TestDNSUnknownCreateOutcomeRecoversExactHandleBeforeCleanup(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	providerRef := uuid.MustParse("40000000-0000-4000-8000-000000000001").String()
	zeroHandle := RemoteTXTHandle{}
	records := &recoverableChallengeRecords{
		challengeRecords: &challengeRecords{
			presentError:  errors.New("provider response lost"),
			presentHandle: &zeroHandle,
		},
		recoverHandle: RemoteTXTHandle{ProviderRef: providerRef, RecordRef: "record/recovered"},
		recoverFound:  true,
	}
	worker := newTestWorker(t, protocol, nil, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	operations := newMemoryOperations()
	worker.deps.Operations = operations
	request := validIssueRequest(ChallengeDNS01, "unknown-create.example.test")

	_, err := worker.Issue(t.Context(), request)
	if ErrorCodeOf(err) != CodeChallengePublishFailed {
		t.Fatalf("Issue() error = %v", err)
	}
	if len(records.recovered) != 1 || len(records.deleted) != 1 {
		t.Fatalf("recovered=%+v deleted=%v", records.recovered, records.deleted)
	}
	wantDelete := providerRef + "|record/recovered|" + records.recovered[0].ExactValue
	if records.deleted[0] != wantDelete {
		t.Fatalf("DeleteTXT() = %q, want %q", records.deleted[0], wantDelete)
	}
	operations.mu.Lock()
	item := operations.items[operationKey(request.ScopeID, request.OperationID)]
	operations.mu.Unlock()
	if item == nil || item.lease.State.Status != OperationRetryWait {
		t.Fatalf("operation = %+v", item)
	}
}

func TestDNSUnknownCreateOutcomeZeroMatchCleansWithoutDelete(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	zeroHandle := RemoteTXTHandle{}
	records := &recoverableChallengeRecords{
		challengeRecords: &challengeRecords{
			presentError:  errors.New("provider response lost"),
			presentHandle: &zeroHandle,
		},
	}
	worker := newTestWorker(t, protocol, nil, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	operations := newMemoryOperations()
	worker.deps.Operations = operations
	request := validIssueRequest(ChallengeDNS01, "zero-match.example.test")

	_, err := worker.Issue(t.Context(), request)
	if ErrorCodeOf(err) != CodeChallengePublishFailed || len(records.recovered) != 1 || len(records.deleted) != 0 {
		t.Fatalf("error=%v recovered=%+v deleted=%v", err, records.recovered, records.deleted)
	}
	operations.mu.Lock()
	defer operations.mu.Unlock()
	item := operations.items[operationKey(request.ScopeID, request.OperationID)]
	if item == nil || len(item.states) != 1 {
		t.Fatalf("operation=%+v", item)
	}
	for attemptID, state := range item.states {
		if state != "cleaned" || item.challenges[attemptID].TXTHandle != (RemoteTXTHandle{}) {
			t.Fatalf("zero-match challenge=%+v state=%q", item.challenges[attemptID], state)
		}
	}
}

func TestDNSUnknownCreateOutcomeWithoutRecoveryFailsClosed(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	zeroHandle := RemoteTXTHandle{}
	records := &challengeRecords{
		presentError:  errors.New("provider response lost"),
		presentHandle: &zeroHandle,
	}
	worker := newTestWorker(t, protocol, nil, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)

	_, err := worker.Issue(t.Context(), validIssueRequest(ChallengeDNS01, "unknown-create.example.test"))
	if ErrorCodeOf(err) != CodeChallengePublishFailed || len(records.deleted) != 0 {
		t.Fatalf("Issue() error=%v deleted=%v", err, records.deleted)
	}
}

func TestCleanupProviderCallDoesNotHoldOperationStoreLock(t *testing.T) {
	operations := newMemoryOperations()
	request := validIssueRequest(ChallengeHTTP01, "unlocked-cleanup.example.test")
	request.DirectoryURL = "https://ca.example/directory"
	now := testNow
	claim, err := operations.Claim(t.Context(), request, issueRequestDigest(request), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := operations.PrepareChallenge(t.Context(), claim.Lease, ChallengeIdentity{
		ChallengeType: ChallengeHTTP01,
		Identifier:    request.Domains[0],
		RecordName:    request.Domains[0],
		Token:         "cleanup-token",
		ExactValue:    "cleanup-value",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := operations.MarkChallenge(t.Context(), claim.Lease, challenge, "published", now); err != nil {
		t.Fatal(err)
	}

	providerEntered := make(chan struct{})
	releaseProvider := make(chan struct{})
	records := &challengeRecords{}
	provider := &blockingHTTP01CleanupProvider{
		challengeRecords: records,
		entered:          providerEntered,
		release:          releaseProvider,
	}
	worker := &Worker{
		config: Config{Clock: func() time.Time { return now }, CleanupTimeout: time.Second},
		deps:   Dependencies{Operations: operations, HTTP01: provider},
	}
	cleanupDone := make(chan error, 1)
	go func() { cleanupDone <- worker.cleanupChallenge(t.Context(), claim.Lease, challenge) }()
	select {
	case <-providerEntered:
	case cleanupErr := <-cleanupDone:
		t.Fatalf("cleanup returned before entering the provider: %v", cleanupErr)
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup provider was not entered within 2 seconds")
	}

	readDone := make(chan error, 1)
	go func() {
		_, readErr := operations.OutstandingChallenges(t.Context(), claim.Lease, now)
		readDone <- readErr
	}()
	select {
	case readErr := <-readDone:
		if readErr != nil {
			t.Fatal(readErr)
		}
	case <-time.After(100 * time.Millisecond):
		close(releaseProvider)
		<-cleanupDone
		t.Fatal("operation store remained locked during provider cleanup")
	}
	close(releaseProvider)
	if err := <-cleanupDone; err != nil {
		t.Fatal(err)
	}
}

type blockingHTTP01CleanupProvider struct {
	*challengeRecords
	entered chan struct{}
	release chan struct{}
}

func (p *blockingHTTP01CleanupProvider) Delete(ctx context.Context, challenge ChallengeIdentity) error {
	close(p.entered)
	select {
	case <-p.release:
		return p.challengeRecords.Delete(ctx, challenge)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestDNSHandleMustPersistBeforeObserveAndDelete(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	operations := newMemoryOperations()
	persisted := false
	operations.afterMark = func(state string) {
		if state == "published" {
			persisted = true
		}
	}
	records := &challengeRecords{
		onObserve: func(challenge ChallengeIdentity) {
			if !persisted {
				t.Error("ObserveTXT called before the handle was persisted")
			}
			if challenge.TenantID == uuid.Nil || challenge.OperationID == "" || challenge.AttemptID == uuid.Nil ||
				challenge.TXTHandle == (RemoteTXTHandle{}) {
				t.Errorf("ObserveTXT received incomplete identity: %+v", challenge)
			}
		},
		onDeleteTXT: func(challenge ChallengeIdentity) {
			if !persisted {
				t.Error("DeleteTXT called before the handle was persisted")
			}
			if challenge.TenantID == uuid.Nil || challenge.OperationID == "" || challenge.AttemptID == uuid.Nil ||
				challenge.TXTHandle == (RemoteTXTHandle{}) {
				t.Errorf("DeleteTXT received incomplete identity: %+v", challenge)
			}
		},
	}
	worker := newTestWorker(t, protocol, nil, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	worker.deps.Operations = operations

	if _, err := worker.Issue(context.Background(), validIssueRequest(ChallengeDNS01, "persist.example.test")); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if !persisted || len(records.waited) != 1 || len(records.deleted) != 1 {
		t.Fatalf("persisted=%t observed=%v deleted=%v", persisted, records.waited, records.deleted)
	}
}

func TestDNSInvalidOrUnpersistedHandleNeverObservedOrDeleted(t *testing.T) {
	providerRef := uuid.MustParse("40000000-0000-4000-8000-000000000001").String()
	for _, test := range []struct {
		name      string
		handle    RemoteTXTHandle
		markError error
	}{
		{name: "empty handle"},
		{name: "provider mismatch", handle: RemoteTXTHandle{ProviderRef: "other-provider", RecordRef: "record/1"}},
		{name: "control character", handle: RemoteTXTHandle{ProviderRef: providerRef, RecordRef: "record/\n1"}},
		{name: "oversized record reference", handle: RemoteTXTHandle{ProviderRef: providerRef, RecordRef: strings.Repeat("r", 2049)}},
		{name: "persistence failure", handle: RemoteTXTHandle{ProviderRef: providerRef, RecordRef: "record/1"}, markError: failure(CodeOperationStoreFailed, nil)},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newProtocolServer(t, testNow, protocolOptions{})
			handle := test.handle
			records := &challengeRecords{presentHandle: &handle}
			operations := newMemoryOperations()
			operations.markError = test.markError
			worker := newTestWorker(t, protocol, nil, records,
				&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
			worker.deps.Operations = operations

			_, err := worker.Issue(context.Background(), validIssueRequest(ChallengeDNS01, "invalid-handle.example.test"))
			if err == nil || len(records.waited) != 0 || len(records.deleted) != 0 || protocol.finalized {
				t.Fatalf("error=%v observed=%v deleted=%v finalized=%t", err, records.waited, records.deleted, protocol.finalized)
			}
		})
	}
}

func TestDNSCrashTakeoverDeletesPersistedRemoteHandle(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, nil, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	worker.config.MaxConcurrentAuthorizations = 1
	operations := newMemoryOperations()
	operations.afterMark = panicOnEvent("published")
	worker.deps.Operations = operations
	now := testNow
	worker.config.Clock = func() time.Time { return now }
	request := validIssueRequest(ChallengeDNS01, "dns-crash.example.test")

	executeUntilCrash(t, worker, request)
	firstAttempt := records.identities[0]
	firstHandle := RemoteTXTHandle{
		ProviderRef: firstAttempt.ProviderRef,
		RecordRef:   "record/" + firstAttempt.AttemptID.String(),
	}
	operations.afterMark = nil
	now = now.Add(worker.config.LeaseDuration + time.Second)
	if _, err := worker.Issue(context.Background(), request); err != nil {
		t.Fatalf("takeover Issue() error = %v", err)
	}
	wantDelete := firstHandle.ProviderRef + "|" + firstHandle.RecordRef + "|" + firstAttempt.ExactValue
	if len(records.deleted) < 2 || records.deleted[0] != wantDelete {
		t.Fatalf("persisted handle cleanup=%v want first=%s", records.deleted, wantDelete)
	}
}

func TestIssueRequestFreezesOrderAndActorIdentity(t *testing.T) {
	request := validIssueRequest(ChallengeHTTP01, "identity.example.test")
	if _, err := normalizeIssueRequest(&request); err != nil {
		t.Fatalf("valid request error = %v", err)
	}
	baseDigest := issueRequestDigest(request)

	for _, mutate := range []func(*IssueRequest){
		func(item *IssueRequest) { item.CertificateOrderID = uuid.Nil },
		func(item *IssueRequest) { item.ActorUserID = uuid.Nil },
		func(item *IssueRequest) { item.OperationID = uuid.NewString() },
	} {
		invalid := request
		mutate(&invalid)
		if _, err := normalizeIssueRequest(&invalid); ErrorCodeOf(err) != CodeInvalidInput {
			t.Fatalf("normalizeIssueRequest() error = %v for %+v", err, invalid)
		}
	}

	changedActor := request
	changedActor.ActorUserID = uuid.New()
	changedOrder := request
	setRequestOrderID(&changedOrder, "changed-order")
	if issueRequestDigest(changedActor) == baseDigest || issueRequestDigest(changedOrder) == baseDigest {
		t.Fatal("actor/order changes did not alter the frozen request digest")
	}
}

func TestRemoteTXTHandleBoundsMatch060Schema(t *testing.T) {
	providerRef := uuid.MustParse("40000000-0000-4000-8000-000000000001").String()
	if err := validateRemoteTXTHandle(RemoteTXTHandle{
		ProviderRef: providerRef,
		RecordRef:   strings.Repeat("r", 2048),
	}, providerRef); err != nil {
		t.Fatalf("2048-byte record reference rejected: %v", err)
	}
	for _, recordRef := range []string{strings.Repeat("r", 2049), " record/1", "record/1 "} {
		if err := validateRemoteTXTHandle(RemoteTXTHandle{
			ProviderRef: providerRef,
			RecordRef:   recordRef,
		}, providerRef); err == nil {
			t.Fatalf("invalid record reference accepted: %q", recordRef)
		}
	}
}

func TestDNSCreateResponseLossLeavesReconciliationIdentityWithoutBlindDelete(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	empty := RemoteTXTHandle{}
	records := &challengeRecords{presentHandle: &empty, presentError: errors.New("create response lost")}
	worker := newTestWorker(t, protocol, nil, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)

	_, err := worker.Issue(context.Background(), validIssueRequest(ChallengeDNS01, "orphan.example.test"))
	if ErrorCodeOf(err) != CodeChallengePublishFailed || len(records.deleted) != 0 || len(records.identities) != 1 {
		t.Fatalf("error=%v deleted=%v identities=%+v", err, records.deleted, records.identities)
	}
	identity := records.identities[0]
	if identity.TenantID == uuid.Nil || identity.OperationID == "" || identity.AttemptID == uuid.Nil ||
		identity.ProviderRef == "" || identity.RecordName == "" || identity.ExactValue == "" {
		t.Fatalf("orphan reconciliation identity is incomplete: %+v", identity)
	}
}

func TestIssueRequestRejectsContactsOutside048AccountFactContract(t *testing.T) {
	for _, contacts := range [][]string{
		{"mailto:ops@example.test", "mailto:ops@example.test"},
		{"mailto:ops@example.test "},
		{"mailto:ops @example.test"},
		{"mailto:ops\t@example.test"},
		{"mailto:ops\x00@example.test"},
		{"mailto:missing-at.example.test"},
	} {
		request := validIssueRequest(ChallengeHTTP01, "contact.example.test")
		request.Contacts = contacts
		if _, err := normalizeIssueRequest(&request); ErrorCodeOf(err) != CodeInvalidInput {
			t.Fatalf("contacts accepted: %q error=%v", contacts, err)
		}
	}
}

func TestIssuePersistent429ReturnsRetryableStableCode(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{rateLimitCount: 10})
	worker := newTestWorker(t, protocol, &challengeRecords{}, &challengeRecords{},
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, func(config *Config) { config.MaxRetries = 1 })

	_, err := worker.Issue(context.Background(), validIssueRequest(ChallengeHTTP01, "limited.example.test"))
	var workerError *Error
	if !errors.As(err, &workerError) || workerError.Code != CodeRateLimited || !workerError.Temporary || protocol.newOrderAttempts != 2 {
		t.Fatalf("error=%+v attempts=%d", err, protocol.newOrderAttempts)
	}
}

func TestRetryAfterIsParsedAndCapped(t *testing.T) {
	config := DefaultConfig("https://acme.example.test/directory")
	config.Clock = func() time.Time { return testNow }
	config.MaxRetryAfter = 5 * time.Second
	worker := &Worker{config: config}
	response := &http.Response{Header: make(http.Header)}

	response.Header.Set("Retry-After", "120")
	if delay := worker.retryBackoff(1, nil, response); delay != 5*time.Second {
		t.Fatalf("seconds Retry-After delay = %s", delay)
	}
	response.Header.Set("Retry-After", testNow.Add(3*time.Second).Format(http.TimeFormat))
	if delay := worker.retryBackoff(1, nil, response); delay != 3*time.Second {
		t.Fatalf("date Retry-After delay = %s", delay)
	}
	if delay := worker.retryBackoff(config.MaxRetries+1, nil, response); delay >= 0 {
		t.Fatalf("exhausted retry delay = %s", delay)
	}
}

func TestIssueErrorsDoNotRenderSignerSecrets(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	secret := "account-private-material-should-not-leak"
	worker := newTestWorker(t, protocol, &challengeRecords{}, &challengeRecords{},
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	worker.deps.Signers = &memorySigners{err: errors.New(secret)}

	_, err := worker.Issue(context.Background(), validIssueRequest(ChallengeHTTP01, "secret.example.test"))
	if ErrorCodeOf(err) != CodeKeyUnavailable || strings.Contains(fmt.Sprintf("%+v", err), secret) ||
		strings.Contains(fmt.Sprintf("%#v", err), secret) {
		t.Fatalf("rendered error leaked secret: %+v", err)
	}
}

func TestProviderErrorsDoNotRenderOrPersistSecrets(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	secret := "dns-api-secret-value"
	records := &challengeRecords{presentError: errors.New(secret)}
	operations := newMemoryOperations()
	worker := newTestWorker(t, protocol, nil, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	worker.deps.Operations = operations
	request := validIssueRequest(ChallengeDNS01, "secret-provider.example.test")
	_, err := worker.Issue(context.Background(), request)
	if ErrorCodeOf(err) != CodeChallengePublishFailed || strings.Contains(fmt.Sprintf("%+v", err), secret) {
		t.Fatalf("rendered provider error = %+v", err)
	}
	operations.mu.Lock()
	defer operations.mu.Unlock()
	encoded := fmt.Sprintf("%+v", operations.items)
	if strings.Contains(encoded, secret) {
		t.Fatalf("operation facts leaked provider secret")
	}
}

func TestHTTP01NodeAggregateCapabilityFailureIsStableAndNotRetryable(t *testing.T) {
	cause := &Error{Code: CodeHTTP01NodeAggregateRequired}
	for _, phaseCode := range []ErrorCode{CodeChallengePublishFailed, CodeChallengeCleanupFailed} {
		err := phaseFailure(phaseCode, cause)
		if ErrorCodeOf(err) != CodeHTTP01NodeAggregateRequired ||
			err.Error() != string(CodeHTTP01NodeAggregateRequired) || retryableFailure(err) {
			t.Fatalf("phase %s capability error = %+v retryable=%t", phaseCode, err, retryableFailure(err))
		}
	}
}

type nodeAggregateBlockedHTTP01Provider struct {
	publishCalls int
	deleteCalls  int
}

func (p *nodeAggregateBlockedHTTP01Provider) Publish(context.Context, ChallengeIdentity) error {
	p.publishCalls++
	return &Error{Code: CodeHTTP01NodeAggregateRequired}
}

func (p *nodeAggregateBlockedHTTP01Provider) Delete(context.Context, ChallengeIdentity) error {
	p.deleteCalls++
	return &Error{Code: CodeHTTP01NodeAggregateRequired}
}

func TestHTTP01NodeAggregateCleanupRemainsRecoverable(t *testing.T) {
	t.Run("new publish", func(t *testing.T) {
		protocol := newProtocolServer(t, testNow, protocolOptions{})
		provider := &nodeAggregateBlockedHTTP01Provider{}
		operations := newMemoryOperations()
		worker := newTestWorker(t, protocol, provider, nil,
			&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
		worker.deps.Operations = operations
		now := testNow
		worker.config.Clock = func() time.Time { return now }
		request := validIssueRequest(ChallengeHTTP01, "blocked.example.test")

		_, err := worker.Issue(t.Context(), request)
		assertCleanupRetryOperation(t, operations, request, err, CodeHTTP01NodeAggregateRequired)
		if provider.publishCalls != 1 || provider.deleteCalls != 1 {
			t.Fatalf("provider calls publish=%d delete=%d", provider.publishCalls, provider.deleteCalls)
		}
		now = now.Add(worker.config.RetryDelay + time.Second)
		_, replayErr := worker.Issue(t.Context(), request)
		if ErrorCodeOf(replayErr) != CodeHTTP01NodeAggregateRequired ||
			provider.publishCalls != 1 || provider.deleteCalls != 2 {
			t.Fatalf("terminal replay error=%v publish=%d delete=%d", replayErr, provider.publishCalls, provider.deleteCalls)
		}
		assertCleanupRetryOperation(t, operations, request, replayErr, CodeHTTP01NodeAggregateRequired)
	})

	t.Run("outstanding cleanup", func(t *testing.T) {
		protocol := newProtocolServer(t, testNow, protocolOptions{})
		provider := &nodeAggregateBlockedHTTP01Provider{}
		operations := newMemoryOperations()
		worker := newTestWorker(t, protocol, provider, nil,
			&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
		worker.deps.Operations = operations
		now := testNow
		worker.config.Clock = func() time.Time { return now }
		request := validIssueRequest(ChallengeHTTP01, "recovery-blocked.example.test")
		request.DirectoryURL = worker.config.DirectoryURL
		digest := issueRequestDigest(request)
		claim, err := operations.Claim(t.Context(), request, digest, now, now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		attemptID := uuid.New()
		identity := ChallengeIdentity{
			TenantID: request.TenantID, ScopeID: request.ScopeID, OperationID: request.OperationID, AttemptID: attemptID,
			ChallengeType: ChallengeHTTP01, Identifier: request.Domains[0], RecordName: request.Domains[0],
			Token: "blocked-token", ExactValue: "blocked-token.blocked-value",
		}
		operations.mu.Lock()
		item := operations.items[operationKey(request.ScopeID, request.OperationID)]
		item.challenges[attemptID] = identity
		item.states[attemptID] = "published"
		item.lease.ExpiresAt = now.Add(-time.Second)
		operations.mu.Unlock()

		_, err = worker.Issue(t.Context(), request)
		assertCleanupRetryOperation(t, operations, request, err, CodeHTTP01NodeAggregateRequired)
		if provider.publishCalls != 0 || provider.deleteCalls != 1 {
			t.Fatalf("recovery provider calls publish=%d delete=%d", provider.publishCalls, provider.deleteCalls)
		}
		operations.mu.Lock()
		state := operations.items[operationKey(request.ScopeID, request.OperationID)].states[attemptID]
		operations.mu.Unlock()
		if state != "cleanup_claimed" {
			t.Fatalf("blocked cleanup changed challenge state to %q", state)
		}
		if claim.Lease.Token == uuid.Nil {
			t.Fatal("seed claim was invalid")
		}
		now = now.Add(worker.config.RetryDelay + time.Second)
		_, replayErr := worker.Issue(t.Context(), request)
		if ErrorCodeOf(replayErr) != CodeHTTP01NodeAggregateRequired || provider.deleteCalls != 2 {
			t.Fatalf("recovery terminal replay error=%v delete=%d", replayErr, provider.deleteCalls)
		}
		assertCleanupRetryOperation(t, operations, request, replayErr, CodeHTTP01NodeAggregateRequired)
	})
}

func assertCleanupRetryOperation(
	t *testing.T,
	operations *memoryOperations,
	request IssueRequest,
	err error,
	wantResultCode ErrorCode,
) {
	t.Helper()
	if ErrorCodeOf(err) != wantResultCode {
		t.Fatalf("operation error=%v want=%s", err, wantResultCode)
	}
	operations.mu.Lock()
	defer operations.mu.Unlock()
	item := operations.items[operationKey(request.ScopeID, request.OperationID)]
	if item == nil || item.lease.State.Status != OperationRetryWait ||
		item.lease.State.FailureCode != CodeChallengeCleanupFailed ||
		item.lease.Token != uuid.Nil || item.nextReconcile.IsZero() {
		t.Fatalf("cleanup retry operation = %+v", item)
	}
}

func TestIssueRejectsWildcardHTTPBeforeNetwork(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	worker := newTestWorker(t, protocol, &challengeRecords{}, &challengeRecords{},
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)

	_, err := worker.Issue(context.Background(), validIssueRequest(ChallengeHTTP01, "*.example.test"))
	if ErrorCodeOf(err) != CodeInvalidInput || protocol.newOrderAttempts != 0 {
		t.Fatalf("error=%v attempts=%d", err, protocol.newOrderAttempts)
	}
}

func newTestWorker(
	t *testing.T,
	protocol *protocolServer,
	httpProvider HTTP01Provider,
	dnsProvider DNS01Provider,
	certificates CertificateStore,
	mutate func(*Config),
) *Worker {
	t.Helper()
	config := DefaultConfig(protocol.url("/directory"))
	config.HTTPClient = protocol.server.Client()
	config.Clock = func() time.Time { return testNow }
	config.OrderTimeout = 2 * time.Second
	config.RequestTimeout = time.Second
	config.ChallengeTimeout = time.Second
	config.PropagationTimeout = time.Second
	config.CleanupTimeout = time.Second
	config.RetryBase = time.Millisecond
	config.MaxRetryAfter = 5 * time.Millisecond
	if mutate != nil {
		mutate(&config)
	}
	accountKey := mustKey(t)
	certificateKey := mustKey(t)
	worker, err := New(config, Dependencies{
		Signers: &memorySigners{keys: map[string]crypto.Signer{
			"account-key": accountKey, "certificate-key": certificateKey,
		}},
		Accounts:     &memoryAccounts{},
		HTTP01:       httpProvider,
		DNS01:        dnsProvider,
		Certificates: certificates,
		Operations:   newMemoryOperations(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func validIssueRequest(challengeType ChallengeType, domains ...string) IssueRequest {
	orderID := uuid.MustParse("20000000-0000-4000-8000-000000000001")
	scopeID := uuid.MustParse("10000000-0000-4000-8000-000000000002")
	providerID := uuid.Nil
	zoneID := uuid.Nil
	providerRef := ""
	if challengeType == ChallengeDNS01 {
		providerID = uuid.MustParse("40000000-0000-4000-8000-000000000001")
		zoneID = uuid.MustParse("50000000-0000-4000-8000-000000000001")
		providerRef = providerID.String()
	}
	return IssueRequest{
		TenantID:           uuid.MustParse("10000000-0000-4000-8000-000000000001"),
		ScopeID:            scopeID,
		OperationID:        orderID.String(),
		CertificateOrderID: orderID,
		ActorUserID:        uuid.MustParse("30000000-0000-4000-8000-000000000001"),
		ProviderID:         providerID,
		ZoneID:             zoneID,
		ProviderRef:        providerRef,
		AccountKeyRef:      "account-key",
		CertificateKeyRef:  "certificate-key",
		Contacts:           []string{"mailto:ops@example.test"},
		AcceptTerms:        true,
		Domains:            domains,
		ChallengeType:      challengeType,
	}
}

func setRequestOrderID(request *IssueRequest, label string) {
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(label))
	request.OperationID = id.String()
	request.CertificateOrderID = id
}

func panicOnEvent(want string) func(string) {
	return func(event string) {
		if event == want {
			panic("simulated process crash")
		}
	}
}

func mapsEqual(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if _, found := right[key]; !found {
			return false
		}
	}
	return true
}

func executeUntilCrash(t *testing.T, worker *Worker, request IssueRequest) {
	t.Helper()
	domains, err := normalizeIssueRequest(&request)
	if err != nil {
		t.Fatal(err)
	}
	request.Domains = domains
	request.DirectoryURL = worker.config.DirectoryURL
	now := worker.config.Clock().UTC()
	claim, err := worker.deps.Operations.Claim(context.Background(), request, issueRequestDigest(request),
		now, now.Add(worker.config.LeaseDuration))
	if err != nil || claim.State != OperationClaimed {
		t.Fatalf("Claim() = %+v, %v", claim, err)
	}
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		if _, err := worker.execute(context.Background(), &claim.Lease, issueRequestDigest(request)); err != nil {
			t.Fatalf("execute returned before crash: %v", err)
		}
	}()
	if !panicked {
		t.Fatal("execute did not reach simulated process crash")
	}
}

type codedPresentError struct{}

func (codedPresentError) Error() string { return "dns_provider_remote_invalid_response" }

// fix-acmedns: a failed PresentTXT with no handle reports the provider's own
// error, not "invalid remote TXT handle" (cause_type=*errors.errorString), and
// a failing cleanup keeps its cause.
// fix-certstuck（73 订单 01a178e0）：CA 把这笔订单的 pending ACME order 复用给了
// 同域名的另一笔申请并由它完成签发，恢复时拿到的证书公钥不是本单的密钥。这是终态：
// 错误要标 Terminal（调度据此立即把订单转 failed），日志 detail 要有真实原因。
func TestForeignKeyCertificateIsTerminalWithReadableCause(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{foreignLeafKey: true})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, records, records, &memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	request := validIssueRequest(ChallengeHTTP01, "reused.example.test")

	_, err := worker.Issue(t.Context(), request)
	if ErrorCodeOf(err) != CodeCertificateInvalid || !IsTerminal(err) {
		t.Fatalf("Issue() error = %v code=%s terminal=%t", err, ErrorCodeOf(err), IsTerminal(err))
	}
	if detail := FailureDetail(err); detail != "cause=certificate_public_key_mismatch" {
		t.Fatalf("FailureDetail() = %q", detail)
	}
	// 再次领取同一操作：worker 已落终态，重试也必须明确是终态。
	_, err = worker.Issue(t.Context(), request)
	if ErrorCodeOf(err) != CodeCertificateInvalid || !IsTerminal(err) {
		t.Fatalf("replayed Issue() error = %v terminal=%t", err, IsTerminal(err))
	}
}

// 可重试失败（如清理失败）不得标终态。
func TestRetryableFailureIsNotTerminal(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{deleteError: errors.New("delete failed")}
	worker := newTestWorker(t, protocol, records, records, &memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)

	_, err := worker.Issue(t.Context(), validIssueRequest(ChallengeHTTP01, "retry.example.test"))
	if err == nil || IsTerminal(err) {
		t.Fatalf("Issue() error = %v terminal=%t", err, IsTerminal(err))
	}
}

func TestDNSPublishFailureKeepsProviderCause(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	zeroHandle := RemoteTXTHandle{}
	records := &recoverableChallengeRecords{
		challengeRecords: &challengeRecords{presentError: codedPresentError{}, presentHandle: &zeroHandle},
		recoverError:     errors.New("dns_provider_remote_source_unavailable"),
	}
	worker := newTestWorker(t, protocol, nil, records,
		&memoryCertificates{items: make(map[string]IssuedCertificate)}, nil)
	worker.deps.Operations = newMemoryOperations()

	_, err := worker.Issue(t.Context(), validIssueRequest(ChallengeDNS01, "publish-cause.example.test"))
	if ErrorCodeOf(err) != CodeChallengePublishFailed {
		t.Fatalf("Issue() error = %v", err)
	}
	if detail := FailureDetail(err); detail != "cause=dns_provider_remote_invalid_response" {
		t.Fatalf("FailureDetail() = %q", detail)
	}
	// Issue joins the publish error with the outstanding-cleanup error.
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok || len(joined.Unwrap()) != 2 {
		t.Fatalf("Issue() error = %#v, want publish and cleanup errors", err)
	}
	cleanupErr := joined.Unwrap()[1]
	if ErrorCodeOf(cleanupErr) != CodeChallengeCleanupFailed ||
		FailureDetail(cleanupErr) != "cause=dns_provider_remote_source_unavailable" {
		t.Fatalf("cleanup error = %v detail = %q", cleanupErr, FailureDetail(cleanupErr))
	}
}
