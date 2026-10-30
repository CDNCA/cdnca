package dnsproviderremote

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

type fakeReconcileAuthority struct {
	revision           int64
	providerType       string
	credentials        map[string]string
	claimState         MutationClaimState
	claimStateExplicit bool
	providerRecordID   string
	finalRevision      int64
	recoveryReady      bool
	finalizeErr        error
	finalized          int
	uncertainErr       error
	uncertain          int
	uncertainCtx       error
}

func (authority *fakeReconcileAuthority) CurrentRevision(context.Context, dnscheck.ProviderRevisionRequest) (int64, error) {
	return authority.revision, nil
}

func (authority *fakeReconcileAuthority) LoadRevision(context.Context, dnscheck.ProviderMutation) (RevisionSnapshot, error) {
	credentials := make(map[string]string, len(authority.credentials))
	for name, value := range authority.credentials {
		credentials[name] = value
	}
	return RevisionSnapshot{
		Revision: authority.revision,
		Config:   ProviderConfig{ProviderType: authority.providerType, Credentials: credentials},
	}, nil
}

func (authority *fakeReconcileAuthority) AcquireMutationClaim(ctx context.Context,
	mutation dnscheck.ProviderMutation) (MutationClaim, error) {
	snapshot, err := authority.LoadRevision(ctx, mutation)
	state := authority.claimState
	if state == "" && !authority.claimStateExplicit {
		state = MutationClaimed
	}
	return MutationClaim{
		RevisionSnapshot: snapshot, ClaimID: uuid.New(), State: state, RecoveryReady: authority.recoveryReady,
		ProviderRequestID: deterministicProviderRequestID(mutation.ClientRequestID),
		ProviderRecordID:  authority.providerRecordID, FinalRevision: authority.finalRevision,
	}, err
}

func (authority *fakeReconcileAuthority) ValidateMutationClaim(ctx context.Context,
	mutation dnscheck.ProviderMutation, claim MutationClaim) error {
	current, err := authority.LoadRevision(ctx, mutation)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, claim.RevisionSnapshot) {
		return dnscheck.ErrProviderRevisionConflict
	}
	return nil
}

func (authority *fakeReconcileAuthority) MarkMutationUncertain(ctx context.Context, _ dnscheck.ProviderMutation,
	_ MutationClaim, _ string) error {
	authority.uncertain++
	authority.uncertainCtx = ctx.Err()
	return authority.uncertainErr
}

func (authority *fakeReconcileAuthority) FinalizeMutationClaim(_ context.Context,
	mutation dnscheck.ProviderMutation, claim MutationClaim, outcome MutationClaimState, _, _ string) (int64, error) {
	advance := outcome == MutationSucceeded && authority.revision == mutation.ExpectedRevision
	return authority.FinalizeRevision(context.Background(), mutation, claim.RevisionSnapshot, advance)
}

func (authority *fakeReconcileAuthority) FinalizeRevision(_ context.Context, mutation dnscheck.ProviderMutation,
	snapshot RevisionSnapshot, advance bool) (int64, error) {
	authority.finalized++
	if authority.finalizeErr != nil {
		return 0, authority.finalizeErr
	}
	if snapshot.Revision != authority.revision {
		return 0, dnscheck.ErrProviderRevisionConflict
	}
	if advance {
		if authority.revision != mutation.ExpectedRevision {
			return 0, dnscheck.ErrProviderRevisionConflict
		}
		authority.revision++
	}
	if authority.revision != mutation.ExpectedRevision+1 {
		return 0, dnscheck.ErrProviderRevisionConflict
	}
	return authority.revision, nil
}

type fakeReconcileRemote struct {
	lookup         []ReconcileLookup
	mutate         int
	lookupStarted  chan struct{}
	releaseLookup  chan struct{}
	credentialRefs []map[string]string
	lookupErr      error
	mutateErr      error
	cancelMutation context.CancelFunc
}

func (remote *fakeReconcileRemote) Lookup(ctx context.Context, config ProviderConfig, _ dnscheck.ProviderOperation) (ReconcileLookup, error) {
	remote.credentialRefs = append(remote.credentialRefs, config.Credentials)
	if remote.lookupStarted != nil {
		select {
		case remote.lookupStarted <- struct{}{}:
		default:
		}
	}
	if remote.releaseLookup != nil {
		select {
		case <-remote.releaseLookup:
		case <-ctx.Done():
			return ReconcileLookup{}, ctx.Err()
		}
	}
	if remote.lookupErr != nil {
		return ReconcileLookup{}, remote.lookupErr
	}
	if len(remote.lookup) == 0 {
		return ReconcileLookup{}, errors.New("unexpected lookup")
	}
	result := remote.lookup[0]
	remote.lookup = remote.lookup[1:]
	return result, nil
}

func (remote *fakeReconcileRemote) Mutate(context.Context, ProviderConfig, dnscheck.ProviderOperation) (string, error) {
	remote.mutate++
	if remote.cancelMutation != nil {
		remote.cancelMutation()
	}
	return "record-1", remote.mutateErr
}

func (remote *fakeReconcileRemote) credentialsCleared() bool {
	for _, credentials := range remote.credentialRefs {
		if len(credentials) != 0 {
			return false
		}
	}
	return true
}

type malformedAppliedAuthority struct {
	revision          int64
	state             MutationClaimState
	claimID           uuid.UUID
	providerRequestID string
	providerRecordID  string
	finalRevision     int64
	recoveryReady     bool
	recoveryNotBefore time.Time
	config            ProviderConfig
}

func (authority *malformedAppliedAuthority) CurrentRevision(context.Context,
	dnscheck.ProviderRevisionRequest) (int64, error) {
	return authority.revision, nil
}

func (authority *malformedAppliedAuthority) AcquireMutationClaim(_ context.Context,
	mutation dnscheck.ProviderMutation) (MutationClaim, error) {
	if authority.claimID == uuid.Nil {
		authority.claimID = uuid.New()
		authority.state = MutationClaimed
		authority.providerRequestID = deterministicProviderRequestID(mutation.ClientRequestID)
	}
	config := authority.config
	if config.ProviderType == "" {
		config = ProviderConfig{
			ProviderType: providerCloudflare,
			Credentials:  map[string]string{"api_token": "malformed-applied-token"},
		}
	} else {
		config.Credentials = make(map[string]string, len(authority.config.Credentials))
		for key, value := range authority.config.Credentials {
			config.Credentials[key] = value
		}
	}
	claim := MutationClaim{
		RevisionSnapshot: RevisionSnapshot{
			Revision: authority.revision,
			Config:   config,
		},
		ClaimID: authority.claimID, State: authority.state,
		ProviderRequestID: authority.providerRequestID, ProviderRecordID: authority.providerRecordID,
		FinalRevision: authority.finalRevision,
	}
	if authority.state == MutationUncertain {
		value := reflect.ValueOf(&claim).Elem()
		notBefore := value.FieldByName("RecoveryNotBefore")
		ready := value.FieldByName("RecoveryReady")
		if !notBefore.IsValid() || !ready.IsValid() || !notBefore.CanSet() || !ready.CanSet() {
			return MutationClaim{}, errors.New("mutation claim recovery window contract is missing")
		}
		notBefore.Set(reflect.ValueOf(authority.recoveryNotBefore))
		ready.SetBool(authority.recoveryReady)
	}
	return claim, nil
}

func (*malformedAppliedAuthority) ValidateMutationClaim(context.Context, dnscheck.ProviderMutation,
	MutationClaim) error {
	return nil
}

func (authority *malformedAppliedAuthority) MarkMutationUncertain(_ context.Context,
	_ dnscheck.ProviderMutation, claim MutationClaim, providerRequestID string) error {
	if claim.ClaimID != authority.claimID || providerRequestID != authority.providerRequestID {
		return dnscheck.ErrProviderRevisionConflict
	}
	authority.state = MutationUncertain
	return nil
}

func (authority *malformedAppliedAuthority) FinalizeMutationClaim(_ context.Context,
	mutation dnscheck.ProviderMutation, claim MutationClaim, outcome MutationClaimState,
	providerRequestID, providerRecordID string) (int64, error) {
	if claim.ClaimID != authority.claimID || providerRequestID != authority.providerRequestID {
		return 0, dnscheck.ErrProviderRevisionConflict
	}
	authority.state = outcome
	authority.providerRecordID = providerRecordID
	authority.finalRevision = mutation.ExpectedRevision
	if outcome == MutationSucceeded {
		authority.revision = mutation.ExpectedRevision + 1
		authority.finalRevision = authority.revision
	}
	return authority.finalRevision, nil
}

type malformedAppliedRemote struct {
	lookups   []ReconcileLookup
	mutations int
	malformed bool
}

func (remote *malformedAppliedRemote) Lookup(context.Context, ProviderConfig,
	dnscheck.ProviderOperation) (ReconcileLookup, error) {
	if len(remote.lookups) == 0 {
		return ReconcileLookup{}, errors.New("unexpected lookup")
	}
	result := remote.lookups[0]
	remote.lookups = remote.lookups[1:]
	return result, nil
}

func (remote *malformedAppliedRemote) Mutate(context.Context, ProviderConfig,
	dnscheck.ProviderOperation) (string, error) {
	remote.mutations++
	if remote.malformed && remote.mutations == 1 {
		return "", malformedProviderResponse()
	}
	return "record-1", nil
}

func TestReconcileAdapterMalformedAppliedResponseStaysUncertainUntilDelayedLookup(t *testing.T) {
	for _, action := range []dnscheck.ProviderAction{
		dnscheck.ProviderCreate, dnscheck.ProviderUpdate, dnscheck.ProviderDelete,
	} {
		t.Run(string(action), func(t *testing.T) {
			operation := dnscheck.ProviderOperation{
				Action: action, RecordID: "record-1", Name: "www.example.com.", Type: dnscheck.RecordA,
				Value: "192.0.2.10", TTL: 300, PreviousValue: "192.0.2.9", PreviousTTL: 300,
			}
			if action == dnscheck.ProviderCreate {
				operation.RecordID, operation.PreviousValue, operation.PreviousTTL = "", "", 0
			}
			authority := &malformedAppliedAuthority{
				revision: 7, recoveryNotBefore: time.Now().Add(MutationVisibilityWindow),
			}
			remote := &malformedAppliedRemote{malformed: true, lookups: []ReconcileLookup{
				{}, {}, {TargetComplete: true, RecordID: "record-1"},
			}}
			adapter, err := NewReconcileAdapter(authority, remote)
			if err != nil {
				t.Fatal(err)
			}
			mutation := dnscheck.ProviderMutation{
				ClientRequestID: "malformed-applied-" + string(action), TenantID: uuid.New(),
				SiteID: uuid.New(), ZoneID: uuid.New(), ExpectedRevision: 7, Operation: operation,
			}
			_, firstErr := adapter.Mutate(t.Context(), mutation)
			var providerErr *dnscheck.ProviderError
			if !errors.As(firstErr, &providerErr) || providerErr.Class != dnscheck.ProviderErrorTransient ||
				providerErr.Code != "provider_recovery_pending" || authority.state != MutationUncertain {
				t.Fatalf("first mutation error=%v state=%s", firstErr, authority.state)
			}
			if _, err := adapter.Mutate(t.Context(), mutation); err == nil || remote.mutations != 1 || len(remote.lookups) != 1 {
				t.Fatalf("early recovery error=%v mutations=%d remaining lookups=%d", err, remote.mutations, len(remote.lookups))
			}
			authority.recoveryReady = true
			result, err := adapter.Mutate(t.Context(), mutation)
			if err != nil || result.Revision != 8 || result.RecordID != "record-1" ||
				authority.state != MutationSucceeded || remote.mutations != 1 {
				t.Fatalf("recovery=(%+v,%v) state=%s mutations=%d", result, err, authority.state, remote.mutations)
			}
		})
	}
}

func TestReconcileAdapterPersistsUnknownOutcomeWithFreshBoundedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	authority := &fakeReconcileAuthority{revision: 7, providerType: providerCloudflare}
	remote := &fakeReconcileRemote{
		lookup: []ReconcileLookup{{}, {}}, cancelMutation: cancel,
		mutateErr: &Error{Code: CodeInvalidResponse},
	}
	adapter, err := NewReconcileAdapter(authority, remote)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Mutate(ctx, testAdapterMutation("fresh-persistence-context"))
	if err == nil || authority.uncertain != 1 || authority.uncertainCtx != nil {
		t.Fatalf("Mutate() error=%v uncertain=%d persistence context error=%v",
			err, authority.uncertain, authority.uncertainCtx)
	}
}

func TestReconcileAdapterReturnsUncertainPersistenceFailure(t *testing.T) {
	want := errors.New("persist uncertain failed")
	authority := &fakeReconcileAuthority{
		revision: 7, providerType: providerCloudflare, uncertainErr: want,
	}
	remote := &postMutationLookupFailureRemote{}
	adapter, err := NewReconcileAdapter(authority, remote)
	if err != nil {
		t.Fatal(err)
	}
	mutation := testAdapterMutation("uncertain-persistence-error")
	_, err = adapter.Mutate(t.Context(), mutation)
	var providerErr *dnscheck.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Class != dnscheck.ProviderErrorTransient ||
		providerErr.Code != "provider_recovery_persistence_failed" ||
		providerErr.ProviderRequestID != deterministicProviderRequestID(mutation.ClientRequestID) ||
		authority.uncertain != 1 || remote.mutations != 1 {
		t.Fatalf("Mutate() error=%v uncertain=%d mutations=%d", err, authority.uncertain, remote.mutations)
	}
}

func TestReconcileAdapterPostMutationMismatchFinalizesNotAppliedWithoutReplay(t *testing.T) {
	authority := &malformedAppliedAuthority{revision: 7}
	remote := &malformedAppliedRemote{lookups: []ReconcileLookup{{}, {}, {}, {}, {}}}
	adapter, err := NewReconcileAdapter(authority, remote)
	if err != nil {
		t.Fatal(err)
	}
	mutation := testAdapterMutation("post-mutation-mismatch")
	_, err = adapter.Mutate(t.Context(), mutation)
	var providerErr *dnscheck.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Class != dnscheck.ProviderErrorTransient ||
		providerErr.Code != "provider_recovery_pending" ||
		providerErr.ProviderRequestID != deterministicProviderRequestID(mutation.ClientRequestID) ||
		authority.state != MutationUncertain || remote.mutations != 1 {
		t.Fatalf("first recovery=(%v) state=%s mutations=%d", err, authority.state, remote.mutations)
	}
	authority.recoveryReady = true
	_, err = adapter.Mutate(t.Context(), mutation)
	if !errors.As(err, &providerErr) || providerErr.Class != dnscheck.ProviderErrorTransient ||
		providerErr.Code != "provider_recovery_pending" || authority.state != MutationNotApplied ||
		remote.mutations != 1 || len(remote.lookups) != 0 {
		t.Fatalf("delayed recovery=(%v) state=%s mutations=%d lookups=%d",
			err, authority.state, remote.mutations, len(remote.lookups))
	}
}

type postMutationLookupFailureRemote struct {
	lookups   int
	mutations int
}

func (remote *postMutationLookupFailureRemote) Lookup(context.Context, ProviderConfig,
	dnscheck.ProviderOperation) (ReconcileLookup, error) {
	remote.lookups++
	if remote.lookups == 3 {
		return ReconcileLookup{}, &Error{Code: CodeInvalidResponse}
	}
	return ReconcileLookup{}, nil
}

func (remote *postMutationLookupFailureRemote) Mutate(context.Context, ProviderConfig,
	dnscheck.ProviderOperation) (string, error) {
	remote.mutations++
	return "record-1", nil
}

func testAdapterMutation(clientRequestID string) dnscheck.ProviderMutation {
	return dnscheck.ProviderMutation{
		ClientRequestID: clientRequestID, TenantID: uuid.New(), SiteID: uuid.New(), ZoneID: uuid.New(),
		ExpectedRevision: 7,
		Operation: dnscheck.ProviderOperation{
			Action: dnscheck.ProviderCreate, Name: "www.example.com.", Type: dnscheck.RecordA,
			Value: "192.0.2.10", TTL: 300,
		},
	}
}

func TestReconcileAdapterClaimStateGate(t *testing.T) {
	assertNoWork := func(t *testing.T, authority *fakeReconcileAuthority, remote *fakeReconcileRemote) {
		t.Helper()
		if len(remote.credentialRefs) != 0 || remote.mutate != 0 || authority.finalized != 0 || authority.uncertain != 0 {
			t.Fatalf("lookups=%d mutations=%d finalized=%d uncertain=%d",
				len(remote.credentialRefs), remote.mutate, authority.finalized, authority.uncertain)
		}
	}

	for _, test := range []struct {
		name  string
		state MutationClaimState
	}{
		{name: "empty"},
		{name: "not applied", state: MutationNotApplied},
		{name: "unknown future", state: MutationClaimState("future_state")},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := &fakeReconcileAuthority{
				revision: 7, providerType: providerCloudflare,
				claimState: test.state, claimStateExplicit: true,
			}
			remote := &fakeReconcileRemote{}
			adapter, err := NewReconcileAdapter(authority, remote)
			if err != nil {
				t.Fatal(err)
			}
			result, err := adapter.Mutate(t.Context(), testAdapterMutation("invalid-claim-state-"+test.name))
			if !errors.Is(err, dnscheck.ErrProviderRevisionConflict) ||
				!reflect.DeepEqual(result, dnscheck.ProviderMutationResult{}) {
				t.Fatalf("Mutate() = (%+v, %v)", result, err)
			}
			assertNoWork(t, authority, remote)
		})
	}

	t.Run("claimed enters normal mutation", func(t *testing.T) {
		authority := &fakeReconcileAuthority{
			revision: 7, providerType: providerCloudflare,
			claimState: MutationClaimed, claimStateExplicit: true,
		}
		remote := &fakeReconcileRemote{lookup: []ReconcileLookup{
			{}, {}, {TargetComplete: true, RecordID: "record-1"},
		}}
		adapter, _ := NewReconcileAdapter(authority, remote)
		result, err := adapter.Mutate(t.Context(), testAdapterMutation("claimed-state-control"))
		if err != nil || result.Revision != 8 || result.RecordID != "record-1" ||
			len(remote.credentialRefs) != 3 || remote.mutate != 1 || authority.finalized != 1 {
			t.Fatalf("Mutate()=(%+v,%v) lookups=%d mutations=%d finalized=%d",
				result, err, len(remote.credentialRefs), remote.mutate, authority.finalized)
		}
	})

	t.Run("uncertain enters recovery", func(t *testing.T) {
		authority := &fakeReconcileAuthority{
			revision: 7, providerType: providerCloudflare,
			claimState: MutationUncertain, claimStateExplicit: true, recoveryReady: true,
		}
		remote := &fakeReconcileRemote{lookup: []ReconcileLookup{
			{TargetComplete: true, RecordID: "record-1"},
		}}
		adapter, _ := NewReconcileAdapter(authority, remote)
		result, err := adapter.Mutate(t.Context(), testAdapterMutation("uncertain-state-control"))
		if err != nil || result.Revision != 8 || result.RecordID != "record-1" ||
			len(remote.credentialRefs) != 1 || remote.mutate != 0 || authority.finalized != 1 {
			t.Fatalf("Mutate()=(%+v,%v) lookups=%d mutations=%d finalized=%d",
				result, err, len(remote.credentialRefs), remote.mutate, authority.finalized)
		}
	})

	t.Run("succeeded replays terminal result", func(t *testing.T) {
		authority := &fakeReconcileAuthority{
			revision: 7, providerType: providerCloudflare, claimStateExplicit: true,
			claimState: MutationSucceeded, providerRecordID: "record-1", finalRevision: 8,
		}
		remote := &fakeReconcileRemote{}
		adapter, _ := NewReconcileAdapter(authority, remote)
		mutation := testAdapterMutation("succeeded-state-control")
		result, err := adapter.Mutate(t.Context(), mutation)
		if err != nil || result.ProviderRequestID != deterministicProviderRequestID(mutation.ClientRequestID) ||
			result.RecordID != "record-1" || result.Revision != 8 {
			t.Fatalf("Mutate() = (%+v, %v)", result, err)
		}
		assertNoWork(t, authority, remote)
	})

	t.Run("conflict remains terminal", func(t *testing.T) {
		authority := &fakeReconcileAuthority{
			revision: 7, providerType: providerCloudflare,
			claimState: MutationConflict, claimStateExplicit: true,
		}
		remote := &fakeReconcileRemote{}
		adapter, _ := NewReconcileAdapter(authority, remote)
		result, err := adapter.Mutate(t.Context(), testAdapterMutation("conflict-state-control"))
		if !errors.Is(err, dnscheck.ErrProviderRevisionConflict) ||
			!reflect.DeepEqual(result, dnscheck.ProviderMutationResult{}) {
			t.Fatalf("Mutate() = (%+v, %v)", result, err)
		}
		assertNoWork(t, authority, remote)
	})
}

func TestReconcileAdapterLostResponseRetryUsesExactLookupWithoutReplay(t *testing.T) {
	for _, providerType := range []string{providerCloudflare, providerAliyun, providerHuawei, providerDNSPodCN, providerDNSCom, providerDNSLA} {
		t.Run(providerType, func(t *testing.T) {
			operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.com.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300}
			authority := &fakeReconcileAuthority{revision: 8, providerType: providerType}
			remote := &fakeReconcileRemote{lookup: []ReconcileLookup{{TargetComplete: true, RecordID: "record-1"}, {TargetComplete: true, RecordID: "record-1"}}}
			adapter, err := NewReconcileAdapter(authority, remote)
			if err != nil {
				t.Fatal(err)
			}
			request := dnscheck.ProviderMutation{ClientRequestID: "client-request-1", TenantID: uuid.New(), SiteID: uuid.New(), ZoneID: uuid.New(), ExpectedRevision: 7, Operation: operation}
			result, err := adapter.Mutate(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if remote.mutate != 0 || result.Revision != 8 || result.RecordID != "record-1" || result.ProviderRequestID == "" {
				t.Fatalf("result=%+v mutate=%d", result, remote.mutate)
			}
			replayed, err := adapter.Mutate(context.Background(), request)
			if err != nil || replayed != result || remote.mutate != 0 {
				t.Fatalf("replay=(%+v,%v) first=%+v mutate=%d", replayed, err, result, remote.mutate)
			}
		})
	}
}

func TestReconcileAdapterMutatesOnceOnlyAtMatchingRevisionAndConfirmedTarget(t *testing.T) {
	operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: "record-1", Name: "www.example.com.", Type: dnscheck.RecordAAAA, Value: "2001:db8::1", TTL: 300, PreviousValue: "2001:db8::2", PreviousTTL: 300}
	authority := &fakeReconcileAuthority{revision: 7, providerType: providerCloudflare}
	remote := &fakeReconcileRemote{lookup: []ReconcileLookup{{}, {}, {TargetComplete: true, RecordID: "record-1"}}}
	adapter, _ := NewReconcileAdapter(authority, remote)
	request := dnscheck.ProviderMutation{ClientRequestID: "client-request-2", TenantID: uuid.New(), SiteID: uuid.New(), ZoneID: uuid.New(), ExpectedRevision: 7, Operation: operation}
	result, err := adapter.Mutate(context.Background(), request)
	if err != nil || remote.mutate != 1 || result.Revision != 8 {
		t.Fatalf("result=(%+v,%v) mutate=%d", result, err, remote.mutate)
	}
}

func TestReconcileAdapterConflictsFailClosedWithoutMutation(t *testing.T) {
	operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: "record-1", Name: "www.example.com.", Type: dnscheck.RecordCNAME, Value: "edge.example.net.", TTL: 300}
	for _, test := range []struct {
		name     string
		revision int64
		lookup   ReconcileLookup
	}{
		{name: "revision mismatch", revision: 9},
		{name: "ambiguous remote rrset", revision: 7, lookup: ReconcileLookup{Ambiguous: true}},
		{name: "conflicting remote state", revision: 7, lookup: ReconcileLookup{Conflict: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := &fakeReconcileAuthority{revision: test.revision, providerType: providerCloudflare}
			remote := &fakeReconcileRemote{lookup: []ReconcileLookup{test.lookup}}
			adapter, _ := NewReconcileAdapter(authority, remote)
			_, err := adapter.Mutate(context.Background(), dnscheck.ProviderMutation{
				ClientRequestID: "client-request-3", TenantID: uuid.New(), SiteID: uuid.New(), ZoneID: uuid.New(), ExpectedRevision: 7, Operation: operation,
			})
			if err == nil || remote.mutate != 0 {
				t.Fatalf("error=%v mutate=%d", err, remote.mutate)
			}
		})
	}
}

func TestReconcileAdapterPropagatesConflictFinalizationFailure(t *testing.T) {
	want := errors.New("persist conflict failed")
	for _, test := range []struct {
		name     string
		revision int64
		state    MutationClaimState
		lookups  []ReconcileLookup
	}{
		{name: "initial ambiguity", revision: 7, lookups: []ReconcileLookup{{Ambiguous: true}}},
		{name: "uncertain repeated ambiguity", revision: 7, state: MutationUncertain,
			lookups: []ReconcileLookup{{}, {Ambiguous: true}}},
		{name: "uncertain lookup drift", revision: 7, state: MutationUncertain,
			lookups: []ReconcileLookup{{}, {RecordID: "drifted-record"}}},
		{name: "advanced revision without target", revision: 8, lookups: []ReconcileLookup{{}}},
		{name: "claimed repeated conflict", revision: 7,
			lookups: []ReconcileLookup{{}, {Conflict: true}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := &fakeReconcileAuthority{
				revision: test.revision, providerType: providerCloudflare,
				claimState: test.state, recoveryReady: true, finalizeErr: want,
			}
			remote := &fakeReconcileRemote{lookup: test.lookups}
			adapter, err := NewReconcileAdapter(authority, remote)
			if err != nil {
				t.Fatal(err)
			}
			mutation := testAdapterMutation("finalize-conflict")
			_, err = adapter.Mutate(t.Context(), mutation)
			var providerErr *dnscheck.ProviderError
			if !errors.As(err, &providerErr) || providerErr.Class != dnscheck.ProviderErrorTransient ||
				providerErr.Code != "provider_recovery_persistence_failed" ||
				providerErr.ProviderRequestID != ProviderMutationRequestID(mutation.ClientRequestID) ||
				authority.finalized != 1 || remote.mutate != 0 {
				t.Fatalf("Mutate() error=%v finalized=%d mutations=%d", err, authority.finalized, remote.mutate)
			}
		})
	}
}

func TestReconcileAdapterDoesNotFinalizeWhileRemoteLookupIsBlocked(t *testing.T) {
	authority := &fakeReconcileAuthority{
		revision: 7, providerType: providerCloudflare,
		credentials: map[string]string{"api_token": "sensitive-token"},
	}
	remote := &fakeReconcileRemote{
		lookup:        []ReconcileLookup{{TargetComplete: true, RecordID: "record-1"}},
		lookupStarted: make(chan struct{}, 1), releaseLookup: make(chan struct{}),
	}
	adapter, err := NewReconcileAdapter(authority, remote)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, mutateErr := adapter.Mutate(context.Background(), dnscheck.ProviderMutation{
			ClientRequestID: "blocked-lookup", TenantID: uuid.New(), SiteID: uuid.New(), ZoneID: uuid.New(),
			ExpectedRevision: 6,
			Operation: dnscheck.ProviderOperation{
				Action: dnscheck.ProviderCreate, Name: "www.example.com.", Type: dnscheck.RecordA,
				Value: "192.0.2.10", TTL: 300,
			},
		})
		done <- mutateErr
	}()
	<-remote.lookupStarted
	if authority.finalized != 0 {
		t.Fatalf("finalize called %d times while remote I/O was blocked", authority.finalized)
	}
	close(remote.releaseLookup)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if authority.finalized != 1 || !remote.credentialsCleared() {
		t.Fatalf("finalized=%d credentialsCleared=%v", authority.finalized, remote.credentialsCleared())
	}
}

func TestReconcileAdapterRevisionDriftFailsClosedAndClearsCredentials(t *testing.T) {
	authority := &fakeReconcileAuthority{
		revision: 7, providerType: providerCloudflare,
		credentials: map[string]string{"api_token": "sensitive-token"},
		finalizeErr: dnscheck.ErrProviderRevisionConflict,
	}
	remote := &fakeReconcileRemote{lookup: []ReconcileLookup{{TargetComplete: true, RecordID: "record-1"}}}
	adapter, _ := NewReconcileAdapter(authority, remote)
	_, err := adapter.Mutate(context.Background(), dnscheck.ProviderMutation{
		ClientRequestID: "revision-drift", TenantID: uuid.New(), SiteID: uuid.New(), ZoneID: uuid.New(),
		ExpectedRevision: 6,
		Operation: dnscheck.ProviderOperation{
			Action: dnscheck.ProviderCreate, Name: "www.example.com.", Type: dnscheck.RecordA,
			Value: "192.0.2.10", TTL: 300,
		},
	})
	if !errors.Is(err, dnscheck.ErrProviderRevisionConflict) || remote.mutate != 0 || !remote.credentialsCleared() {
		t.Fatalf("error=%v mutate=%d credentialsCleared=%v", err, remote.mutate, remote.credentialsCleared())
	}
}

func TestReconcileAdapterClearsCredentialsAfterRemoteFailure(t *testing.T) {
	authority := &fakeReconcileAuthority{
		revision: 7, providerType: providerCloudflare,
		credentials: map[string]string{"api_token": "sensitive-token"},
	}
	remote := &fakeReconcileRemote{lookupErr: failure(CodeUnavailable, true)}
	adapter, _ := NewReconcileAdapter(authority, remote)
	_, err := adapter.Mutate(context.Background(), dnscheck.ProviderMutation{
		ClientRequestID: "remote-failure", TenantID: uuid.New(), SiteID: uuid.New(), ZoneID: uuid.New(),
		ExpectedRevision: 7,
		Operation: dnscheck.ProviderOperation{
			Action: dnscheck.ProviderCreate, Name: "www.example.com.", Type: dnscheck.RecordA,
			Value: "192.0.2.10", TTL: 300,
		},
	})
	var providerErr *dnscheck.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Class != dnscheck.ProviderErrorTransient ||
		authority.finalized != 0 || !remote.credentialsCleared() {
		t.Fatalf("error=%v finalized=%d credentialsCleared=%v", err, authority.finalized, remote.credentialsCleared())
	}
}
