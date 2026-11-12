package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/google/uuid"
)

type fakeEntitlementRevocationRefresher struct {
	err   error
	calls int
}

func (refresher *fakeEntitlementRevocationRefresher) Refresh(context.Context) error {
	refresher.calls++
	return refresher.err
}

type fakeEntitlementRevocationSyncer struct {
	snapshot entitlementguard.RevocationSnapshot
	err      error
	calls    int
}

type fakeEntitlementLeaseInitializer struct {
	err       error
	prepared  entitlement.SignedLease
	fetched   int
	installed int
}

func (initializer *fakeEntitlementLeaseInitializer) FetchOnce(context.Context) (entitlement.SignedLease, error) {
	initializer.fetched++
	return initializer.prepared, initializer.err
}

func (initializer *fakeEntitlementLeaseInitializer) Install(context.Context, entitlement.SignedLease) (entitlementguard.Snapshot, error) {
	initializer.installed++
	return entitlementguard.Snapshot{}, initializer.err
}

func (syncer *fakeEntitlementRevocationSyncer) SyncOnce(context.Context) (entitlementguard.RevocationSnapshot, error) {
	syncer.calls++
	return syncer.snapshot, syncer.err
}

type fakeEntitlementRevocationStore struct {
	snapshot entitlementguard.RevocationSnapshot
	err      error
	current  func(context.Context, time.Time) (entitlementguard.RevocationSnapshot, error)
	calls    int
}

func (store *fakeEntitlementRevocationStore) LastKnownGood(ctx context.Context, now time.Time) (entitlementguard.RevocationSnapshot, error) {
	store.calls++
	if store.current != nil {
		return store.current(ctx, now)
	}
	return store.snapshot, store.err
}

type temporaryRevocationNetworkError struct{}

func (temporaryRevocationNetworkError) Error() string   { return "license service unavailable" }
func (temporaryRevocationNetworkError) Timeout() bool   { return false }
func (temporaryRevocationNetworkError) Temporary() bool { return true }

var _ net.Error = temporaryRevocationNetworkError{}

type testEntitlementRevocationSigner struct {
	keyID   string
	private ed25519.PrivateKey
}

func (signer testEntitlementRevocationSigner) KeyID() string { return signer.keyID }

func (signer testEntitlementRevocationSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func newTestEntitlementRevocationRuntime(
	refresher entitlementRevocationKeysetRefresher,
	syncer entitlementRevocationSyncer,
	store entitlementRevocationCurrentStore,
) *entitlementRevocationRuntime {
	return &entitlementRevocationRuntime{
		keysets:      refresher,
		syncer:       syncer,
		store:        store,
		now:          func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
		wait:         waitEntitlementRevocationContext,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		readyTimeout: 50 * time.Millisecond,
	}
}

func TestEntitlementRevocationInitialSyncAllowsOnlyCurrentLKGOnRemoteFailure(t *testing.T) {
	current := entitlementguard.RevocationSnapshot{Revision: 7, ExpiresAt: time.Unix(1_800_000_900, 0).UTC()}
	remote := temporaryRevocationNetworkError{}

	runtime := newTestEntitlementRevocationRuntime(
		&fakeEntitlementRevocationRefresher{err: remote},
		&fakeEntitlementRevocationSyncer{err: remote},
		&fakeEntitlementRevocationStore{snapshot: current},
	)
	if err := initializeEntitlementRevocationRuntime(t.Context(), runtime); err != nil {
		t.Fatalf("current LKG did not permit outage startup: %v", err)
	}

	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "missing", err: entitlementguard.ErrRevocationUnavailable},
		{name: "expired", err: entitlementguard.ErrRevocationExpired},
		{name: "corrupt", err: entitlementguard.ErrRevocationInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := newTestEntitlementRevocationRuntime(
				&fakeEntitlementRevocationRefresher{err: remote},
				&fakeEntitlementRevocationSyncer{err: remote},
				&fakeEntitlementRevocationStore{err: test.err},
			)
			if err := initializeEntitlementRevocationRuntime(t.Context(), runtime); err == nil {
				t.Fatal("startup accepted unusable LKG")
			}
		})
	}
}

func TestEntitlementLeaseIsFetchedThenInstalledAroundInitialRevocationSync(t *testing.T) {
	prepared := entitlement.SignedLease{Lease: entitlement.Lease{Serial: 1}}
	initializer := &fakeEntitlementLeaseInitializer{prepared: prepared}
	lease, err := fetchEntitlementLeaseBeforeRevocations(t.Context(), "/run/secrets/activation-code", initializer)
	if err != nil || lease == nil || lease.signed.Lease.Serial != 1 {
		t.Fatalf("fetch entitlement lease = (%#v, %v)", lease, err)
	}
	if initializer.fetched != 1 || initializer.installed != 0 {
		t.Fatalf("before revocation fetched=%d installed=%d", initializer.fetched, initializer.installed)
	}
	if err := installEntitlementLeaseAfterRevocations(t.Context(), lease, initializer); err != nil {
		t.Fatalf("install entitlement lease: %v", err)
	}
	if initializer.installed != 1 {
		t.Fatalf("after revocation installed=%d", initializer.installed)
	}

	initializer = &fakeEntitlementLeaseInitializer{}
	lease, err = fetchEntitlementLeaseBeforeRevocations(t.Context(), "", initializer)
	if err != nil || lease != nil || initializer.fetched != 0 {
		t.Fatalf("restart fetch = (%#v, %v), calls=%d", lease, err, initializer.fetched)
	}

	want := errors.New("activation rejected")
	initializer = &fakeEntitlementLeaseInitializer{err: want}
	if _, err := fetchEntitlementLeaseBeforeRevocations(t.Context(), "/run/secrets/activation-code", initializer); !errors.Is(err, want) {
		t.Fatalf("activation error = %v, want %v", err, want)
	}
}

func TestEntitlementRevocationHTTPSInitial304AndOutage(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	installationID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	_, installationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifyUntil := now.Add(24 * time.Hour)
	signed, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: "11111111-1111-4111-8111-111111111111", InstallationID: installationID.String(),
		LicenseID: "33333333-3333-4333-8333-333333333333", Revision: 1,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(entitlement.RevocationSetWindow).Unix(), RevokedSerials: []uint64{},
	}, testEntitlementRevocationSigner{keyID: "test-revocation-key", private: signingPrivate},
		entitlement.RevocationKeyWindow{NotBefore: now.Add(-time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	digest := entitlement.RevocationSetDigest(artifact)
	etag := entitlement.RevocationSetETag(artifact)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != entitlement.RevocationSetPath {
			t.Fatalf("request path = %q", request.URL.Path)
		}
		response.Header().Set("ETag", etag)
		response.Header().Set("X-Cdnca-Revocation-Revision", "1")
		response.Header().Set("X-Cdnca-Revocation-Digest", base64.RawURLEncoding.EncodeToString(digest[:]))
		response.Header().Set("X-Cdnca-Revocation-Expires-At", strconv.FormatInt(signed.Body.ExpiresAt, 10))
		if requests == 2 {
			if request.Header.Get("If-None-Match") != etag {
				t.Fatalf("If-None-Match = %q", request.Header.Get("If-None-Match"))
			}
			response.WriteHeader(http.StatusNotModified)
			return
		}
		response.Header().Set("Content-Type", entitlement.RevocationSetMediaTypeV2)
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(artifact)
	}))
	base, err := entitlementsync.NewClient(server.URL, server.Client())
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	client, err := entitlementsync.NewRevocationClient(base)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	initial, err := client.Fetch(t.Context(), entitlementsync.RevocationFetchRequest{
		InstallationID: installationID, PrivateKey: installationPrivate, Now: now,
	})
	if err != nil || initial.NotModified || string(initial.Artifact) != string(artifact) {
		server.Close()
		t.Fatalf("initial fetch = (%#v, %v)", initial, err)
	}
	known := entitlementguard.RevocationSnapshot{InstallationID: installationID.String(), Revision: 1,
		ArtifactSHA256: digest, ETag: etag, ExpiresAt: time.Unix(signed.Body.ExpiresAt, 0).UTC()}
	notModified, err := client.Fetch(t.Context(), entitlementsync.RevocationFetchRequest{
		InstallationID: installationID, PrivateKey: installationPrivate, Now: now, Known: &known,
	})
	if err != nil || !notModified.NotModified || len(notModified.Artifact) != 0 {
		server.Close()
		t.Fatalf("304 fetch = (%#v, %v)", notModified, err)
	}
	server.Close()
	_, err = client.Fetch(t.Context(), entitlementsync.RevocationFetchRequest{
		InstallationID: installationID, PrivateKey: installationPrivate, Now: now, Known: &known,
	})
	if err == nil || !isEntitlementRevocationRemoteError(err) {
		t.Fatalf("closed HTTPS endpoint error = %v", err)
	}
}

func TestEntitlementRevocationInitialSyncRejectsInvalidRemoteState(t *testing.T) {
	runtime := newTestEntitlementRevocationRuntime(
		&fakeEntitlementRevocationRefresher{},
		&fakeEntitlementRevocationSyncer{err: errors.New("invalid signed revocation artifact")},
		&fakeEntitlementRevocationStore{snapshot: entitlementguard.RevocationSnapshot{Revision: 7}},
	)
	if err := initializeEntitlementRevocationRuntime(t.Context(), runtime); err == nil {
		t.Fatal("invalid remote state fell back to LKG")
	}
}

// Startup must treat a rejected remote artifact the same way Run does: keep a
// current LKG and alert, instead of exiting and failing release acceptance.
func TestEntitlementRevocationInitialSyncRetainsCurrentLKGOnDeferredError(t *testing.T) {
	current := entitlementguard.RevocationSnapshot{Revision: 7, ExpiresAt: time.Unix(1_800_000_900, 0).UTC()}
	for _, deferred := range []error{
		entitlementguard.ErrRevocationInvalid, entitlementguard.ErrRevocationExpired,
		entitlementguard.ErrRevocationConflict, entitlementguard.ErrRevocationRollback,
		entitlementguard.ErrRevocationShrink,
	} {
		t.Run(deferred.Error(), func(t *testing.T) {
			runtime := newTestEntitlementRevocationRuntime(&fakeEntitlementRevocationRefresher{},
				&fakeEntitlementRevocationSyncer{err: deferred}, &fakeEntitlementRevocationStore{snapshot: current})
			if err := initializeEntitlementRevocationRuntime(t.Context(), runtime); err != nil {
				t.Fatalf("current LKG did not survive deferred startup error: %v", err)
			}
			runtime = newTestEntitlementRevocationRuntime(&fakeEntitlementRevocationRefresher{},
				&fakeEntitlementRevocationSyncer{err: deferred},
				&fakeEntitlementRevocationStore{err: entitlementguard.ErrRevocationUnavailable})
			if err := initializeEntitlementRevocationRuntime(t.Context(), runtime); !errors.Is(err, deferred) {
				t.Fatalf("startup without LKG error = %v, want %v", err, deferred)
			}
		})
	}
}

func TestEntitlementRevocationRemoteConflictIsRetryable(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "concurrent revocation state", err: &entitlementsync.HTTPError{
			StatusCode: http.StatusConflict, Code: "revocation_state_conflict",
		}, want: true},
		{name: "other conflict", err: &entitlementsync.HTTPError{
			StatusCode: http.StatusConflict, Code: "other_conflict",
		}, want: false},
		{name: "service unavailable", err: &entitlementsync.HTTPError{
			StatusCode: http.StatusServiceUnavailable, Code: "revocation_unavailable",
		}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isEntitlementRevocationRemoteError(test.err); got != test.want {
				t.Fatalf("isEntitlementRevocationRemoteError() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestEntitlementRevocationDeferredErrorsRetainLKG(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "invalid artifact", err: entitlementguard.ErrRevocationInvalid},
		{name: "expired artifact", err: entitlementguard.ErrRevocationExpired},
		{name: "revision conflict", err: entitlementguard.ErrRevocationConflict},
		{name: "revision rollback", err: entitlementguard.ErrRevocationRollback},
		{name: "serial shrink", err: entitlementguard.ErrRevocationShrink},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !isEntitlementRevocationDeferredError(test.err) {
				t.Fatalf("isEntitlementRevocationDeferredError(%v) = false", test.err)
			}
		})
	}
	if isEntitlementRevocationDeferredError(errors.New("unexpected runtime failure")) {
		t.Fatal("unknown runtime failure was deferred")
	}
}

func TestEntitlementRevocationRuntimeContinuesAfterDeferredError(t *testing.T) {
	refresher := &fakeEntitlementRevocationRefresher{}
	syncer := &fakeEntitlementRevocationSyncer{err: entitlementguard.ErrRevocationInvalid}
	runtime := newTestEntitlementRevocationRuntime(refresher, syncer,
		&fakeEntitlementRevocationStore{snapshot: entitlementguard.RevocationSnapshot{Revision: 1}})
	waits := 0
	ctx, cancel := context.WithCancel(context.Background())
	runtime.wait = func(ctx context.Context, _ time.Duration) error {
		waits++
		if waits == 1 {
			return nil
		}
		cancel()
		return ctx.Err()
	}
	defer cancel()
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want cancellation after deferred error", err)
	}
	if syncer.calls != 1 || waits != 2 {
		t.Fatalf("deferred error stopped or repeated sync: calls=%d waits=%d", syncer.calls, waits)
	}
}

func TestEntitlementRevocationReadinessIsBoundedAndChecksCurrent(t *testing.T) {
	store := &fakeEntitlementRevocationStore{current: func(ctx context.Context, _ time.Time) (entitlementguard.RevocationSnapshot, error) {
		<-ctx.Done()
		return entitlementguard.RevocationSnapshot{}, ctx.Err()
	}}
	runtime := newTestEntitlementRevocationRuntime(
		&fakeEntitlementRevocationRefresher{}, &fakeEntitlementRevocationSyncer{}, store,
	)
	started := time.Now()
	if err := runtime.Ready(); err == nil {
		t.Fatal("blocked current-state read reported ready")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("readiness was not bounded: %s", elapsed)
	}

	store.current = nil
	store.err = nil
	store.snapshot = entitlementguard.RevocationSnapshot{Revision: 8}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("current state reported not ready: %v", err)
	}
}

func TestEntitlementRevocationRuntimeWaitsSixtySecondsBeforePolling(t *testing.T) {
	refresher := &fakeEntitlementRevocationRefresher{}
	syncer := &fakeEntitlementRevocationSyncer{}
	runtime := newTestEntitlementRevocationRuntime(refresher, syncer, &fakeEntitlementRevocationStore{})
	waited := make(chan time.Duration, 1)
	ctx, cancel := context.WithCancel(context.Background())
	runtime.wait = func(ctx context.Context, _ time.Duration) error {
		waited <- entitlementRevocationPollInterval
		cancel()
		return ctx.Err()
	}
	defer cancel()
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	if duration := <-waited; duration != time.Minute {
		t.Fatalf("first poll wait = %s, want %s", duration, time.Minute)
	}
	if refresher.calls != 0 || syncer.calls != 0 {
		t.Fatalf("polled before first interval: refresh=%d sync=%d", refresher.calls, syncer.calls)
	}
}

func TestEntitlementRevocationRuntimeCancellationAndTerminalFailure(t *testing.T) {
	runtime := newTestEntitlementRevocationRuntime(
		&fakeEntitlementRevocationRefresher{}, &fakeEntitlementRevocationSyncer{},
		&fakeEntitlementRevocationStore{snapshot: entitlementguard.RevocationSnapshot{Revision: 1}},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled runtime did not stop")
	}

	terminal := errors.New("poll scheduler stopped")
	runtime = newTestEntitlementRevocationRuntime(
		&fakeEntitlementRevocationRefresher{}, &fakeEntitlementRevocationSyncer{},
		&fakeEntitlementRevocationStore{snapshot: entitlementguard.RevocationSnapshot{Revision: 1}},
	)
	runtime.wait = func(context.Context, time.Duration) error { return terminal }
	if err := runtime.Run(context.Background()); !errors.Is(err, terminal) {
		t.Fatalf("terminal Run() error = %v", err)
	}
	if err := runtime.Ready(); !errors.Is(err, terminal) {
		t.Fatalf("terminal readiness error = %v", err)
	}
}

func TestEntitlementRevocationRuntimeRefreshesLeaseEachPollAndSurvivesFailure(t *testing.T) {
	syncer := &fakeEntitlementRevocationSyncer{snapshot: entitlementguard.RevocationSnapshot{Revision: 1}}
	runtime := newTestEntitlementRevocationRuntime(&fakeEntitlementRevocationRefresher{}, syncer,
		&fakeEntitlementRevocationStore{snapshot: entitlementguard.RevocationSnapshot{Revision: 1}})
	refreshes := 0
	runtime.leaseRefresh = func(context.Context) error {
		refreshes++
		if refreshes == 1 {
			return errors.New("license service unavailable")
		}
		return nil
	}
	waits := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime.wait = func(ctx context.Context, _ time.Duration) error {
		waits++
		if waits <= 2 {
			return nil
		}
		cancel()
		return ctx.Err()
	}
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want cancellation", err)
	}
	if syncer.calls != 2 || refreshes != 2 {
		t.Fatalf("revocation syncs=%d lease refreshes=%d, want 2 and 2", syncer.calls, refreshes)
	}
}

// longPollingRevocationSyncer scripts LongPollOnce results; SyncOnce succeeds.
type longPollingRevocationSyncer struct {
	fakeEntitlementRevocationSyncer
	longPolls int
	results   []error
	delay     time.Duration
	stop      func()
}

func (syncer *longPollingRevocationSyncer) LongPollOnce(context.Context) (entitlementguard.RevocationSnapshot, error) {
	syncer.longPolls++
	time.Sleep(syncer.delay)
	if syncer.longPolls > len(syncer.results) {
		syncer.stop()
		return entitlementguard.RevocationSnapshot{}, context.Canceled
	}
	return entitlementguard.RevocationSnapshot{Revision: uint64(syncer.longPolls)}, syncer.results[syncer.longPolls-1]
}

// after one successful 60 s round the runtime long polls with no
// wait between answers; a failed long poll falls back to the minute poll,
// and the next successful poll resumes long polling.
func TestEntitlementRevocationRuntimeLongPollsAndFallsBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncer := &longPollingRevocationSyncer{results: []error{nil, nil, temporaryRevocationNetworkError{}, nil},
		delay: 1100 * time.Millisecond, stop: cancel}
	refresher := &fakeEntitlementRevocationRefresher{}
	runtime := newTestEntitlementRevocationRuntime(refresher, syncer,
		&fakeEntitlementRevocationStore{snapshot: entitlementguard.RevocationSnapshot{Revision: 1}})
	waits := 0
	runtime.wait = func(ctx context.Context, delay time.Duration) error {
		if delay != entitlementRevocationPollInterval {
			t.Fatalf("wait %v", delay)
		}
		waits++
		return ctx.Err()
	}
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	// wait+sync, long poll ×3 (third fails), wait+sync, long poll, long poll (stop).
	if waits != 2 || syncer.calls != 2 || syncer.longPolls != 5 || refresher.calls != 6 {
		t.Fatalf("waits=%d syncs=%d long polls=%d keyset refreshes=%d, want 2 2 5 6",
			waits, syncer.calls, syncer.longPolls, refresher.calls)
	}
}

// A license service that answers long polls at once (no hold) is not polled
// in a tight loop: after entitlementRevocationQuickLimit quick unchanged
// answers the runtime goes back to the minute poll.
func TestEntitlementRevocationRuntimeQuickLongPollAnswersFallBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncer := &longPollingRevocationSyncer{results: make([]error, 10), stop: cancel}
	syncer.snapshot = entitlementguard.RevocationSnapshot{Revision: 1}
	runtime := newTestEntitlementRevocationRuntime(&fakeEntitlementRevocationRefresher{}, syncer,
		&fakeEntitlementRevocationStore{snapshot: entitlementguard.RevocationSnapshot{Revision: 1}})
	// Every answer is the same revision 1.
	syncer.results = make([]error, 10)
	same := &sameRevisionLongPoller{longPollingRevocationSyncer: syncer}
	runtime.syncer = same
	waits := 0
	runtime.wait = func(ctx context.Context, _ time.Duration) error {
		waits++
		if waits == 3 {
			cancel()
		}
		return ctx.Err()
	}
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	if waits != 3 || syncer.longPolls != 2*entitlementRevocationQuickLimit {
		t.Fatalf("waits=%d long polls=%d, want 3 and %d", waits, syncer.longPolls, 2*entitlementRevocationQuickLimit)
	}
}

type sameRevisionLongPoller struct {
	*longPollingRevocationSyncer
}

func (syncer *sameRevisionLongPoller) LongPollOnce(ctx context.Context) (entitlementguard.RevocationSnapshot, error) {
	_, err := syncer.longPollingRevocationSyncer.LongPollOnce(ctx)
	return entitlementguard.RevocationSnapshot{Revision: 1}, err
}

// A flaky path to the license service must not
// stop the control API. Response and HTTP failures are deferred like network ones.
func transientRevocationErrors() map[string]error {
	return map[string]error{
		"invalid response":    fmt.Errorf("fetch: %w", entitlementsync.ErrInvalidResponse),
		"cut-off body":        fmt.Errorf("read body: %w", io.ErrUnexpectedEOF),
		"cdn 403":             &entitlementsync.HTTPError{StatusCode: http.StatusForbidden},
		"cdn 404 html":        &entitlementsync.HTTPError{StatusCode: http.StatusNotFound},
		"invalid proof 401":   &entitlementsync.HTTPError{StatusCode: http.StatusUnauthorized, Code: "invalid_proof"},
		"bad request 400":     &entitlementsync.HTTPError{StatusCode: http.StatusBadRequest},
		"wrapped bad gateway": fmt.Errorf("sync: %w", &entitlementsync.HTTPError{StatusCode: http.StatusBadGateway}),
	}
}

func TestEntitlementRevocationRunSurvivesTransientErrorsWithBackoff(t *testing.T) {
	for name, syncErr := range transientRevocationErrors() {
		t.Run(name, func(t *testing.T) {
			syncer := &fakeEntitlementRevocationSyncer{err: syncErr}
			runtime := newTestEntitlementRevocationRuntime(&fakeEntitlementRevocationRefresher{}, syncer,
				&fakeEntitlementRevocationStore{snapshot: entitlementguard.RevocationSnapshot{Revision: 5}})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var delays []time.Duration
			runtime.wait = func(ctx context.Context, delay time.Duration) error {
				delays = append(delays, delay)
				if len(delays) == 5 {
					cancel()
					return ctx.Err()
				}
				return nil
			}
			if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() = %v, want the process to keep running until canceled", err)
			}
			want := []time.Duration{time.Minute, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute}
			if fmt.Sprint(delays) != fmt.Sprint(want) {
				t.Fatalf("poll delays = %v, want %v", delays, want)
			}
			if syncer.calls != 4 || runtime.transientFailures.Load() != 4 {
				t.Fatalf("sync calls=%d counted failures=%d, want 4 and 4", syncer.calls, runtime.transientFailures.Load())
			}
		})
	}
}

func TestEntitlementRevocationBackoffResetsAfterASuccessfulRound(t *testing.T) {
	syncer := &fakeEntitlementRevocationSyncer{err: &entitlementsync.HTTPError{StatusCode: http.StatusForbidden}}
	runtime := newTestEntitlementRevocationRuntime(&fakeEntitlementRevocationRefresher{}, syncer,
		&fakeEntitlementRevocationStore{snapshot: entitlementguard.RevocationSnapshot{Revision: 5}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var delays []time.Duration
	runtime.wait = func(ctx context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		switch len(delays) {
		case 3:
			syncer.err = nil
		case 5:
			cancel()
			return ctx.Err()
		}
		return nil
	}
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v", err)
	}
	want := []time.Duration{time.Minute, time.Minute, 2 * time.Minute, time.Minute, time.Minute}
	if fmt.Sprint(delays) != fmt.Sprint(want) {
		t.Fatalf("poll delays = %v, want %v", delays, want)
	}
}

// The process stays up, but the revocation state is still required to be current:
// once the LKG itself is past its validity, readiness fails (fail closed).
func TestEntitlementRevocationExpiredStateStaysLockedWhileRunKeepsRetrying(t *testing.T) {
	store := &fakeEntitlementRevocationStore{err: entitlementguard.ErrRevocationExpired}
	syncer := &fakeEntitlementRevocationSyncer{err: &entitlementsync.HTTPError{StatusCode: http.StatusForbidden}}
	runtime := newTestEntitlementRevocationRuntime(&fakeEntitlementRevocationRefresher{}, syncer, store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits := 0
	runtime.wait = func(ctx context.Context, _ time.Duration) error {
		if waits++; waits == 3 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v, want it to keep retrying", err)
	}
	if err := runtime.Ready(); !errors.Is(err, entitlementguard.ErrRevocationExpired) {
		t.Fatalf("Ready() with an expired state = %v, want ErrRevocationExpired", err)
	}
	store.err = nil
	store.snapshot = entitlementguard.RevocationSnapshot{Revision: 6}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready() with a current state = %v", err)
	}
}

func TestEntitlementRevocationRunStillStopsOnAnUnclassifiedError(t *testing.T) {
	runtime := newTestEntitlementRevocationRuntime(&fakeEntitlementRevocationRefresher{},
		&fakeEntitlementRevocationSyncer{err: errors.New("local database corrupted")},
		&fakeEntitlementRevocationStore{snapshot: entitlementguard.RevocationSnapshot{Revision: 5}})
	runtime.wait = func(context.Context, time.Duration) error { return nil }
	if err := runtime.Run(context.Background()); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v, want the unclassified error", err)
	}
}

func TestEntitlementRevocationKeysetRefreshFailuresAreDeferredToo(t *testing.T) {
	for name, refreshErr := range transientRevocationErrors() {
		t.Run(name, func(t *testing.T) {
			runtime := newTestEntitlementRevocationRuntime(&fakeEntitlementRevocationRefresher{err: refreshErr},
				&fakeEntitlementRevocationSyncer{}, &fakeEntitlementRevocationStore{snapshot: entitlementguard.RevocationSnapshot{Revision: 5}})
			if err := initializeEntitlementRevocationRuntime(t.Context(), runtime); err != nil {
				t.Fatalf("startup keyset refresh %v stopped the control API: %v", refreshErr, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			waits := 0
			runtime.wait = func(ctx context.Context, _ time.Duration) error {
				if waits++; waits == 2 {
					cancel()
					return ctx.Err()
				}
				return nil
			}
			if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() = %v, want it to keep running", err)
			}
		})
	}
}

func TestEntitlementRevocationStartupWithCurrentLKGSurvivesTransientErrors(t *testing.T) {
	for name, syncErr := range transientRevocationErrors() {
		t.Run(name, func(t *testing.T) {
			runtime := newTestEntitlementRevocationRuntime(&fakeEntitlementRevocationRefresher{},
				&fakeEntitlementRevocationSyncer{err: syncErr},
				&fakeEntitlementRevocationStore{snapshot: entitlementguard.RevocationSnapshot{Revision: 7}})
			if err := initializeEntitlementRevocationRuntime(t.Context(), runtime); err != nil {
				t.Fatalf("startup with a current LKG and %v = %v, want it to continue", syncErr, err)
			}
			// First start: no LKG at all keeps today's behavior and fails.
			runtime = newTestEntitlementRevocationRuntime(&fakeEntitlementRevocationRefresher{},
				&fakeEntitlementRevocationSyncer{err: syncErr}, &fakeEntitlementRevocationStore{})
			if err := initializeEntitlementRevocationRuntime(t.Context(), runtime); err == nil {
				t.Fatalf("startup without an LKG and %v continued", syncErr)
			}
		})
	}
}
