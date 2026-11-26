package accountregistrationhttp

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/google/uuid"
)

// replayingRegistrationStore records registrations by idempotency key and
// answers the replay read as the PostgreSQL store does.
type replayingRegistrationStore struct {
	byKey   map[string]accountregistration.RegistrationRecord
	records []accountregistration.RegistrationRecord
}

func (store *replayingRegistrationStore) Register(_ context.Context, record accountregistration.RegistrationRecord) (accountregistration.StoreResult, error) {
	if previous, ok := store.byKey[record.IdempotencyKey]; ok {
		if previous.RequestDigest != record.RequestDigest {
			return accountregistration.StoreResult{}, accountregistration.ErrIdempotencyConflict
		}
		return accountregistration.StoreResult{Replayed: true}, nil
	}
	store.byKey[record.IdempotencyKey] = record
	store.records = append(store.records, record)
	return accountregistration.StoreResult{}, nil
}

func (store *replayingRegistrationStore) CompletedRegistration(_ context.Context, key string, digest [32]byte) (bool, error) {
	previous, ok := store.byKey[key]
	if !ok {
		return false, nil
	}
	if previous.RequestDigest != digest {
		return false, accountregistration.ErrIdempotencyConflict
	}
	return true, nil
}

type allowRegistrationLimiter struct{}

func (allowRegistrationLimiter) Allow(context.Context, accountregistration.RateLimitRequest) (bool, error) {
	return true, nil
}

var termsTestNow = time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)

// replayingProofs returns one evidence per reference, as a consumed proof
// replays for its idempotency key.
type replayingProofs struct{ calls int }

func (proofs *replayingProofs) VerifyAndConsume(_ context.Context, request accountregistration.RegistrationProofRequest) (accountregistration.RegistrationProof, error) {
	proofs.calls++
	return accountregistration.RegistrationProof{EvidenceID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(request.Reference)),
		Channel: request.Channel, Destination: request.Destination,
		HumanVerifiedAt: termsTestNow.Add(-time.Minute), ContactVerifiedAt: termsTestNow.Add(-30 * time.Second), ExpiresAt: termsTestNow.Add(5 * time.Minute)}, nil
}

// termsTestHandler is the Turnstile entry over the real registration service.
func termsTestHandler(t *testing.T, config Config, required func(context.Context) (bool, error)) (*Handler, *replayingRegistrationStore, *replayingProofs) {
	t.Helper()
	store := &replayingRegistrationStore{byKey: map[string]accountregistration.RegistrationRecord{}}
	proofs := &replayingProofs{}
	service, err := accountregistration.NewService(store, allowRegistrationLimiter{}, accountregistration.ServiceConfig{
		DigestKey: bytes.Repeat([]byte{0x41}, 32), ProofAuthority: proofs, Clock: func() time.Time { return termsTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	service.RequireTermsWhen(required)
	config.Logger, config.TermsRequired = slog.Default(), required
	handler, err := NewHandler(service, &registrationSourceStub{address: netip.MustParseAddr("203.0.113.8")},
		&registrationProofReferenceStub{reference: "server-proof-reference-registration"}, config)
	if err != nil {
		t.Fatal(err)
	}
	return handler, store, proofs
}

func postRegistration(handler *Handler, body, key string) *httptest.ResponseRecorder {
	request := registrationHTTPRequest(body)
	request.Header.Set("Idempotency-Key", key)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// without a pinned version the current one is read per request
// (the terms on the settings page). A completed registration retried
// unchanged after the version changed replays its 202; a first submission of
// the old version is refused; the same key with other details is a conflict.
// the qq field reaches the registration.
func TestRegistrationHTTPCurrentTermsVersionAndQQ(t *testing.T) {
	current, currentErr := "terms-2026-08", error(nil)
	handler, store, proofs := termsTestHandler(t,
		Config{CurrentTermsVersion: func(context.Context) (string, error) { return current, currentErr }}, nil)
	body := strings.Replace(validRegistrationHTTPBody(), `"verification_channel"`, `"qq":"123456","verification_channel"`, 1)
	if response := postRegistration(handler, body, "registration-http-1"); response.Code != http.StatusAccepted ||
		len(store.records) != 1 || store.records[0].QQ != "123456" || store.records[0].TermsVersion != "terms-2026-08" {
		t.Fatalf("current terms: %d %s %+v", response.Code, response.Body.String(), store.records)
	}
	current = "terms-0123456789ab"
	response := postRegistration(handler, body, "registration-http-1")
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"replayed":true`) || len(store.records) != 1 {
		t.Fatalf("replay after the terms changed: %d %s", response.Code, response.Body.String())
	}
	spent := proofs.calls
	response = postRegistration(handler, body, "registration-http-2")
	assertRegistrationHTTPError(t, response, http.StatusUnprocessableEntity, "account_registration_terms_required")
	if proofs.calls != spent || len(store.records) != 1 {
		t.Fatalf("a first submission of old terms spent a proof (%d) or was stored (%d)", proofs.calls-spent, len(store.records))
	}
	other := strings.Replace(body, `"display_name":"Alice Example"`, `"display_name":"Mallory"`, 1)
	assertRegistrationHTTPError(t, postRegistration(handler, other, "registration-http-1"), http.StatusConflict, "account_registration_idempotency_conflict")
	currentErr = errors.New("settings unavailable")
	assertRegistrationHTTPError(t, postRegistration(handler, body, "registration-http-3"), http.StatusServiceUnavailable, "account_registration_unavailable")
	if _, err := NewHandler(&registrationApplicationStub{}, &registrationSourceStub{}, &registrationProofReferenceStub{}, Config{}); err == nil {
		t.Fatal("a handler without any terms version was built")
	}
}

// the Turnstile entry: with a readable terms source (here a
// pinned version and the requirement on) the acceptance is checked as
// before; with none a sign-up without it is registered with no acceptance
// recorded, and replays once terms are required; the requirement read
// failing is unavailable.
func TestRegistrationHTTPTermsRequirement(t *testing.T) {
	required, requiredErr := true, error(nil)
	handler, store, _ := termsTestHandler(t, Config{TermsVersion: "terms-2026-08"},
		func(context.Context) (bool, error) { return required, requiredErr })
	unaccepted := strings.Replace(strings.Replace(validRegistrationHTTPBody(), `"terms_accepted":true`, `"terms_accepted":false`, 1),
		`"terms_version":"terms-2026-08"`, `"terms_version":""`, 1)
	assertRegistrationHTTPError(t, postRegistration(handler, unaccepted, "registration-terms-1"), http.StatusUnprocessableEntity, "account_registration_terms_required")
	if len(store.records) != 0 {
		t.Fatalf("unaccepted terms were registered")
	}
	required = false
	if response := postRegistration(handler, unaccepted, "registration-terms-2"); response.Code != http.StatusAccepted ||
		len(store.records) != 1 || store.records[0].TermsVersion != "" {
		t.Fatalf("no terms source: %d %s %+v", response.Code, response.Body.String(), store.records)
	}
	required = true
	if response := postRegistration(handler, unaccepted, "registration-terms-2"); response.Code != http.StatusAccepted ||
		!strings.Contains(response.Body.String(), `"replayed":true`) {
		t.Fatalf("replay once terms are required: %d %s", response.Code, response.Body.String())
	}
	requiredErr = errors.New("site unreadable")
	assertRegistrationHTTPError(t, postRegistration(handler, unaccepted, "registration-terms-3"), http.StatusServiceUnavailable, "account_registration_unavailable")
}
