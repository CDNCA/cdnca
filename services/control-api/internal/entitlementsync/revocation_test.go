package entitlementsync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

type memoryRevocationStore struct {
	mu       sync.Mutex
	current  *entitlementguard.RevocationSnapshot
	installs [][]byte
}

func (store *memoryRevocationStore) Current(_ context.Context, now time.Time) (entitlementguard.RevocationSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current == nil {
		return entitlementguard.RevocationSnapshot{}, entitlementguard.ErrRevocationUnavailable
	}
	if !now.Before(store.current.ExpiresAt) {
		return entitlementguard.RevocationSnapshot{}, entitlementguard.ErrRevocationExpired
	}
	return *store.current, nil
}

func (store *memoryRevocationStore) Install(_ context.Context, artifact []byte, now time.Time) (entitlementguard.RevocationSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	signed, err := entitlement.DecodeRevocationSet(artifact)
	if err != nil {
		return entitlementguard.RevocationSnapshot{}, err
	}
	snapshot := entitlementguard.RevocationSnapshot{
		InstallationID: signed.Body.InstallationID, CustomerID: signed.Body.CustomerID,
		LicenseID: signed.Body.LicenseID, Revision: signed.Body.Revision, KeyID: signed.KeyID,
		Artifact: append([]byte(nil), artifact...), ArtifactSHA256: entitlement.RevocationSetDigest(artifact),
		ETag: entitlement.RevocationSetETag(artifact), IssuedAt: time.Unix(signed.Body.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(signed.Body.ExpiresAt, 0).UTC(), AcceptedAt: now.UTC(),
		RevokedSerials: append([]uint64(nil), signed.Body.RevokedSerials...),
	}
	store.current = &snapshot
	store.installs = append(store.installs, append([]byte(nil), artifact...))
	return snapshot, nil
}

type scriptedRevocationFetcher struct {
	mu        sync.Mutex
	responses []RevocationFetchResponse
	errors    []error
	requests  []RevocationFetchRequest
}

func (fetcher *scriptedRevocationFetcher) Fetch(_ context.Context, request RevocationFetchRequest) (RevocationFetchResponse, error) {
	fetcher.mu.Lock()
	defer fetcher.mu.Unlock()
	fetcher.requests = append(fetcher.requests, request)
	index := len(fetcher.requests) - 1
	if index < len(fetcher.errors) && fetcher.errors[index] != nil {
		return RevocationFetchResponse{}, fetcher.errors[index]
	}
	if index >= len(fetcher.responses) {
		return RevocationFetchResponse{}, errors.New("unexpected fetch")
	}
	return fetcher.responses[index], nil
}

func TestRevocationClientFetchSignsExactProofAndValidatesResponse(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	installationID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	installationPublic, installationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := mustSignedRevocationArtifact(t, now)
	knownDigest := entitlement.RevocationSetDigest([]byte("known"))
	known := entitlementguard.RevocationSnapshot{Revision: 6, ArtifactSHA256: knownDigest,
		ETag: `"sha256-` + base64.RawURLEncoding.EncodeToString(knownDigest[:]) + `"`, ExpiresAt: now.Add(time.Minute)}

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != entitlement.RevocationSetPath ||
			request.Header.Get("Accept") != entitlement.RevocationSetMediaTypeV2 ||
			request.Header.Get("X-CDNCA-Installation-ID") != installationID.String() ||
			request.Header.Get("X-CDNCA-Known-Revocation-Revision") != "6" ||
			request.Header.Get("If-None-Match") != known.ETag {
			t.Fatalf("request = %s %s headers=%v", request.Method, request.URL.Path, request.Header)
		}
		proof := entitlement.RevocationFetchProof{
			InstallationID: installationID.String(), RequestID: request.Header.Get("X-Request-ID"),
			RequestedAt: now.Unix(), KnownRevision: known.Revision,
			KnownDigest: base64.RawURLEncoding.EncodeToString(knownDigest[:]), IfNoneMatch: known.ETag,
			Signature: request.Header.Get("X-CDNCA-Proof"),
		}
		if err := entitlement.VerifyRevocationFetchProof(proof, installationPublic, now); err != nil {
			t.Fatalf("request proof error = %v", err)
		}
		header := revocationArtifactHeaders(t, artifact)
		return &http.Response{StatusCode: http.StatusOK, Header: header,
			Body: io.NopCloser(strings.NewReader(string(artifact)))}, nil
	})
	base, err := NewClient("https://license.example.test", &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewRevocationClient(base)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Fetch(t.Context(), RevocationFetchRequest{InstallationID: installationID,
		PrivateKey: installationPrivate, Now: now, Known: &known})
	if err != nil || response.NotModified || string(response.Artifact) != string(artifact) {
		t.Fatalf("Fetch() = (%#v, %v)", response, err)
	}
}

func TestRevocationClientRejectsUnboundResponses(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	installationID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	artifact := mustSignedRevocationArtifact(t, now)
	tests := []struct {
		name      string
		response  func() *http.Response
		wantError error
	}{
		{name: "304 without known state", response: func() *http.Response {
			return &http.Response{StatusCode: http.StatusNotModified, Header: make(http.Header), Body: http.NoBody}
		}, wantError: ErrInvalidResponse},
		{name: "wrong artifact ETag", response: func() *http.Response {
			header := revocationArtifactHeaders(t, artifact)
			header.Set("ETag", `"sha256-`+strings.Repeat("a", 43)+`"`)
			return &http.Response{StatusCode: http.StatusOK, Header: header,
				Body: io.NopCloser(strings.NewReader(string(artifact)))}
		}, wantError: ErrInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) { return test.response(), nil })
			base, err := NewClient("https://license.example.test", &http.Client{Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewRevocationClient(base)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Fetch(t.Context(), RevocationFetchRequest{InstallationID: installationID,
				PrivateKey: privateKey, Now: now}); !errors.Is(err, test.wantError) {
				t.Fatalf("Fetch() error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestRevocationClientRejectsInvalidResponseMetadata(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	installationID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	artifact := mustSignedRevocationArtifact(t, now)
	known := revocationSnapshotForArtifact(t, artifact)

	responseTests := []struct {
		name   string
		status int
		known  *entitlementguard.RevocationSnapshot
		mutate func(http.Header)
	}{
		{name: "304 missing ETag", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) { header.Del("ETag") }},
		{name: "304 duplicate ETag", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) { header.Add("ETag", known.ETag) }},
		{name: "304 mismatched ETag", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) { header.Set("ETag", `"sha256-`+strings.Repeat("a", 43)+`"`) }},
		{name: "304 missing revision", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) { header.Del("X-Cdnca-Revocation-Revision") }},
		{name: "304 duplicate revision", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) {
				header.Add("X-Cdnca-Revocation-Revision", strconv.FormatUint(known.Revision, 10))
			}},
		{name: "304 noncanonical revision", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Revision", "07") }},
		{name: "304 revision overflow", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Revision", "9223372036854775808") }},
		{name: "304 mismatched revision", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Revision", "8") }},
		{name: "304 missing digest", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) { header.Del("X-Cdnca-Revocation-Digest") }},
		{name: "304 duplicate digest", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) {
				header.Add("X-Cdnca-Revocation-Digest", base64.RawURLEncoding.EncodeToString(known.ArtifactSHA256[:]))
			}},
		{name: "304 malformed digest", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Digest", "not-a-digest") }},
		{name: "304 digest alias", status: http.StatusNotModified, known: &known, mutate: func(header http.Header) {
			header.Del("X-Cdnca-Revocation-Digest")
			header.Set("X-Cdnca-Revocation-SHA256", base64.RawURLEncoding.EncodeToString(known.ArtifactSHA256[:]))
		}},
		{name: "304 missing expiry", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) { header.Del("X-Cdnca-Revocation-Expires-At") }},
		{name: "304 duplicate expiry", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) {
				header.Add("X-Cdnca-Revocation-Expires-At", strconv.FormatInt(known.ExpiresAt.Unix(), 10))
			}},
		{name: "304 noncanonical expiry", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Expires-At", "+1900000900") }},
		{name: "304 expiry overflow", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Expires-At", "9223372036854775808") }},
		{name: "304 mismatched expiry", status: http.StatusNotModified, known: &known,
			mutate: func(header http.Header) {
				header.Set("X-Cdnca-Revocation-Expires-At", strconv.FormatInt(known.ExpiresAt.Add(time.Second).Unix(), 10))
			}},
		{name: "200 duplicate ETag", status: http.StatusOK,
			mutate: func(header http.Header) { header.Add("ETag", entitlement.RevocationSetETag(artifact)) }},
		{name: "200 missing revision", status: http.StatusOK,
			mutate: func(header http.Header) { header.Del("X-Cdnca-Revocation-Revision") }},
		{name: "200 duplicate revision", status: http.StatusOK,
			mutate: func(header http.Header) { header.Add("X-Cdnca-Revocation-Revision", "7") }},
		{name: "200 noncanonical revision", status: http.StatusOK,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Revision", "07") }},
		{name: "200 revision overflow", status: http.StatusOK,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Revision", "9223372036854775808") }},
		{name: "200 body revision disagreement", status: http.StatusOK,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Revision", "8") }},
		{name: "200 missing digest", status: http.StatusOK,
			mutate: func(header http.Header) { header.Del("X-Cdnca-Revocation-Digest") }},
		{name: "200 duplicate digest", status: http.StatusOK,
			mutate: func(header http.Header) { header.Add("X-Cdnca-Revocation-Digest", strings.Repeat("a", 43)) }},
		{name: "200 malformed digest", status: http.StatusOK,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Digest", "not-a-digest") }},
		{name: "200 body digest disagreement", status: http.StatusOK,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Digest", strings.Repeat("a", 43)) }},
		{name: "200 missing expiry", status: http.StatusOK,
			mutate: func(header http.Header) { header.Del("X-Cdnca-Revocation-Expires-At") }},
		{name: "200 duplicate expiry", status: http.StatusOK,
			mutate: func(header http.Header) { header.Add("X-Cdnca-Revocation-Expires-At", "1900000900") }},
		{name: "200 noncanonical expiry", status: http.StatusOK,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Expires-At", "+1900000900") }},
		{name: "200 expiry overflow", status: http.StatusOK,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Expires-At", "9223372036854775808") }},
		{name: "200 body expiry disagreement", status: http.StatusOK,
			mutate: func(header http.Header) { header.Set("X-Cdnca-Revocation-Expires-At", "1900000901") }},
	}

	for _, test := range responseTests {
		t.Run(test.name, func(t *testing.T) {
			header := revocationArtifactHeaders(t, artifact)
			test.mutate(header)
			var body io.ReadCloser = http.NoBody
			if test.status == http.StatusOK {
				body = io.NopCloser(strings.NewReader(string(artifact)))
			}
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Header: header, Body: body}, nil
			})
			base, err := NewClient("https://license.example.test", &http.Client{Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewRevocationClient(base)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Fetch(t.Context(), RevocationFetchRequest{InstallationID: installationID,
				PrivateKey: privateKey, Now: now, Known: test.known}); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Fetch() error = %v, want %v", err, ErrInvalidResponse)
			}
		})
	}
}

func revocationArtifactHeaders(t *testing.T, artifact []byte) http.Header {
	t.Helper()
	signed, err := entitlement.DecodeRevocationSet(artifact)
	if err != nil {
		t.Fatal(err)
	}
	digest := entitlement.RevocationSetDigest(artifact)
	header := make(http.Header)
	header.Set("Content-Type", entitlement.RevocationSetMediaTypeV2)
	header.Set("ETag", entitlement.RevocationSetETag(artifact))
	header.Set("X-Cdnca-Revocation-Revision", strconv.FormatUint(signed.Body.Revision, 10))
	header.Set("X-Cdnca-Revocation-Digest", base64.RawURLEncoding.EncodeToString(digest[:]))
	header.Set("X-Cdnca-Revocation-Expires-At", strconv.FormatInt(signed.Body.ExpiresAt, 10))
	return header
}

func revocationSnapshotForArtifact(t *testing.T, artifact []byte) entitlementguard.RevocationSnapshot {
	t.Helper()
	signed, err := entitlement.DecodeRevocationSet(artifact)
	if err != nil {
		t.Fatal(err)
	}
	digest := entitlement.RevocationSetDigest(artifact)
	return entitlementguard.RevocationSnapshot{
		InstallationID: signed.Body.InstallationID,
		Revision:       signed.Body.Revision,
		ArtifactSHA256: digest,
		ETag:           entitlement.RevocationSetETag(artifact),
		ExpiresAt:      time.Unix(signed.Body.ExpiresAt, 0).UTC(),
	}
}

func TestRevocationClientPreservesStableErrorCode(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	installationID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusServiceUnavailable,
			`{"error":{"code":"revocation_unavailable"}}`, nil), nil
	})
	base, _ := NewClient("https://license.example.test", &http.Client{Transport: transport})
	client, _ := NewRevocationClient(base)
	_, err := client.Fetch(t.Context(), RevocationFetchRequest{InstallationID: installationID,
		PrivateKey: privateKey, Now: now})
	var httpError *HTTPError
	if !errors.As(err, &httpError) || httpError.StatusCode != http.StatusServiceUnavailable ||
		httpError.Code != "revocation_unavailable" || !httpError.Retryable() {
		t.Fatalf("Fetch() error = %#v", err)
	}
}

func TestRevocationSyncerRetainsLKGUntilExpiryAndRecovers(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	installationID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	current := entitlementguard.RevocationSnapshot{InstallationID: installationID.String(), Revision: 6,
		ExpiresAt: now.Add(time.Minute), Artifact: []byte("current")}
	store := &memoryRevocationStore{current: &current}
	recovery := mustSignedRevocationArtifact(t, now.Add(time.Minute))
	fetcher := &scriptedRevocationFetcher{
		errors:    []error{errors.New("license service unavailable"), nil},
		responses: []RevocationFetchResponse{{}, {Artifact: recovery}},
	}
	clock := now
	syncer, err := NewRevocationSyncer(RevocationSyncConfig{
		Client: fetcher, Store: store, InstallationID: installationID, PrivateKey: privateKey,
		Now: func() time.Time { return clock }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.SyncOnce(t.Context()); err == nil {
		t.Fatal("transport outage unexpectedly succeeded")
	}
	if store.current == nil || store.current.Revision != 6 || len(store.installs) != 0 {
		t.Fatalf("outage changed LKG: %#v installs=%d", store.current, len(store.installs))
	}
	clock = now.Add(time.Minute)
	recovered, err := syncer.SyncOnce(t.Context())
	if err != nil || recovered.Revision != 7 || len(store.installs) != 1 {
		t.Fatalf("recovery = (%#v, %v), installs=%d", recovered, err, len(store.installs))
	}
	if fetcher.requests[0].Known == nil || fetcher.requests[1].Known != nil {
		t.Fatalf("known states = (%#v, %#v), expired state must not drive 304", fetcher.requests[0].Known, fetcher.requests[1].Known)
	}
}

func TestRevocationSyncerPollsEverySixtySeconds(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	installationID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	artifact := mustSignedRevocationArtifact(t, now)
	store := &memoryRevocationStore{}
	fetcher := &scriptedRevocationFetcher{responses: []RevocationFetchResponse{{Artifact: artifact}, {NotModified: true}}}
	ctx, cancel := context.WithCancel(t.Context())
	var waits []time.Duration
	syncer, err := NewRevocationSyncer(RevocationSyncConfig{
		Client: fetcher, Store: store, InstallationID: installationID, PrivateKey: privateKey,
		Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Wait: func(_ context.Context, delay time.Duration) error {
			waits = append(waits, delay)
			if len(waits) == 2 {
				cancel()
				return context.Canceled
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	if len(waits) != 2 || waits[0] != time.Minute || waits[1] != time.Minute {
		t.Fatalf("poll waits = %v", waits)
	}
}

func mustSignedRevocationArtifact(t *testing.T, issuedAt time.Time) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifyUntil := issuedAt.Add(24 * time.Hour)
	signed, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID:     "11111111-1111-4111-8111-111111111111",
		InstallationID: "22222222-2222-4222-8222-222222222222",
		LicenseID:      "33333333-3333-4333-8333-333333333333", Revision: 7,
		IssuedAt: issuedAt.Unix(), ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(),
		RevokedSerials: []uint64{2, 9},
	}, syncRevocationSigner{id: "revocation-key-1", private: privateKey}, entitlement.RevocationKeyWindow{
		NotBefore: issuedAt.Add(-time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

type syncRevocationSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (signer syncRevocationSigner) KeyID() string { return signer.id }

func (signer syncRevocationSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func TestLeaseRefreshGenerationHeaderParsing(t *testing.T) {
	for _, tc := range []struct {
		values []string
		want   uint64
		ok     bool
	}{
		{[]string{"0"}, 0, true},
		{[]string{"42"}, 42, true},
		{nil, 0, false},
		{[]string{"1", "2"}, 0, false},
		{[]string{"-1"}, 0, false},
		{[]string{"+3"}, 0, false},
		{[]string{"007"}, 0, false},
		{[]string{" 5"}, 0, false},
		{[]string{"18446744073709551616"}, 0, false},
	} {
		header := http.Header{}
		for _, value := range tc.values {
			header.Add(entitlement.RevocationLeaseRefreshGenerationHeader, value)
		}
		got, ok := leaseRefreshGeneration(header)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%v: (%d, %v), want (%d, %v)", tc.values, got, ok, tc.want, tc.ok)
		}
	}
}

func TestRevocationClientReturnsLeaseRefreshGeneration(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	installationID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	_, installationPrivate, _ := ed25519.GenerateKey(rand.Reader)
	artifact := mustSignedRevocationArtifact(t, now)
	signed, err := entitlement.DecodeRevocationSet(artifact)
	if err != nil {
		t.Fatal(err)
	}
	known := entitlementguard.RevocationSnapshot{Revision: signed.Body.Revision,
		ArtifactSHA256: entitlement.RevocationSetDigest(artifact), ETag: entitlement.RevocationSetETag(artifact),
		ExpiresAt: time.Unix(signed.Body.ExpiresAt, 0)}
	status := http.StatusOK
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		header := revocationArtifactHeaders(t, artifact)
		header.Set(entitlement.RevocationLeaseRefreshGenerationHeader, "9")
		body := string(artifact)
		if status == http.StatusNotModified {
			body = ""
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	base, err := NewClient("https://license.example.test", &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewRevocationClient(base)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Fetch(t.Context(), RevocationFetchRequest{InstallationID: installationID,
		PrivateKey: installationPrivate, Now: now})
	if err != nil || !response.HasLeaseRefreshGeneration || response.LeaseRefreshGeneration != 9 {
		t.Fatalf("200 Fetch() = (%+v, %v)", response, err)
	}
	status = http.StatusNotModified
	response, err = client.Fetch(t.Context(), RevocationFetchRequest{InstallationID: installationID,
		PrivateKey: installationPrivate, Now: now, Known: &known})
	if err != nil || !response.NotModified || !response.HasLeaseRefreshGeneration || response.LeaseRefreshGeneration != 9 {
		t.Fatalf("304 Fetch() = (%+v, %v)", response, err)
	}
}

type countingLeaseRefresher struct {
	calls int
	err   error
}

func (refresher *countingLeaseRefresher) SyncOnce(context.Context) (entitlementguard.Snapshot, error) {
	refresher.calls++
	return entitlementguard.Snapshot{}, refresher.err
}

func TestRevocationSyncerRefreshesLeaseOnlyWhenGenerationChanges(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	installationID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	artifact := mustSignedRevocationArtifact(t, now)
	gen := func(value uint64) RevocationFetchResponse {
		return RevocationFetchResponse{NotModified: true, LeaseRefreshGeneration: value, HasLeaseRefreshGeneration: true}
	}
	fetcher := &scriptedRevocationFetcher{responses: []RevocationFetchResponse{
		{Artifact: artifact, HasLeaseRefreshGeneration: true}, // generation 0: nothing changed yet
		gen(0), gen(3), gen(3), {NotModified: true} /* header missing: keep 3 */, gen(4), gen(5), gen(5),
	}}
	lease := &countingLeaseRefresher{}
	syncer, err := NewRevocationSyncer(RevocationSyncConfig{
		Client: fetcher, Store: &memoryRevocationStore{}, InstallationID: installationID, PrivateKey: privateKey,
		Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Lease: lease,
	})
	if err != nil {
		t.Fatal(err)
	}
	step := func(wantCalls int, refreshErr error, wantErr bool) {
		t.Helper()
		if _, err := syncer.SyncOnce(t.Context()); err != nil {
			t.Fatalf("SyncOnce: %v", err)
		}
		lease.err = refreshErr
		if err := syncer.RefreshLease(t.Context()); (err != nil) != wantErr || lease.calls != wantCalls {
			t.Fatalf("RefreshLease err=%v calls=%d, want err=%v calls=%d", err, lease.calls, wantErr, wantCalls)
		}
	}
	step(0, nil, false)                       // 0
	step(0, nil, false)                       // 0
	step(1, nil, false)                       // 0 → 3
	step(1, nil, false)                       // 3 unchanged
	step(1, nil, false)                       // header missing
	step(2, errors.New("license down"), true) // 3 → 4, renewal fails
	step(3, nil, false)                       // 5 (still pending), renewed
	step(3, nil, false)                       // 5 unchanged
	without, err := NewRevocationSyncer(RevocationSyncConfig{Client: fetcher, Store: &memoryRevocationStore{},
		InstallationID: installationID, PrivateKey: privateKey})
	if err != nil || without.RefreshLease(t.Context()) != nil {
		t.Fatalf("no lease refresher: %v", err)
	}
}
