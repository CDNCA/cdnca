package entitlementsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

var errTransportUnknown = errors.New("transport result unknown")

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type memoryStore struct {
	mu       sync.Mutex
	current  *entitlement.SignedLease
	installs []entitlementguard.InstallBundle
}

func (store *memoryStore) Current(context.Context) (entitlement.SignedLease, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current == nil {
		return entitlement.SignedLease{}, ErrNoLocalLease
	}
	return *store.current, nil
}

func (store *memoryStore) Install(
	_ context.Context,
	bundle entitlementguard.InstallBundle,
	now time.Time,
) (entitlementguard.Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.installs = append(store.installs, bundle)
	current := bundle.SignedLease
	store.current = &current
	return entitlementguard.Snapshot{
		InstallationID: bundle.InstallationID,
		Serial:         current.Lease.Serial,
		KeyID:          current.KeyID,
		Status:         entitlement.StatusValid,
		VerifiedAt:     now,
	}, nil
}

type testSigner struct {
	id  string
	key ed25519.PrivateKey
}

func (signer testSigner) KeyID() string { return signer.id }

func (signer testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, payload), nil
}

func TestActivationRetriesStableRequestAndInstallsVerifiedLease(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	installationID := uuid.New()
	installationPublic, installationPrivate := mustKeyPair(t)
	platformPublic, platformPrivate := mustKeyPair(t)
	trust := mustTrust(t, "platform-key", platformPublic)
	signed := mustSignedLease(t, testSigner{"platform-key", platformPrivate}, testLease(now, installationID, 1))
	encodedResponse := mustJSON(t, leaseResponse{LeaseID: uuid.New(), SignedLease: signed})

	var bodies [][]byte
	var requestIDs []string
	attempt := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		requestIDs = append(requestIDs, request.Header.Get("Idempotency-Key"))
		attempt++
		switch attempt {
		case 1:
			return nil, errTransportUnknown
		case 2:
			return jsonResponse(http.StatusInternalServerError, `{"code":"internal"}`, nil), nil
		case 3:
			return jsonResponse(http.StatusTooManyRequests, `{"code":"rate_limited"}`, map[string]string{"Retry-After": "30"}), nil
		default:
			return jsonResponse(http.StatusOK, string(encodedResponse), nil), nil
		}
	})
	client, err := NewClient("https://license.example.test", &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryStore{}
	var waits []time.Duration
	syncer, err := New(Config{
		Client: client, Store: store, Trust: trust, InstallationID: installationID,
		InstallationName: "Primary control", PrivateKey: installationPrivate,
		Activation: func(context.Context) (string, error) {
			return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), nil
		},
		Now: func() time.Time { return now },
		Wait: func(_ context.Context, delay time.Duration) error {
			waits = append(waits, delay)
			return nil
		},
		Jitter: func(delay time.Duration) time.Duration { return delay },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), BackoffMin: time.Second, BackoffMax: 4 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := syncer.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("SyncOnce() error = %v", err)
	}
	if snapshot.Serial != 1 || len(store.installs) != 1 {
		t.Fatalf("activation snapshot=%#v installs=%d", snapshot, len(store.installs))
	}
	if len(bodies) != 4 || len(waits) != 3 || waits[0] != time.Second || waits[1] != 2*time.Second || waits[2] != 4*time.Second {
		t.Fatalf("attempt bodies=%d waits=%v", len(bodies), waits)
	}
	for index := 1; index < len(bodies); index++ {
		if !bytes.Equal(bodies[0], bodies[index]) || requestIDs[0] != requestIDs[index] {
			t.Fatalf("retry %d changed idempotency identity or body", index)
		}
	}
	if requestIDs[0] == "" || requestIDs[0] != requestIDs[len(requestIDs)-1] {
		t.Fatalf("request IDs = %#v", requestIDs)
	}
	var activation struct {
		InstallationID uuid.UUID `json:"installation_id"`
		Name           string    `json:"name"`
		ActivationCode string    `json:"activation_code"`
		PublicKey      string    `json:"public_key"`
		Proof          string    `json:"proof"`
	}
	if err := json.Unmarshal(bodies[0], &activation); err != nil {
		t.Fatal(err)
	}
	proof, _ := base64.RawURLEncoding.DecodeString(activation.Proof)
	encodedPublic, _ := base64.RawURLEncoding.DecodeString(activation.PublicKey)
	if !bytes.Equal(encodedPublic, installationPublic) {
		t.Fatal("activation body contains a different installation public key")
	}
	expected := licenseActivationProof(requestIDs[0], installationID, activation.Name, installationPublic, activation.ActivationCode)
	if !ed25519.Verify(installationPublic, expected, proof) {
		t.Fatal("activation proof is not compatible with the license-service v1 message")
	}
}

func TestActivationCanBeFetchedBeforeRevocationAndInstalledAfter(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	installationID := uuid.New()
	_, installationPrivate := mustKeyPair(t)
	platformPublic, platformPrivate := mustKeyPair(t)
	trust := mustTrust(t, "platform-key", platformPublic)
	signed := mustSignedLease(t, testSigner{"platform-key", platformPrivate}, testLease(now, installationID, 1))
	client, _ := NewClient("https://license.example.test", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, string(mustJSON(t, leaseResponse{LeaseID: uuid.New(), SignedLease: signed})), nil), nil
	})})
	store := &memoryStore{}
	syncer, err := New(Config{
		Client: client, Store: store, Trust: trust, InstallationID: installationID,
		InstallationName: "Primary control", PrivateKey: installationPrivate,
		Activation: func(context.Context) (string, error) {
			return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), nil
		},
		Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	prepared, err := syncer.FetchOnce(t.Context())
	if err != nil {
		t.Fatalf("FetchOnce() error = %v", err)
	}
	if len(store.installs) != 0 {
		t.Fatal("FetchOnce installed the lease before revocation initialization")
	}
	if _, err := syncer.Install(t.Context(), prepared); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if len(store.installs) != 1 || store.installs[0].SignedLease.Lease.Serial != 1 {
		t.Fatalf("installs = %#v", store.installs)
	}
}

func TestRestartWithLocalLeaseRenewsWithoutActivationCredential(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	installationID := uuid.New()
	installationPublic, installationPrivate := mustKeyPair(t)
	platformPublic, platformPrivate := mustKeyPair(t)
	trust := mustTrust(t, "platform-key", platformPublic)
	current := mustSignedLease(t, testSigner{"platform-key", platformPrivate}, testLease(now, installationID, 9))
	next := mustSignedLease(t, testSigner{"platform-key", platformPrivate}, testLease(now, installationID, 10))
	store := &memoryStore{current: &current}

	var observedPath, observedRequestID string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		observedPath = request.URL.Path
		observedRequestID = request.Header.Get("Idempotency-Key")
		var body struct {
			Proof string `json:"proof"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		proof, _ := base64.RawURLEncoding.DecodeString(body.Proof)
		if !ed25519.Verify(installationPublic, licenseRenewalProof(installationID, observedRequestID), proof) {
			t.Fatal("renewal proof is not compatible with the license-service v1 message")
		}
		return jsonResponse(http.StatusOK, string(mustJSON(t, leaseResponse{LeaseID: uuid.New(), SignedLease: next})), nil), nil
	})
	client, _ := NewClient("https://license.example.test", &http.Client{Transport: transport})
	syncer, err := New(Config{
		Client: client, Store: store, Trust: trust, InstallationID: installationID,
		InstallationName: "Primary control", PrivateKey: installationPrivate,
		Activation: func(context.Context) (string, error) {
			t.Fatal("restart with a local lease unexpectedly read activation credential")
			return "", nil
		},
		Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce() renewal error = %v", err)
	}
	if observedPath != "/activation/v1/installations/"+installationID.String()+"/leases:renew" ||
		observedRequestID != "control-renew-"+installationID.String()+"-9" {
		t.Fatalf("renew path=%q requestID=%q", observedPath, observedRequestID)
	}
	if len(store.installs) != 1 || store.installs[0].SignedLease.Lease.Serial != 10 {
		t.Fatalf("renew installs = %#v", store.installs)
	}
}

func TestSynchronizedLeaseMustBeCurrentAndTrusted(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	installationID := uuid.New()
	_, installationPrivate := mustKeyPair(t)
	platformPublic, platformPrivate := mustKeyPair(t)
	_, unknownPrivate := mustKeyPair(t)
	trust := mustTrust(t, "platform-key", platformPublic)
	base := testLease(now, installationID, 1)
	tests := []struct {
		name   string
		signed func(*testing.T) entitlement.SignedLease
	}{
		{"wrong audience", func(t *testing.T) entitlement.SignedLease {
			lease := base
			lease.Audience = "another-control-plane"
			return mustSignedLease(t, testSigner{"platform-key", platformPrivate}, lease)
		}},
		{"wrong installation", func(t *testing.T) entitlement.SignedLease {
			lease := base
			lease.InstallationID = uuid.NewString()
			return mustSignedLease(t, testSigner{"platform-key", platformPrivate}, lease)
		}},
		{"unknown key", func(t *testing.T) entitlement.SignedLease {
			return mustSignedLease(t, testSigner{"unknown-key", unknownPrivate}, base)
		}},
		{"tampered", func(t *testing.T) entitlement.SignedLease {
			signed := mustSignedLease(t, testSigner{"platform-key", platformPrivate}, base)
			signed.Lease.Serial++
			return signed
		}},
		{"expired", func(t *testing.T) entitlement.SignedLease {
			lease := base
			lease.NotBefore = now.Add(-3 * time.Hour).Unix()
			lease.ExpiresAt = now.Add(-2 * time.Hour).Unix()
			lease.GraceUntil = now.Add(-time.Hour).Unix()
			return mustSignedLease(t, testSigner{"platform-key", platformPrivate}, lease)
		}},
		{"not yet valid", func(t *testing.T) entitlement.SignedLease {
			lease := base
			lease.NotBefore = now.Add(time.Hour).Unix()
			lease.ExpiresAt = now.Add(2 * time.Hour).Unix()
			lease.GraceUntil = now.Add(3 * time.Hour).Unix()
			return mustSignedLease(t, testSigner{"platform-key", platformPrivate}, lease)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &memoryStore{}
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, string(mustJSON(t, leaseResponse{
					LeaseID: uuid.New(), SignedLease: test.signed(t),
				})), nil), nil
			})
			client, _ := NewClient("https://license.example.test", &http.Client{Transport: transport})
			syncer, err := New(Config{
				Client: client, Store: store, Trust: trust, InstallationID: installationID,
				InstallationName: "Primary", PrivateKey: installationPrivate,
				Activation: func(context.Context) (string, error) {
					return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), nil
				},
				Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := syncer.SyncOnce(context.Background()); err == nil {
				t.Fatal("untrusted synchronized lease unexpectedly installed")
			}
			if len(store.installs) != 0 {
				t.Fatalf("untrusted synchronized lease wrote %d installs", len(store.installs))
			}
		})
	}
}

func TestDefinitiveHTTPFailureIsNotRetried(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	installationID := uuid.New()
	_, installationPrivate := mustKeyPair(t)
	platformPublic, _ := mustKeyPair(t)
	trust := mustTrust(t, "platform-key", platformPublic)
	attempts := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		return jsonResponse(http.StatusUnauthorized, `{"code":"invalid_credential"}`, nil), nil
	})
	client, _ := NewClient("https://license.example.test", &http.Client{Transport: transport})
	syncer, err := New(Config{
		Client: client, Store: &memoryStore{}, Trust: trust, InstallationID: installationID,
		InstallationName: "Primary", PrivateKey: installationPrivate,
		Activation: func(context.Context) (string, error) {
			return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), nil
		},
		Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("401 unexpectedly succeeded")
	}
	if attempts != 1 {
		t.Fatalf("definitive response attempts = %d", attempts)
	}
}

func TestRunUsesRemainingTTLAndStopsWithContext(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	installationID := uuid.New()
	_, installationPrivate := mustKeyPair(t)
	platformPublic, platformPrivate := mustKeyPair(t)
	trust := mustTrust(t, "platform-key", platformPublic)
	lease := testLease(now, installationID, 1)
	lease.NotBefore = now.Add(-time.Hour).Unix()
	lease.ExpiresAt = now.Add(2 * time.Hour).Unix()
	lease.GraceUntil = now.Add(3 * time.Hour).Unix()
	current := mustSignedLease(t, testSigner{"platform-key", platformPrivate}, lease)
	store := &memoryStore{current: &current}
	client, _ := NewClient("https://license.example.test", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("Run contacted license service before renewal window")
		return nil, nil
	})})
	var delay time.Duration
	syncer, err := New(Config{
		Client: client, Store: store, Trust: trust, InstallationID: installationID,
		InstallationName: "Primary", PrivateKey: installationPrivate, Now: func() time.Time { return now },
		Wait: func(ctx context.Context, value time.Duration) error {
			delay = value
			return context.Canceled
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	if delay != time.Hour {
		t.Fatalf("renewal delay = %v, want 1h", delay)
	}
}

// ui-leftover3 #3：一次不可重试的续租失败（此处 401）曾让 Run 直接返回，main.go 的续租
// goroutine 随之退出、此后永不续租，宽限期一过主控即被锁成 lease_expired 只读。
// Run 必须记录失败、退避后继续续租，只在 context 结束时返回。
func TestRunKeepsRenewingAfterDefinitiveRenewalFailure(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	installationID := uuid.New()
	_, installationPrivate := mustKeyPair(t)
	platformPublic, platformPrivate := mustKeyPair(t)
	trust := mustTrust(t, "platform-key", platformPublic)
	lease := testLease(now, installationID, 3)
	lease.NotBefore = now.Add(-time.Hour).Unix()
	lease.ExpiresAt = now.Add(time.Minute).Unix() // inside the renewal window
	current := mustSignedLease(t, testSigner{"platform-key", platformPrivate}, lease)
	attempts := 0
	client, _ := NewClient("https://license.example.test", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		return jsonResponse(http.StatusUnauthorized, `{"code":"invalid_proof"}`, nil), nil
	})})
	var waits []time.Duration
	syncer, err := New(Config{
		Client: client, Store: &memoryStore{current: &current}, Trust: trust, InstallationID: installationID,
		InstallationName: "Primary", PrivateKey: installationPrivate, Now: func() time.Time { return now },
		Wait: func(_ context.Context, value time.Duration) error {
			waits = append(waits, value)
			if len(waits) == 2 {
				return context.Canceled
			}
			return nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want it to keep renewing until the context ends", err)
	}
	if attempts != 2 || len(waits) != 2 || waits[0] != defaultBackoffMax {
		t.Fatalf("attempts=%d waits=%v, want 2 attempts separated by a %v back-off", attempts, waits, defaultBackoffMax)
	}
}

func TestUnavailableLicenseServiceKeepsCurrentLease(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	installationID := uuid.New()
	_, installationPrivate := mustKeyPair(t)
	platformPublic, platformPrivate := mustKeyPair(t)
	trust := mustTrust(t, "platform-key", platformPublic)
	current := mustSignedLease(t, testSigner{"platform-key", platformPrivate}, testLease(now, installationID, 6))
	store := &memoryStore{current: &current}
	client, _ := NewClient("https://license.example.test", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errTransportUnknown
	})})
	syncer, err := New(Config{
		Client: client, Store: store, Trust: trust, InstallationID: installationID,
		InstallationName: "Primary", PrivateKey: installationPrivate, Now: func() time.Time { return now },
		Wait:   func(context.Context, time.Duration) error { return context.Canceled },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.SyncOnce(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("SyncOnce() unavailable error = %v", err)
	}
	if len(store.installs) != 0 || store.current == nil || store.current.Lease.Serial != 6 {
		t.Fatalf("unavailable service changed local lease: current=%#v installs=%d", store.current, len(store.installs))
	}
}

func TestNewClientRequiresHTTPS(t *testing.T) {
	for _, rawURL := range []string{"", "http://license.example.test", "https://user@license.example.test", "https://license.example.test?token=x"} {
		if _, err := NewClient(rawURL, nil); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("NewClient(%q) error = %v", rawURL, err)
		}
	}
	if _, err := NewClient("https://license.example.test", nil); err != nil {
		t.Fatalf("NewClient(https) error = %v", err)
	}
}

func testLease(now time.Time, installationID uuid.UUID, serial uint64) entitlement.Lease {
	return entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		CustomerID: uuid.NewString(), InstallationID: installationID.String(), LicenseID: uuid.NewString(), Serial: serial,
		NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), GraceUntil: now.Add(2 * time.Hour).Unix(),
		Version:  entitlement.VersionRange{Channel: "stable", Min: "1.0.0", Max: "2.0.0"},
		Features: []entitlement.Feature{{Code: "nodes.manage"}}, Quotas: []entitlement.Quota{{Code: "nodes.count", Limit: 2}},
	}
}

func mustSignedLease(t *testing.T, signer entitlement.Signer, lease entitlement.Lease) entitlement.SignedLease {
	t.Helper()
	signed, err := entitlement.Sign(context.Background(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func mustTrust(t *testing.T, keyID string, publicKey ed25519.PublicKey) *entitlementguard.TrustStore {
	t.Helper()
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: keyID, PublicKey: publicKey}})
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

func mustKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func jsonResponse(status int, body string, headers map[string]string) *http.Response {
	response := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	for name, value := range headers {
		response.Header.Set(name, value)
	}
	return response
}

func licenseActivationProof(
	requestID string,
	installationID uuid.UUID,
	name string,
	publicKey ed25519.PublicKey,
	activationCode string,
) []byte {
	codeHash := sha256.Sum256([]byte(activationCode))
	return licenseDigestFields(
		"cdnca-license-activation-proof/v1", requestID, installationID.String(), strings.TrimSpace(name),
		base64.RawURLEncoding.EncodeToString(publicKey), base64.RawURLEncoding.EncodeToString(codeHash[:]),
	)
}

func licenseRenewalProof(installationID uuid.UUID, requestID string) []byte {
	return licenseDigestFields("cdnca-license-renewal-proof/v1", requestID, installationID.String())
}

func licenseDigestFields(values ...string) []byte {
	hash := sha256.New()
	var size [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	return hash.Sum(nil)
}
