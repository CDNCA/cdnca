package certificateasset

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestUsePublicationMaterialsInTxPublishesSortedUploadedBindingsAndZeroes(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "publication-success")
	store := newPublicationStore(t, pool, &testEnvelopeCipher{}, certificateTestClock)
	pki := newCertificateFixture(t, leafOptions{domains: []string{"*.example.com"}})
	result := createBoundPublicationAsset(t, store, tenant, pki, tenant.siteOne, tenant.siteTwo)

	expectedSites := []uuid.UUID{tenant.siteOne, tenant.siteTwo}
	sort.Slice(expectedSites, func(left, right int) bool {
		return bytes.Compare(expectedSites[left][:], expectedSites[right][:]) < 0
	})
	requestSites := []uuid.UUID{expectedSites[1], expectedSites[0]}
	var tenantID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`,
		tenant.actor.ScopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareCertificate(pki.certificatePEM, pki.privateKeyPEM, nil, certificateTestNow)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(prepared.CanonicalPrivateKey)

	var retained [][]byte
	resolverCalls := 0
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return store.UsePublicationMaterialsInTx(t.Context(), tx, PublicationRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteIDs: requestSites, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1,
			OpaqueResolver: func(context.Context, OpaquePublicationResolveRequest) ([]byte, error) {
				resolverCalls++
				return nil, errPublicationOpaqueResolverInjected
			},
		}, func(materials []PublicationMaterial) error {
			if len(materials) != len(expectedSites) {
				t.Fatalf("material count = %d, want %d", len(materials), len(expectedSites))
			}
			for index, material := range materials {
				if material.SiteID != expectedSites[index] {
					t.Fatalf("material[%d].SiteID = %s, want %s", index, material.SiteID, expectedSites[index])
				}
				if material.TenantID != tenantID || material.TenantScopeID != tenant.actor.ScopeID ||
					material.AssetID != result.Asset.ID || material.AssetRevision != 2 ||
					material.CertificateVersionID != result.Version.ID || material.CertificateVersion != 1 ||
					material.BindingRevision != 1 {
					t.Fatalf("unexpected publication identity: %#v", material)
				}
				if !bytes.Equal(material.CertificatePEM, prepared.CanonicalPEM) ||
					!equalPublicationStrings(material.SANs, prepared.SANs) ||
					material.FingerprintSHA256 != prepared.Fingerprint ||
					material.PublicKeySHA256 != prepared.PublicKeySHA256 ||
					!material.NotBefore.Equal(prepared.NotBefore) || !material.NotAfter.Equal(prepared.NotAfter) ||
					!bytes.Equal(material.PrivateKeyPEM, prepared.CanonicalPrivateKey) {
					t.Fatalf("unexpected publication certificate material for site %s", material.SiteID)
				}
				retained = append(retained, material.PrivateKeyPEM)
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPublicationKeysZeroed(t, retained)
	if resolverCalls != 0 {
		t.Fatalf("uploaded publication called opaque resolver %d times", resolverCalls)
	}
}

func TestUsePublicationMaterialsInTxZeroesOnConsumerErrorAndPanic(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "publication-cleanup")
	store := newPublicationStore(t, pool, &testEnvelopeCipher{}, certificateTestClock)
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	result := createBoundPublicationAsset(t, store, tenant, pki, tenant.siteOne)
	request := PublicationRequest{TenantScopeID: tenant.actor.ScopeID, SiteIDs: []uuid.UUID{tenant.siteOne}, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1}
	sentinel := errors.New("publication consumer failure")

	var retainedOnError []byte
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return store.UsePublicationMaterialsInTx(t.Context(), tx, request, func(materials []PublicationMaterial) error {
			retainedOnError = materials[0].PrivateKeyPEM
			materials[0].PrivateKeyPEM = nil
			return sentinel
		})
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("consumer error = %v, want %v", err, sentinel)
	}
	assertPublicationKeysZeroed(t, [][]byte{retainedOnError})

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var retainedOnPanic []byte
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = store.UsePublicationMaterialsInTx(t.Context(), tx, request, func(materials []PublicationMaterial) error {
			retainedOnPanic = materials[0].PrivateKeyPEM
			materials[0].PrivateKeyPEM = nil
			panic(sentinel)
		})
	}()
	if recovered != sentinel {
		t.Fatalf("recovered panic = %v, want %v", recovered, sentinel)
	}
	assertPublicationKeysZeroed(t, [][]byte{retainedOnPanic})
}

func TestUsePublicationMaterialsInTxResolvesOpaqueACMEAndZeroes(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "publication-opaque-resolver")
	store := newPublicationStore(t, pool, &publicationOpaqueEnvelopeCipher{
		testEnvelopeCipher: &testEnvelopeCipher{},
	}, certificateTestClock)
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	wrapped := bytes.Repeat([]byte{0x71}, 64)
	result := createBoundOpaquePublicationAsset(t, pool, store, tenant, pki, wrapped, tenant.siteOne)
	prepared, err := prepareCertificate(pki.certificatePEM, pki.privateKeyPEM, nil, certificateTestNow)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(prepared.CanonicalPrivateKey)
	sentinel := errors.New("opaque publication consumer failure")
	var wrappedAlias, resolvedAlias, materialAlias []byte
	resolverCalls := 0

	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return store.UsePublicationMaterialsInTx(t.Context(), tx, PublicationRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteIDs: []uuid.UUID{tenant.siteOne}, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1,
			OpaqueResolver: func(_ context.Context, request OpaquePublicationResolveRequest) ([]byte, error) {
				resolverCalls++
				wrappedAlias = request.WrappedKeyMaterial
				if request.TenantScopeID != tenant.actor.ScopeID ||
					request.PrivateKeyReference != "acme-provider:key-1" ||
					request.ExpectedPublicKeySHA256 != prepared.PublicKeySHA256 ||
					!bytes.Equal(request.WrappedKeyMaterial, wrapped) {
					t.Fatalf("unexpected opaque resolver request: %#v", request)
				}
				var metadata struct {
					Schema string          `json:"schema"`
					Kind   string          `json:"kind"`
					Source json.RawMessage `json:"source"`
				}
				if json.Unmarshal(request.OuterEnvelopeMetadata, &metadata) != nil ||
					metadata.Schema != "cdnca.acme-certificate-envelope.v1" ||
					metadata.Kind != "opaque_wrapped" || !json.Valid(metadata.Source) {
					t.Fatalf("unexpected outer envelope metadata: %s", request.OuterEnvelopeMetadata)
				}
				// The production resolver returns the PKCS#8 DER acmeruntime
				// wrapped (certificatepublish/acme_resolver.go), not PEM.
				der, err := x509.MarshalPKCS8PrivateKey(pki.leafKey)
				if err != nil {
					t.Fatal(err)
				}
				resolvedAlias = der
				return resolvedAlias, nil
			},
		}, func(materials []PublicationMaterial) error {
			if len(materials) != 1 || materials[0].AssetID != result.Asset.ID ||
				!bytes.Equal(materials[0].PrivateKeyPEM, prepared.CanonicalPrivateKey) {
				t.Fatalf("unexpected resolved publication material: %#v", materials)
			}
			assertPublicationBytesZeroed(t, wrappedAlias)
			assertPublicationBytesZeroed(t, resolvedAlias)
			materialAlias = materials[0].PrivateKeyPEM
			return sentinel
		})
	})
	if !errors.Is(err, sentinel) || resolverCalls != 1 {
		t.Fatalf("opaque publication error = %v, resolver calls = %d", err, resolverCalls)
	}
	assertPublicationBytesZeroed(t, materialAlias)
}

func TestUsePublicationMaterialsInTxRejectsOpaqueResolverFailuresAndZeroes(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "publication-opaque-failures")
	store := newPublicationStore(t, pool, &publicationOpaqueEnvelopeCipher{
		testEnvelopeCipher: &testEnvelopeCipher{},
	}, certificateTestClock)
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	wrapped := bytes.Repeat([]byte{0x72}, 64)
	result := createBoundOpaquePublicationAsset(t, pool, store, tenant, pki, wrapped, tenant.siteOne)
	wrongPKI := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	base := PublicationRequest{TenantScopeID: tenant.actor.ScopeID, SiteIDs: []uuid.UUID{tenant.siteOne}, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1}

	t.Run("missing", func(t *testing.T) {
		assertPublicationError(t, pool, store, base, ErrEnvelopeUnavailable)
	})

	tests := []struct {
		name     string
		resolver func(*[]byte, *[]byte) OpaquePublicationResolver
	}{
		{name: "empty", resolver: func(wrappedAlias, _ *[]byte) OpaquePublicationResolver {
			return func(_ context.Context, request OpaquePublicationResolveRequest) ([]byte, error) {
				*wrappedAlias = request.WrappedKeyMaterial
				return nil, nil
			}
		}},
		{name: "error with bytes", resolver: func(wrappedAlias, resolvedAlias *[]byte) OpaquePublicationResolver {
			return func(_ context.Context, request OpaquePublicationResolveRequest) ([]byte, error) {
				*wrappedAlias = request.WrappedKeyMaterial
				*resolvedAlias = bytes.Repeat([]byte{0x73}, 64)
				return *resolvedAlias, errPublicationOpaqueResolverInjected
			}
		}},
		{name: "panic", resolver: func(wrappedAlias, _ *[]byte) OpaquePublicationResolver {
			return func(_ context.Context, request OpaquePublicationResolveRequest) ([]byte, error) {
				*wrappedAlias = request.WrappedKeyMaterial
				panic(errPublicationOpaqueResolverInjected)
			}
		}},
		{name: "wrong key", resolver: func(wrappedAlias, resolvedAlias *[]byte) OpaquePublicationResolver {
			return func(_ context.Context, request OpaquePublicationResolveRequest) ([]byte, error) {
				*wrappedAlias = request.WrappedKeyMaterial
				*resolvedAlias = append([]byte(nil), wrongPKI.privateKeyPEM...)
				return *resolvedAlias, nil
			}
		}},
		{name: "wrapped material tamper", resolver: func(wrappedAlias, _ *[]byte) OpaquePublicationResolver {
			return func(_ context.Context, request OpaquePublicationResolveRequest) ([]byte, error) {
				*wrappedAlias = request.WrappedKeyMaterial
				expected := append([]byte(nil), wrapped...)
				expected[0] ^= 0xff
				if bytes.Equal(request.WrappedKeyMaterial, expected) {
					t.Fatal("tampered material unexpectedly matched the authenticated fixture")
				}
				return nil, errPublicationOpaqueResolverInjected
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var wrappedAlias, resolvedAlias []byte
			request := base
			request.OpaqueResolver = test.resolver(&wrappedAlias, &resolvedAlias)
			assertPublicationError(t, pool, store, request, ErrEnvelopeUnavailable)
			assertPublicationBytesZeroed(t, wrappedAlias)
			if resolvedAlias != nil {
				assertPublicationBytesZeroed(t, resolvedAlias)
			}
		})
	}
}

func TestUsePublicationMaterialsInTxFailsClosedAtPublicationGates(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)

	t.Run("unbound and cross tenant", func(t *testing.T) {
		tenant := createCertificateTenant(t, pool, "publication-unbound")
		other := createCertificateTenant(t, pool, "publication-cross-tenant")
		store := newPublicationStore(t, pool, &testEnvelopeCipher{}, certificateTestClock)
		pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
		result := createBoundPublicationAsset(t, store, tenant, pki)
		assertPublicationError(t, pool, store, PublicationRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteIDs: []uuid.UUID{tenant.siteOne}, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1,
		}, ErrNotFound)
		resolverCalls := 0
		assertPublicationError(t, pool, store, PublicationRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteIDs: []uuid.UUID{other.siteOne}, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1,
			OpaqueResolver: func(context.Context, OpaquePublicationResolveRequest) ([]byte, error) {
				resolverCalls++
				return nil, errPublicationOpaqueResolverInjected
			},
		}, ErrNotFound)
		if resolverCalls != 0 {
			t.Fatalf("cross-tenant publication called opaque resolver %d times", resolverCalls)
		}
	})

	t.Run("validity boundaries", func(t *testing.T) {
		tenant := createCertificateTenant(t, pool, "publication-validity")
		store := newPublicationStore(t, pool, &testEnvelopeCipher{}, certificateTestClock)
		pki := newCertificateFixture(t, leafOptions{
			domains: []string{"www.example.com"}, notBefore: certificateTestNow.Add(-time.Hour),
			notAfter: certificateTestNow.Add(time.Hour),
		})
		result := createBoundPublicationAsset(t, store, tenant, pki, tenant.siteOne)
		store.now = func() time.Time { return pki.leaf.NotAfter }
		assertPublicationError(t, pool, store, PublicationRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteIDs: []uuid.UUID{tenant.siteOne}, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1,
		}, ErrCertificateExpired)
		store.now = func() time.Time { return pki.leaf.NotBefore.Add(-time.Second) }
		assertPublicationError(t, pool, store, PublicationRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteIDs: []uuid.UUID{tenant.siteOne}, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1,
		}, ErrCertificateNotYetValid)
	})

	t.Run("current site domain coverage", func(t *testing.T) {
		tenant := createCertificateTenant(t, pool, "publication-domain")
		store := newPublicationStore(t, pool, &testEnvelopeCipher{}, certificateTestClock)
		pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
		result := createBoundPublicationAsset(t, store, tenant, pki, tenant.siteOne)
		if _, err := pool.Exec(t.Context(), `UPDATE sites SET domain='drifted.example.net' WHERE id=$1`,
			tenant.siteOne); err != nil {
			t.Fatal(err)
		}
		assertPublicationError(t, pool, store, PublicationRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteIDs: []uuid.UUID{tenant.siteOne}, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1,
		}, ErrDomainNotCovered)
	})

	t.Run("opaque ACME material", func(t *testing.T) {
		tenant := createCertificateTenant(t, pool, "publication-opaque-acme")
		store := newPublicationStore(t, pool, &testEnvelopeCipher{}, certificateTestClock)
		pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
		publicKeyDER, err := x509.MarshalPKIXPublicKey(pki.leafKey.Public())
		if err != nil {
			t.Fatal(err)
		}
		orderID := insertCertificateOrder(t, pool, tenant.actor, pki.leaf.DNSNames, pki.leaf.NotAfter)
		result, err := store.Import(t.Context(), tenant.actor, ImportRequest{
			TenantScopeID: tenant.actor.ScopeID, Name: "opaque ACME publication", Source: SourceACME,
			ACMEOrderID: &orderID, CertificatePEM: pki.certificatePEM,
			OpaquePrivateKey: &OpaquePrivateKey{
				KeyReference: "acme-provider:key-1", PublicKeySPKIDER: publicKeyDER,
				WrappedKeyMaterial: bytes.Repeat([]byte{0x5a}, 32), Metadata: []byte(`{"provider":"test"}`),
			},
			IdempotencyKey: "publication-opaque-import", RequestID: "publication-opaque-import",
		})
		if err != nil {
			t.Fatal(err)
		}
		activateAndBindPublicationAsset(t, store, tenant, result, tenant.siteOne)
		assertPublicationError(t, pool, store, PublicationRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteIDs: []uuid.UUID{tenant.siteOne}, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1,
		}, ErrEnvelopeUnavailable)
	})

	t.Run("unseal failure", func(t *testing.T) {
		tenant := createCertificateTenant(t, pool, "publication-unseal-failure")
		cipher := &testEnvelopeCipher{}
		store := newPublicationStore(t, pool, cipher, certificateTestClock)
		pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
		result := createBoundPublicationAsset(t, store, tenant, pki, tenant.siteOne)
		cipher.err = errors.New("injected unseal failure")
		assertPublicationError(t, pool, store, PublicationRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteIDs: []uuid.UUID{tenant.siteOne}, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1,
		}, ErrEnvelopeUnavailable)
	})

	t.Run("unsealed key mismatch", func(t *testing.T) {
		tenant := createCertificateTenant(t, pool, "publication-key-mismatch")
		wrongPKI := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
		enveloper := &publicationWrongKeyEnveloper{
			testEnvelopeCipher: &testEnvelopeCipher{}, plaintext: wrongPKI.privateKeyPEM,
		}
		store := newPublicationStore(t, pool, enveloper, certificateTestClock)
		pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
		result := createBoundPublicationAsset(t, store, tenant, pki, tenant.siteOne)
		assertPublicationError(t, pool, store, PublicationRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteIDs: []uuid.UUID{tenant.siteOne}, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1,
		}, ErrEnvelopeUnavailable)
	})
}

func TestUsePublicationMaterialsInTxHoldsSiteLockThroughConsumer(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "publication-lock")
	store := newPublicationStore(t, pool, &testEnvelopeCipher{}, certificateTestClock)
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	result := createBoundPublicationAsset(t, store, tenant, pki, tenant.siteOne)
	entered := make(chan struct{})
	release := make(chan struct{})
	publicationDone := make(chan error, 1)

	go func() {
		publicationDone <- pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
			return store.UsePublicationMaterialsInTx(context.Background(), tx, PublicationRequest{
				TenantScopeID: tenant.actor.ScopeID, SiteIDs: []uuid.UUID{tenant.siteOne}, AssetID: result.Asset.ID, VersionID: result.Version.ID, BindingRevision: 1,
			}, func([]PublicationMaterial) error {
				close(entered)
				<-release
				return nil
			})
		})
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("publication consumer did not start")
	}

	unbindDone := make(chan error, 1)
	go func() {
		_, err := store.Unbind(context.Background(), tenant.actor, UnbindRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOne, ExpectedRevision: 1,
			IdempotencyKey: "publication-lock-unbind", RequestID: "publication-lock-unbind",
		})
		unbindDone <- err
	}()
	select {
	case err := <-unbindDone:
		close(release)
		t.Fatalf("unbind completed while publication held the site lock: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-publicationDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("publication transaction did not finish after release")
	}
	select {
	case err := <-unbindDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unbind did not finish after publication released its locks")
	}
}

type publicationWrongKeyEnveloper struct {
	*testEnvelopeCipher
	plaintext []byte
}

func (enveloper *publicationWrongKeyEnveloper) Unseal(
	context.Context,
	PrivateKeyUnsealRequest,
) ([]byte, error) {
	return append([]byte(nil), enveloper.plaintext...), nil
}

type publicationOpaqueEnvelopeCipher struct {
	*testEnvelopeCipher
}

func (enveloper *publicationOpaqueEnvelopeCipher) SealOpaque(
	_ context.Context,
	request OpaquePrivateKeySealRequest,
) (PrivateKeyEnvelope, error) {
	envelope, err := sealTestEnvelope(request.Context, request.WrappedKeyMaterial, "test-kek-v1")
	if err != nil {
		return PrivateKeyEnvelope{}, err
	}
	envelope.Metadata, err = json.Marshal(struct {
		Schema string          `json:"schema"`
		Kind   string          `json:"kind"`
		Source json.RawMessage `json:"source"`
	}{
		Schema: "cdnca.acme-certificate-envelope.v1", Kind: "opaque_wrapped",
		Source: append(json.RawMessage(nil), request.Metadata...),
	})
	if err != nil {
		return PrivateKeyEnvelope{}, err
	}
	return envelope, nil
}

func newPublicationStore(
	t *testing.T,
	pool *pgxpool.Pool,
	enveloper PrivateKeyEnveloper,
	now Clock,
) *Store {
	t.Helper()
	store, err := NewStoreWithDependencies(pool, enveloper, audit.New(pool), now)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func createBoundPublicationAsset(
	t *testing.T,
	store *Store,
	tenant certificateTenantFixture,
	pki certificateFixture,
	siteIDs ...uuid.UUID,
) ImportResult {
	t.Helper()
	result, err := store.Import(t.Context(), tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "uploaded publication", Source: SourceUploaded,
		CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
		IdempotencyKey: "publication-import-" + uuid.NewString(),
		RequestID:      "publication-import-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	activateAndBindPublicationAsset(t, store, tenant, result, siteIDs...)
	return result
}

func createBoundOpaquePublicationAsset(
	t *testing.T,
	pool *pgxpool.Pool,
	store *Store,
	tenant certificateTenantFixture,
	pki certificateFixture,
	wrapped []byte,
	siteIDs ...uuid.UUID,
) ImportResult {
	t.Helper()
	publicKeyDER, err := x509.MarshalPKIXPublicKey(pki.leafKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	orderID := insertCertificateOrder(t, pool, tenant.actor, pki.leaf.DNSNames, pki.leaf.NotAfter)
	result, err := store.Import(t.Context(), tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "opaque ACME publication", Source: SourceACME,
		ACMEOrderID: &orderID, CertificatePEM: pki.certificatePEM,
		OpaquePrivateKey: &OpaquePrivateKey{
			KeyReference: "acme-provider:key-1", PublicKeySPKIDER: publicKeyDER,
			WrappedKeyMaterial: append([]byte(nil), wrapped...), Metadata: []byte(`{"provider":"test"}`),
		},
		IdempotencyKey: "publication-opaque-import-" + uuid.NewString(),
		RequestID:      "publication-opaque-import-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	activateAndBindPublicationAsset(t, store, tenant, result, siteIDs...)
	return result
}

func activateAndBindPublicationAsset(
	t *testing.T,
	store *Store,
	tenant certificateTenantFixture,
	result ImportResult,
	siteIDs ...uuid.UUID,
) {
	t.Helper()
	if _, err := store.Activate(t.Context(), tenant.actor, ActivateRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: result.Asset.ID, VersionID: result.Version.ID,
		ExpectedRevision: result.Asset.Revision, IdempotencyKey: "publication-activate-" + uuid.NewString(),
		RequestID: "publication-activate-" + uuid.NewString(),
	}); err != nil {
		t.Fatal(err)
	}
	for _, siteID := range siteIDs {
		if _, err := store.Bind(t.Context(), tenant.actor, BindRequest{
			TenantScopeID: tenant.actor.ScopeID, SiteID: siteID, AssetID: result.Asset.ID,
			VersionID: result.Version.ID, ExpectedRevision: 0,
			IdempotencyKey: "publication-bind-" + uuid.NewString(),
			RequestID:      "publication-bind-" + uuid.NewString(),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func assertPublicationError(
	t *testing.T,
	pool *pgxpool.Pool,
	store *Store,
	request PublicationRequest,
	want error,
) {
	t.Helper()
	consumerCalled := false
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return store.UsePublicationMaterialsInTx(t.Context(), tx, request, func([]PublicationMaterial) error {
			consumerCalled = true
			return nil
		})
	})
	if !errors.Is(err, want) {
		t.Fatalf("publication error = %v, want %v", err, want)
	}
	if consumerCalled {
		t.Fatal("publication consumer was called after a failed gate")
	}
}

func assertPublicationKeysZeroed(t *testing.T, keys [][]byte) {
	t.Helper()
	if len(keys) == 0 {
		t.Fatal("no private key aliases retained")
	}
	for keyIndex, key := range keys {
		if len(key) == 0 {
			t.Fatalf("private key alias %d is unexpectedly empty", keyIndex)
		}
		for byteIndex, value := range key {
			if value != 0 {
				t.Fatalf("private key alias %d byte %d was not zeroed", keyIndex, byteIndex)
			}
		}
	}
}
