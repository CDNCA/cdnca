package entitlementguard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type integrationSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (signer integrationSigner) KeyID() string { return signer.id }

func (signer integrationSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func TestDecodeTrustAndBundleStrictJSON(t *testing.T) {
	publicOne, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(one) error = %v", err)
	}
	publicTwo, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(two) error = %v", err)
	}
	trustedJSON := trustedKeysJSON{Keys: []verificationKeyJSON{{
		KeyID: "strict-json-key", PublicKey: base64.RawURLEncoding.EncodeToString(publicOne),
	}}}
	encodedTrust, err := json.Marshal(trustedJSON)
	if err != nil {
		t.Fatalf("Marshal(trust) error = %v", err)
	}
	if trust, err := DecodeTrustedKeys(encodedTrust); err != nil || trust == nil {
		t.Fatalf("DecodeTrustedKeys() = (%#v, %v)", trust, err)
	}
	duplicateTrust, err := json.Marshal(trustedKeysJSON{Keys: []verificationKeyJSON{
		{KeyID: "duplicate-key", PublicKey: base64.RawURLEncoding.EncodeToString(publicOne)},
		{KeyID: "duplicate-key", PublicKey: base64.RawURLEncoding.EncodeToString(publicTwo)},
	}})
	if err != nil {
		t.Fatalf("Marshal(duplicate trust) error = %v", err)
	}
	if _, err := DecodeTrustedKeys(duplicateTrust); !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("DecodeTrustedKeys(duplicate) error = %v, want ErrKeyConflict", err)
	}
	for _, invalid := range [][]byte{
		{},
		append(encodedTrust, []byte(` {}`)...),
		[]byte(`{"keys":[]}`),
		[]byte(`{"keys":[{"key_id":"k","public_key":"bad"}]}`),
		[]byte(`{"keys":[],"unknown":true}`),
	} {
		if _, err := DecodeTrustedKeys(invalid); !errors.Is(err, ErrInvalidTrustStore) {
			t.Fatalf("DecodeTrustedKeys(%q) error = %v", invalid, err)
		}
	}

	wire := installBundleJSON{InstallationID: "strict-json-installation"}
	encodedBundle, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("Marshal(bundle) error = %v", err)
	}
	if bundle, err := DecodeInstallBundle(encodedBundle); err != nil || bundle.InstallationID != wire.InstallationID {
		t.Fatalf("DecodeInstallBundle() = (%#v, %v)", bundle, err)
	}
	for _, invalid := range [][]byte{
		{},
		append(encodedBundle, []byte(` {}`)...),
		[]byte(`{"installation_id":"x","unknown":true}`),
		[]byte(`{"installation_id":"x","keys":[{"key_id":"attacker","public_key":"value"}]}`),
	} {
		if _, err := DecodeInstallBundle(invalid); !errors.Is(err, ErrInvalidBundle) {
			t.Fatalf("DecodeInstallBundle(%q) error = %v, want ErrInvalidBundle", invalid, err)
		}
	}
}

func TestInstallRequiresIndependentTrustAnchors(t *testing.T) {
	pool := isolatedEntitlementPool(t)
	var now time.Time
	if err := pool.QueryRow(t.Context(), `SELECT date_trunc('second',clock_timestamp())`).Scan(&now); err != nil {
		t.Fatalf("read database clock: %v", err)
	}
	publicOne, privateOne, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(one) error = %v", err)
	}
	publicTwo, privateTwo, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(two) error = %v", err)
	}
	verifyUntil := now.Add(24 * time.Hour)
	legitimateKey := VerificationKey{KeyID: "trusted-key-1", PublicKey: publicOne,
		NotBefore: now.Add(-24 * time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil}
	secondKey := VerificationKey{KeyID: "trusted-key-2", PublicKey: publicTwo,
		NotBefore: now.Add(-24 * time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil}
	trustOne := mustTrustStore(t, legitimateKey)
	service := NewService(pool, trustOne)
	legitimateSigner := integrationSigner{id: legitimateKey.KeyID, private: privateOne}
	attackerUnknownSigner := integrationSigner{id: "attacker-key", private: privateTwo}
	attackerSameIDSigner := integrationSigner{id: legitimateKey.KeyID, private: privateTwo}

	legitimateLease := integrationLease(now, 1)
	legitimateSigned := signIntegrationLease(t, legitimateLease, legitimateSigner)
	unknownSigned := signIntegrationLease(t, legitimateLease, attackerUnknownSigner)
	assertInstallError(t, service, InstallBundle{
		InstallationID: unknownSigned.Lease.InstallationID, SignedLease: unknownSigned,
	}, now, entitlement.ErrUnknownKey)
	sameIDSigned := signIntegrationLease(t, legitimateLease, attackerSameIDSigner)
	assertInstallError(t, service, InstallBundle{
		InstallationID: sameIDSigned.Lease.InstallationID, SignedLease: sameIDSigned,
	}, now, entitlement.ErrInvalidSignature)
	assertInstallError(t, NewService(pool, nil), InstallBundle{
		InstallationID: legitimateSigned.Lease.InstallationID, SignedLease: legitimateSigned,
	}, now, ErrTrustUnavailable)
	assertInstallError(t, service, InstallBundle{
		InstallationID: legitimateSigned.Lease.InstallationID,
		RevokedSerials: []uint64{legitimateSigned.Lease.Serial},
		SignedLease:    legitimateSigned,
	}, now, ErrUntrustedRevocations)

	tampered := legitimateSigned
	if tampered.Signature[0] == 'A' {
		tampered.Signature = "B" + tampered.Signature[1:]
	} else {
		tampered.Signature = "A" + tampered.Signature[1:]
	}
	assertInstallError(t, service, InstallBundle{
		InstallationID: tampered.Lease.InstallationID, SignedLease: tampered,
	}, now, entitlement.ErrInvalidSignature)
	badSchema := legitimateSigned
	badSchema.Lease.Schema = "cdnca.entitlement.lease/v0"
	assertInstallError(t, service, InstallBundle{
		InstallationID: badSchema.Lease.InstallationID, SignedLease: badSchema,
	}, now, entitlement.ErrInvalidLease)
	wrongAudienceLease := integrationLease(now, 1)
	wrongAudienceLease.Audience = "another-control-plane"
	wrongAudience := signIntegrationLease(t, wrongAudienceLease, legitimateSigner)
	assertInstallError(t, service, InstallBundle{
		InstallationID: wrongAudience.Lease.InstallationID, SignedLease: wrongAudience,
	}, now, entitlement.ErrAudienceMismatch)
	assertInstallError(t, service, InstallBundle{
		InstallationID: "different-installation", SignedLease: legitimateSigned,
	}, now, entitlement.ErrInstallationMismatch)

	var installationCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM control_installation_entitlement`).Scan(&installationCount); err != nil {
		t.Fatalf("count installation state after rejected bundles: %v", err)
	}
	if installationCount != 0 {
		t.Fatalf("rejected bundles persisted %d installation rows", installationCount)
	}
	acceptIntegrationRevocation(t, pool, trustOne, legitimateSigner, now, now.Add(-time.Second), 1, nil)

	snapshot, err := service.Install(context.Background(), InstallBundle{
		InstallationID: legitimateSigned.Lease.InstallationID,
		SignedLease:    legitimateSigned,
	}, now)
	if err != nil || snapshot.Status != entitlement.StatusValid || snapshot.Serial != 1 {
		t.Fatalf("Install(valid trusted anchor) = (%#v, %v)", snapshot, err)
	}

	if _, err := pool.Exec(context.Background(), `
		UPDATE entitlement_verification_keys SET public_key = $2 WHERE key_id = $1`,
		legitimateKey.KeyID, []byte(publicTwo)); err != nil {
		t.Fatalf("tamper persisted public key: %v", err)
	}
	restarted := NewService(pool, mustTrustStore(t, legitimateKey))
	attackerLease := integrationLease(now, 2)
	attackerAfterRestart := signIntegrationLease(t, attackerLease, attackerSameIDSigner)
	assertInstallError(t, restarted, InstallBundle{
		InstallationID: attackerAfterRestart.Lease.InstallationID,
		SignedLease:    attackerAfterRestart,
	}, now, entitlement.ErrInvalidSignature)
	var currentSerial int64
	if err := pool.QueryRow(context.Background(), `SELECT current_serial FROM control_installation_entitlement WHERE singleton`).Scan(&currentSerial); err != nil {
		t.Fatalf("read serial after attacker restart attempt: %v", err)
	}
	if currentSerial != 1 {
		t.Fatalf("attacker changed current serial to %d", currentSerial)
	}

	legitimateSecond := signIntegrationLease(t, attackerLease, legitimateSigner)
	if _, err := restarted.Install(context.Background(), InstallBundle{
		InstallationID: legitimateSecond.Lease.InstallationID,
		SignedLease:    legitimateSecond,
	}, now); err != nil {
		t.Fatalf("Install(repair trusted key metadata) error = %v", err)
	}
	var storedPublicKey []byte
	if err := pool.QueryRow(context.Background(), `
		SELECT public_key FROM entitlement_verification_keys WHERE key_id = $1`, legitimateKey.KeyID,
	).Scan(&storedPublicKey); err != nil {
		t.Fatalf("read repaired public key: %v", err)
	}
	if !bytes.Equal(storedPublicKey, publicOne) {
		t.Fatal("persisted public key was not restored from the deployment trust anchor")
	}

	secondSigner := integrationSigner{id: secondKey.KeyID, private: privateTwo}
	secondSigned := signIntegrationLease(t, integrationLease(now, 3), secondSigner)
	assertInstallError(t, restarted, InstallBundle{
		InstallationID: secondSigned.Lease.InstallationID, SignedLease: secondSigned,
	}, now, entitlement.ErrUnknownKey)
	preconfiguredRotation := NewService(pool, mustTrustStore(t, legitimateKey, secondKey))
	if _, err := preconfiguredRotation.Install(context.Background(), InstallBundle{
		InstallationID: secondSigned.Lease.InstallationID, SignedLease: secondSigned,
	}, now); err != nil {
		t.Fatalf("Install(preconfigured second anchor) error = %v", err)
	}

	assertInstallError(t, preconfiguredRotation, InstallBundle{
		InstallationID: legitimateSigned.Lease.InstallationID, SignedLease: legitimateSigned,
	}, now, ErrStaleLease)
	conflictingLease := integrationLease(now, 3)
	conflictingLease.Quotas[0].Limit++
	conflicting := signIntegrationLease(t, conflictingLease, secondSigner)
	assertInstallError(t, preconfiguredRotation, InstallBundle{
		InstallationID: conflicting.Lease.InstallationID, SignedLease: conflicting,
	}, now, ErrLeaseConflict)

	graceLease := integrationLease(now, 4)
	graceLease.NotBefore = now.Add(-3 * time.Hour).Unix()
	graceLease.ExpiresAt = now.Add(-time.Hour).Unix()
	graceLease.GraceUntil = now.Add(time.Hour).Unix()
	assertInstallStatus(t, preconfiguredRotation, graceLease, secondSigner, now, entitlement.StatusGrace)
	expiredLease := integrationLease(now, 5)
	expiredLease.NotBefore = now.Add(-4 * time.Hour).Unix()
	expiredLease.ExpiresAt = now.Add(-2 * time.Hour).Unix()
	expiredLease.GraceUntil = now.Add(-time.Hour).Unix()
	assertInstallStatus(t, preconfiguredRotation, expiredLease, secondSigner, now, entitlement.StatusExpired)

	var currentStatus string
	if err := pool.QueryRow(context.Background(), `
		SELECT current_serial, last_status FROM control_installation_entitlement WHERE singleton`,
	).Scan(&currentSerial, &currentStatus); err != nil {
		t.Fatalf("read current entitlement: %v", err)
	}
	if currentSerial != 5 || currentStatus != string(entitlement.StatusExpired) {
		t.Fatalf("current entitlement = serial %d status %q", currentSerial, currentStatus)
	}
}

func mustTrustStore(t *testing.T, keys ...VerificationKey) *TrustStore {
	t.Helper()
	store, err := NewTrustStore(keys)
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}
	return store
}

func integrationLease(now time.Time, serial uint64) entitlement.Lease {
	return entitlement.Lease{
		Schema:         entitlement.SchemaV1,
		Audience:       entitlement.ControlAudience,
		CustomerID:     integrationCustomerID,
		InstallationID: integrationInstallationID,
		LicenseID:      integrationLicenseID,
		Serial:         serial,
		NotBefore:      now.Add(-time.Hour).Unix(),
		ExpiresAt:      now.Add(time.Hour).Unix(),
		GraceUntil:     now.Add(2 * time.Hour).Unix(),
		Version:        entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features:       []entitlement.Feature{{Code: FeatureSitesManage}},
		Quotas:         []entitlement.Quota{{Code: QuotaDomainsCount, Limit: 10}},
	}
}

const (
	integrationCustomerID     = "11111111-1111-4111-8111-111111111111"
	integrationInstallationID = "22222222-2222-4222-8222-222222222222"
	integrationLicenseID      = "33333333-3333-4333-8333-333333333333"
)

func acceptIntegrationRevocation(t *testing.T, pool *pgxpool.Pool, trust *TrustStore,
	signer integrationSigner, acceptedAt, issuedAt time.Time, revision uint64, revoked []uint64,
) RevocationSnapshot {
	t.Helper()
	verifyUntil := issuedAt.Add(24 * time.Hour)
	ensureIntegrationKeyset(t, pool, trust, signer.id, acceptedAt, issuedAt.Add(-24*time.Hour), verifyUntil)
	signed, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: integrationCustomerID, InstallationID: integrationInstallationID,
		LicenseID: integrationLicenseID, Revision: revision, IssuedAt: issuedAt.Unix(),
		ExpiresAt:      issuedAt.Add(entitlement.RevocationSetWindow).Unix(),
		RevokedSerials: append([]uint64{}, revoked...),
	}, signer, entitlement.RevocationKeyWindow{NotBefore: issuedAt.Add(-24 * time.Hour),
		SignUntil: &verifyUntil, VerifyUntil: &verifyUntil})
	if err != nil {
		t.Fatalf("SignRevocationSet() error = %v", err)
	}
	artifact, err := signed.Encode()
	if err != nil {
		t.Fatalf("Encode(revocation) error = %v", err)
	}
	snapshot, err := NewRevocationService(pool, trust).Accept(t.Context(), artifact, acceptedAt)
	if err != nil {
		t.Fatalf("Accept(revocation %d) error = %v", revision, err)
	}
	return snapshot
}

func ensureIntegrationKeyset(t *testing.T, pool *pgxpool.Pool, trust *TrustStore, keyID string,
	acceptedAt, notBefore, verifyUntil time.Time,
) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM entitlement_signing_keyset_current_keys WHERE key_id=$1
	)`, keyID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		return
	}
	publicKey, found := trust.PublicKey(keyID)
	if !found {
		t.Fatalf("integration signing key %q is not trusted", keyID)
	}
	fingerprint := sha256.Sum256(publicKey)
	keysetPayload := []byte(fmt.Sprintf(
		`{"schema":"cdnca.signing-keyset/v2","active_key_id":%q,"keys":[`+
			`{"key_id":%q,"algorithm":"Ed25519","public_key":%q,"fingerprint":%q,`+
			`"status":"active","not_before":%q,"sign_until":%q,"verify_until":%q}],"rotations":[]}`,
		keyID, keyID, base64.RawURLEncoding.EncodeToString(publicKey),
		base64.RawURLEncoding.EncodeToString(fingerprint[:]), notBefore.Format(time.RFC3339Nano),
		verifyUntil.Format(time.RFC3339Nano), verifyUntil.Format(time.RFC3339Nano)))
	digest := sha256.Sum256(keysetPayload)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_lkg(
			singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,accepted_at,updated_at)
			VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`,
			`"`+base64.RawURLEncoding.EncodeToString(digest[:])+`"`, keyID,
			keysetPayload, digest[:], acceptedAt.UTC()); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_current_keys(
			key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at)
			VALUES($1,$2,'active',$3,$4,$4,$5,$6)`, keyID, publicKey, notBefore.UTC(),
			verifyUntil.UTC(), digest[:], acceptedAt.UTC())
		return err
	}); err != nil {
		t.Fatalf("seed integration signing keyset: %v", err)
	}
}

func signIntegrationLease(t *testing.T, lease entitlement.Lease, signer integrationSigner) entitlement.SignedLease {
	t.Helper()
	signed, err := entitlement.Sign(context.Background(), lease, signer)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return signed
}

func assertInstallError(t *testing.T, service *Service, bundle InstallBundle, now time.Time, expected error) {
	t.Helper()
	if _, err := service.Install(context.Background(), bundle, now); !errors.Is(err, expected) {
		t.Fatalf("Install() error = %v, want %v", err, expected)
	}
}

func assertInstallStatus(
	t *testing.T,
	service *Service,
	lease entitlement.Lease,
	signer integrationSigner,
	now time.Time,
	expected entitlement.Status,
) {
	t.Helper()
	signed := signIntegrationLease(t, lease, signer)
	snapshot, err := service.Install(context.Background(), InstallBundle{
		InstallationID: lease.InstallationID,
		SignedLease:    signed,
	}, now)
	if err != nil || snapshot.Status != expected {
		t.Fatalf("Install(status %s) = (%#v, %v)", expected, snapshot, err)
	}
}

func isolatedEntitlementPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open test administration pool: %v", err)
	}
	schema := "entitlement_guard_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^entitlement_guard_test_[a-f0-9]{32}$`).MatchString(schema) {
		adminPool.Close()
		t.Fatalf("refusing unexpected test schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		adminPool.Close()
		t.Fatalf("create isolated test schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		adminPool.Close()
		t.Fatalf("parse test database URL: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatalf("open isolated test pool: %v", err)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatalf("migrate isolated test schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := adminPool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated test schema: %v", err)
		}
		adminPool.Close()
	})
	return pool
}
