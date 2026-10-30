// Package guardtest installs the local entitlement facts integration tests
// need before entitlementguard.Service.Install accepts a lease: the signing
// keyset LKG and a signed revocation set for the lease's installation
// (Install refuses a lease while no revocation LKG exists).
package guardtest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Signer is the lease signer of a test: its key ID and private key.
type Signer interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

// AcceptRevocation stores signer's key as the active signing keyset LKG and
// accepts an empty signed revocation set (revision 1) for lease's customer,
// installation and license, all valid at now. The lease IDs must be canonical
// UUIDs (revocation sets accept nothing else).
func AcceptRevocation(t testing.TB, pool *pgxpool.Pool, trust *entitlementguard.TrustStore, signer Signer,
	lease entitlement.Lease, now time.Time) {
	t.Helper()
	publicKey, ok := trust.PublicKey(signer.KeyID())
	if !ok {
		t.Fatalf("signing key %q is not trusted", signer.KeyID())
	}
	notBefore, until := now.Add(-24*time.Hour), now.Add(24*time.Hour)
	fingerprint := sha256.Sum256(publicKey)
	keyset := []byte(fmt.Sprintf(
		`{"schema":"cdnca.signing-keyset/v2","active_key_id":%q,"keys":[`+
			`{"key_id":%q,"algorithm":"Ed25519","public_key":%q,"fingerprint":%q,`+
			`"status":"active","not_before":%q,"sign_until":%q,"verify_until":%q}],"rotations":[]}`,
		signer.KeyID(), signer.KeyID(), base64.RawURLEncoding.EncodeToString(publicKey),
		base64.RawURLEncoding.EncodeToString(fingerprint[:]), notBefore.Format(time.RFC3339Nano),
		until.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano)))
	digest := sha256.Sum256(keyset)
	if _, err := pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_lkg(
		singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,accepted_at,updated_at
	) VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`,
		`"`+base64.RawURLEncoding.EncodeToString(digest[:])+`"`, signer.KeyID(), keyset, digest[:], now); err != nil {
		t.Fatalf("seed signing keyset LKG: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_current_keys(
		key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at
	) VALUES($1,$2,'active',$3,$4,$4,$5,$6)`, signer.KeyID(), []byte(ed25519.PublicKey(publicKey)),
		notBefore, until, digest[:], now); err != nil {
		t.Fatalf("seed signing keyset key: %v", err)
	}
	issuedAt := now.Add(-time.Minute)
	revocation, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: lease.CustomerID, InstallationID: lease.InstallationID, LicenseID: lease.LicenseID,
		Revision: 1, IssuedAt: issuedAt.Unix(), ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(),
		RevokedSerials: []uint64{},
	}, signer, entitlement.RevocationKeyWindow{NotBefore: notBefore, SignUntil: &until, VerifyUntil: &until})
	if err != nil {
		t.Fatalf("sign revocation set: %v", err)
	}
	artifact, err := revocation.Encode()
	if err != nil {
		t.Fatalf("encode revocation set: %v", err)
	}
	if _, err := entitlementguard.NewRevocationService(pool, trust).Accept(t.Context(), artifact, now); err != nil {
		t.Fatalf("accept revocation set: %v", err)
	}
}
