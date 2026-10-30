package artifactsync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/google/uuid"
)

type communityTestSigner struct{ key ed25519.PrivateKey }

func (signer communityTestSigner) KeyID() string { return "community-test" }
func (signer communityTestSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, payload), nil
}

type communityTestTrust struct{ key ed25519.PublicKey }

func (trust communityTestTrust) VerifyDetached(keyID string, payload, signature []byte, _, _ time.Time) error {
	if keyID != "community-test" || !ed25519.Verify(trust.key, payload, signature) {
		return errors.New("untrusted signature")
	}
	return nil
}

// cdncaCE: the control-plane half of the license service's
// TestCommunityInstallationRegistrationAndPurchase. A pack bought by a
// community installation is sealed and its CEK wrapped to the installation
// encryption key the installer generates (generate-installation-encryption-key),
// exactly as buildRulePackEntries does; the signed catalog verifies and the
// community key opens the pack (2 rules). Another installation's key does not.
func TestCommunityInstallationOpensBoughtPack(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "installation-encryption.key")
	public, err := entitlementsync.GenerateEncryptionKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	private, err := entitlementsync.LoadEncryptionKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := rulepack.Compile([]byte(`{"schema":"cdnca.rule-pack/v1","pack_id":"dev/acme/sqli-pro","version":"1.0.0",
		"layer":"developer","engine":"waf_v2","engine_min_version":1,"name":"SQLi pro","description":"d",
		"params_schema":{},"exports":["r1","r2"],"defaults":{},
		"rules":[{"id":"r1","name":"a","waf":{"match":{"path":{"kind":"prefix","value":"/a"}},"action":"block","flow":"stop"}},
		{"id":"r2","name":"b","waf":{"match":{"path":{"kind":"prefix","value":"/b"}},"action":"block","flow":"stop"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	sealed, err := rulepack.Seal(compiled.Canonical, cek, nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(sealed)
	digest := hex.EncodeToString(sum[:])
	pack := compiled.Pack
	wrapped, err := rulepack.WrapKey(public, cek, rulepack.WrapContext{Purpose: rulepack.WrapPurposeInstallation,
		RecipientKeyID: rulepack.X25519KeyID(public), PackID: pack.PackID, Version: pack.Version, SealedSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	entry := artifactcatalog.Entry{ArtifactID: artifactcatalog.RulePackArtifactID(pack.PackID), Kind: artifactcatalog.KindRulePack,
		MediaType: artifactcatalog.MediaTypeRulePack, Encryption: artifactcatalog.EncryptionInstallWrapped, Resident: true,
		Revision: 1, Version: pack.Version, SHA256: digest, Size: int64(len(sealed)), WrappedKey: wrapped, RequiresFeature: "pack.sqli-pro"}
	installation := uuid.New()
	now := time.Now().UTC()
	_, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := artifactcatalog.Sign(t.Context(), artifactcatalog.Envelope{DeliveryID: uuid.Must(uuid.NewV7()).String(),
		InstallationID: installation.String(), ScopeRevision: 1, SignedAt: now.Unix(), ValidFrom: now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(7 * 24 * time.Hour).Unix()},
		artifactcatalog.Catalog{Schema: artifactcatalog.CatalogSchema, Entries: []artifactcatalog.Entry{entry}},
		communityTestSigner{signingKey})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := artifactcatalog.Verify(signed, communityTestTrust{signingKey.Public().(ed25519.PublicKey)},
		artifactcatalog.VerifyOptions{Now: now, InstallationID: installation.String()})
	if err != nil || len(verified.Signed.Catalog.Entries) != 1 {
		t.Fatalf("verify community catalog: %v", err)
	}
	served := verified.Signed.Catalog.Entries[0]
	if _, err := verifyRulePack(served, sealed, private); err != nil {
		t.Fatalf("control plane rejects the bought pack: %v", err)
	}
	opened, err := unwrapInstallationKey(private, served.WrappedKey, pack.PackID, pack.Version, served.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := rulepack.Open(sealed, served.SHA256, opened); err != nil || len(result.Pack.Rules) != 2 {
		t.Fatalf("open bought pack: %v", err)
	}
	other, err := entitlementsync.LoadEncryptionKey(otherKeyFile(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRulePack(served, sealed, other); err == nil {
		t.Fatal("another installation's key opened the pack")
	}
	if _, err := verifyRulePack(served, sealed, nil); !errors.Is(err, ErrNoEncryptionKey) {
		t.Fatalf("no key: %v", err)
	}
}

func otherKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "other.key")
	if _, err := entitlementsync.GenerateEncryptionKey(path); err != nil {
		t.Fatal(err)
	}
	return path
}
