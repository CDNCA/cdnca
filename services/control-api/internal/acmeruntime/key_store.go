package acmeruntime

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	keyRefPrefix        = "acme:v1:"
	maximumWrappingKeys = 4
)

type keyPurpose string

const (
	purposeAccount     keyPurpose = "account"
	purposeCertificate keyPurpose = "certificate"
)

type KeyStore struct {
	pool     *pgxpool.Pool
	activeID string
	aeads    map[string]cipher.AEAD
	random   io.Reader
}

type WrappingKey struct {
	ID  string
	Key []byte
}

func NewKeyStore(pool *pgxpool.Pool, wrappingKeyID string, wrappingKey []byte) (*KeyStore, error) {
	return NewKeyStoreWithKeyring(pool, WrappingKey{ID: wrappingKeyID, Key: wrappingKey})
}

func NewKeyStoreWithKeyring(pool *pgxpool.Pool, active WrappingKey, previous ...WrappingKey) (*KeyStore, error) {
	if pool == nil || len(previous)+1 > maximumWrappingKeys {
		return nil, ErrInvalidInput
	}
	aeads := make(map[string]cipher.AEAD, len(previous)+1)
	for _, wrappingKey := range append([]WrappingKey{active}, previous...) {
		if strings.TrimSpace(wrappingKey.ID) != wrappingKey.ID || wrappingKey.ID == "" ||
			len(wrappingKey.ID) > 200 || strings.IndexFunc(wrappingKey.ID, unicode.IsControl) >= 0 ||
			len(wrappingKey.Key) != 32 {
			return nil, ErrInvalidInput
		}
		if _, exists := aeads[wrappingKey.ID]; exists {
			return nil, ErrInvalidInput
		}
		block, err := aes.NewCipher(append([]byte(nil), wrappingKey.Key...))
		if err != nil {
			return nil, ErrInvalidInput
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrInvalidInput
		}
		aeads[wrappingKey.ID] = aead
	}
	return &KeyStore{pool: pool, activeID: active.ID, aeads: aeads, random: rand.Reader}, nil
}

func AccountKeyRef(tenantID uuid.UUID, directoryURL string) (string, error) {
	if tenantID == uuid.Nil || !validHTTPSURL(directoryURL) {
		return "", ErrInvalidInput
	}
	digest := sha256.Sum256([]byte(directoryURL))
	return fmt.Sprintf("%s%s:%s:%x", keyRefPrefix, tenantID, purposeAccount, digest), nil
}

func CertificateKeyRef(tenantID, orderID uuid.UUID) (string, error) {
	if tenantID == uuid.Nil || orderID == uuid.Nil {
		return "", ErrInvalidInput
	}
	return fmt.Sprintf("%s%s:%s:%s", keyRefPrefix, tenantID, purposeCertificate, orderID), nil
}

func parseKeyRef(ref string) (uuid.UUID, keyPurpose, string, error) {
	parts := strings.Split(ref, ":")
	if len(parts) != 5 || parts[0] != "acme" || parts[1] != "v1" || ref != strings.TrimSpace(ref) || len(ref) > 200 {
		return uuid.Nil, "", "", ErrInvalidInput
	}
	tenantID, err := uuid.Parse(parts[2])
	if err != nil || tenantID == uuid.Nil {
		return uuid.Nil, "", "", ErrInvalidInput
	}
	purpose := keyPurpose(parts[3])
	switch purpose {
	case purposeAccount:
		decoded, decodeErr := hex.DecodeString(parts[4])
		if decodeErr != nil || len(decoded) != sha256.Size {
			return uuid.Nil, "", "", ErrInvalidInput
		}
	case purposeCertificate:
		orderID, parseErr := uuid.Parse(parts[4])
		if parseErr != nil || orderID == uuid.Nil {
			return uuid.Nil, "", "", ErrInvalidInput
		}
	default:
		return uuid.Nil, "", "", ErrInvalidInput
	}
	return tenantID, purpose, parts[4], nil
}

func (s *KeyStore) ensureKey(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, actorID uuid.UUID,
	purpose keyPurpose,
	keyRef string,
) error {
	if tx == nil || tenantID == uuid.Nil || actorID == uuid.Nil || s == nil {
		return ErrInvalidInput
	}
	parsedTenant, parsedPurpose, _, err := parseKeyRef(keyRef)
	if err != nil || parsedTenant != tenantID || parsedPurpose != purpose {
		return ErrInvalidInput
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenantID.String()+"/"+keyRef); err != nil {
		return err
	}
	found, err := s.validateExistingKey(ctx, tx, tenantID, purpose, keyRef)
	if err != nil || found {
		return err
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), s.random)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	defer clear(privateDER)
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return err
	}
	publicDigest := sha256.Sum256(publicDER)
	aead := s.aeads[s.activeID]
	if aead == nil {
		return ErrConflict
	}
	aad, err := wrappingAAD(tenantID, purpose, keyRef, "ecdsa", publicDigest[:], s.activeID)
	if err != nil {
		return err
	}
	aadDigest := sha256.Sum256(aad)
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		return err
	}
	ciphertext := aead.Seal(nil, nonce, privateDER, aad)
	_, err = tx.Exec(ctx, `INSERT INTO acme_tenant_key_facts(
		tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
		wrapped_key_ciphertext,wrapping_key_id,wrapping_nonce,wrapping_aad_sha256,
		created_by_user_id
	) VALUES($1,$2,$3,$4,'ecdsa',$5,$6,$7,$8,$9,$10)`,
		tenantID, uuid.New(), keyRef, string(purpose), publicDigest[:], ciphertext,
		s.activeID, nonce, aadDigest[:], actorID)
	return err
}

func (s *KeyStore) validateExistingKey(
	ctx context.Context,
	tx pgx.Tx,
	tenantID uuid.UUID,
	purpose keyPurpose,
	keyRef string,
) (bool, error) {
	var storedPurpose, algorithm string
	var digest []byte
	err := tx.QueryRow(ctx, `SELECT key.purpose,key.algorithm,key.public_key_spki_sha256
		FROM acme_tenant_key_facts key
		JOIN users account ON account.id=key.created_by_user_id
		 AND acme_runtime_actor_is_active_048(key.tenant_scope_id,key.created_by_user_id)
		WHERE key.tenant_scope_id=$1 AND key.key_ref=$2`, tenantID, keyRef).Scan(&storedPurpose, &algorithm, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if storedPurpose != string(purpose) || !validKeyAlgorithm(algorithm) || len(digest) != sha256.Size {
		return false, ErrConflict
	}
	return true, nil
}

func (s *KeyStore) Signer(ctx context.Context, keyRef string) (crypto.Signer, error) {
	if s == nil || s.pool == nil {
		return nil, ErrInvalidInput
	}
	tenantID, purpose, _, err := parseKeyRef(keyRef)
	if err != nil {
		return nil, err
	}
	var algorithm string
	var publicDigest, ciphertext, nonce, aadDigest []byte
	var externalRef, wrappingKeyID *string
	err = s.pool.QueryRow(ctx, `SELECT key.algorithm,key.public_key_spki_sha256,
		key.external_key_reference,key.wrapped_key_ciphertext,key.wrapping_key_id,
		key.wrapping_nonce,key.wrapping_aad_sha256
		FROM acme_tenant_key_facts key
		JOIN access_scopes scope ON scope.id=key.tenant_scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		JOIN users account ON account.id=key.created_by_user_id
		 AND acme_runtime_actor_is_active_048(key.tenant_scope_id,key.created_by_user_id)
		WHERE key.tenant_scope_id=$1 AND key.key_ref=$2 AND key.purpose=$3`,
		tenantID, keyRef, string(purpose)).Scan(
		&algorithm, &publicDigest, &externalRef, &ciphertext, &wrappingKeyID, &nonce, &aadDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	if externalRef != nil {
		return nil, ErrUnsupportedKeyMaterial
	}
	if wrappingKeyID == nil {
		return nil, ErrConflict
	}
	return s.parseWrappedSigner(tenantID, purpose, keyRef, algorithm, publicDigest,
		*wrappingKeyID, nonce, ciphertext, aadDigest)
}

func (s *KeyStore) parseWrappedSigner(
	tenantID uuid.UUID,
	purpose keyPurpose,
	keyRef, algorithm string,
	publicDigest []byte,
	wrappingKeyID string,
	nonce, ciphertext, aadDigest []byte,
) (crypto.Signer, error) {
	if s == nil {
		return nil, ErrInvalidInput
	}
	aead, exists := s.aeads[wrappingKeyID]
	if !exists || aead == nil || len(publicDigest) != sha256.Size || len(nonce) != aead.NonceSize() ||
		len(aadDigest) != sha256.Size || len(ciphertext) < aead.Overhead() {
		return nil, ErrConflict
	}
	aad, err := wrappingAAD(tenantID, purpose, keyRef, algorithm, publicDigest, wrappingKeyID)
	if err != nil {
		return nil, err
	}
	expectedAAD := sha256.Sum256(aad)
	if subtle.ConstantTimeCompare(aadDigest, expectedAAD[:]) != 1 {
		return nil, ErrConflict
	}
	privateDER, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrConflict
	}
	defer clear(privateDER)
	parsed, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, ErrConflict
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok || signerAlgorithm(signer) != algorithm {
		return nil, ErrConflict
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, ErrConflict
	}
	digest := sha256.Sum256(publicDER)
	if subtle.ConstantTimeCompare(publicDigest, digest[:]) != 1 {
		return nil, ErrConflict
	}
	return signer, nil
}

func wrappingAAD(
	tenantID uuid.UUID,
	purpose keyPurpose,
	keyRef, algorithm string,
	publicDigest []byte,
	wrappingKeyID string,
) ([]byte, error) {
	if tenantID == uuid.Nil || len(publicDigest) != sha256.Size || keyRef == "" || wrappingKeyID == "" {
		return nil, ErrInvalidInput
	}
	return json.Marshal(struct {
		Schema        string `json:"schema"`
		TenantID      string `json:"tenant_id"`
		Purpose       string `json:"purpose"`
		KeyRef        string `json:"key_ref"`
		Algorithm     string `json:"algorithm"`
		PublicSPKI    string `json:"public_spki_sha256"`
		WrappingKeyID string `json:"wrapping_key_id"`
	}{
		Schema: "cdnca.acme-wrapped-key.v1", TenantID: tenantID.String(),
		Purpose: string(purpose), KeyRef: keyRef, Algorithm: algorithm,
		PublicSPKI: hex.EncodeToString(publicDigest), WrappingKeyID: wrappingKeyID,
	})
}

func signerAlgorithm(signer crypto.Signer) string {
	switch signer.(type) {
	case *rsa.PrivateKey:
		return "rsa"
	case *ecdsa.PrivateKey:
		return "ecdsa"
	case ed25519.PrivateKey:
		return "ed25519"
	default:
		return ""
	}
}

func validKeyAlgorithm(algorithm string) bool {
	return algorithm == "rsa" || algorithm == "ecdsa" || algorithm == "ed25519"
}
