package acmedispatch

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PGKeyMaterialLoader loads provider-wrapped certificate keys without
// decrypting them. External-only key facts fail closed until certificateasset
// has a distinct external-handle contract.
type PGKeyMaterialLoader struct{}

func NewPGKeyMaterialLoader() *PGKeyMaterialLoader {
	return &PGKeyMaterialLoader{}
}

func (*PGKeyMaterialLoader) LoadOpaquePrivateKey(
	ctx context.Context,
	tx pgx.Tx,
	tenantID uuid.UUID,
	keyRef string,
	expectedSPKIDER []byte,
) (certificateasset.OpaquePrivateKey, error) {
	if tx == nil || tenantID == uuid.Nil || keyRef == "" || keyRef != strings.TrimSpace(keyRef) ||
		len(keyRef) > 200 || len(expectedSPKIDER) == 0 || len(expectedSPKIDER) > 4096 {
		return certificateasset.OpaquePrivateKey{}, ErrInvalidInput
	}
	if _, err := x509.ParsePKIXPublicKey(expectedSPKIDER); err != nil {
		return certificateasset.OpaquePrivateKey{}, ErrInvalidInput
	}

	var algorithm string
	var storedDigest, wrappedCiphertext, nonce, aadDigest []byte
	var externalReference, wrappingKeyID *string
	err := tx.QueryRow(ctx, `SELECT key.algorithm,key.public_key_spki_sha256,
		key.external_key_reference,key.wrapped_key_ciphertext,key.wrapping_key_id,
		key.wrapping_nonce,key.wrapping_aad_sha256
		FROM acme_tenant_key_facts key
		JOIN access_scopes scope
		  ON scope.id=key.tenant_scope_id AND scope.kind='tenant'
		JOIN tenants tenant
		  ON tenant.id=scope.tenant_id AND tenant.status='active'
		JOIN users account
		  ON account.id=key.created_by_user_id
		 AND acme_runtime_actor_is_active_048(key.tenant_scope_id,key.created_by_user_id)
		WHERE key.tenant_scope_id=$1 AND key.key_ref=$2 AND key.purpose='certificate'
		FOR UPDATE OF key`, tenantID, keyRef).Scan(
		&algorithm, &storedDigest, &externalReference, &wrappedCiphertext,
		&wrappingKeyID, &nonce, &aadDigest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return certificateasset.OpaquePrivateKey{}, ErrConflict
	}
	if err != nil {
		return certificateasset.OpaquePrivateKey{}, err
	}

	expectedDigest := sha256.Sum256(expectedSPKIDER)
	if len(storedDigest) != sha256.Size || subtle.ConstantTimeCompare(storedDigest, expectedDigest[:]) != 1 {
		return certificateasset.OpaquePrivateKey{}, ErrConflict
	}
	if externalReference != nil {
		return certificateasset.OpaquePrivateKey{}, ErrUnsupportedKeyMaterial
	}
	if wrappingKeyID == nil || len(wrappedCiphertext) < 16 || len(wrappedCiphertext) > 128*1024 ||
		len(nonce) < 8 || len(nonce) > 64 || len(aadDigest) != sha256.Size {
		return certificateasset.OpaquePrivateKey{}, ErrConflict
	}

	metadata, err := json.Marshal(struct {
		Schema         string `json:"schema"`
		Algorithm      string `json:"algorithm"`
		WrappingKeyID  string `json:"wrapping_key_id"`
		WrappingNonce  []byte `json:"wrapping_nonce"`
		WrappingAADSHA []byte `json:"wrapping_aad_sha256"`
	}{
		Schema: "cdnca.acme-wrapped-key.v1", Algorithm: algorithm,
		WrappingKeyID: *wrappingKeyID, WrappingNonce: nonce, WrappingAADSHA: aadDigest,
	})
	if err != nil {
		return certificateasset.OpaquePrivateKey{}, err
	}
	return certificateasset.OpaquePrivateKey{
		KeyReference:       keyRef,
		PublicKeySPKIDER:   append([]byte(nil), expectedSPKIDER...),
		WrappedKeyMaterial: append([]byte(nil), wrappedCiphertext...),
		Metadata:           metadata,
	}, nil
}
