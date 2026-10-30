package acmeruntime

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestKeyStoreRotationSelectsActiveKeyForWrites(t *testing.T) {
	store, err := NewKeyStoreWithKeyring(&pgxpool.Pool{},
		WrappingKey{ID: "active", Key: rotationKey(1)},
		WrappingKey{ID: "previous", Key: rotationKey(2)},
	)
	if err != nil {
		t.Fatalf("NewKeyStoreWithKeyring() error = %v", err)
	}
	if store.activeID != "active" || store.aeads[store.activeID] == nil {
		t.Fatalf("active wrapping key = %q, present = %t", store.activeID, store.aeads[store.activeID] != nil)
	}
}

func TestKeyStoreRotationReadsPreviousKey(t *testing.T) {
	store, err := NewKeyStoreWithKeyring(&pgxpool.Pool{},
		WrappingKey{ID: "active", Key: rotationKey(1)},
		WrappingKey{ID: "previous", Key: rotationKey(2)},
	)
	if err != nil {
		t.Fatalf("NewKeyStoreWithKeyring() error = %v", err)
	}
	fields := rotationWrappedSigner(t, "previous", store.aeads["previous"])

	signer, err := store.parseWrappedSigner(fields.tenantID, purposeCertificate, fields.keyRef,
		"ecdsa", fields.publicDigest, "previous", fields.nonce, fields.ciphertext, fields.aadDigest)
	if err != nil {
		t.Fatalf("parseWrappedSigner() error = %v", err)
	}
	if _, ok := signer.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("parseWrappedSigner() type = %T, want *ecdsa.PrivateKey", signer)
	}
}

func TestKeyStoreRotationRejectsUnknownRetiredKey(t *testing.T) {
	store, err := NewKeyStoreWithKeyring(&pgxpool.Pool{}, WrappingKey{ID: "active", Key: rotationKey(1)})
	if err != nil {
		t.Fatalf("NewKeyStoreWithKeyring() error = %v", err)
	}
	fields := rotationWrappedSigner(t, "retired", rotationAEAD(t, rotationKey(3)))

	_, err = store.parseWrappedSigner(fields.tenantID, purposeCertificate, fields.keyRef,
		"ecdsa", fields.publicDigest, "retired", fields.nonce, fields.ciphertext, fields.aadDigest)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("parseWrappedSigner() error = %v, want ErrConflict", err)
	}
}

func TestKeyStoreRotationRejectsDuplicateIDs(t *testing.T) {
	tests := []struct {
		name     string
		previous []WrappingKey
	}{
		{name: "active repeated", previous: []WrappingKey{{ID: "active", Key: rotationKey(2)}}},
		{name: "previous repeated", previous: []WrappingKey{
			{ID: "previous", Key: rotationKey(2)},
			{ID: "previous", Key: rotationKey(3)},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewKeyStoreWithKeyring(&pgxpool.Pool{},
				WrappingKey{ID: "active", Key: rotationKey(1)}, test.previous...)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("NewKeyStoreWithKeyring() error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestKeyStoreRotationRejectsMoreThanFourKeys(t *testing.T) {
	_, err := NewKeyStoreWithKeyring(&pgxpool.Pool{},
		WrappingKey{ID: "active", Key: rotationKey(1)},
		WrappingKey{ID: "previous-1", Key: rotationKey(2)},
		WrappingKey{ID: "previous-2", Key: rotationKey(3)},
		WrappingKey{ID: "previous-3", Key: rotationKey(4)},
		WrappingKey{ID: "previous-4", Key: rotationKey(5)},
	)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NewKeyStoreWithKeyring() error = %v, want ErrInvalidInput", err)
	}
}

func TestKeyStoreRotationRejectsTamperedCiphertext(t *testing.T) {
	store, err := NewKeyStoreWithKeyring(&pgxpool.Pool{}, WrappingKey{ID: "active", Key: rotationKey(1)})
	if err != nil {
		t.Fatalf("NewKeyStoreWithKeyring() error = %v", err)
	}
	fields := rotationWrappedSigner(t, "active", store.aeads["active"])
	fields.ciphertext[len(fields.ciphertext)-1] ^= 0xff

	_, err = store.parseWrappedSigner(fields.tenantID, purposeCertificate, fields.keyRef,
		"ecdsa", fields.publicDigest, "active", fields.nonce, fields.ciphertext, fields.aadDigest)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("parseWrappedSigner() error = %v, want ErrConflict", err)
	}
}

type rotationSignerFields struct {
	tenantID              uuid.UUID
	keyRef                string
	publicDigest, nonce   []byte
	ciphertext, aadDigest []byte
}

func rotationWrappedSigner(t *testing.T, keyID string, aead cipher.AEAD) rotationSignerFields {
	t.Helper()
	tenantID := uuid.New()
	keyRef, err := CertificateKeyRef(tenantID, uuid.New())
	if err != nil {
		t.Fatalf("CertificateKeyRef() error = %v", err)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	publicDigest := sha256.Sum256(publicDER)
	aad, err := wrappingAAD(tenantID, purposeCertificate, keyRef, "ecdsa", publicDigest[:], keyID)
	if err != nil {
		t.Fatalf("wrappingAAD() error = %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	aadDigest := sha256.Sum256(aad)
	return rotationSignerFields{
		tenantID: tenantID, keyRef: keyRef, publicDigest: publicDigest[:], nonce: nonce,
		ciphertext: aead.Seal(nil, nonce, privateDER, aad), aadDigest: aadDigest[:],
	}
}

func rotationAEAD(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	store, err := NewKeyStore(&pgxpool.Pool{}, "rotation-helper", key)
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}
	return store.aeads[store.activeID]
}

func rotationKey(value byte) []byte {
	key := make([]byte, 32)
	for index := range key {
		key[index] = value
	}
	return key
}
