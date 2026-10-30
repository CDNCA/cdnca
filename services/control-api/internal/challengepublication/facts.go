package challengepublication

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	KeyRoleCurrent  = "current"
	KeyRolePrevious = "previous"
	KeyRoleApp      = "app"

	challengeKeyFactDomain = "cdnca-challenge-key-fact-v1\x00"
)

type KeyFact struct {
	TenantScopeID, TenantID, SiteID, PolicyID uuid.UUID
	Host                                      string
	PolicyRevision                            int64
	Role, Reference, MaterialKeyID            string
	WrappingKeyID, SigningKeyID               string
	Ciphertext, Signature                     []byte
}

type KeyFactSource interface {
	LoadChallengeKeyFacts(context.Context, PublicationSnapshot) ([]KeyFact, error)
}

type BoundFactCipher interface {
	DecryptBound(string, []byte, []byte) ([]byte, error)
}

type FactSignatureVerifier interface {
	VerifyChallengeKeyFact(string, []byte, []byte) bool
}

type AESGCMFactCipher struct {
	keyID string
	key   []byte
	aead  cipher.AEAD
}

func NewAESGCMFactCipher(keyID string, key []byte) (*AESGCMFactCipher, error) {
	if !validIdentifier(keyID) || len(key) != 32 {
		return nil, ErrKeyUnavailable
	}
	owned := slices.Clone(key)
	block, err := aes.NewCipher(owned)
	if err != nil {
		clear(owned)
		return nil, ErrKeyUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		clear(owned)
		return nil, ErrKeyUnavailable
	}
	return &AESGCMFactCipher{keyID: keyID, key: owned, aead: aead}, nil
}

func (factCipher *AESGCMFactCipher) KeyID() string {
	if factCipher == nil {
		return ""
	}
	return factCipher.keyID
}

func (factCipher *AESGCMFactCipher) DecryptBound(keyID string, ciphertext, associatedData []byte) ([]byte, error) {
	if factCipher == nil || keyID != factCipher.keyID || factCipher.aead == nil ||
		len(ciphertext) <= factCipher.aead.NonceSize() || len(associatedData) == 0 {
		return nil, ErrKeyUnavailable
	}
	plaintext, err := factCipher.aead.Open(nil, ciphertext[:factCipher.aead.NonceSize()],
		ciphertext[factCipher.aead.NonceSize():], associatedData)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	return plaintext, nil
}

type Ed25519FactVerifier struct{ keys map[string]ed25519.PublicKey }

func NewEd25519FactVerifier(keys map[string]ed25519.PublicKey) *Ed25519FactVerifier {
	owned := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, publicKey := range keys {
		if validIdentifier(keyID) && len(publicKey) == ed25519.PublicKeySize {
			owned[keyID] = slices.Clone(publicKey)
		}
	}
	return &Ed25519FactVerifier{keys: owned}
}

func (verifier *Ed25519FactVerifier) VerifyChallengeKeyFact(keyID string, message, signature []byte) bool {
	if verifier == nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	publicKey := verifier.keys[keyID]
	return len(publicKey) == ed25519.PublicKeySize && ed25519.Verify(publicKey, message, signature)
}

type FactKeyResolver struct {
	source   KeyFactSource
	cipher   BoundFactCipher
	verifier FactSignatureVerifier
}

func NewFactKeyResolver(source KeyFactSource, factCipher BoundFactCipher,
	verifier FactSignatureVerifier) (*FactKeyResolver, error) {
	if nilFactDependency(source) || nilFactDependency(factCipher) || nilFactDependency(verifier) {
		return nil, ErrInvalidRuntime
	}
	return &FactKeyResolver{source: source, cipher: factCipher, verifier: verifier}, nil
}

func (resolver *FactKeyResolver) ResolveChallengeKeys(
	ctx context.Context, snapshot PublicationSnapshot,
) (ResolvedKeys, error) {
	if resolver == nil || ctx == nil || snapshot.PolicyID == uuid.Nil || snapshot.TenantScopeID == uuid.Nil ||
		snapshot.TenantID == uuid.Nil || snapshot.SiteID == uuid.Nil || snapshot.Revision < 1 ||
		snapshot.Host == "" || snapshot.KeyReference == "" {
		return ResolvedKeys{}, ErrKeyUnavailable
	}
	facts, err := resolver.source.LoadChallengeKeyFacts(ctx, snapshot)
	if err != nil || len(facts) == 0 || len(facts) > 3 {
		return ResolvedKeys{}, ErrKeyUnavailable
	}
	var result ResolvedKeys
	seen := make(map[string]struct{}, len(facts))
	for _, fact := range facts {
		if fact.TenantScopeID != snapshot.TenantScopeID || fact.TenantID != snapshot.TenantID ||
			fact.SiteID != snapshot.SiteID || fact.Host != snapshot.Host || fact.PolicyID != snapshot.PolicyID ||
			fact.PolicyRevision != snapshot.Revision || !validIdentifier(fact.MaterialKeyID) ||
			!validIdentifier(fact.WrappingKeyID) || !validIdentifier(fact.SigningKeyID) ||
			len(fact.Ciphertext) < 29 || len(fact.Ciphertext) > 4096 || len(fact.Signature) != ed25519.SignatureSize {
			clearResolvedKeys(&result)
			return ResolvedKeys{}, ErrKeyUnavailable
		}
		if _, duplicate := seen[fact.Role]; duplicate {
			clearResolvedKeys(&result)
			return ResolvedKeys{}, ErrKeyUnavailable
		}
		seen[fact.Role] = struct{}{}
		aad, aadErr := challengeKeyFactAAD(fact)
		if aadErr != nil || !resolver.verifier.VerifyChallengeKeyFact(fact.SigningKeyID,
			challengeKeyFactMessage(aad, fact.Ciphertext), fact.Signature) {
			clearResolvedKeys(&result)
			return ResolvedKeys{}, ErrKeyUnavailable
		}
		plaintext, decryptErr := resolver.cipher.DecryptBound(fact.WrappingKeyID, fact.Ciphertext, aad)
		if decryptErr != nil {
			clearResolvedKeys(&result)
			return ResolvedKeys{}, ErrKeyUnavailable
		}
		switch fact.Role {
		case KeyRoleCurrent:
			if fact.Reference != snapshot.KeyReference || len(plaintext) < 32 || len(plaintext) > 128 {
				clear(plaintext)
				clearResolvedKeys(&result)
				return ResolvedKeys{}, ErrKeyUnavailable
			}
			result.Current = ArtifactSecret{KeyID: fact.MaterialKeyID, Secret: plaintext}
		case KeyRolePrevious:
			if fact.Reference == snapshot.KeyReference || len(plaintext) < 32 || len(plaintext) > 128 {
				clear(plaintext)
				clearResolvedKeys(&result)
				return ResolvedKeys{}, ErrKeyUnavailable
			}
			result.Previous = &ArtifactSecret{KeyID: fact.MaterialKeyID, Secret: plaintext}
		case KeyRoleApp:
			var credential ExternalCredentialSecret
			decoder := json.NewDecoder(bytes.NewReader(plaintext))
			decoder.DisallowUnknownFields()
			decodeErr := decoder.Decode(&credential)
			var extra any
			eofErr := decoder.Decode(&extra)
			if snapshot.ExternalProvider == nil || fact.Reference != snapshot.ExternalProvider.AppReference ||
				decodeErr != nil || !errors.Is(eofErr, io.EOF) || credential.SchemaVersion != ExternalCredentialSchemaVersion ||
				credential.Provider != snapshot.ExternalProvider.Provider || !validIdentifier(credential.AppID) ||
				len(credential.Secret) < 16 || len(credential.Secret) > 256 ||
				(credential.Environment != "sandbox" && credential.Environment != "production") {
				clear(plaintext)
				clear(credential.Secret)
				clearResolvedKeys(&result)
				return ResolvedKeys{}, ErrKeyUnavailable
			}
			result.ExternalCredential = &credential
			clear(plaintext)
		default:
			clear(plaintext)
			clearResolvedKeys(&result)
			return ResolvedKeys{}, ErrKeyUnavailable
		}
	}
	if _, ok := seen[KeyRoleCurrent]; !ok || snapshot.ExternalProvider != nil && result.ExternalCredential == nil ||
		snapshot.ExternalProvider == nil && result.ExternalCredential != nil || !validResolvedKeys(result) {
		clearResolvedKeys(&result)
		return ResolvedKeys{}, ErrKeyUnavailable
	}
	return result, nil
}

type PostgresKeyFactSource struct{ pool *pgxpool.Pool }

func NewPostgresKeyFactSource(pool *pgxpool.Pool) (*PostgresKeyFactSource, error) {
	if pool == nil {
		return nil, ErrInvalidRuntime
	}
	return &PostgresKeyFactSource{pool: pool}, nil
}

func (source *PostgresKeyFactSource) LoadChallengeKeyFacts(
	ctx context.Context, snapshot PublicationSnapshot,
) ([]KeyFact, error) {
	if source == nil || source.pool == nil || ctx == nil {
		return nil, ErrKeyUnavailable
	}
	rows, err := source.pool.Query(ctx, `
		SELECT tenant_scope_id,tenant_id,site_id,host,policy_id,policy_revision,role,reference,
		       material_key_id,wrapping_key_id,signing_key_id,ciphertext,signature
		FROM challenge_key_facts_138
		WHERE tenant_scope_id=$1 AND tenant_id=$2 AND site_id=$3 AND host=$4
		  AND policy_id=$5 AND policy_revision=$6 AND active
		ORDER BY role,reference`, snapshot.TenantScopeID, snapshot.TenantID, snapshot.SiteID,
		snapshot.Host, snapshot.PolicyID, snapshot.Revision)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	defer rows.Close()
	var facts []KeyFact
	for rows.Next() {
		var fact KeyFact
		if err := rows.Scan(&fact.TenantScopeID, &fact.TenantID, &fact.SiteID, &fact.Host, &fact.PolicyID,
			&fact.PolicyRevision, &fact.Role, &fact.Reference, &fact.MaterialKeyID, &fact.WrappingKeyID,
			&fact.SigningKeyID, &fact.Ciphertext, &fact.Signature); err != nil {
			return nil, ErrKeyUnavailable
		}
		facts = append(facts, fact)
	}
	if rows.Err() != nil {
		return nil, ErrKeyUnavailable
	}
	return facts, nil
}

func challengeKeyFactAAD(fact KeyFact) ([]byte, error) {
	if fact.TenantScopeID == uuid.Nil || fact.TenantID == uuid.Nil || fact.SiteID == uuid.Nil ||
		fact.PolicyID == uuid.Nil || fact.PolicyRevision < 1 || fact.Host == "" || fact.Reference == "" ||
		fact.MaterialKeyID == "" || fact.WrappingKeyID == "" || fact.SigningKeyID == "" {
		return nil, ErrKeyUnavailable
	}
	buffer := bytes.NewBufferString(challengeKeyFactDomain)
	for _, value := range []string{fact.TenantScopeID.String(), fact.TenantID.String(), fact.SiteID.String(),
		strings.ToLower(fact.Host), fact.PolicyID.String(), fact.Role, fact.Reference, fact.MaterialKeyID,
		fact.WrappingKeyID, fact.SigningKeyID} {
		if len(value) == 0 || len(value) > 1024 || binary.Write(buffer, binary.BigEndian, uint32(len(value))) != nil ||
			writeAll(buffer, []byte(value)) != nil {
			return nil, ErrKeyUnavailable
		}
	}
	if binary.Write(buffer, binary.BigEndian, uint64(fact.PolicyRevision)) != nil {
		return nil, ErrKeyUnavailable
	}
	return buffer.Bytes(), nil
}

func challengeKeyFactMessage(aad, ciphertext []byte) []byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(challengeKeyFactDomain))
	_, _ = digest.Write(aad)
	_, _ = digest.Write(ciphertext)
	return digest.Sum(nil)
}

func writeAll(writer io.Writer, value []byte) error {
	written, err := writer.Write(value)
	if err != nil {
		return err
	}
	if written != len(value) {
		return io.ErrShortWrite
	}
	return nil
}

func nilFactDependency(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Interface || kind == reflect.Pointer || kind == reflect.Func) && reflect.ValueOf(value).IsNil()
}

var _ KeyFactSource = (*PostgresKeyFactSource)(nil)
var _ KeyResolver = (*FactKeyResolver)(nil)
