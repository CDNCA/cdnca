package challengepublication

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidFactWrite  = errors.New("invalid challenge key fact write")
	ErrFactWriteConflict = errors.New("challenge key fact write conflicts with durable facts")
)

type BoundFactWriterCipher interface {
	BoundFactCipher
	KeyID() string
	EncryptBound(context.Context, []byte, []byte) ([]byte, error)
}

type Ed25519FactSigner interface {
	KeyID() string
	PublicKey() ed25519.PublicKey
	Sign(context.Context, []byte) ([]byte, error)
}

type AESGCMFactWriterCipher struct {
	cipher *AESGCMFactCipher
	random io.Reader
}

func NewAESGCMFactWriterCipher(factCipher *AESGCMFactCipher) (*AESGCMFactWriterCipher, error) {
	return newAESGCMFactWriterCipher(factCipher, rand.Reader)
}

func newAESGCMFactWriterCipher(factCipher *AESGCMFactCipher, random io.Reader) (*AESGCMFactWriterCipher, error) {
	if factCipher == nil || factCipher.aead == nil || !validIdentifier(factCipher.KeyID()) || random == nil {
		return nil, ErrInvalidRuntime
	}
	return &AESGCMFactWriterCipher{cipher: factCipher, random: random}, nil
}

func (factCipher *AESGCMFactWriterCipher) KeyID() string {
	if factCipher == nil || factCipher.cipher == nil {
		return ""
	}
	return factCipher.cipher.KeyID()
}

func (factCipher *AESGCMFactWriterCipher) EncryptBound(
	ctx context.Context, plaintext, associatedData []byte,
) ([]byte, error) {
	if factCipher == nil || factCipher.cipher == nil || factCipher.cipher.aead == nil || ctx == nil ||
		len(plaintext) == 0 || len(associatedData) == 0 {
		return nil, ErrKeyUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nonce := make([]byte, factCipher.cipher.aead.NonceSize())
	if _, err := io.ReadFull(factCipher.random, nonce); err != nil {
		clear(nonce)
		return nil, ErrKeyUnavailable
	}
	return factCipher.cipher.aead.Seal(nonce, nonce, plaintext, associatedData), nil
}

func (factCipher *AESGCMFactWriterCipher) DecryptBound(
	keyID string, ciphertext, associatedData []byte,
) ([]byte, error) {
	if factCipher == nil || factCipher.cipher == nil {
		return nil, ErrKeyUnavailable
	}
	return factCipher.cipher.DecryptBound(keyID, ciphertext, associatedData)
}

type ArtifactFactSigner struct{ signer ArtifactSigner }

func NewArtifactFactSigner(signer ArtifactSigner) (*ArtifactFactSigner, error) {
	if nilFactDependency(signer) || !validIdentifier(signer.ArtifactSigningKeyID()) ||
		len(signer.ArtifactSigningPublicKey()) != ed25519.PublicKeySize {
		return nil, ErrInvalidRuntime
	}
	return &ArtifactFactSigner{signer: signer}, nil
}

func (signer *ArtifactFactSigner) KeyID() string {
	if signer == nil || nilFactDependency(signer.signer) {
		return ""
	}
	return signer.signer.ArtifactSigningKeyID()
}

func (signer *ArtifactFactSigner) PublicKey() ed25519.PublicKey {
	if signer == nil || nilFactDependency(signer.signer) {
		return nil
	}
	return slices.Clone(signer.signer.ArtifactSigningPublicKey())
}

func (signer *ArtifactFactSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if signer == nil || nilFactDependency(signer.signer) || ctx == nil {
		return nil, ErrKeyUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return signer.signer.SignArtifact(ctx, message)
}

type FactMaterial struct {
	Role, Reference, MaterialKeyID string
	Plaintext                      []byte
}

type FactWriteRequest struct {
	TenantScopeID, TenantID, SiteID, PolicyID uuid.UUID
	Host                                      string
	PolicyRevision                            int64
	ActorScopeID, ActorUserID                 uuid.UUID
	Materials                                 []FactMaterial
}

type FactWriteResult struct {
	Replayed  bool
	FactCount int
}

type FactWriter struct {
	run    factTransactionRunner
	cipher BoundFactWriterCipher
	signer Ed25519FactSigner
	now    func() time.Time
	newID  func() (uuid.UUID, error)
}

type factTransactionRunner func(context.Context, func(factWriteTransaction) error) error

type factWriteTransaction interface {
	LockScope(context.Context, FactWriteRequest) error
	LoadPolicyFacts(context.Context, uuid.UUID, int64) ([]storedKeyFact, error)
	InsertFact(context.Context, storedKeyFact) error
}

type storedKeyFact struct {
	KeyFact
	ID                                uuid.UUID
	CreatedByScopeID, CreatedByUserID uuid.UUID
	CreatedAt                         time.Time
	Active                            bool
}

func NewPostgresFactWriter(pool *pgxpool.Pool, factCipher BoundFactWriterCipher,
	signer Ed25519FactSigner) (*FactWriter, error) {
	if pool == nil {
		return nil, ErrInvalidRuntime
	}
	run := func(ctx context.Context, operation func(factWriteTransaction) error) error {
		return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			return operation(postgresFactWriteTransaction{tx: tx})
		})
	}
	return newFactWriter(run, factCipher, signer, time.Now, uuid.NewRandom)
}

func newFactWriter(run factTransactionRunner, factCipher BoundFactWriterCipher, signer Ed25519FactSigner,
	now func() time.Time, newID func() (uuid.UUID, error)) (*FactWriter, error) {
	if run == nil || nilFactDependency(factCipher) || nilFactDependency(signer) || now == nil || newID == nil ||
		!validIdentifier(factCipher.KeyID()) || !validIdentifier(signer.KeyID()) ||
		len(signer.PublicKey()) != ed25519.PublicKeySize {
		return nil, ErrInvalidRuntime
	}
	return &FactWriter{run: run, cipher: factCipher, signer: signer, now: now, newID: newID}, nil
}

func (writer *FactWriter) Write(ctx context.Context, request FactWriteRequest) (FactWriteResult, error) {
	if writer == nil || writer.run == nil || ctx == nil {
		return FactWriteResult{}, ErrInvalidFactWrite
	}
	if err := ctx.Err(); err != nil {
		return FactWriteResult{}, err
	}
	owned, err := validateAndCloneFactWriteRequest(request)
	if err != nil {
		return FactWriteResult{}, err
	}
	defer clearFactMaterials(owned.Materials)

	var result FactWriteResult
	err = writer.run(ctx, func(tx factWriteTransaction) error {
		if err := tx.LockScope(ctx, owned); err != nil {
			return err
		}
		existing, err := tx.LoadPolicyFacts(ctx, owned.PolicyID, owned.PolicyRevision)
		if err != nil {
			return err
		}
		if len(existing) > 0 {
			if !writer.exactReplay(ctx, owned, existing) {
				return ErrFactWriteConflict
			}
			result = FactWriteResult{Replayed: true, FactCount: len(existing)}
			return nil
		}
		prepared, err := writer.prepare(ctx, owned)
		if err != nil {
			return err
		}
		result.FactCount = len(prepared)
		for _, fact := range prepared {
			if err := tx.InsertFact(ctx, fact); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return FactWriteResult{}, err
	}
	return result, nil
}

func (writer *FactWriter) prepare(ctx context.Context, request FactWriteRequest) ([]storedKeyFact, error) {
	createdAt := writer.now().UTC()
	if createdAt.IsZero() {
		return nil, ErrInvalidFactWrite
	}
	prepared := make([]storedKeyFact, 0, len(request.Materials))
	for _, material := range request.Materials {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id, err := writer.newID()
		if err != nil || id == uuid.Nil {
			return nil, ErrInvalidFactWrite
		}
		fact := storedKeyFact{
			ID: id,
			KeyFact: KeyFact{
				TenantScopeID: request.TenantScopeID, TenantID: request.TenantID, SiteID: request.SiteID,
				Host: request.Host, PolicyID: request.PolicyID, PolicyRevision: request.PolicyRevision,
				Role: material.Role, Reference: material.Reference, MaterialKeyID: material.MaterialKeyID,
				WrappingKeyID: writer.cipher.KeyID(), SigningKeyID: writer.signer.KeyID(),
			},
			CreatedByScopeID: request.ActorScopeID, CreatedByUserID: request.ActorUserID,
			CreatedAt: createdAt, Active: true,
		}
		aad, err := challengeKeyFactAAD(fact.KeyFact)
		if err != nil {
			return nil, ErrInvalidFactWrite
		}
		fact.Ciphertext, err = writer.cipher.EncryptBound(ctx, material.Plaintext, aad)
		if err != nil || len(fact.Ciphertext) < 29 || len(fact.Ciphertext) > 4096 {
			return nil, ErrKeyUnavailable
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		message := challengeKeyFactMessage(aad, fact.Ciphertext)
		fact.Signature, err = writer.signer.Sign(ctx, message)
		if err != nil || len(fact.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(writer.signer.PublicKey(), message, fact.Signature) {
			return nil, ErrKeyUnavailable
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		prepared = append(prepared, fact)
	}
	return prepared, nil
}

func (writer *FactWriter) exactReplay(ctx context.Context, request FactWriteRequest, existing []storedKeyFact) bool {
	if len(request.Materials) != len(existing) {
		return false
	}
	byRole := make(map[string]storedKeyFact, len(existing))
	for _, fact := range existing {
		if _, duplicate := byRole[fact.Role]; duplicate {
			return false
		}
		byRole[fact.Role] = fact
	}
	for _, material := range request.Materials {
		if ctx.Err() != nil {
			return false
		}
		expected := storedKeyFact{KeyFact: KeyFact{
			TenantScopeID: request.TenantScopeID, TenantID: request.TenantID, SiteID: request.SiteID,
			Host: request.Host, PolicyID: request.PolicyID, PolicyRevision: request.PolicyRevision,
			Role: material.Role, Reference: material.Reference, MaterialKeyID: material.MaterialKeyID,
			WrappingKeyID: writer.cipher.KeyID(), SigningKeyID: writer.signer.KeyID(),
		}}
		actual, found := byRole[material.Role]
		if !found || !sameStoredFactMetadata(actual, expected) || !actual.Active ||
			actual.CreatedByScopeID != request.ActorScopeID || actual.CreatedByUserID != request.ActorUserID {
			return false
		}
		aad, err := challengeKeyFactAAD(actual.KeyFact)
		if err != nil || !ed25519.Verify(writer.signer.PublicKey(), challengeKeyFactMessage(aad, actual.Ciphertext), actual.Signature) {
			return false
		}
		plaintext, err := writer.cipher.DecryptBound(actual.WrappingKeyID, actual.Ciphertext, aad)
		if err != nil {
			return false
		}
		matches := bytes.Equal(plaintext, material.Plaintext)
		clear(plaintext)
		if !matches {
			return false
		}
	}
	return true
}

func validateAndCloneFactWriteRequest(request FactWriteRequest) (FactWriteRequest, error) {
	if request.TenantScopeID == uuid.Nil || request.TenantID == uuid.Nil || request.SiteID == uuid.Nil ||
		request.PolicyID == uuid.Nil || request.PolicyRevision < 1 || request.ActorScopeID == uuid.Nil ||
		request.ActorUserID == uuid.Nil || !validFactHost(request.Host) || len(request.Materials) < 1 || len(request.Materials) > 3 {
		return FactWriteRequest{}, ErrInvalidFactWrite
	}
	owned := request
	owned.Materials = make([]FactMaterial, len(request.Materials))
	roles := make(map[string]struct{}, len(request.Materials))
	materialIDs := make(map[string]struct{}, len(request.Materials))
	currentReference := ""
	for index, material := range request.Materials {
		if _, exists := roles[material.Role]; exists || !validIdentifier(material.MaterialKeyID) {
			clearFactMaterials(owned.Materials)
			return FactWriteRequest{}, ErrInvalidFactWrite
		}
		if _, exists := materialIDs[material.MaterialKeyID]; exists {
			clearFactMaterials(owned.Materials)
			return FactWriteRequest{}, ErrInvalidFactWrite
		}
		roles[material.Role] = struct{}{}
		materialIDs[material.MaterialKeyID] = struct{}{}
		if !validFactReference(material.Reference) {
			clearFactMaterials(owned.Materials)
			return FactWriteRequest{}, ErrInvalidFactWrite
		}
		switch material.Role {
		case KeyRoleCurrent:
			if !validChallengeKeyReference(material.Reference) || len(material.Plaintext) < 32 || len(material.Plaintext) > 128 {
				clearFactMaterials(owned.Materials)
				return FactWriteRequest{}, ErrInvalidFactWrite
			}
			currentReference = material.Reference
		case KeyRolePrevious:
			if !validChallengeKeyReference(material.Reference) || len(material.Plaintext) < 32 || len(material.Plaintext) > 128 {
				clearFactMaterials(owned.Materials)
				return FactWriteRequest{}, ErrInvalidFactWrite
			}
		case KeyRoleApp:
			if !strings.HasPrefix(material.Reference, "appref:") || !validExternalCredentialMaterial(material.Plaintext) {
				clearFactMaterials(owned.Materials)
				return FactWriteRequest{}, ErrInvalidFactWrite
			}
		default:
			clearFactMaterials(owned.Materials)
			return FactWriteRequest{}, ErrInvalidFactWrite
		}
		owned.Materials[index] = material
		owned.Materials[index].Plaintext = slices.Clone(material.Plaintext)
	}
	if currentReference == "" {
		clearFactMaterials(owned.Materials)
		return FactWriteRequest{}, ErrInvalidFactWrite
	}
	for _, material := range owned.Materials {
		if material.Role == KeyRolePrevious && material.Reference == currentReference {
			clearFactMaterials(owned.Materials)
			return FactWriteRequest{}, ErrInvalidFactWrite
		}
	}
	return owned, nil
}

func validExternalCredentialMaterial(value []byte) bool {
	var credential ExternalCredentialSecret
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credential); err != nil {
		return false
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) || credential.SchemaVersion != ExternalCredentialSchemaVersion ||
		!validIdentifier(credential.Provider) || !validIdentifier(credential.AppID) || len(credential.Secret) < 16 ||
		len(credential.Secret) > 256 || credential.Environment != "sandbox" && credential.Environment != "production" {
		clear(credential.Secret)
		return false
	}
	clear(credential.Secret)
	return true
}

func validFactReference(value string) bool {
	if len(value) < 8 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range []byte(value) {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._:/-", rune(character)) {
			continue
		}
		return false
	}
	return strings.HasPrefix(value, "keyref:") || strings.HasPrefix(value, "vault:") ||
		strings.HasPrefix(value, "kms:") || strings.HasPrefix(value, "appref:")
}

func validChallengeKeyReference(value string) bool {
	return strings.HasPrefix(value, "keyref:") || strings.HasPrefix(value, "vault:") ||
		strings.HasPrefix(value, "kms:")
}

func validFactHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || host != strings.ToLower(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range []byte(label) {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func sameStoredFactMetadata(left, right storedKeyFact) bool {
	return left.TenantScopeID == right.TenantScopeID && left.TenantID == right.TenantID && left.SiteID == right.SiteID &&
		left.Host == right.Host && left.PolicyID == right.PolicyID && left.PolicyRevision == right.PolicyRevision &&
		left.Role == right.Role && left.Reference == right.Reference && left.MaterialKeyID == right.MaterialKeyID &&
		left.WrappingKeyID == right.WrappingKeyID && left.SigningKeyID == right.SigningKeyID
}

func clearFactMaterials(materials []FactMaterial) {
	for index := range materials {
		clear(materials[index].Plaintext)
	}
}

type postgresFactWriteTransaction struct{ tx pgx.Tx }

func (transaction postgresFactWriteTransaction) LockScope(ctx context.Context, request FactWriteRequest) error {
	_, err := transaction.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
		fmt.Sprintf("challenge-key-fact:%s:%d", request.PolicyID, request.PolicyRevision))
	if err != nil {
		return err
	}
	var keyReference string
	var externalProvider, externalAppReference *string
	var enabled, deleted bool
	err = transaction.tx.QueryRow(ctx, `
		SELECT key_reference,external_provider,external_app_reference,enabled,deleted
		FROM challenge_policy_revisions
		WHERE policy_id=$1 AND revision=$2 AND tenant_scope_id=$3 AND tenant_id=$4 AND site_id=$5 AND host=$6
		FOR UPDATE`, request.PolicyID, request.PolicyRevision, request.TenantScopeID, request.TenantID,
		request.SiteID, request.Host).Scan(&keyReference, &externalProvider, &externalAppReference, &enabled, &deleted)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidFactWrite
		}
		return err
	}
	currentReference, requestedProvider, requestedAppReference := requestedPolicyKeys(request)
	if !enabled || deleted || keyReference != currentReference ||
		!sameOptionalString(externalProvider, requestedProvider) ||
		!sameOptionalString(externalAppReference, requestedAppReference) {
		return ErrInvalidFactWrite
	}
	var actorActive bool
	if err := transaction.tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM memberships
			WHERE scope_id=$1 AND user_id=$2 AND status='active'
		)`, request.ActorScopeID, request.ActorUserID).Scan(&actorActive); err != nil {
		return err
	}
	if !actorActive {
		return ErrInvalidFactWrite
	}
	return nil
}

func requestedPolicyKeys(request FactWriteRequest) (string, *string, *string) {
	var currentReference string
	var provider, appReference *string
	for _, material := range request.Materials {
		switch material.Role {
		case KeyRoleCurrent:
			currentReference = material.Reference
		case KeyRoleApp:
			var credential ExternalCredentialSecret
			if json.Unmarshal(material.Plaintext, &credential) == nil {
				providerValue := credential.Provider
				appReferenceValue := material.Reference
				provider, appReference = &providerValue, &appReferenceValue
				clear(credential.Secret)
			}
		}
	}
	return currentReference, provider, appReference
}

func sameOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func (transaction postgresFactWriteTransaction) LoadPolicyFacts(
	ctx context.Context, policyID uuid.UUID, revision int64,
) ([]storedKeyFact, error) {
	rows, err := transaction.tx.Query(ctx, `
		SELECT id,tenant_scope_id,tenant_id,site_id,host,policy_id,policy_revision,role,reference,
		       material_key_id,wrapping_key_id,signing_key_id,ciphertext,signature,active,
		       created_by_scope_id,created_by_user_id,created_at
		FROM challenge_key_facts_138
		WHERE policy_id=$1 AND policy_revision=$2
		ORDER BY role
		FOR UPDATE`, policyID, revision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var facts []storedKeyFact
	for rows.Next() {
		var fact storedKeyFact
		if err := rows.Scan(&fact.ID, &fact.TenantScopeID, &fact.TenantID, &fact.SiteID, &fact.Host,
			&fact.PolicyID, &fact.PolicyRevision, &fact.Role, &fact.Reference, &fact.MaterialKeyID,
			&fact.WrappingKeyID, &fact.SigningKeyID, &fact.Ciphertext, &fact.Signature, &fact.Active,
			&fact.CreatedByScopeID, &fact.CreatedByUserID, &fact.CreatedAt); err != nil {
			return nil, err
		}
		facts = append(facts, fact)
	}
	return facts, rows.Err()
}

func (transaction postgresFactWriteTransaction) InsertFact(ctx context.Context, fact storedKeyFact) error {
	_, err := transaction.tx.Exec(ctx, `
		INSERT INTO challenge_key_facts_138(
			id,tenant_scope_id,tenant_id,site_id,host,policy_id,policy_revision,role,reference,
			material_key_id,wrapping_key_id,signing_key_id,ciphertext,signature,active,
			created_by_scope_id,created_by_user_id,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		fact.ID, fact.TenantScopeID, fact.TenantID, fact.SiteID, fact.Host, fact.PolicyID,
		fact.PolicyRevision, fact.Role, fact.Reference, fact.MaterialKeyID, fact.WrappingKeyID,
		fact.SigningKeyID, fact.Ciphertext, fact.Signature, fact.Active, fact.CreatedByScopeID,
		fact.CreatedByUserID, fact.CreatedAt)
	return err
}
