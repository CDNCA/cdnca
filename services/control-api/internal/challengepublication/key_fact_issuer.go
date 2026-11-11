package challengepublication

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// KeyFactIssueRequest names one enabled challenge policy revision that needs
// its HMAC key fact. The revision row must already exist in tx.
type KeyFactIssueRequest struct {
	TenantScopeID, TenantID, SiteID, PolicyID uuid.UUID
	Host, KeyReference                        string
	PolicyRevision                            int64
	ActorScopeID, ActorUserID                 uuid.UUID
}

// KeyFactIssuer is the production writer of the policy HMAC key
// (challenge_key_facts_138, role current): the policy store calls it in the
// transaction that creates a revision. A revision keeps the secret of the
// closest earlier revision that has one for the same key reference (so
// outstanding pass cookies stay valid across edits); a new or changed
// reference gets a fresh 32-byte random secret, and the replaced secret is
// kept as role previous for one revision. Secrets are sealed with the fact
// KEK bound to the fact's identity and signed like every fact.
type KeyFactIssuer struct {
	writer *FactWriter
	random io.Reader
}

func NewKeyFactIssuer(factCipher BoundFactWriterCipher, signer Ed25519FactSigner) (*KeyFactIssuer, error) {
	return newKeyFactIssuer(factCipher, signer, rand.Reader)
}

func newKeyFactIssuer(factCipher BoundFactWriterCipher, signer Ed25519FactSigner, random io.Reader) (*KeyFactIssuer, error) {
	if random == nil {
		return nil, ErrInvalidRuntime
	}
	run := func(context.Context, func(factWriteTransaction) error) error { return ErrInvalidRuntime }
	writer, err := newFactWriter(run, factCipher, signer, time.Now, uuid.NewRandom)
	if err != nil {
		return nil, err
	}
	return &KeyFactIssuer{writer: writer, random: random}, nil
}

// IssueTx writes the facts of request's revision in tx; a revision that
// already has facts is left alone.
func (issuer *KeyFactIssuer) IssueTx(ctx context.Context, tx pgx.Tx, request KeyFactIssueRequest) error {
	if issuer == nil || issuer.writer == nil || tx == nil || ctx == nil || request.PolicyRevision < 1 ||
		!validChallengeKeyReference(request.KeyReference) {
		return ErrInvalidFactWrite
	}
	transaction := postgresFactWriteTransaction{tx: tx}
	existing, err := transaction.LoadPolicyFacts(ctx, request.PolicyID, request.PolicyRevision)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return nil
	}
	materials, err := issuer.materials(ctx, tx, request)
	if err != nil {
		return err
	}
	defer clearFactMaterials(materials)
	owned := FactWriteRequest{
		TenantScopeID: request.TenantScopeID, TenantID: request.TenantID, SiteID: request.SiteID,
		PolicyID: request.PolicyID, Host: request.Host, PolicyRevision: request.PolicyRevision,
		ActorScopeID: request.ActorScopeID, ActorUserID: request.ActorUserID, Materials: materials,
	}
	prepared, err := issuer.writer.prepare(ctx, owned)
	if err != nil {
		return err
	}
	for _, fact := range prepared {
		if err := transaction.InsertFact(ctx, fact); err != nil {
			return err
		}
	}
	return nil
}

// materials is the current secret (carried over or fresh) and, when the key
// reference changed, the replaced secret as previous.
func (issuer *KeyFactIssuer) materials(ctx context.Context, tx pgx.Tx, request KeyFactIssueRequest) ([]FactMaterial, error) {
	var (
		priorRevision int64
		prior         storedKeyFact
	)
	err := tx.QueryRow(ctx, `
		SELECT policy_revision,id,tenant_scope_id,tenant_id,site_id,host,policy_id,role,reference,
		       material_key_id,wrapping_key_id,signing_key_id,ciphertext,signature
		FROM challenge_key_facts_138
		WHERE policy_id=$1 AND policy_revision<$2 AND role='current' AND active
		ORDER BY policy_revision DESC LIMIT 1`, request.PolicyID, request.PolicyRevision).
		Scan(&priorRevision, &prior.ID, &prior.TenantScopeID, &prior.TenantID, &prior.SiteID, &prior.Host,
			&prior.PolicyID, &prior.Role, &prior.Reference, &prior.MaterialKeyID, &prior.WrappingKeyID,
			&prior.SigningKeyID, &prior.Ciphertext, &prior.Signature)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		prior.PolicyRevision = priorRevision
		aad, aadErr := challengeKeyFactAAD(prior.KeyFact)
		if aadErr != nil {
			return nil, ErrKeyUnavailable
		}
		plaintext, decryptErr := issuer.writer.cipher.DecryptBound(prior.WrappingKeyID, prior.Ciphertext, aad)
		if decryptErr != nil {
			// The KEK that sealed the earlier secret is gone: do not mint a
			// silently different key, surface it.
			return nil, ErrKeyUnavailable
		}
		if prior.Reference == request.KeyReference {
			return []FactMaterial{{Role: KeyRoleCurrent, Reference: request.KeyReference,
				MaterialKeyID: prior.MaterialKeyID, Plaintext: plaintext}}, nil
		}
		fresh, err := issuer.fresh(request.KeyReference)
		if err != nil {
			clear(plaintext)
			return nil, err
		}
		return []FactMaterial{fresh, {Role: KeyRolePrevious, Reference: prior.Reference,
			MaterialKeyID: prior.MaterialKeyID, Plaintext: plaintext}}, nil
	}
	fresh, err := issuer.fresh(request.KeyReference)
	if err != nil {
		return nil, err
	}
	return []FactMaterial{fresh}, nil
}

func (issuer *KeyFactIssuer) fresh(reference string) (FactMaterial, error) {
	secret := make([]byte, 32)
	identifier := make([]byte, 8)
	if _, err := io.ReadFull(issuer.random, secret); err != nil {
		return FactMaterial{}, ErrKeyUnavailable
	}
	if _, err := io.ReadFull(issuer.random, identifier); err != nil {
		clear(secret)
		return FactMaterial{}, ErrKeyUnavailable
	}
	return FactMaterial{Role: KeyRoleCurrent, Reference: reference,
		MaterialKeyID: "k" + hex.EncodeToString(identifier), Plaintext: secret}, nil
}
