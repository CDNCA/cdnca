package challengepublication

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// the provider app credential a tenant enters in the console
// (migration 655 challenge_external_credentials). The secret is AES-256-GCM
// under CHALLENGE_POLICY_FACT_KEK with ExternalCredentialAAD; the row is
// mutable (one per policy), so it is bound by its own revision instead of a
// signature like challenge_key_facts_138.
const externalCredentialDomain = "cdnca-challenge-external-credential-v1\x00"

// ExternalCredentialSource loads the console credential of a policy.
type ExternalCredentialSource interface {
	LoadExternalCredential(context.Context, PublicationSnapshot) (*ExternalCredentialSecret, error)
}

// ExternalCredentialAAD binds a ciphertext to its policy, provider, app id,
// environment and credential revision.
func ExternalCredentialAAD(policyID uuid.UUID, provider, appID, environment string, revision int64) ([]byte, error) {
	if policyID == uuid.Nil || !ValidExternalProvider(provider) || !ValidExternalAppID(appID) ||
		(environment != "sandbox" && environment != "production") || revision < 1 {
		return nil, ErrKeyUnavailable
	}
	buffer := bytes.NewBufferString(externalCredentialDomain)
	for _, value := range []string{policyID.String(), provider, appID, environment} {
		if binary.Write(buffer, binary.BigEndian, uint32(len(value))) != nil || writeAll(buffer, []byte(value)) != nil {
			return nil, ErrKeyUnavailable
		}
	}
	if binary.Write(buffer, binary.BigEndian, uint64(revision)) != nil {
		return nil, ErrKeyUnavailable
	}
	return buffer.Bytes(), nil
}

type PostgresExternalCredentialSource struct {
	pool   *pgxpool.Pool
	cipher BoundFactCipher
}

func NewPostgresExternalCredentialSource(pool *pgxpool.Pool, factCipher BoundFactCipher) (*PostgresExternalCredentialSource, error) {
	if pool == nil || nilFactDependency(factCipher) {
		return nil, ErrInvalidRuntime
	}
	return &PostgresExternalCredentialSource{pool: pool, cipher: factCipher}, nil
}

func (source *PostgresExternalCredentialSource) LoadExternalCredential(
	ctx context.Context, snapshot PublicationSnapshot,
) (*ExternalCredentialSecret, error) {
	if source == nil || ctx == nil || snapshot.ExternalProvider == nil || snapshot.PolicyID == uuid.Nil {
		return nil, ErrKeyUnavailable
	}
	var provider, appID, environment, wrappingKeyID string
	var ciphertext []byte
	var revision int64
	err := source.pool.QueryRow(ctx, `
		SELECT provider, app_id, environment, secret_ciphertext, wrapping_key_id, revision
		FROM challenge_external_credentials
		WHERE policy_id=$1 AND tenant_scope_id=$2`, snapshot.PolicyID, snapshot.TenantScopeID).
		Scan(&provider, &appID, &environment, &ciphertext, &wrappingKeyID, &revision)
	if errors.Is(err, pgx.ErrNoRows) || err != nil || provider != snapshot.ExternalProvider.Provider {
		return nil, ErrKeyUnavailable
	}
	aad, err := ExternalCredentialAAD(snapshot.PolicyID, provider, appID, environment, revision)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	secret, err := source.cipher.DecryptBound(wrappingKeyID, ciphertext, aad)
	if err != nil || len(secret) < 16 || len(secret) > 256 {
		clear(secret)
		return nil, ErrKeyUnavailable
	}
	return &ExternalCredentialSecret{SchemaVersion: ExternalCredentialSchemaVersion, Provider: provider,
		AppID: appID, Secret: secret, Environment: environment}, nil
}

var _ ExternalCredentialSource = (*PostgresExternalCredentialSource)(nil)
