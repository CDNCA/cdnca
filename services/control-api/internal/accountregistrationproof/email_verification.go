package accountregistrationproof

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RowQuerier is a pool or transaction.
type RowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// VerifiedRegistration is the registration that created a user.
type VerifiedRegistration struct {
	TenantID uuid.UUID
	ScopeID  uuid.UUID
}

// VerifiedRegistrationEmail reports whether email is the address whose code
// the user's own registration consumed: the account was created by a
// registration, and that registration spent an email proof for exactly this
// destination. An address set later (profile, administrator, import) or a
// registration proved only by SMS or by the image CAPTCHA is not verified.
// keys are the digest keys the proofs were stored under (the Turnstile and
// built-in registration flows each have one). The proof lookup runs whether
// or not a registration exists, so a miss costs the same queries as a hit.
func VerifiedRegistrationEmail(
	ctx context.Context,
	query RowQuerier,
	keys [][]byte,
	userID uuid.UUID,
	email string,
) (VerifiedRegistration, bool, error) {
	if query == nil {
		return VerifiedRegistration{}, false, ErrAuthorityFailure
	}
	var registration VerifiedRegistration
	var idempotencyKey string
	err := query.QueryRow(ctx, `SELECT idempotency_key,tenant_id,scope_id
		FROM account_registration_requests_159
		WHERE user_id=$1 AND outcome='created'`, userID).
		Scan(&idempotencyKey, &registration.TenantID, &registration.ScopeID)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return VerifiedRegistration{}, false, err
	}
	idempotencyDigests := make([][]byte, 0, len(keys))
	destinationDigests := make([][]byte, 0, len(keys))
	for _, key := range keys {
		if len(key) < 32 {
			continue
		}
		idempotency := authorityDigest(key, idempotencyDigestDomain, []byte(idempotencyKey))
		destination := authorityDigest(key, destinationDigestDomain, []byte(email))
		idempotencyDigests = append(idempotencyDigests, idempotency[:])
		destinationDigests = append(destinationDigests, destination[:])
	}
	var proved bool
	if err := query.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM account_registration_proofs_162 proof
		JOIN unnest($1::bytea[],$2::bytea[]) AS expected(idempotency_digest,destination_digest)
		  ON proof.consumed_idempotency_digest=expected.idempotency_digest
		 AND proof.destination_digest=expected.destination_digest
		WHERE proof.channel='email' AND proof.use_revision=1)`, idempotencyDigests, destinationDigests).
		Scan(&proved); err != nil {
		return VerifiedRegistration{}, false, err
	}
	if !found || !proved || email == "" {
		return VerifiedRegistration{}, false, nil
	}
	return registration, true, nil
}
