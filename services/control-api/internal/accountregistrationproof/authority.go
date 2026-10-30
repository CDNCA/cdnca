package accountregistrationproof

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	ReferenceBytes         = 32
	ReferenceEncodedLength = 43
	RiskContextNormal      = "normal"
	RiskContextStepUp      = "step_up"
	defaultMaxTTL          = 10 * time.Minute
	maximumMaxTTL          = 30 * time.Minute
)

var (
	ErrInvalidConfig    = errors.New("invalid account registration proof authority config")
	ErrInvalidInput     = errors.New("invalid account registration proof claim")
	ErrAuthorityFailure = errors.New("account registration proof authority unavailable")

	registrationPhonePattern = regexp.MustCompile(`^\+?[0-9]{6,20}$`)
	metadataPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

	referenceDigestDomain   = []byte("account-registration-proof:v1:reference\x00")
	destinationDigestDomain = []byte("account-registration-proof:v1:destination\x00")
	sourceDigestDomain      = []byte("account-registration-proof:v1:source\x00")
	idempotencyDigestDomain = []byte("account-registration-proof:v1:idempotency\x00")
	bindingDigestDomain     = []byte("account-registration-proof:v1:binding\x00")
)

type Config struct {
	DigestKey []byte
	Clock     func() time.Time
	MaxTTL    time.Duration
	NextID    func() (uuid.UUID, error)
	Random    io.Reader
}

type Authority struct {
	pool      *pgxpool.Pool
	digestKey []byte
	now       func() time.Time
	maxTTL    time.Duration
	nextID    func() (uuid.UUID, error)
	random    io.Reader
}

type IssueRequest struct {
	Channel           string
	Destination       string
	Source            string
	SubjectDigest     [32]byte
	HumanVerifiedAt   time.Time
	ContactVerifiedAt time.Time
	ExpiresAt         time.Time
	AttemptRevision   int64
	RiskContext       string
}

type IssueResult struct {
	Reference string
	Proof     accountregistration.RegistrationProof
}

type storedProof struct {
	evidenceID                uuid.UUID
	channel                   string
	destinationDigest         []byte
	subjectDigest             []byte
	sourceDigest              []byte
	riskContext               string
	humanVerifiedAt           time.Time
	contactVerifiedAt         time.Time
	expiresAt                 time.Time
	attemptRevision           int64
	useRevision               int64
	consumedIdempotencyDigest []byte
	consumedBindingDigest     []byte
	databaseNow               time.Time
}

func NewAuthority(pool *pgxpool.Pool, config Config) (*Authority, error) {
	if pool == nil || len(config.DigestKey) < 32 {
		return nil, ErrInvalidConfig
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.MaxTTL == 0 {
		config.MaxTTL = defaultMaxTTL
	}
	if config.MaxTTL <= 0 || config.MaxTTL > maximumMaxTTL {
		return nil, ErrInvalidConfig
	}
	if config.NextID == nil {
		config.NextID = uuid.NewV7
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	return &Authority{
		pool: pool, digestKey: append([]byte(nil), config.DigestKey...), now: config.Clock,
		maxTTL: config.MaxTTL, nextID: config.NextID, random: config.Random,
	}, nil
}

func (authority *Authority) Issue(ctx context.Context, request IssueRequest) (IssueResult, error) {
	if authority == nil || authority.pool == nil || len(authority.digestKey) < 32 || authority.now == nil ||
		authority.nextID == nil || authority.random == nil {
		return IssueResult{}, ErrAuthorityFailure
	}
	now := canonicalTime(authority.now())
	destination, source, ok := validateIssueRequest(request, now, authority.maxTTL)
	if !ok {
		return IssueResult{}, ErrInvalidInput
	}
	referenceBytes := make([]byte, ReferenceBytes)
	if _, err := io.ReadFull(authority.random, referenceBytes); err != nil {
		return IssueResult{}, fmt.Errorf("%w: generate reference", ErrAuthorityFailure)
	}
	reference := base64.RawURLEncoding.EncodeToString(referenceBytes)
	evidenceID, err := authority.nextID()
	if err != nil || evidenceID == uuid.Nil {
		return IssueResult{}, fmt.Errorf("%w: generate evidence identity", ErrAuthorityFailure)
	}
	humanVerifiedAt := canonicalTime(request.HumanVerifiedAt)
	contactVerifiedAt := canonicalTime(request.ContactVerifiedAt)
	expiresAt := canonicalTime(request.ExpiresAt)
	referenceDigest := authorityDigest(authority.digestKey, referenceDigestDomain, []byte(reference))
	destinationDigest := authorityDigest(authority.digestKey, destinationDigestDomain, []byte(destination))
	sourceDigest := authorityDigest(authority.digestKey, sourceDigestDomain, []byte(source))
	_, err = authority.pool.Exec(ctx, `INSERT INTO account_registration_proofs_162 (
		evidence_id,reference_digest,channel,destination_digest,subject_digest,source_digest,risk_context,
		human_verified_at,contact_verified_at,expires_at,attempt_revision,use_revision,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0,clock_timestamp())`,
		evidenceID, referenceDigest[:], request.Channel, destinationDigest[:], request.SubjectDigest[:],
		sourceDigest[:], request.RiskContext, humanVerifiedAt, contactVerifiedAt, expiresAt, request.AttemptRevision)
	if err != nil {
		return IssueResult{}, fmt.Errorf("%w: persist evidence", ErrAuthorityFailure)
	}
	return IssueResult{
		Reference: reference,
		Proof: accountregistration.RegistrationProof{
			EvidenceID: evidenceID, Channel: request.Channel, Destination: destination,
			HumanVerifiedAt: humanVerifiedAt, ContactVerifiedAt: contactVerifiedAt, ExpiresAt: expiresAt,
		},
	}, nil
}

func (authority *Authority) VerifyAndConsume(
	ctx context.Context,
	request accountregistration.RegistrationProofRequest,
) (accountregistration.RegistrationProof, error) {
	if authority == nil || authority.pool == nil || len(authority.digestKey) < 32 {
		return accountregistration.RegistrationProof{}, ErrAuthorityFailure
	}
	destination, source, ok := validateConsumeRequest(request)
	if !ok {
		return accountregistration.RegistrationProof{}, accountregistration.ErrProofInvalid
	}
	referenceDigest := authorityDigest(authority.digestKey, referenceDigestDomain, []byte(request.Reference))
	destinationDigest := authorityDigest(authority.digestKey, destinationDigestDomain, []byte(destination))
	sourceDigest := authorityDigest(authority.digestKey, sourceDigestDomain, []byte(source))
	idempotencyDigest := authorityDigest(authority.digestKey, idempotencyDigestDomain, []byte(request.IdempotencyKey))
	var result accountregistration.RegistrationProof
	err := pgx.BeginTxFunc(ctx, authority.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		stored, err := loadStoredProof(ctx, tx, referenceDigest)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return accountregistration.ErrProofInvalid
			}
			return err
		}
		bindingDigest := consumeBindingDigest(authority.digestKey, request.Channel, stored.attemptRevision,
			request.SubjectDigest, destinationDigest, sourceDigest)
		if !validStoredProof(stored, request.Channel, request.SubjectDigest, destinationDigest, sourceDigest) {
			return accountregistration.ErrProofInvalid
		}
		if stored.useRevision == 1 {
			if !hmac.Equal(stored.consumedIdempotencyDigest, idempotencyDigest[:]) ||
				!hmac.Equal(stored.consumedBindingDigest, bindingDigest[:]) {
				return accountregistration.ErrProofInvalid
			}
		} else {
			command, err := tx.Exec(ctx, `UPDATE account_registration_proofs_162
				SET use_revision=1,consumed_idempotency_digest=$2,consumed_binding_digest=$3,
				    consumed_at=clock_timestamp()
				WHERE evidence_id=$1 AND use_revision=0`, stored.evidenceID, idempotencyDigest[:], bindingDigest[:])
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return accountregistration.ErrProofInvalid
			}
		}
		result = accountregistration.RegistrationProof{
			EvidenceID: stored.evidenceID, Channel: stored.channel, Destination: destination,
			HumanVerifiedAt: stored.humanVerifiedAt, ContactVerifiedAt: stored.contactVerifiedAt,
			ExpiresAt: stored.expiresAt,
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, accountregistration.ErrProofInvalid) {
			return accountregistration.RegistrationProof{}, accountregistration.ErrProofInvalid
		}
		return accountregistration.RegistrationProof{}, fmt.Errorf("%w: consume evidence", ErrAuthorityFailure)
	}
	return result, nil
}

func loadStoredProof(ctx context.Context, tx pgx.Tx, referenceDigest [32]byte) (storedProof, error) {
	var proof storedProof
	err := tx.QueryRow(ctx, `SELECT evidence_id,channel,destination_digest,subject_digest,source_digest,risk_context,
		human_verified_at,contact_verified_at,expires_at,attempt_revision,use_revision,
		consumed_idempotency_digest,consumed_binding_digest,clock_timestamp()
		FROM account_registration_proofs_162 WHERE reference_digest=$1 FOR UPDATE`, referenceDigest[:]).Scan(
		&proof.evidenceID, &proof.channel, &proof.destinationDigest, &proof.subjectDigest, &proof.sourceDigest,
		&proof.riskContext, &proof.humanVerifiedAt, &proof.contactVerifiedAt, &proof.expiresAt,
		&proof.attemptRevision, &proof.useRevision, &proof.consumedIdempotencyDigest,
		&proof.consumedBindingDigest, &proof.databaseNow,
	)
	return proof, err
}

func validStoredProof(
	proof storedProof,
	channel string,
	subjectDigest [32]byte,
	destinationDigest [32]byte,
	sourceDigest [32]byte,
) bool {
	now := canonicalTime(proof.databaseNow)
	return proof.evidenceID != uuid.Nil && proof.channel == channel && validRiskContext(proof.riskContext) &&
		proof.attemptRevision > 0 && (proof.useRevision == 0 || proof.useRevision == 1) &&
		hmac.Equal(proof.destinationDigest, destinationDigest[:]) &&
		hmac.Equal(proof.subjectDigest, subjectDigest[:]) && hmac.Equal(proof.sourceDigest, sourceDigest[:]) &&
		!proof.humanVerifiedAt.IsZero() && !proof.contactVerifiedAt.IsZero() && !proof.expiresAt.IsZero() &&
		!proof.humanVerifiedAt.After(now) && !proof.contactVerifiedAt.After(now) && proof.expiresAt.After(now) &&
		!proof.humanVerifiedAt.After(proof.expiresAt) && !proof.contactVerifiedAt.After(proof.expiresAt) &&
		((proof.useRevision == 0 && len(proof.consumedIdempotencyDigest) == 0 && len(proof.consumedBindingDigest) == 0) ||
			(proof.useRevision == 1 && len(proof.consumedIdempotencyDigest) == sha256.Size &&
				len(proof.consumedBindingDigest) == sha256.Size))
}

func validateIssueRequest(request IssueRequest, now time.Time, maxTTL time.Duration) (string, string, bool) {
	destination, destinationOK := canonicalDestination(request.Channel, request.Destination)
	source, sourceOK := canonicalSource(request.Source)
	humanVerifiedAt := canonicalTime(request.HumanVerifiedAt)
	contactVerifiedAt := canonicalTime(request.ContactVerifiedAt)
	expiresAt := canonicalTime(request.ExpiresAt)
	validTimes := !humanVerifiedAt.IsZero() && !contactVerifiedAt.IsZero() && !expiresAt.IsZero() &&
		!humanVerifiedAt.After(now) && !contactVerifiedAt.After(now) && expiresAt.After(now) &&
		!expiresAt.After(now.Add(maxTTL)) && !humanVerifiedAt.After(expiresAt) && !contactVerifiedAt.After(expiresAt)
	return destination, source, destinationOK && sourceOK && subtle.ConstantTimeCompare(request.SubjectDigest[:], make([]byte, 32)) == 0 &&
		request.AttemptRevision > 0 && validRiskContext(request.RiskContext) && validTimes
}

func validateConsumeRequest(request accountregistration.RegistrationProofRequest) (string, string, bool) {
	destination, destinationOK := canonicalDestination(request.Channel, request.Destination)
	source, sourceOK := canonicalSource(request.Source)
	return destination, source, validReference(request.Reference) && destinationOK && sourceOK &&
		metadataPattern.MatchString(request.IdempotencyKey) &&
		subtle.ConstantTimeCompare(request.SubjectDigest[:], make([]byte, 32)) == 0
}

func canonicalDestination(channel, destination string) (string, bool) {
	switch channel {
	case accountregistration.VerificationEmail:
		canonical := strings.ToLower(strings.TrimSpace(destination))
		address, err := mail.ParseAddress(canonical)
		return canonical, err == nil && canonical == destination && address.Address == canonical && len(canonical) <= 254
	case accountregistration.VerificationSMS:
		canonical := strings.TrimSpace(destination)
		return canonical, canonical == destination && registrationPhonePattern.MatchString(canonical)
	default:
		return "", false
	}
}

func canonicalSource(source string) (string, bool) {
	address, err := netip.ParseAddr(source)
	if err != nil || !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
		return "", false
	}
	canonical := address.Unmap().String()
	return canonical, source == canonical
}

func validReference(reference string) bool {
	if len(reference) != ReferenceEncodedLength {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(reference)
	return err == nil && len(decoded) == ReferenceBytes && base64.RawURLEncoding.EncodeToString(decoded) == reference
}

func validRiskContext(value string) bool {
	return value == RiskContextNormal || value == RiskContextStepUp
}

func authorityDigest(key, domain, value []byte) [32]byte {
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(domain)
	_, _ = digest.Write(value)
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func consumeBindingDigest(
	key []byte,
	channel string,
	attemptRevision int64,
	subjectDigest [32]byte,
	destinationDigest [32]byte,
	sourceDigest [32]byte,
) [32]byte {
	value := bytes.NewBuffer(make([]byte, 0, len(channel)+1+8+96))
	value.WriteString(channel)
	value.WriteByte(0)
	_ = binary.Write(value, binary.BigEndian, attemptRevision)
	value.Write(subjectDigest[:])
	value.Write(destinationDigest[:])
	value.Write(sourceDigest[:])
	return authorityDigest(key, bindingDigestDomain, value.Bytes())
}

func canonicalTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}
