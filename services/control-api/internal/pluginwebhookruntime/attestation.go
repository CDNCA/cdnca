package pluginwebhookruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Migration 084 accepts a broker publication (delivery outbox or dead letter)
// only with an Ed25519 attestation by the active runtime attestation key. The
// runtime holds the private key; the database holds the public key in
// plugin_webhook_runtime_attestation_head and verifies every signature.

// attestationKeyLifetime bounds the first-generation key installed by the
// runtime when the database has no attestation head yet. Rotation (retire the
// head key, install generation+1, advance the head) is an operator action.
const attestationKeyLifetime = 5 * 365 * 24 * time.Hour

var (
	attestationKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	errAttestationKey       = errors.New("plugin webhook runtime attestation key does not match the database head")
)

type attestationHead struct {
	generation uint64
	keyID      string
	natsDomain string
	// key is the configured private key whose public half the head carries.
	key ed25519.PrivateKey
}

func validAttestationKey(keyID string, key ed25519.PrivateKey) bool {
	return attestationKeyIDPattern.MatchString(keyID) && len(key) == ed25519.PrivateKeySize
}

// validNextAttestationKey: the staged rotation key is optional, but when set it
// must be complete and differ from the current key in both ID and key.
func validNextAttestationKey(config Config) bool {
	if config.NextAttestationKeyID == "" && config.NextAttestationKey == nil {
		return true
	}
	return validAttestationKey(config.NextAttestationKeyID, config.NextAttestationKey) &&
		config.NextAttestationKeyID != config.AttestationKeyID &&
		!bytes.Equal(config.NextAttestationKey.Public().(ed25519.PublicKey),
			config.AttestationKey.Public().(ed25519.PublicKey))
}

// headKey returns the configured key (current or staged next) that the head
// names, or nil when neither matches.
func (runtime *Runtime) headKey(keyID string, publicKey []byte) ed25519.PrivateKey {
	for _, candidate := range []struct {
		id  string
		key ed25519.PrivateKey
	}{{runtime.config.AttestationKeyID, runtime.config.AttestationKey},
		{runtime.config.NextAttestationKeyID, runtime.config.NextAttestationKey}} {
		if candidate.key != nil && keyID == candidate.id &&
			bytes.Equal(publicKey, candidate.key.Public().(ed25519.PublicKey)) {
			return candidate.key
		}
	}
	return nil
}

// lockAttestationHead reads the head in the publishing transaction (FOR SHARE,
// the order 084's publication functions take it in) and requires it to carry
// this runtime's key and JetStream identity.
func (runtime *Runtime) lockAttestationHead(ctx context.Context, tx pgx.Tx) (attestationHead, error) {
	var head attestationHead
	var generation, stream, prefix string
	var publicKey []byte
	err := tx.QueryRow(ctx, `SELECT key_generation::text,key_id,public_key,nats_domain,delivery_stream,
			delivery_subject_prefix FROM plugin_webhook_runtime_attestation_head WHERE singleton=true FOR SHARE`).
		Scan(&generation, &head.keyID, &publicKey, &head.natsDomain, &stream, &prefix)
	if errors.Is(err, pgx.ErrNoRows) {
		return attestationHead{}, fmt.Errorf("%w: no attestation head is installed", errAttestationKey)
	}
	if err != nil {
		return attestationHead{}, err
	}
	if head.generation, err = parseUint(generation); err != nil {
		return attestationHead{}, err
	}
	head.key = runtime.headKey(head.keyID, publicKey)
	if head.key == nil ||
		stream != runtime.config.JetStream.DeliveryStream || prefix != runtime.config.JetStream.DeliverySubjectPrefix {
		return attestationHead{}, errAttestationKey
	}
	return head, nil
}

// ensureAttestationHead installs generation 1 with this runtime's key when the
// database has no head. It needs INSERT on the attestation tables (the schema
// owner); an existing head is never changed here.
func (runtime *Runtime) ensureAttestationHead(ctx context.Context) error {
	var exists bool
	if err := runtime.pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM plugin_webhook_runtime_attestation_head WHERE singleton=true)`).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	tx, err := runtime.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE plugin_webhook_runtime_attestation_keys IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return fmt.Errorf("install plugin webhook runtime attestation key: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM plugin_webhook_runtime_attestation_head WHERE singleton=true)`).Scan(&exists); err != nil || exists {
		return err
	}
	public := runtime.config.AttestationKey.Public().(ed25519.PublicKey)
	var notBefore, expiresAt time.Time
	if err := tx.QueryRow(ctx, `SELECT date_trunc('second',clock_timestamp())-interval '1 minute',
		date_trunc('second',clock_timestamp())+$1::interval`, attestationKeyLifetime.String()).
		Scan(&notBefore, &expiresAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO plugin_webhook_runtime_attestation_keys(
			key_generation,key_id,public_key,status,not_before,expires_at) VALUES(1,$1,$2,'active',$3,$4)`,
		runtime.config.AttestationKeyID, []byte(public), notBefore, expiresAt); err != nil {
		return fmt.Errorf("install plugin webhook runtime attestation key: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO plugin_webhook_runtime_attestation_head(
			singleton,key_generation,key_id,public_key,status,not_before,expires_at,nats_domain,
			delivery_stream,delivery_subject_prefix,dead_letter_stream,dead_letter_subject)
		VALUES(true,1,$1,$2,'active',$3,$4,'',$5,$6,$7,$8)`,
		runtime.config.AttestationKeyID, []byte(public), notBefore, expiresAt,
		runtime.config.JetStream.DeliveryStream, runtime.config.JetStream.DeliverySubjectPrefix,
		runtime.config.JetStream.DeadLetterStream, runtime.config.JetStream.DeadLetterSubject); err != nil {
		return fmt.Errorf("install plugin webhook runtime attestation head: %w", err)
	}
	return tx.Commit(ctx)
}

// attestationFrame is 084's plugin_webhook_attestation_frame_084: each field
// prefixed by its big-endian uint32 length.
func attestationFrame(fields ...string) []byte {
	var framed []byte
	var size [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		framed = append(framed, size[:]...)
		framed = append(framed, field...)
	}
	return framed
}

func signAttestation(key ed25519.PrivateKey, fields ...string) []byte {
	digest := sha256.Sum256(attestationFrame(fields...))
	return ed25519.Sign(key, digest[:])
}

type outboxPublication struct {
	eventID, outboxID uuid.UUID
	publishAttempt    uint64
	queueDigest       []byte
}

// outboxAttestation signs 084's plugin_webhook_outbox_attestation_sha256_084
// fields for one delivery-stream publication.
func (runtime *Runtime) outboxAttestation(head attestationHead, lease outboxLease, facts outboxPublication,
	epoch int64, subject string, sequence uint64) []byte {
	return signAttestation(head.key, "cdnca.plugin-webhook.nats-publication/outbox/v1",
		strconv.FormatUint(head.generation, 10), head.keyID, head.natsDomain,
		lease.tenantScope.String(), lease.subscription.String(), lease.delivery.String(),
		facts.eventID.String(), facts.outboxID.String(), lease.leaseToken.String(),
		strconv.FormatUint(facts.publishAttempt, 10), runtime.config.JetStream.DeliveryStream,
		strconv.FormatInt(epoch, 10), subject, strconv.FormatUint(sequence, 10), lease.messageID,
		hex.EncodeToString(facts.queueDigest), "0")
}

func optionalUintText(value *uint64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatUint(*value, 10)
}

// deadLetterAttestation signs 084's plugin_webhook_dead_letter_attestation_sha256_084
// fields for one dead-letter stream publication at sequence.
func (runtime *Runtime) deadLetterAttestation(head attestationHead, row deadLetterRow, epoch int64,
	sequence uint64, wireDigest []byte) []byte {
	return signAttestation(head.key, "cdnca.plugin-webhook.nats-publication/dead-letter/v1",
		strconv.FormatUint(head.generation, 10), head.keyID, head.natsDomain,
		row.tenantScope.String(), row.subscription.String(), row.delivery.String(), row.eventID.String(),
		row.id.String(), row.generation.String(), row.phase, optionalUintText(row.high),
		optionalUintText(row.boundary), optionalUintText(row.cursor), row.stream, strconv.FormatInt(epoch, 10),
		row.subject, strconv.FormatUint(sequence, 10), row.messageID, hex.EncodeToString(row.payloadDigest),
		hex.EncodeToString(wireDigest), strconv.FormatUint(sequence-1, 10))
}

// prepareAttestation installs the first attestation head once per runtime
// before the first publication needs it.
func (runtime *Runtime) prepareAttestation(ctx context.Context) error {
	runtime.attestationMu.Lock()
	defer runtime.attestationMu.Unlock()
	if runtime.attestationReady {
		return nil
	}
	if err := runtime.ensureAttestationHead(ctx); err != nil {
		return err
	}
	runtime.attestationReady = true
	return nil
}
