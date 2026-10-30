package installationban

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	contract "github.com/cdnca/cdnca/libs/entitlement/installationban"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// KeyLookup returns a trusted license signing key (entitlementguard.TrustStore.PublicKey).
type KeyLookup func(keyID string) (ed25519.PublicKey, bool)

// State is the last accepted documents and the lease fields the lock reads.
type State struct {
	Notice       []byte
	NoticeBody   *contract.BanNotice
	Ticket       []byte
	TicketBody   *contract.ServiceTicket
	LeaseStatus  string    // control_installation_entitlement.last_status ("" without a lease row)
	LeaseGrace   time.Time // grace_until of the current lease (zero without one)
	LeasePresent bool
}

// Store keeps control_installation_ban_state (control migration 429).
type Store struct {
	pool           *pgxpool.Pool
	installationID uuid.UUID
	keys           KeyLookup
}

func NewStore(pool *pgxpool.Pool, installationID uuid.UUID, keys KeyLookup) (*Store, error) {
	if pool == nil || installationID == uuid.Nil || keys == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Store{pool: pool, installationID: installationID, keys: keys}, nil
}

func (store *Store) verifyOptions(keyID string, now time.Time) contract.VerifyOptions {
	keys := map[string]ed25519.PublicKey{}
	if key, ok := store.keys(keyID); ok {
		keys[keyID] = key
	}
	return contract.VerifyOptions{Now: now, ExpectedInstallationID: store.installationID.String(), Keys: keys}
}

// Accept verifies the fetched documents and keeps each one whose revision is
// not lower than the stored one of its kind (the shared revision decides
// between a ban and a ticket in contract.Evaluate). A document that fails
// verification is refused and reported; the stored one stays (LKG).
func (store *Store) Accept(ctx context.Context, documents Documents, now time.Time) (State, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return State{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO control_installation_ban_state (installation_id, received_at, updated_at)
		VALUES ($1, $2, $2) ON CONFLICT (singleton) DO NOTHING`, store.installationID, now.UTC()); err != nil {
		return State{}, err
	}
	var storedInstallation uuid.UUID
	var storedNotice, storedTicket []byte
	var noticeRevision, ticketRevision *int64
	if err := tx.QueryRow(ctx, `SELECT installation_id, notice, notice_revision, ticket, ticket_revision
		FROM control_installation_ban_state WHERE singleton FOR UPDATE`).Scan(&storedInstallation, &storedNotice,
		&noticeRevision, &storedTicket, &ticketRevision); err != nil {
		return State{}, err
	}
	if storedInstallation != store.installationID {
		return State{}, fmt.Errorf("installation ban state belongs to installation %s", storedInstallation)
	}
	var refused error
	if documents.Notice != nil {
		if err := store.acceptNotice(ctx, tx, documents.Notice, storedNotice, noticeRevision, now); err != nil {
			refused = errors.Join(refused, fmt.Errorf("ban notice refused: %w", err))
		}
	}
	if documents.Ticket != nil {
		if err := store.acceptTicket(ctx, tx, documents.Ticket, storedTicket, ticketRevision, now); err != nil {
			refused = errors.Join(refused, fmt.Errorf("service ticket refused: %w", err))
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return State{}, err
	}
	state, err := store.Current(ctx, now)
	if err != nil {
		return State{}, err
	}
	return state, refused
}

func revisionOf(value *int64) uint64 {
	if value == nil {
		return 0
	}
	return uint64(*value)
}

func (store *Store) acceptNotice(ctx context.Context, tx pgx.Tx, encoded, stored []byte, storedRevision *int64,
	now time.Time,
) error {
	decoded, err := contract.DecodeNotice(encoded)
	if err != nil {
		return err
	}
	notice, err := contract.VerifyNotice(encoded, store.verifyOptions(decoded.KeyID, now))
	if err != nil {
		return err
	}
	if err := contract.CheckRevision(revisionOf(storedRevision), digestOrZero(stored), notice.Revision,
		contract.Digest(encoded)); err != nil {
		return err
	}
	digest := contract.Digest(encoded)
	var until *time.Time
	if notice.Until != nil {
		value := time.Unix(*notice.Until, 0).UTC()
		until = &value
	}
	_, err = tx.Exec(ctx, `UPDATE control_installation_ban_state SET notice=$1, notice_revision=$2, notice_sha256=$3,
		notice_state=$4, ban_id=$5, reason_code=$6, reason_text=$7, starts_at=$8, until=$9, received_at=$10, updated_at=$10
		WHERE singleton`, encoded, int64(notice.Revision), digest[:], notice.State, notice.BanID, notice.ReasonCode,
		notice.ReasonText, time.Unix(notice.StartsAt, 0).UTC(), until, now.UTC())
	return err
}

func (store *Store) acceptTicket(ctx context.Context, tx pgx.Tx, encoded, stored []byte, storedRevision *int64,
	now time.Time,
) error {
	decoded, err := contract.DecodeTicket(encoded)
	if err != nil {
		return err
	}
	ticket, err := contract.VerifyTicket(encoded, store.verifyOptions(decoded.KeyID, now))
	if err != nil {
		return err
	}
	if err := contract.CheckRevision(revisionOf(storedRevision), digestOrZero(stored), ticket.Revision,
		contract.Digest(encoded)); err != nil {
		return err
	}
	digest := contract.Digest(encoded)
	_, err = tx.Exec(ctx, `UPDATE control_installation_ban_state SET ticket=$1, ticket_revision=$2, ticket_sha256=$3,
		ticket_not_after=$4, received_at=$5, updated_at=$5 WHERE singleton`, encoded, int64(ticket.Revision), digest[:],
		time.Unix(ticket.NotAfter, 0).UTC(), now.UTC())
	return err
}

func digestOrZero(encoded []byte) [32]byte {
	if encoded == nil {
		return [32]byte{}
	}
	return contract.Digest(encoded)
}

// Current reads the stored documents (decoded without a time check: a stored
// notice was verified when accepted) and the current lease's status.
func (store *Store) Current(ctx context.Context, _ time.Time) (State, error) {
	var state State
	err := store.pool.QueryRow(ctx, `SELECT notice, ticket FROM control_installation_ban_state WHERE singleton`).
		Scan(&state.Notice, &state.Ticket)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return State{}, err
	}
	if state.Notice != nil {
		signed, err := contract.DecodeNotice(state.Notice)
		if err != nil {
			return State{}, fmt.Errorf("stored ban notice: %w", err)
		}
		state.NoticeBody = &signed.Body
	}
	if state.Ticket != nil {
		signed, err := contract.DecodeTicket(state.Ticket)
		if err != nil {
			return State{}, fmt.Errorf("stored service ticket: %w", err)
		}
		state.TicketBody = &signed.Body
	}
	var grace *time.Time
	err = store.pool.QueryRow(ctx, `SELECT entitlement.last_status, lease.grace_until
		FROM control_installation_entitlement entitlement
		LEFT JOIN entitlement_cached_leases lease ON lease.serial = entitlement.current_serial
		WHERE entitlement.singleton`).Scan(&state.LeaseStatus, &grace)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return State{}, err
	default:
		state.LeasePresent = true
		if grace != nil {
			state.LeaseGrace = grace.UTC()
		}
	}
	return state, nil
}
