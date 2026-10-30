package securityrulereport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Snapshot struct {
	InstallationID uuid.UUID
	Sequence       uint64
	RequestID      string
	ObservedAt     time.Time
	Report         rulecatalog.Report
	Digest         [32]byte
}

type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, now: now}
}

// Prepare records the canonical report and returns the snapshot to send. A
// changed digest consumes the next sequence with a fresh request id; an
// unchanged, unsent snapshot is retried with its original identity so the
// license service can deduplicate it.
func (store *Store) Prepare(ctx context.Context, installationID uuid.UUID, report rulecatalog.Report, digest [32]byte) (Snapshot, bool, error) {
	if store == nil || store.pool == nil || installationID == uuid.Nil {
		return Snapshot{}, false, errors.New("invalid security custom rule report store request")
	}
	var snapshot Snapshot
	var send bool
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var storedReport, storedDigest []byte
		var sentAt *time.Time
		snapshot = Snapshot{InstallationID: installationID}
		err := tx.QueryRow(ctx, `SELECT sequence,request_id,observed_at,report,report_digest,sent_at
			FROM security_custom_rule_report_state WHERE installation_id=$1 FOR UPDATE`, installationID).
			Scan(&snapshot.Sequence, &snapshot.RequestID, &snapshot.ObservedAt, &storedReport, &storedDigest, &sentAt)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && string(storedDigest) == string(digest[:]) {
			if err := json.Unmarshal(storedReport, &snapshot.Report); err != nil {
				return fmt.Errorf("decode stored security custom rule report: %w", err)
			}
			canonical, storedCanonicalDigest, err := rulecatalog.CanonicalReport(snapshot.Report)
			if err != nil || storedCanonicalDigest != digest {
				return errors.New("stored security custom rule report does not match its digest")
			}
			snapshot.Report, snapshot.Digest, snapshot.ObservedAt = canonical, digest, snapshot.ObservedAt.UTC()
			send = sentAt == nil
			return nil
		}
		now := store.now().UTC().Truncate(time.Second)
		encoded, encodeErr := json.Marshal(report)
		if encodeErr != nil {
			return encodeErr
		}
		// Sequence is at least the observation second, so a lost sender state
		// (e.g. 283 rolled back) still lands above the license service's latest.
		snapshot.Sequence = max(snapshot.Sequence+1, uint64(now.Unix()))
		snapshot.RequestID, snapshot.ObservedAt, snapshot.Report, snapshot.Digest = uuid.NewString(), now, report, digest
		_, err = tx.Exec(ctx, `INSERT INTO security_custom_rule_report_state
			(installation_id,sequence,request_id,observed_at,report,report_digest,updated_at) VALUES($1,$2,$3,$4,$5,$6,$4)
			ON CONFLICT (installation_id) DO UPDATE SET sequence=EXCLUDED.sequence,request_id=EXCLUDED.request_id,
			observed_at=EXCLUDED.observed_at,report=EXCLUDED.report,report_digest=EXCLUDED.report_digest,
			sent_at=NULL,last_error='',updated_at=EXCLUDED.updated_at`,
			installationID, snapshot.Sequence, snapshot.RequestID, now, encoded, digest[:])
		send = true
		return err
	})
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("prepare security custom rule report: %w", err)
	}
	return snapshot, send, nil
}

func (store *Store) MarkSent(ctx context.Context, snapshot Snapshot) error {
	_, err := store.pool.Exec(ctx, `UPDATE security_custom_rule_report_state SET sent_at=$5,last_error='',updated_at=$5
		WHERE installation_id=$1 AND sequence=$2 AND request_id=$3 AND report_digest=$4 AND sent_at IS NULL`,
		snapshot.InstallationID, snapshot.Sequence, snapshot.RequestID, snapshot.Digest[:], store.now().UTC())
	if err != nil {
		return fmt.Errorf("mark security custom rule report sent: %w", err)
	}
	return nil
}

// MarkFailed keeps the last delivery/collection error visible to operators.
func (store *Store) MarkFailed(ctx context.Context, installationID uuid.UUID, cause error) error {
	message := []rune(cause.Error())
	if len(message) > 200 {
		message = message[:200]
	}
	_, err := store.pool.Exec(ctx, `UPDATE security_custom_rule_report_state SET last_error=$2,updated_at=$3 WHERE installation_id=$1`,
		installationID, string(message), store.now().UTC())
	return err
}
