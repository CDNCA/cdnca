package wafreport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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

// Prepare stores a canonical snapshot and returns whether it needs delivery.
// The row is locked so concurrent reporters cannot consume the same sequence.
func (store *Store) Prepare(ctx context.Context, installationID uuid.UUID, policies []json.RawMessage, digest [32]byte) (Snapshot, bool, error) {
	if store == nil || store.pool == nil || installationID == uuid.Nil {
		return Snapshot{}, false, errors.New("invalid WAF report store request")
	}
	var snapshot Snapshot
	var send bool
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var sequence uint64
		var requestID string
		var observedAt time.Time
		var storedPolicies []byte
		var storedDigest []byte
		var sentAt *time.Time
		err := tx.QueryRow(ctx, `SELECT sequence,request_id,observed_at,policies,policies_digest,sent_at
			FROM waf_custom_rule_report_state WHERE installation_id=$1 FOR UPDATE`, installationID).
			Scan(&sequence, &requestID, &observedAt, &storedPolicies, &storedDigest, &sentAt)
		if errors.Is(err, pgx.ErrNoRows) {
			sequence = 1
			requestID = uuid.NewString()
			observedAt = store.now().UTC().Truncate(time.Second)
			encoded, encodeErr := json.Marshal(policies)
			if encodeErr != nil {
				return encodeErr
			}
			_, err = tx.Exec(ctx, `INSERT INTO waf_custom_rule_report_state
				(installation_id,sequence,request_id,observed_at,policies,policies_digest,updated_at)
				VALUES($1,$2,$3,$4,$5,$6,$7)`, installationID, sequence, requestID, observedAt, encoded, digest[:], observedAt)
			if err != nil {
				return err
			}
			snapshot = Snapshot{InstallationID: installationID, Sequence: sequence, RequestID: requestID,
				ObservedAt: observedAt, Policies: clonePolicies(policies), PoliciesDigest: digest}
			send = true
			return nil
		}
		if err != nil {
			return err
		}
		if len(storedDigest) != len(digest) {
			return errors.New("stored WAF report digest is invalid")
		}
		if string(storedDigest) != string(digest[:]) {
			sequence++
			requestID = uuid.NewString()
			observedAt = store.now().UTC().Truncate(time.Second)
			encoded, encodeErr := json.Marshal(policies)
			if encodeErr != nil {
				return encodeErr
			}
			_, err = tx.Exec(ctx, `UPDATE waf_custom_rule_report_state SET sequence=$2,request_id=$3,observed_at=$4,
				policies=$5,policies_digest=$6,sent_at=NULL,updated_at=$7 WHERE installation_id=$1`,
				installationID, sequence, requestID, observedAt, encoded, digest[:], observedAt)
			if err != nil {
				return err
			}
			snapshot = Snapshot{InstallationID: installationID, Sequence: sequence, RequestID: requestID,
				ObservedAt: observedAt, Policies: clonePolicies(policies), PoliciesDigest: digest}
			send = true
			return nil
		}
		var decoded []json.RawMessage
		if err := json.Unmarshal(storedPolicies, &decoded); err != nil {
			return fmt.Errorf("decode stored WAF report policies: %w", err)
		}
		snapshot = Snapshot{InstallationID: installationID, Sequence: sequence, RequestID: requestID,
			ObservedAt: observedAt.UTC(), Policies: decoded, PoliciesDigest: digest, Sent: sentAt != nil}
		send = sentAt == nil
		return nil
	})
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("prepare WAF report: %w", err)
	}
	return snapshot, send, nil
}

func (store *Store) MarkSent(ctx context.Context, snapshot Snapshot) error {
	if store == nil || store.pool == nil || snapshot.InstallationID == uuid.Nil || snapshot.Sequence == 0 || snapshot.RequestID == "" {
		return errors.New("invalid WAF report acknowledgement")
	}
	_, err := store.pool.Exec(ctx, `UPDATE waf_custom_rule_report_state SET sent_at=$5,updated_at=$5
		WHERE installation_id=$1 AND sequence=$2 AND request_id=$3 AND policies_digest=$4 AND sent_at IS NULL`,
		snapshot.InstallationID, snapshot.Sequence, snapshot.RequestID, snapshot.PoliciesDigest[:], store.now().UTC())
	if err != nil {
		return fmt.Errorf("mark WAF report sent: %w", err)
	}
	return nil
}

func clonePolicies(policies []json.RawMessage) []json.RawMessage {
	result := make([]json.RawMessage, len(policies))
	for index := range policies {
		result[index] = append(json.RawMessage(nil), policies[index]...)
	}
	return result
}
