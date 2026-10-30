package dnspropagation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrProviderRetryStateConflict    = errors.New("dns provider retry state conflict")
	ErrProviderRetryStateUnavailable = errors.New("dns provider retry state unavailable")
)

type ProviderRetryKey struct {
	TenantID   uuid.UUID
	ZoneID     uuid.UUID
	ProviderID uuid.UUID
}

type ProviderRetryStoreResult struct {
	State     ProviderRetryState
	UpdatedAt time.Time
	Replayed  bool
}

type retryStateQueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type PostgresRetryStore struct {
	query retryStateQueryRower
}

func NewPostgresRetryStore(query retryStateQueryRower) (*PostgresRetryStore, error) {
	if query == nil {
		return nil, ErrInvalidInput
	}
	return &PostgresRetryStore{query: query}, nil
}

func (store *PostgresRetryStore) Load(
	ctx context.Context,
	key ProviderRetryKey,
) (ProviderRetryStoreResult, bool, error) {
	if store == nil || store.query == nil || ctx == nil || ctx.Err() != nil ||
		key.TenantID == uuid.Nil || key.ZoneID == uuid.Nil || key.ProviderID == uuid.Nil {
		return ProviderRetryStoreResult{}, false, ErrInvalidInput
	}
	var revision int64
	var encoded []byte
	var updatedAt time.Time
	err := store.query.QueryRow(ctx, `SELECT revision,state,updated_at
		FROM dns_provider_retry_states
		WHERE tenant_id=$1 AND zone_id=$2 AND provider_id=$3`,
		key.TenantID, key.ZoneID, key.ProviderID,
	).Scan(&revision, &encoded, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProviderRetryStoreResult{}, false, nil
	}
	if err != nil {
		return ProviderRetryStoreResult{}, false, ErrProviderRetryStateUnavailable
	}
	persisted, valid := decodeProviderRetryState(encoded)
	if revision < 1 || !valid || persisted.Revision != uint64(revision) ||
		updatedAt.IsZero() || !updatedAt.Equal(updatedAt.UTC().Truncate(time.Microsecond)) {
		return ProviderRetryStoreResult{}, false, ErrProviderRetryStateUnavailable
	}
	return ProviderRetryStoreResult{State: persisted, UpdatedAt: updatedAt}, true, nil
}

func (store *PostgresRetryStore) CompareAndSwap(
	ctx context.Context,
	key ProviderRetryKey,
	expectedRevision uint64,
	next ProviderRetryState,
	updatedAt time.Time,
) (ProviderRetryStoreResult, error) {
	if store == nil || store.query == nil || ctx == nil || ctx.Err() != nil ||
		key.TenantID == uuid.Nil || key.ZoneID == uuid.Nil || key.ProviderID == uuid.Nil ||
		expectedRevision >= math.MaxInt64 || next.Revision != expectedRevision+1 ||
		!validProviderRetrySnapshot(next) || updatedAt.IsZero() {
		return ProviderRetryStoreResult{}, ErrInvalidInput
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return ProviderRetryStoreResult{}, ErrProviderRetryStateUnavailable
	}
	updatedAt = updatedAt.UTC().Truncate(time.Microsecond)

	var persistedRevision int64
	var persistedJSON []byte
	var persistedUpdatedAt time.Time
	var replayed bool
	err = store.query.QueryRow(ctx, `WITH prior AS MATERIALIZED (
		SELECT revision,state,updated_at
		FROM dns_provider_retry_states
		WHERE tenant_id=$1 AND zone_id=$2 AND provider_id=$3
		FOR UPDATE
	), write AS (
		INSERT INTO dns_provider_retry_states(
			tenant_id,zone_id,provider_id,revision,state,updated_at
		)
		SELECT $1,$2,$3,$5,$6::jsonb,$7
		WHERE $4=0 OR EXISTS (SELECT 1 FROM prior)
		ON CONFLICT (tenant_id,zone_id,provider_id) DO UPDATE SET
			revision=EXCLUDED.revision,
			state=EXCLUDED.state,
			updated_at=EXCLUDED.updated_at
		WHERE dns_provider_retry_states.revision=$4 OR
			(dns_provider_retry_states.revision=$5 AND
			 dns_provider_retry_states.state=$6::jsonb AND
			 dns_provider_retry_states.updated_at=$7)
		RETURNING revision,state,updated_at
	)
	SELECT write.revision,write.state,write.updated_at,
		COALESCE(prior.revision=$5 AND prior.state=$6::jsonb AND prior.updated_at=$7,false)
	FROM write LEFT JOIN prior ON true`,
		key.TenantID, key.ZoneID, key.ProviderID, int64(expectedRevision), int64(next.Revision), encoded, updatedAt,
	).Scan(&persistedRevision, &persistedJSON, &persistedUpdatedAt, &replayed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ProviderRetryStoreResult{}, ErrProviderRetryStateConflict
		}
		return ProviderRetryStoreResult{}, ErrProviderRetryStateUnavailable
	}

	persisted, valid := decodeProviderRetryState(persistedJSON)
	if persistedRevision < 0 || !valid ||
		persisted.Revision != uint64(persistedRevision) || persisted != next ||
		!persistedUpdatedAt.Equal(updatedAt) {
		return ProviderRetryStoreResult{}, ErrProviderRetryStateUnavailable
	}
	return ProviderRetryStoreResult{State: persisted, UpdatedAt: persistedUpdatedAt, Replayed: replayed}, nil
}

func decodeProviderRetryState(encoded []byte) (ProviderRetryState, bool) {
	var state ProviderRetryState
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil {
		return ProviderRetryState{}, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || !validProviderRetrySnapshot(state) {
		return ProviderRetryState{}, false
	}
	return state, true
}

func validProviderRetrySnapshot(state ProviderRetryState) bool {
	if state.Revision == 0 || state.Revision > math.MaxInt64 || state.WindowStartedAt.IsZero() ||
		!validRetryReference(state.LastOperationID) ||
		!validRetryReference(state.LastProviderRequestID) {
		return false
	}
	switch state.Phase {
	case CircuitClosed:
		return state.OpenUntil.IsZero() && state.ProbeOperationID == ""
	case CircuitOpen:
		return !state.OpenUntil.IsZero() && state.ProbeOperationID == ""
	case CircuitHalfOpen:
		return state.OpenUntil.IsZero() && validRetryReference(state.ProbeOperationID)
	default:
		return false
	}
}
