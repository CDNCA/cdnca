package domaineventsource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	maxPayloadBytes  = 16 << 10
	maxDedupKeyBytes = 512
)

var (
	ErrInvalidEvent = errors.New("invalid domain event source")
	// ErrDedupConflict means the dedup key is already bound to a different fact.
	ErrDedupConflict = errors.New("domain event dedup key bound to a different fact")
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// Fact is one public domain event source fact. Data holds only the contract
// fields; fanout adds subscription_id and subject_sequence per delivery.
type Fact struct {
	ID            uuid.UUID
	EventType     string
	TenantScopeID uuid.UUID
	// SiteID is set for site-bound events and drives the subscription site filter.
	SiteID     uuid.UUID
	Subject    string
	DedupKey   string
	OccurredAt time.Time
	Data       map[string]any
}

// Appended reports the outcome of EnqueueTx. Replayed is true when the dedup
// key already held the same fact (the business write was retried).
type Appended struct {
	ID              uuid.UUID
	SubjectSequence uint64
	Replayed        bool
}

// Canonical validates the fact against its contract and returns the stored
// payload bytes (encoding/json sorts map keys, so the bytes are deterministic).
func (fact Fact) Canonical() ([]byte, error) {
	contract, ok := Lookup(fact.EventType)
	if !ok || fact.ID == uuid.Nil || fact.TenantScopeID == uuid.Nil || !ValidSubject(fact.EventType, fact.Subject) ||
		fact.DedupKey == "" || len(fact.DedupKey) > maxDedupKeyBytes || strings.TrimSpace(fact.DedupKey) != fact.DedupKey ||
		!requestIDPattern.MatchString(fact.ID.String()) || fact.OccurredAt.IsZero() ||
		fact.OccurredAt.Year() < 2000 || fact.OccurredAt.Year() > 9999 ||
		contract.SiteBound != (fact.SiteID != uuid.Nil) {
		return nil, fmt.Errorf("%w: identity, subject, dedup key, time, or site binding", ErrInvalidEvent)
	}
	payload, err := json.Marshal(fact.Data)
	if err != nil || len(payload) < 2 || len(payload) > maxPayloadBytes {
		return nil, fmt.Errorf("%w: payload encoding", ErrInvalidEvent)
	}
	var decoded map[string]json.RawMessage
	if json.Unmarshal(payload, &decoded) != nil || len(decoded)+2 > MaxDataFields || !ValidPayload(contract, decoded) {
		return nil, fmt.Errorf("%w: payload contract", ErrInvalidEvent)
	}
	if contract.SiteBound {
		var site string
		if json.Unmarshal(decoded["site_id"], &site) != nil || site != fact.SiteID.String() {
			return nil, fmt.Errorf("%w: site_id differs from the fact site", ErrInvalidEvent)
		}
	}
	return payload, nil
}

// EnqueueTx appends the fact in the caller's transaction (it never begins or
// commits one), so the business write and its event commit or roll back
// together. Per-subject sequencing and dedup run in domain_event_append_368,
// which locks the subject head row: a later writer of the same subject waits
// for the earlier one to commit, so subject_sequence follows commit order.
func EnqueueTx(ctx context.Context, tx pgx.Tx, fact Fact) (Appended, error) {
	if ctx == nil || tx == nil {
		return Appended{}, fmt.Errorf("%w: transaction context", ErrInvalidEvent)
	}
	payload, err := fact.Canonical()
	if err != nil {
		return Appended{}, err
	}
	var site any
	if fact.SiteID != uuid.Nil {
		site = fact.SiteID
	}
	var result Appended
	var conflict bool
	if err := tx.QueryRow(ctx, `SELECT id,subject_sequence,replayed,conflict
		FROM domain_event_append_368($1,$2,$3,$4,$5,$6,$7,$8)`,
		fact.ID, fact.EventType, fact.TenantScopeID, site, fact.Subject, fact.DedupKey,
		fact.OccurredAt.UTC().Truncate(time.Microsecond), payload).
		Scan(&result.ID, &result.SubjectSequence, &result.Replayed, &conflict); err != nil {
		return Appended{}, fmt.Errorf("append domain event source: %w", err)
	}
	if conflict {
		return Appended{}, fmt.Errorf("%w: %s", ErrDedupConflict, fact.DedupKey)
	}
	return result, nil
}
