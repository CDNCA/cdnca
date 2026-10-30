package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// canonicalVersion 2 (unified-log) adds category, actor kind/ref, source IP,
// reason code and changes to the hashed form. tp-b6b adds user_agent to the
// version-2 form only when non-empty (omitempty), so rows without one (all
// earlier rows, background jobs, and the SQL-computed package monitor hash in
// migration 392) keep exactly the same canonical bytes.
const canonicalVersion = 2

var ErrInvalidChain = errors.New("invalid audit chain")

// Actor kinds stored in audit_events.actor_kind.
const (
	ActorUser   = "user"
	ActorSystem = "system"
	ActorPlugin = "plugin"
	ActorNode   = "node"
)

type Event struct {
	ScopeID      uuid.UUID
	ActorUserID  *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   string
	RequestID    string
	Result       string
	Payload      map[string]any

	// ActorKind is user/system/plugin/node. Empty: the context actor
	// (WithActor), else user when ActorUserID is set, else system.
	ActorKind string
	// ActorRef identifies a non-user actor ("plugin:<id>", "node:<id>",
	// "job:<name>") or how a user acted ("api_key:<id>"). Optional.
	ActorRef string
	// SourceIP is the client address. Empty: Payload["ip"], else the request
	// context (WithSourceIP, set by the HTTP middleware).
	SourceIP string
	// ReasonCode explains a denied/failure result. Empty: Payload["reason_code"].
	ReasonCode string
	// Changes summarise before -> after of the changed fields. Empty:
	// Payload["changes"]. Secret fields are redacted when written.
	Changes []Change
	// OccurredAt overrides the log clock (zero = now).
	OccurredAt time.Time
}

// Change is one changed field. Before/After are JSON values; nil means unset.
type Change struct {
	Field  string `json:"field"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

type Log struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

type record struct {
	ID             uuid.UUID
	ScopeID        uuid.UUID
	StreamPosition int64
	ActorUserID    *uuid.UUID
	Action         string
	ResourceType   string
	ResourceID     string
	RequestID      string
	Result         string
	Payload        []byte
	PreviousHash   []byte
	EventHash      []byte
	OccurredAt     time.Time
	Category       string
	ActorKind      string
	ActorRef       string
	SourceIP       string
	ReasonCode     string
	Changes        []byte // JSON array
	UserAgent      string // request User-Agent, cleaned; "" when not from a browser request
}

type canonicalEvent struct {
	Version        int             `json:"version"`
	ID             string          `json:"id"`
	ScopeID        string          `json:"scope_id"`
	StreamPosition int64           `json:"stream_position"`
	ActorUserID    *string         `json:"actor_user_id"`
	Action         string          `json:"action"`
	ResourceType   string          `json:"resource_type"`
	ResourceID     string          `json:"resource_id"`
	RequestID      string          `json:"request_id"`
	Result         string          `json:"result"`
	Payload        json.RawMessage `json:"payload"`
	PreviousHash   string          `json:"previous_hash"`
	OccurredAt     string          `json:"occurred_at"`
	Category       string          `json:"category"`
	ActorKind      string          `json:"actor_kind"`
	ActorRef       string          `json:"actor_ref"`
	SourceIP       string          `json:"source_ip"`
	ReasonCode     string          `json:"reason_code"`
	Changes        json.RawMessage `json:"changes"`
	UserAgent      string          `json:"user_agent,omitempty"`
}

func New(pool *pgxpool.Pool) *Log {
	return NewWithClock(pool, time.Now)
}

func NewWithClock(pool *pgxpool.Pool, now func() time.Time) *Log {
	if now == nil {
		now = time.Now
	}
	return &Log{pool: pool, now: now}
}

func (l *Log) Append(ctx context.Context, tx pgx.Tx, input Event) error {
	if input.OccurredAt.IsZero() {
		input.OccurredAt = l.now()
	}
	_, err := AppendTx(ctx, tx, input)
	return err
}

// AppendTx appends input to its scope's chain inside tx and returns the new
// event ID. input.OccurredAt zero means time.Now.
func AppendTx(ctx context.Context, tx pgx.Tx, input Event) (uuid.UUID, error) {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", auditStreamLockKey(input.ScopeID)); err != nil {
		return uuid.Nil, fmt.Errorf("lock audit stream: %w", err)
	}
	var previousHash []byte
	var position int64
	err := tx.QueryRow(ctx, `
		SELECT event_hash, stream_position
		FROM audit_events
		WHERE scope_id = $1
		ORDER BY stream_position DESC
		LIMIT 1`, input.ScopeID).Scan(&previousHash, &position)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("read audit head: %w", err)
	}
	enriched, err := enrich(ctx, input)
	if err != nil {
		return uuid.Nil, err
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("generate audit event ID: %w", err)
	}
	enriched.ID = eventID
	enriched.StreamPosition = position + 1
	enriched.PreviousHash = previousHash
	eventHash, err := computeHash(enriched)
	if err != nil {
		return uuid.Nil, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_events (
			id, scope_id, stream_position, actor_user_id, action, resource_type,
			resource_id, request_id, result, payload, previous_hash, event_hash, occurred_at,
			category, actor_kind, actor_ref, source_ip, reason_code, changes, user_agent
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
		enriched.ID, enriched.ScopeID, enriched.StreamPosition, enriched.ActorUserID, enriched.Action,
		enriched.ResourceType, enriched.ResourceID, enriched.RequestID, enriched.Result, enriched.Payload,
		enriched.PreviousHash, eventHash, enriched.OccurredAt, enriched.Category, enriched.ActorKind,
		enriched.ActorRef, enriched.SourceIP, enriched.ReasonCode, enriched.Changes, enriched.UserAgent,
	)
	if err != nil {
		// Under the stream lock a taken position means the transaction's
		// snapshot predates an append committed meanwhile (Repeatable Read or
		// Serializable): the head read above was stale. That is a
		// serialization failure; report 40001 so callers retry the whole
		// transaction instead of treating it as a permanent conflict
		// (fix-cnamewait: CNAME intents waited for their 16-minute lease).
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" &&
			postgresError.ConstraintName == "audit_events_scope_id_stream_position_key" {
			return uuid.Nil, fmt.Errorf("append audit event: %w", &pgconn.PgError{Severity: "ERROR", Code: "40001",
				Message: "audit stream head changed after the transaction snapshot", ConstraintName: postgresError.ConstraintName})
		}
		return uuid.Nil, fmt.Errorf("append audit event: %w", err)
	}
	return eventID, nil
}

func auditStreamLockKey(scopeID uuid.UUID) int64 {
	digest := sha256.Sum256(scopeID[:])
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

// ChainColumns is the audit_events column list ScanChainRecord reads, in order.
const ChainColumns = `id, scope_id, stream_position, actor_user_id, action, resource_type,
	resource_id, request_id, result, payload::text, previous_hash, event_hash, occurred_at,
	category, actor_kind, actor_ref, source_ip, reason_code, changes::text, user_agent`

// ChainCopyColumns lists every persistent audit_events column (archive copies
// and chain verification read exactly these).
const ChainCopyColumns = `id, scope_id, stream_position, actor_user_id, action, resource_type, resource_id,
	request_id, result, payload, previous_hash, event_hash, occurred_at,
	category, actor_kind, actor_ref, source_ip, reason_code, changes, user_agent`

// ChainRecord is one audit_events (or audit_event_archive) row.
type ChainRecord = record

// ScanChainRecord reads a row selected with ChainColumns.
func ScanChainRecord(row pgx.Row) (ChainRecord, error) {
	var event record
	var payload, changes string
	if err := row.Scan(&event.ID, &event.ScopeID, &event.StreamPosition, &event.ActorUserID, &event.Action,
		&event.ResourceType, &event.ResourceID, &event.RequestID, &event.Result, &payload,
		&event.PreviousHash, &event.EventHash, &event.OccurredAt, &event.Category, &event.ActorKind,
		&event.ActorRef, &event.SourceIP, &event.ReasonCode, &changes, &event.UserAgent); err != nil {
		return record{}, err
	}
	event.Payload = []byte(payload)
	event.Changes = []byte(changes)
	return event, nil
}

// VerifyChainRecord checks that event sits at expectedPosition, links to
// previousHash and carries its own canonical hash.
func VerifyChainRecord(event ChainRecord, expectedPosition int64, previousHash []byte) error {
	return verifyRecord(event, expectedPosition, previousHash)
}

// VerifyScope verifies the scope's chain from its archive checkpoint (FX01):
// rows after the checkpoint must link from the checkpoint hash, and rows kept
// at or below it (still pinned) must be unchanged archived copies.
func (l *Log) VerifyScope(ctx context.Context, scopeID uuid.UUID) error {
	var previousHash []byte
	var checkpoint int64
	err := l.pool.QueryRow(ctx, `SELECT through_position, through_hash FROM audit_chain_checkpoints
		WHERE scope_id = $1`, scopeID).Scan(&checkpoint, &previousHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read audit checkpoint: %w", err)
	}
	rows, err := l.pool.Query(ctx, `
		SELECT event.id, event.scope_id, event.stream_position, event.actor_user_id, event.action,
		       event.resource_type, event.resource_id, event.request_id, event.result, event.payload::text,
		       event.previous_hash, event.event_hash, event.occurred_at, event.category, event.actor_kind,
		       event.actor_ref, event.source_ip, event.reason_code, event.changes::text, event.user_agent, archived.event_hash
		FROM audit_events event
		LEFT JOIN audit_event_archive archived ON archived.id = event.id
		WHERE event.scope_id = $1
		ORDER BY event.stream_position`, scopeID)
	if err != nil {
		return fmt.Errorf("read audit stream: %w", err)
	}
	defer rows.Close()

	expectedPosition := checkpoint + 1
	for rows.Next() {
		var event record
		var payload, changes string
		var archivedHash []byte
		if err := rows.Scan(&event.ID, &event.ScopeID, &event.StreamPosition, &event.ActorUserID, &event.Action,
			&event.ResourceType, &event.ResourceID, &event.RequestID, &event.Result, &payload,
			&event.PreviousHash, &event.EventHash, &event.OccurredAt, &event.Category, &event.ActorKind,
			&event.ActorRef, &event.SourceIP, &event.ReasonCode, &changes, &event.UserAgent, &archivedHash); err != nil {
			return fmt.Errorf("scan audit event: %w", err)
		}
		event.Payload = []byte(payload)
		event.Changes = []byte(changes)
		if event.StreamPosition <= checkpoint {
			expected, hashErr := computeHash(event)
			if hashErr != nil || !bytes.Equal(archivedHash, event.EventHash) ||
				subtle.ConstantTimeCompare(event.EventHash, expected) != 1 {
				return fmt.Errorf("%w at position %d: kept row differs from archive", ErrInvalidChain, event.StreamPosition)
			}
			continue
		}
		if err := verifyRecord(event, expectedPosition, previousHash); err != nil {
			return err
		}
		previousHash = append(previousHash[:0], event.EventHash...)
		expectedPosition++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read audit stream: %w", err)
	}
	return nil
}

func computeHash(event record) ([]byte, error) {
	payload, err := normalizePayload(event.Payload)
	if err != nil {
		return nil, fmt.Errorf("normalize audit payload: %w", err)
	}
	changes, err := normalizeChanges(event.Changes)
	if err != nil {
		return nil, fmt.Errorf("normalize audit changes: %w", err)
	}
	var actorUserID *string
	if event.ActorUserID != nil {
		value := event.ActorUserID.String()
		actorUserID = &value
	}
	canonical, err := json.Marshal(canonicalEvent{
		Version:        canonicalVersion,
		ID:             event.ID.String(),
		ScopeID:        event.ScopeID.String(),
		StreamPosition: event.StreamPosition,
		ActorUserID:    actorUserID,
		Action:         event.Action,
		ResourceType:   event.ResourceType,
		ResourceID:     event.ResourceID,
		RequestID:      event.RequestID,
		Result:         event.Result,
		Payload:        payload,
		PreviousHash:   hex.EncodeToString(event.PreviousHash),
		OccurredAt:     event.OccurredAt.UTC().Format(time.RFC3339Nano),
		Category:       event.Category,
		ActorKind:      event.ActorKind,
		ActorRef:       event.ActorRef,
		SourceIP:       event.SourceIP,
		ReasonCode:     event.ReasonCode,
		Changes:        changes,
		UserAgent:      event.UserAgent,
	})
	if err != nil {
		return nil, fmt.Errorf("encode canonical audit event: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return digest[:], nil
}

func verifyRecord(event record, expectedPosition int64, previousHash []byte) error {
	if event.StreamPosition != expectedPosition || !bytes.Equal(event.PreviousHash, previousHash) {
		return fmt.Errorf("%w at position %d: broken sequence", ErrInvalidChain, event.StreamPosition)
	}
	expectedHash, err := computeHash(event)
	if err != nil {
		return fmt.Errorf("%w at position %d: %v", ErrInvalidChain, event.StreamPosition, err)
	}
	if len(event.EventHash) != sha256.Size || subtle.ConstantTimeCompare(event.EventHash, expectedHash) != 1 {
		return fmt.Errorf("%w at position %d: hash mismatch", ErrInvalidChain, event.StreamPosition)
	}
	return nil
}

func normalizePayload(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("payload must contain one JSON object")
	}
	if payload == nil {
		return []byte("null"), nil
	}
	payload = redactPayloadValue(payload).(map[string]any)
	return json.Marshal(payload)
}

func redactPayloadValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if sensitivePayloadKey(key) {
				typed[key] = "[REDACTED]"
				continue
			}
			typed[key] = redactPayloadValue(child)
		}
	case []any:
		for index, child := range typed {
			typed[index] = redactPayloadValue(child)
		}
	}
	return value
}

func sensitivePayloadKey(key string) bool {
	normalized := strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToLower(key))
	for _, suffix := range []string{"password", "passphrase", "secret", "secretkey", "token", "authorization", "cookie", "apikey", "accesskey", "accesskeyid", "privatekey"} {
		if normalized == suffix || strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}
