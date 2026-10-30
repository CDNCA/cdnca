package identitysessionhttp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultListLimit = 20
	maxListLimit     = 100
	revokeAction     = "auth.session_family.revoke"
)

var (
	ErrInvalidInput        = errors.New("invalid identity session input")
	ErrInvalidCursor       = errors.New("invalid identity session cursor")
	ErrUnauthenticated     = errors.New("identity session caller is unauthenticated")
	ErrNotFound            = errors.New("identity session family not found")
	ErrRevisionConflict    = errors.New("identity session revision conflict")
	ErrIdempotencyConflict = errors.New("identity session idempotency conflict")
	ErrAlreadyRevoked      = errors.New("identity session family already revoked")
	ErrUnavailable         = errors.New("identity session store unavailable")

	writeIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

const lockActorSQL = `SELECT true
	FROM auth_sessions caller
	JOIN users user_row ON user_row.id=caller.user_id
	JOIN memberships membership ON membership.scope_id=caller.scope_id AND membership.user_id=caller.user_id
	JOIN access_scopes scope ON scope.id=caller.scope_id
	WHERE caller.id=$1 AND caller.scope_id=$2 AND caller.user_id=$3
	  AND caller.revoked_at IS NULL AND caller.expires_at>$4
	  AND user_row.status='active' AND membership.status='active' AND scope.kind=$5
	FOR UPDATE OF caller,user_row,membership`

const listFamiliesSQL = `WITH family_head AS (
	SELECT DISTINCT ON (session.family_id)
		session.family_id,session.id AS head_session_id,session.user_agent,
		host(session.source_ip) AS source_host,session.created_at AS head_created_at
	FROM auth_sessions session
	WHERE session.scope_id=$1 AND session.user_id=$2 AND session.created_at<=$4
	ORDER BY session.family_id,session.created_at DESC,session.id DESC
), family_summary AS (
	SELECT head.family_id,head.user_agent,head.source_host,head.head_created_at,
		max(COALESCE(session.used_at,session.created_at)) AS last_used_at,
		max(session.expires_at) AS expires_at,max(session.revoked_at) AS revoked_at,
		bool_or(session.revoked_at IS NULL AND session.expires_at>$5) AS active,
		bool_or(session.id=$3) AS current_session,count(*)::bigint AS session_count,
		(count(*)+CASE WHEN bool_or(session.revoked_at IS NOT NULL) THEN 1 ELSE 0 END)::bigint AS revision
	FROM family_head head
	JOIN auth_sessions session ON session.family_id=head.family_id AND session.scope_id=$1 AND session.user_id=$2
	WHERE session.created_at<=$4
	GROUP BY head.family_id,head.user_agent,head.source_host,head.head_created_at
)
	SELECT family_id,user_agent,COALESCE(source_host,''),head_created_at,last_used_at,expires_at,revoked_at,
		active,current_session,session_count,revision
	FROM family_summary
	WHERE ($6::timestamptz IS NULL OR (head_created_at,family_id)<($6,$7))
	ORDER BY head_created_at DESC,family_id DESC
	LIMIT $8`

const loadReceiptSQL = `SELECT payload
	FROM audit_events
	WHERE scope_id=$1 AND actor_user_id=$2 AND action='auth.session_family.revoke'
	  AND result='success' AND payload->>'idempotency_key'=$3
	ORDER BY occurred_at DESC,id DESC LIMIT 1`

const lockFamilySQL = `SELECT session.id,session.revoked_at
	FROM auth_sessions session
	WHERE session.family_id=$1 AND session.scope_id=$2 AND session.user_id=$3
	ORDER BY session.id FOR UPDATE`

type Actor struct {
	SessionID uuid.UUID
	ScopeID   uuid.UUID
	UserID    uuid.UUID
	ScopeKind string
}

type ListRequest struct {
	Actor  Actor
	Limit  int
	Cursor string
}

type SessionFamily struct {
	FamilyID     uuid.UUID
	DeviceLabel  string
	IPPrefix     string
	CreatedAt    time.Time
	LastUsedAt   time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	Current      bool
	Active       bool
	SessionCount int64
	Revision     int64
}

type ListResult struct {
	Items      []SessionFamily
	NextCursor string
}

type RevokeRequest struct {
	Actor            Actor
	FamilyID         uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type RevokeResult struct {
	FamilyID  uuid.UUID
	Revision  int64
	RevokedAt time.Time
	Current   bool
	Replayed  bool
}

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Clock func() time.Time

type Store struct {
	pool    *pgxpool.Pool
	auditor AuditAppender
	now     Clock
}

type sessionCursor struct {
	Version       int       `json:"v"`
	ScopeID       uuid.UUID `json:"scope_id"`
	UserID        uuid.UUID `json:"user_id"`
	SnapshotAt    time.Time `json:"snapshot_at"`
	LastCreatedAt time.Time `json:"last_created_at"`
	LastFamilyID  uuid.UUID `json:"last_family_id"`
}

type revokeReceipt struct {
	IdempotencyKey string    `json:"idempotency_key"`
	RequestDigest  string    `json:"request_digest_sha256"`
	FamilyID       uuid.UUID `json:"family_id"`
	Revision       int64     `json:"revision"`
	RevokedAt      time.Time `json:"revoked_at"`
	Current        bool      `json:"current"`
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	return NewStoreWithDependencies(pool, audit.New(pool), time.Now)
}

func NewStoreWithDependencies(pool *pgxpool.Pool, auditor AuditAppender, now Clock) (*Store, error) {
	if pool == nil || auditor == nil || now == nil {
		return nil, ErrUnavailable
	}
	return &Store{pool: pool, auditor: auditor, now: now}, nil
}

func (store *Store) List(ctx context.Context, request ListRequest) (ListResult, error) {
	if store == nil || store.pool == nil || store.auditor == nil || store.now == nil || !validActor(request.Actor) {
		return ListResult{}, ErrUnauthenticated
	}
	if request.Limit == 0 {
		request.Limit = defaultListLimit
	}
	if request.Limit < 1 || request.Limit > maxListLimit {
		return ListResult{}, ErrInvalidInput
	}
	now := store.now().UTC().Truncate(time.Microsecond)
	cursor := sessionCursor{Version: 1, ScopeID: request.Actor.ScopeID, UserID: request.Actor.UserID, SnapshotAt: now}
	var afterCreated any
	if request.Cursor != "" {
		var err error
		cursor, err = decodeCursor(request.Cursor, request.Actor)
		if err != nil {
			return ListResult{}, err
		}
		if cursor.SnapshotAt.After(now) {
			return ListResult{}, ErrInvalidCursor
		}
		afterCreated = cursor.LastCreatedAt
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return ListResult{}, fmt.Errorf("list identity sessions: %w", ErrUnavailable)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := lockActor(ctx, tx, request.Actor, now); err != nil {
		return ListResult{}, err
	}
	rows, err := tx.Query(ctx, listFamiliesSQL, request.Actor.ScopeID, request.Actor.UserID, request.Actor.SessionID,
		cursor.SnapshotAt, now, afterCreated, nullableUUID(cursor.LastFamilyID), request.Limit+1)
	if err != nil {
		return ListResult{}, fmt.Errorf("query identity session families: %w", ErrUnavailable)
	}
	defer rows.Close()
	items := make([]SessionFamily, 0, request.Limit+1)
	for rows.Next() {
		var item SessionFamily
		var rawUserAgent, rawSourceIP string
		if err := rows.Scan(&item.FamilyID, &rawUserAgent, &rawSourceIP, &item.CreatedAt, &item.LastUsedAt,
			&item.ExpiresAt, &item.RevokedAt, &item.Active, &item.Current, &item.SessionCount, &item.Revision); err != nil {
			return ListResult{}, fmt.Errorf("scan identity session family: %w", ErrUnavailable)
		}
		item.DeviceLabel = deviceLabel(rawUserAgent)
		item.IPPrefix = maskSourceIP(rawSourceIP)
		items = append(items, item)
	}
	if rows.Err() != nil {
		return ListResult{}, fmt.Errorf("iterate identity session families: %w", ErrUnavailable)
	}
	result := ListResult{Items: items}
	if len(result.Items) > request.Limit {
		last := result.Items[request.Limit-1]
		result.Items = result.Items[:request.Limit]
		result.NextCursor, err = nextPageCursor(cursor, last)
		if err != nil {
			return ListResult{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ListResult{}, fmt.Errorf("commit identity session list: %w", ErrUnavailable)
	}
	return result, nil
}

func (store *Store) Revoke(ctx context.Context, request RevokeRequest) (RevokeResult, error) {
	if store == nil || store.pool == nil || store.auditor == nil || store.now == nil || !validActor(request.Actor) {
		return RevokeResult{}, ErrUnauthenticated
	}
	if request.FamilyID == uuid.Nil || request.ExpectedRevision < 1 ||
		!writeIdentityPattern.MatchString(request.IdempotencyKey) || !writeIdentityPattern.MatchString(request.RequestID) {
		return RevokeResult{}, ErrInvalidInput
	}
	now := store.now().UTC().Truncate(time.Microsecond)
	digest := revokeRequestDigest(request)
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return RevokeResult{}, fmt.Errorf("begin identity session revoke: %w", ErrUnavailable)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := protocol.BeginAuthorityMutation(ctx, tx, protocol.OperationSessionRevoke,
		[]uuid.UUID{request.Actor.ScopeID}); err != nil {
		return RevokeResult{}, fmt.Errorf("begin identity session authority mutation: %w", ErrUnavailable)
	}
	if err := lockActor(ctx, tx, request.Actor, now); err != nil {
		return RevokeResult{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, revokeAdvisoryKey(request)); err != nil {
		return RevokeResult{}, fmt.Errorf("lock identity session idempotency key: %w", ErrUnavailable)
	}
	result, found, err := loadRevokeReceipt(ctx, tx, request, digest)
	if err != nil {
		return RevokeResult{}, err
	}
	if found {
		if err := tx.Commit(ctx); err != nil {
			return RevokeResult{}, fmt.Errorf("commit identity session replay: %w", ErrUnavailable)
		}
		result.Replayed = true
		return result, nil
	}
	rows, err := tx.Query(ctx, lockFamilySQL, request.FamilyID, request.Actor.ScopeID, request.Actor.UserID)
	if err != nil {
		return RevokeResult{}, fmt.Errorf("lock identity session family: %w", ErrUnavailable)
	}
	var sessionCount int64
	current, alreadyRevoked := false, false
	for rows.Next() {
		var sessionID uuid.UUID
		var revokedAt *time.Time
		if err := rows.Scan(&sessionID, &revokedAt); err != nil {
			rows.Close()
			return RevokeResult{}, fmt.Errorf("scan identity session family lock: %w", ErrUnavailable)
		}
		sessionCount++
		current = current || sessionID == request.Actor.SessionID
		alreadyRevoked = alreadyRevoked || revokedAt != nil
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return RevokeResult{}, fmt.Errorf("iterate identity session family lock: %w", ErrUnavailable)
	}
	if sessionCount == 0 {
		return RevokeResult{}, ErrNotFound
	}
	if alreadyRevoked {
		return RevokeResult{}, ErrAlreadyRevoked
	}
	if sessionCount != request.ExpectedRevision {
		return RevokeResult{}, ErrRevisionConflict
	}
	command, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=$4,revocation_reason='user_device_revoke'
		WHERE family_id=$1 AND scope_id=$2 AND user_id=$3 AND revoked_at IS NULL`,
		request.FamilyID, request.Actor.ScopeID, request.Actor.UserID, now)
	if err != nil || command.RowsAffected() != sessionCount {
		return RevokeResult{}, fmt.Errorf("revoke identity session family: %w", ErrUnavailable)
	}
	result = RevokeResult{FamilyID: request.FamilyID, Revision: sessionCount + 1, RevokedAt: now, Current: current}
	if err := store.auditor.Append(ctx, tx, audit.Event{ScopeID: request.Actor.ScopeID,
		ActorUserID: &request.Actor.UserID, Action: revokeAction, ResourceType: "session_family",
		ResourceID: request.FamilyID.String(), RequestID: request.RequestID, Result: "success",
		Payload: map[string]any{"idempotency_key": request.IdempotencyKey,
			"request_digest_sha256": hex.EncodeToString(digest[:]), "family_id": request.FamilyID.String(),
			"revision": result.Revision, "revoked_at": result.RevokedAt.Format(time.RFC3339Nano),
			"current": result.Current}}); err != nil {
		return RevokeResult{}, fmt.Errorf("append identity session revoke audit: %w", ErrUnavailable)
	}
	if err := tx.Commit(ctx); err != nil {
		return RevokeResult{}, fmt.Errorf("commit identity session revoke: %w", ErrUnavailable)
	}
	return result, nil
}

func lockActor(ctx context.Context, tx pgx.Tx, actor Actor, now time.Time) error {
	var valid bool
	if err := tx.QueryRow(ctx, lockActorSQL, actor.SessionID, actor.ScopeID, actor.UserID, now, actor.ScopeKind).Scan(&valid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnauthenticated
		}
		return fmt.Errorf("authenticate identity session caller: %w", ErrUnavailable)
	}
	if !valid {
		return ErrUnauthenticated
	}
	return nil
}

func loadRevokeReceipt(ctx context.Context, tx pgx.Tx, request RevokeRequest,
	digest [sha256.Size]byte,
) (RevokeResult, bool, error) {
	var raw json.RawMessage
	err := tx.QueryRow(ctx, loadReceiptSQL, request.Actor.ScopeID, request.Actor.UserID,
		request.IdempotencyKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return RevokeResult{}, false, nil
	}
	if err != nil {
		return RevokeResult{}, false, fmt.Errorf("load identity session revoke receipt: %w", ErrUnavailable)
	}
	var receipt revokeReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.IdempotencyKey != request.IdempotencyKey ||
		receipt.RequestDigest != hex.EncodeToString(digest[:]) || receipt.FamilyID != request.FamilyID ||
		receipt.Revision != request.ExpectedRevision+1 || receipt.RevokedAt.IsZero() {
		if receipt.IdempotencyKey == request.IdempotencyKey && receipt.RequestDigest != hex.EncodeToString(digest[:]) {
			return RevokeResult{}, false, ErrIdempotencyConflict
		}
		return RevokeResult{}, false, fmt.Errorf("validate identity session revoke receipt: %w", ErrUnavailable)
	}
	return RevokeResult{FamilyID: receipt.FamilyID, Revision: receipt.Revision,
		RevokedAt: receipt.RevokedAt.UTC(), Current: receipt.Current}, true, nil
}

func encodeCursor(cursor sessionCursor) (string, error) {
	if !validCursor(cursor) {
		return "", ErrInvalidCursor
	}
	raw, err := json.Marshal(cursor)
	if err != nil {
		return "", ErrInvalidCursor
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// nextPageCursor encodes the keyset position after last. pgx scans
// timestamptz in time.Local, so CreatedAt is normalised to UTC here.
func nextPageCursor(current sessionCursor, last SessionFamily) (string, error) {
	return encodeCursor(sessionCursor{Version: 1, ScopeID: current.ScopeID, UserID: current.UserID,
		SnapshotAt: current.SnapshotAt, LastCreatedAt: last.CreatedAt.UTC(), LastFamilyID: last.FamilyID})
}

func decodeCursor(encoded string, actor Actor) (sessionCursor, error) {
	if encoded == "" || len(encoded) > 2048 {
		return sessionCursor{}, ErrInvalidCursor
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return sessionCursor{}, ErrInvalidCursor
	}
	var cursor sessionCursor
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cursor) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || !validCursor(cursor) ||
		cursor.ScopeID != actor.ScopeID || cursor.UserID != actor.UserID {
		return sessionCursor{}, ErrInvalidCursor
	}
	canonical, err := encodeCursor(cursor)
	if err != nil || canonical != encoded {
		return sessionCursor{}, ErrInvalidCursor
	}
	return cursor, nil
}

func validCursor(cursor sessionCursor) bool {
	return cursor.Version == 1 && cursor.ScopeID != uuid.Nil && cursor.UserID != uuid.Nil &&
		!cursor.SnapshotAt.IsZero() && cursor.SnapshotAt.Location() == time.UTC &&
		!cursor.LastCreatedAt.IsZero() && cursor.LastCreatedAt.Location() == time.UTC &&
		!cursor.LastCreatedAt.After(cursor.SnapshotAt) && cursor.LastFamilyID != uuid.Nil &&
		cursor.SnapshotAt.Nanosecond()%1000 == 0 && cursor.LastCreatedAt.Nanosecond()%1000 == 0
}

func revokeRequestDigest(request RevokeRequest) [sha256.Size]byte {
	hash := sha256.New()
	for _, value := range []string{"cdnca.identity.session-family-revoke/v1", request.Actor.SessionID.String(),
		request.Actor.ScopeID.String(), request.Actor.UserID.String(), request.Actor.ScopeKind,
		request.FamilyID.String(), fmt.Sprintf("%d", request.ExpectedRevision), request.IdempotencyKey, request.RequestID} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func revokeAdvisoryKey(request RevokeRequest) int64 {
	digest := sha256.Sum256([]byte(request.Actor.ScopeID.String() + "\x00" + request.Actor.UserID.String() +
		"\x00" + revokeAction + "\x00" + request.IdempotencyKey))
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func maskSourceIP(raw string) string {
	address, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	bits := 64
	if address.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(address, bits).Masked().String()
}

func deviceLabel(raw string) string {
	lower := strings.ToLower(raw)
	browser := "未知浏览器"
	switch {
	case strings.Contains(lower, "edg/"):
		browser = "Edge"
	case strings.Contains(lower, "chrome/"):
		browser = "Chrome"
	case strings.Contains(lower, "firefox/"):
		browser = "Firefox"
	case strings.Contains(lower, "safari/"):
		browser = "Safari"
	}
	platform := "未知系统"
	switch {
	case strings.Contains(lower, "iphone"), strings.Contains(lower, "ipad"):
		platform = "iOS"
	case strings.Contains(lower, "android"):
		platform = "Android"
	case strings.Contains(lower, "mac os"), strings.Contains(lower, "macintosh"):
		platform = "macOS"
	case strings.Contains(lower, "windows"):
		platform = "Windows"
	case strings.Contains(lower, "linux"):
		platform = "Linux"
	}
	return browser + " / " + platform
}

func validActor(actor Actor) bool {
	return actor.SessionID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.UserID != uuid.Nil &&
		(actor.ScopeKind == "tenant" || actor.ScopeKind == "platform")
}

func nullableUUID(value uuid.UUID) any {
	if value == uuid.Nil {
		return nil
	}
	return value
}
