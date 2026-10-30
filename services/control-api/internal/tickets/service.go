package tickets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"regexp"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Config struct {
	Pool     *pgxpool.Pool
	Notifier Notifier
	// Objects enables attachments; without it uploads answer
	// ErrAttachmentsDisabled.
	Objects ObjectStore
	// Scanner, when set, must accept every attachment before it is stored.
	Scanner Scanner
	Now     func() time.Time
	Logf    func(string, ...any)
}

type Service struct {
	pool     *pgxpool.Pool
	notifier Notifier
	objects  ObjectStore
	scanner  Scanner
	auditor  *audit.Log
	now      func() time.Time
	logf     func(string, ...any)
}

func New(config Config) (*Service, error) {
	if config.Pool == nil || config.Notifier == nil {
		return nil, ErrInvalidInput
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logf == nil {
		config.Logf = log.Printf
	}
	return &Service{pool: config.Pool, notifier: config.Notifier, objects: config.Objects, scanner: config.Scanner,
		auditor: audit.NewWithClock(config.Pool, config.Now), now: config.Now, logf: config.Logf}, nil
}

// AttachmentsEnabled reports whether uploads are configured.
func (service *Service) AttachmentsEnabled() bool { return service.objects != nil }

func (service *Service) clock() time.Time { return service.now().UTC().Truncate(time.Microsecond) }

const sessionSQL = `SELECT EXISTS(SELECT 1 FROM auth_sessions session
	JOIN users account ON account.id=session.user_id AND account.status='active'
	JOIN memberships membership ON membership.scope_id=session.scope_id AND membership.user_id=session.user_id
		AND membership.status='active'
	JOIN access_scopes scope ON scope.id=session.scope_id AND scope.kind=$5
	WHERE session.id=$1 AND session.scope_id=$2 AND session.user_id=$3 AND session.revoked_at IS NULL
		AND session.replaced_by_id IS NULL AND session.expires_at>$4)`

// authCustomer re-checks a tenant session inside the transaction.
func authCustomer(ctx context.Context, tx pgx.Tx, actor Actor, now time.Time) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.SessionID == uuid.Nil {
		return ErrUnauthenticated
	}
	var ok bool
	if err := tx.QueryRow(ctx, sessionSQL, actor.SessionID, actor.ScopeID, actor.UserID, now, "tenant").Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrUnauthenticated
	}
	return nil
}

// authStaff re-checks a platform session and one of the permissions
// (platform.admin always qualifies).
func authStaff(ctx context.Context, tx pgx.Tx, actor Actor, now time.Time, permissions ...string) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.SessionID == uuid.Nil {
		return ErrUnauthenticated
	}
	kind := "platform"
	var ok, permitted bool
	if err := tx.QueryRow(ctx, sessionSQL, actor.SessionID, actor.ScopeID, actor.UserID, now, kind).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrUnauthenticated
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM role_assignments assignment
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2
		AND grant_row.permission_name = ANY($3::text[] || ARRAY['platform.admin']))`,
		actor.ScopeID, actor.UserID, permissions).Scan(&permitted); err != nil {
		return err
	}
	if !permitted {
		return ErrPermissionDenied
	}
	return nil
}

func requestDigest(operation string, parts ...any) [32]byte {
	raw, _ := json.Marshal(append([]any{operation}, parts...))
	return sha256.Sum256(raw)
}

// replay returns the ticket id recorded for (actor, operation, key).
func replay(ctx context.Context, tx pgx.Tx, actor Actor, operation, key string, digest [32]byte) (uuid.UUID, bool, error) {
	var stored, body []byte
	err := tx.QueryRow(ctx, `SELECT request_digest,response_body FROM ticket_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`, actor.UserID, operation, key).Scan(&stored, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	if !bytes.Equal(stored, digest[:]) {
		return uuid.Nil, false, ErrIdempotency
	}
	var response struct {
		TicketID uuid.UUID `json:"ticket_id"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return uuid.Nil, false, err
	}
	return response.TicketID, true, nil
}

func recordWrite(ctx context.Context, tx pgx.Tx, actor Actor, operation, key string, digest [32]byte,
	ticketID uuid.UUID, now time.Time,
) error {
	body, _ := json.Marshal(map[string]string{"ticket_id": ticketID.String()})
	_, err := tx.Exec(ctx, `INSERT INTO ticket_write_requests(actor_user_id,operation,idempotency_key,request_digest,
		response_body,created_at) VALUES($1,$2,$3,$4,$5,$6)`, actor.UserID, operation, key, digest[:], body, now)
	return err
}
