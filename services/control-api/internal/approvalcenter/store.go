package approvalcenter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// PendingTTL: a pending request expires after 24 hours (Q8, fixed).
	PendingTTL = 24 * time.Hour
	// groupWindow: grouped steps of one browser action merge within this window.
	groupWindow  = 2 * time.Minute
	maxGroupSize = 100
	maxResult    = 4096
	// StaleExecuting: an executing request older than this is marked unknown.
	StaleExecuting = 10 * time.Minute

	StatePending   = "pending"
	StateExpired   = "expired" // derived on read
	StateRejected  = "rejected"
	StateExecuting = "executing"
	// StateUnknown: executing for longer than StaleExecuting (the process was
	// interrupted mid-replay). Never replayed automatically; the approver checks
	// the original page. A late Finish from the original process still lands.
	StateUnknown  = "unknown"
	StateExecuted = "executed"
	StateFailed   = "failed"

	StepUpMFA  = "mfa"
	StepUpNone = "none"

	PermissionRead    = "approvals.read"
	PermissionApprove = "approvals.approve"
	PermissionManage  = "approvals.manage"
	// platformAdmin may approve its own request, audited as self_approved.
	platformAdmin = "platform.admin"

	StepUpAudience = "approval-center"
	StepUpAction   = "approval_center.approve"

	auditSettings = "approval_center.settings.update"
	auditSubmit   = "approval_center.request.submit"
	auditApprove  = "approval_center.request.approve"
	auditReject   = "approval_center.request.reject"
	auditExecute  = "approval_center.request.execute"
	auditUnknown  = "approval_center.request.outcome_unknown"
)

var (
	ErrInvalidInput     = errors.New("approval center invalid input")
	ErrPermissionDenied = errors.New("approval center permission denied")
	ErrNotFound         = errors.New("approval request not found")
	ErrConflict         = errors.New("approval request revision conflict")
	ErrExpired          = errors.New("approval request expired")
	ErrSameOperator     = errors.New("approval request needs a different approver")
	ErrStepUpRequired   = errors.New("approval requires a step-up verification")
)

// Session is the live platform session behind a request.
type Session struct {
	UserID, ScopeID, SessionID uuid.UUID
	ScopeKind                  string
	Permissions                []string
}

func (s Session) has(permission string) bool {
	for _, held := range s.Permissions {
		if held == permission {
			return true
		}
	}
	return false
}

type Settings struct {
	Enabled  bool     `json:"enabled"`
	Rules    []string `json:"rules"`
	Revision int64    `json:"revision"`
}

// Step is one stored request, replayed as-is.
type Step struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   string            `json:"query"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

type StepResult struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

type Request struct {
	ID            uuid.UUID    `json:"id"`
	Rule          string       `json:"rule"`
	Steps         []Step       `json:"-"`
	StepCount     int          `json:"step_count"`
	Summary       []StepView   `json:"steps"`
	Reason        string       `json:"reason"`
	RequestedBy   uuid.UUID    `json:"requested_by_user_id"`
	RequesterName string       `json:"requested_by_name"`
	RequestedAt   time.Time    `json:"requested_at"`
	ExpiresAt     time.Time    `json:"expires_at"`
	State         string       `json:"state"`
	DecidedBy     *uuid.UUID   `json:"decided_by_user_id,omitempty"`
	DeciderName   string       `json:"decided_by_name,omitempty"`
	DecidedAt     *time.Time   `json:"decided_at,omitempty"`
	DecisionNote  string       `json:"decision_note"`
	StepUp        string       `json:"step_up,omitempty"`
	SelfApproved  bool         `json:"self_approved"`
	Results       []StepResult `json:"results,omitempty"`
	ExecutedAt    *time.Time   `json:"executed_at,omitempty"`
	Revision      int64        `json:"revision"`
	groupKey      string
}

// StepView is the part of a step shown to approvers (the body is shown as
// text; secrets never reach these routes: the managed operations carry none).
type StepView struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Query  string `json:"query,omitempty"`
	Body   string `json:"body,omitempty"`
}

// StepUpConsumer is mfa.Service.ConsumeStepUpTxWithScopes.
type StepUpConsumer interface {
	ConsumeStepUpTxWithScopes(context.Context, pgx.Tx, mfa.Actor, []uuid.UUID, mfa.ConsumeStepUpRequest) (mfa.Evidence, error)
}

type Store struct {
	pool   *pgxpool.Pool
	stepUp StepUpConsumer
	now    func() time.Time
}

func NewStore(pool *pgxpool.Pool, stepUp StepUpConsumer, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, stepUp: stepUp, now: now}
}

func (s *Store) Settings(ctx context.Context) (Settings, error) {
	var result Settings
	err := s.pool.QueryRow(ctx, `SELECT enabled,rules,revision FROM approval_center_settings WHERE singleton`).
		Scan(&result.Enabled, &result.Rules, &result.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{Rules: []string{}}, nil
	}
	return result, err
}

func (s *Store) SaveSettings(ctx context.Context, actor Session, input Settings, requestID string) (Settings, error) {
	if !actor.has(PermissionManage) {
		return Settings{}, ErrPermissionDenied
	}
	if input.Rules == nil {
		input.Rules = []string{}
	}
	if !ValidRules(input.Rules) || input.Revision < 0 {
		return Settings{}, ErrInvalidInput
	}
	now := s.now().UTC()
	var saved Settings
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var current int64
		err := tx.QueryRow(ctx, `SELECT revision FROM approval_center_settings WHERE singleton FOR UPDATE`).Scan(&current)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if current != input.Revision {
			return ErrConflict
		}
		saved = Settings{Enabled: input.Enabled, Rules: input.Rules, Revision: current + 1}
		if _, err := tx.Exec(ctx, `INSERT INTO approval_center_settings(singleton,revision,enabled,rules,updated_by_user_id,updated_at)
			VALUES(true,$1,$2,$3,$4,$5) ON CONFLICT (singleton) DO UPDATE SET revision=EXCLUDED.revision,
			enabled=EXCLUDED.enabled,rules=EXCLUDED.rules,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
			saved.Revision, saved.Enabled, saved.Rules, actor.UserID, now); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, auditSettings, "platform", requestID, "success",
			map[string]any{"enabled": saved.Enabled, "rules": saved.Rules})
	})
	return saved, err
}

// Submit stores step as a pending request, or appends it to the requester's
// pending request of the same group (grouped rules only).
func (s *Store) Submit(ctx context.Context, actor Session, rule Rule, groupKey, reason string, step Step, requestID string) (Request, error) {
	now := s.now().UTC()
	encoded, err := json.Marshal(step)
	if err != nil {
		return Request{}, err
	}
	var result Request
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if rule.Grouped && groupKey != "" {
			var id uuid.UUID
			err := tx.QueryRow(ctx, `SELECT id FROM approval_requests WHERE requested_by_user_id=$1 AND rule=$2
				AND group_key=$3 AND state='pending' AND requested_at>$4 AND expires_at>$5
				AND jsonb_array_length(items)<$6 ORDER BY requested_at DESC LIMIT 1 FOR UPDATE`,
				actor.UserID, rule.Name, groupKey, now.Add(-groupWindow), now, maxGroupSize).Scan(&id)
			if err == nil {
				if _, err := tx.Exec(ctx, `UPDATE approval_requests SET items=items||jsonb_build_array($2::jsonb),
					revision=revision+1 WHERE id=$1`, id, encoded); err != nil {
					return err
				}
				result, err = loadRequest(ctx, tx, id, now)
				return err
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		var group any
		if rule.Grouped && groupKey != "" {
			group = groupKey
		}
		if _, err := tx.Exec(ctx, `INSERT INTO approval_requests(id,rule,items,group_key,reason,requested_by_user_id,
			requested_by_scope_id,requested_at,expires_at,state) VALUES($1,$2,jsonb_build_array($3::jsonb),$4,$5,$6,$7,$8,$9,'pending')`,
			id, rule.Name, encoded, group, reason, actor.UserID, actor.ScopeID, now, now.Add(PendingTTL)); err != nil {
			return err
		}
		if err := appendAudit(ctx, tx, actor, auditSubmit, id.String(), requestID, "success",
			map[string]any{"rule": rule.Name, "reason": reason}); err != nil {
			return err
		}
		result, err = loadRequest(ctx, tx, id, now)
		return err
	})
	return result, err
}

func (s *Store) List(ctx context.Context, actor Session, state string, limit int) ([]Request, error) {
	if !actor.has(PermissionRead) && !actor.has(PermissionApprove) {
		return nil, ErrPermissionDenied
	}
	if limit < 1 || limit > 100 {
		return nil, ErrInvalidInput
	}
	now := s.now().UTC()
	filter := ""
	switch state {
	case "":
	case StatePending:
		filter = "WHERE r.state='pending' AND r.expires_at>$2"
	case StateExpired:
		filter = "WHERE r.state='pending' AND r.expires_at<=$2"
	case StateRejected, StateExecuting, StateUnknown, StateExecuted, StateFailed:
		filter = "WHERE r.state='" + state + "' AND $2::timestamptz IS NOT NULL"
	default:
		return nil, ErrInvalidInput
	}
	if filter == "" {
		filter = "WHERE $2::timestamptz IS NOT NULL"
	}
	rows, err := s.pool.Query(ctx, requestSelect+" "+filter+" ORDER BY r.requested_at DESC, r.id DESC LIMIT $1", limit, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Request{}
	for rows.Next() {
		item, err := scanRequest(rows, now)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) Get(ctx context.Context, actor Session, id uuid.UUID) (Request, error) {
	if !actor.has(PermissionRead) && !actor.has(PermissionApprove) && !actor.has(PermissionManage) {
		return Request{}, ErrPermissionDenied
	}
	var result Request
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		result, err = loadRequest(ctx, tx, id, s.now().UTC())
		return err
	})
	return result, err
}

// Binding is the step-up resource binding of one approval: the request id,
// its revision and the stored steps, so a proof approves exactly what was shown.
func Binding(request Request) [32]byte {
	encoded, _ := json.Marshal(request.Steps)
	digest := sha256.Sum256(encoded)
	return sha256.Sum256([]byte(fmt.Sprintf("cdnca.approval-center/v1\x00%s\x00%d\x00%x", request.ID, request.Revision, digest)))
}

// MFAActive reports whether the approver's latest MFA credential is active (Q3).
func (s *Store) MFAActive(ctx context.Context, actor Session) (bool, error) {
	var active bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM (SELECT id FROM mfa_credentials
		WHERE user_id=$1 AND scope_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1) latest
		WHERE EXISTS(SELECT 1 FROM mfa_credential_events event WHERE event.credential_id=latest.id AND event.event_type='activated')
		AND NOT EXISTS(SELECT 1 FROM mfa_credential_events event WHERE event.credential_id=latest.id AND event.event_type IN ('disabled','reset')))`,
		actor.UserID, actor.ScopeID).Scan(&active)
	return active, err
}

// consumeStepUp consumes a platform-scoped proof bound to the approval in its
// own transaction (as migrate-import does).
func (s *Store) consumeStepUp(ctx context.Context, actor Session, token string, binding [32]byte) error {
	if s.stepUp == nil || token == "" {
		return ErrStepUpRequired
	}
	traceID := "ac-" + uuid.NewString()
	var evidence mfa.Evidence
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		locked, err := iamstage2b.BeginAuthorityMutation(ctx, tx, iamstage2b.OperationMFAConsumeStepUp, []uuid.UUID{actor.ScopeID})
		if err != nil {
			return err
		}
		evidence, err = s.stepUp.ConsumeStepUpTxWithScopes(ctx, tx, mfa.Actor{UserID: actor.UserID, ScopeID: actor.ScopeID,
			SessionID: actor.SessionID}, locked, mfa.ConsumeStepUpRequest{Token: token, PlatformScope: true,
			Audience: StepUpAudience, Action: StepUpAction, ResourceBindingDigest: binding[:],
			Context: mfa.RequestContext{RequestID: traceID, TraceID: traceID}})
		return err
	})
	if err != nil || evidence.ProofID == uuid.Nil || !evidence.PlatformScope || evidence.ActorUserID != actor.UserID ||
		evidence.SessionID != actor.SessionID || evidence.Audience != StepUpAudience || evidence.Action != StepUpAction ||
		!bytes.Equal(evidence.ResourceBindingDigest, binding[:]) {
		return ErrStepUpRequired
	}
	return nil
}

// Approve checks the approver, the 24-hour window and the step-up, then marks
// the request executing; the caller replays the steps with the approver's
// session and records the outcome with Finish.
func (s *Store) Approve(ctx context.Context, actor Session, id uuid.UUID, expectedRevision int64, note, stepUpToken, requestID string) (Request, error) {
	if !actor.has(PermissionApprove) {
		return Request{}, ErrPermissionDenied
	}
	current, err := s.Get(ctx, actor, id)
	if err != nil {
		return Request{}, err
	}
	if err := decidable(current, actor, expectedRevision); err != nil {
		return Request{}, err
	}
	stepUp := StepUpNone
	active, err := s.MFAActive(ctx, actor)
	if err != nil {
		return Request{}, err
	}
	if active {
		if err := s.consumeStepUp(ctx, actor, stepUpToken, Binding(current)); err != nil {
			return Request{}, err
		}
		stepUp = StepUpMFA
	}
	now := s.now().UTC()
	var result Request
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		locked, err := lockRequest(ctx, tx, id, now)
		if err != nil {
			return err
		}
		if err := decidable(locked, actor, expectedRevision); err != nil {
			return err
		}
		self := locked.RequestedBy == actor.UserID
		if _, err := tx.Exec(ctx, `UPDATE approval_requests SET state='executing',decided_by_user_id=$2,decided_at=$3,
			decision_note=$4,step_up=$5,self_approved=$6,revision=revision+1 WHERE id=$1`,
			id, actor.UserID, now, note, stepUp, self); err != nil {
			return err
		}
		payload := map[string]any{"rule": locked.Rule, "step_up": stepUp, "self_approved": self}
		if stepUp == StepUpNone {
			payload["step_up_note"] = "未二次验证"
		}
		if self {
			payload["approval_note"] = "自审"
		}
		if err := appendAudit(ctx, tx, actor, auditApprove, id.String(), requestID, "success", payload); err != nil {
			return err
		}
		result, err = loadRequest(ctx, tx, id, now)
		return err
	})
	if err != nil {
		return Request{}, err
	}
	return result, nil
}

func (s *Store) Reject(ctx context.Context, actor Session, id uuid.UUID, expectedRevision int64, note, requestID string) (Request, error) {
	if !actor.has(PermissionApprove) {
		return Request{}, ErrPermissionDenied
	}
	now := s.now().UTC()
	var result Request
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		locked, err := lockRequest(ctx, tx, id, now)
		if err != nil {
			return err
		}
		if err := decidable(locked, actor, expectedRevision); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE approval_requests SET state='rejected',decided_by_user_id=$2,decided_at=$3,
			decision_note=$4,self_approved=$5,revision=revision+1 WHERE id=$1`,
			id, actor.UserID, now, note, locked.RequestedBy == actor.UserID); err != nil {
			return err
		}
		if err := appendAudit(ctx, tx, actor, auditReject, id.String(), requestID, "success",
			map[string]any{"rule": locked.Rule}); err != nil {
			return err
		}
		result, err = loadRequest(ctx, tx, id, now)
		return err
	})
	return result, err
}

// Finish records the replay outcome of an executing request (or of one the
// recovery already marked unknown: the real outcome replaces "unknown").
func (s *Store) Finish(ctx context.Context, actor Session, id uuid.UUID, results []StepResult, requestID string) (Request, error) {
	state := StateExecuted
	for index := range results {
		if results[index].Status >= 400 {
			state = StateFailed
		}
		if len(results[index].Body) > maxResult {
			results[index].Body = results[index].Body[:maxResult]
		}
	}
	encoded, err := json.Marshal(results)
	if err != nil {
		return Request{}, err
	}
	now := s.now().UTC()
	var result Request
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		command, err := tx.Exec(ctx, `UPDATE approval_requests SET state=$2,results=$3,executed_at=$4,revision=revision+1
			WHERE id=$1 AND state IN ('executing','unknown')`, id, state, encoded, now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrConflict
		}
		outcome := "success"
		if state == StateFailed {
			outcome = "failure"
		}
		if err := appendAudit(ctx, tx, actor, auditExecute, id.String(), requestID, outcome,
			map[string]any{"steps": len(results)}); err != nil {
			return err
		}
		result, err = loadRequest(ctx, tx, id, now)
		return err
	})
	return result, err
}

// MarkStaleExecuting marks requests executing since before now-StaleExecuting
// as unknown and audits each as a system event; it never replays them.
func (s *Store) MarkStaleExecuting(ctx context.Context) (int, error) {
	now := s.now().UTC()
	marked := 0
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE approval_requests SET state='unknown',revision=revision+1
			WHERE state='executing' AND decided_at<=$1 RETURNING id,rule,requested_by_scope_id`, now.Add(-StaleExecuting))
		if err != nil {
			return err
		}
		type stale struct {
			id, scope uuid.UUID
			rule      string
		}
		var items []stale
		for rows.Next() {
			var item stale
			if err := rows.Scan(&item.id, &item.rule, &item.scope); err != nil {
				rows.Close()
				return err
			}
			items = append(items, item)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, item := range items {
			if _, err := audit.AppendTx(ctx, tx, audit.Event{ScopeID: item.scope, ActorKind: audit.ActorSystem,
				ActorRef: "job:approval-center-recovery", Action: auditUnknown, ResourceType: "approval_request",
				ResourceID: item.id.String(), RequestID: "approval-center-recovery/" + uuid.NewString(),
				Result: "failure", ReasonCode: "outcome_unknown",
				Payload: map[string]any{"rule": item.rule}}); err != nil {
				return err
			}
		}
		marked = len(items)
		return nil
	})
	return marked, err
}

func decidable(request Request, actor Session, expectedRevision int64) error {
	switch {
	case request.State == StateExpired:
		return ErrExpired
	case request.State != StatePending || request.Revision != expectedRevision:
		return ErrConflict
	case request.RequestedBy == actor.UserID && !actor.has(platformAdmin):
		return ErrSameOperator
	}
	return nil
}

const requestSelect = `SELECT r.id,r.rule,r.items,COALESCE(r.group_key,''),r.reason,r.requested_by_user_id,
	COALESCE(requester.display_name,''),r.requested_at,r.expires_at,r.state,r.decided_by_user_id,
	COALESCE(decider.display_name,''),r.decided_at,r.decision_note,COALESCE(r.step_up,''),r.self_approved,
	r.results,r.executed_at,r.revision
	FROM approval_requests r
	LEFT JOIN users requester ON requester.id=r.requested_by_user_id
	LEFT JOIN users decider ON decider.id=r.decided_by_user_id`

func loadRequest(ctx context.Context, tx pgx.Tx, id uuid.UUID, now time.Time) (Request, error) {
	return scanOne(tx.QueryRow(ctx, requestSelect+" WHERE r.id=$1", id), now)
}

func lockRequest(ctx context.Context, tx pgx.Tx, id uuid.UUID, now time.Time) (Request, error) {
	return scanOne(tx.QueryRow(ctx, requestSelect+" WHERE r.id=$1 FOR UPDATE OF r", id), now)
}

func scanOne(row pgx.Row, now time.Time) (Request, error) {
	result, err := scanRequest(row, now)
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrNotFound
	}
	return result, err
}

func scanRequest(row pgx.Row, now time.Time) (Request, error) {
	var result Request
	var items, results []byte
	err := row.Scan(&result.ID, &result.Rule, &items, &result.groupKey, &result.Reason, &result.RequestedBy,
		&result.RequesterName, &result.RequestedAt, &result.ExpiresAt, &result.State, &result.DecidedBy,
		&result.DeciderName, &result.DecidedAt, &result.DecisionNote, &result.StepUp, &result.SelfApproved,
		&results, &result.ExecutedAt, &result.Revision)
	if err != nil {
		return Request{}, err
	}
	if err := json.Unmarshal(items, &result.Steps); err != nil {
		return Request{}, fmt.Errorf("decode approval steps: %w", err)
	}
	if len(results) > 0 {
		if err := json.Unmarshal(results, &result.Results); err != nil {
			return Request{}, fmt.Errorf("decode approval results: %w", err)
		}
	}
	result.StepCount = len(result.Steps)
	result.Summary = make([]StepView, len(result.Steps))
	for index, step := range result.Steps {
		result.Summary[index] = StepView{Method: step.Method, Path: step.Path, Query: step.Query, Body: string(step.Body)}
	}
	if result.State == StatePending && !now.Before(result.ExpiresAt) {
		result.State = StateExpired
	}
	return result, nil
}

func appendAudit(ctx context.Context, tx pgx.Tx, actor Session, action, resourceID, requestID, outcome string, payload map[string]any) error {
	userID := actor.UserID
	_, err := audit.AppendTx(ctx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &userID, Action: action, ResourceType: "approval_request",
		ResourceID: resourceID, RequestID: requestID, Result: outcome, Payload: payload,
	})
	return err
}
