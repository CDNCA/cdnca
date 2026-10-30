package rulepackcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Audit actions of the rule pack write operations (BATCH-PLUGIN 第 10 条).
// A refused write is recorded with result denied in its own transaction.
const (
	AuditPackUpdate    = "rule.pack.update"
	AuditVersionDelete = "rule.pack.version.delete"
	AuditOverridePut   = "rule.pack.override.put"
	AuditSitePublish   = "rule.pack.site.publish"
)

// auditRecord is what one write operation knows for its audit event; the
// operation fills it as it learns more (the target scope, the state before).
type auditRecord struct {
	scopeID      uuid.UUID
	resourceType string
	resourceID   string
	payload      map[string]any
	changes      map[string]any
}

func (s *Service) appendAudit(ctx context.Context, tx pgx.Tx, actor Actor, action string, record auditRecord, cause error) error {
	payload := map[string]any{}
	for key, value := range record.payload {
		payload[key] = value
	}
	payload["ip"], payload["actor_scope_kind"] = actor.SourceIP, actor.ScopeKind
	if len(record.changes) != 0 {
		payload["changes"] = record.changes
	}
	result := "success"
	if cause != nil {
		result = "denied"
		payload["reason_code"] = deniedReason(cause)
	}
	event := audit.Event{ScopeID: record.scopeID, Action: action, ResourceType: record.resourceType,
		ResourceID: record.resourceID, RequestID: actor.RequestID, Result: result, Payload: payload}
	if event.RequestID == "" {
		event.RequestID = "rule-pack-" + uuid.NewString()
	}
	if actor.UserID != uuid.Nil {
		userID := actor.UserID
		event.ActorUserID = &userID
	}
	return audit.NewWithClock(nil, s.now).Append(ctx, tx, event)
}

// auditDenied records a refused write (the write itself rolled back) and
// returns err. Internal failures are not refusals and are not recorded.
func (s *Service) auditDenied(ctx context.Context, actor Actor, action string, record auditRecord, err error) error {
	if deniedReason(err) == "" || record.scopeID == uuid.Nil {
		return err
	}
	if auditErr := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return s.appendAudit(ctx, tx, actor, action, record, err)
	}); auditErr != nil {
		return fmt.Errorf("%w (audit denied write: %v)", err, auditErr)
	}
	return err
}

func deniedReason(err error) string {
	var conflict *ConflictError
	switch {
	case errors.As(err, &conflict):
		return "mounts_conflict"
	case errors.Is(err, ErrPermissionDenied):
		return "permission_denied"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrLocked):
		return "locked_by_upper_level"
	case errors.Is(err, ErrInUse):
		return "in_use"
	case errors.Is(err, ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, ErrExists):
		return "exists"
	}
	return ""
}

// change is a before -> after pair; nil before = unknown or unset.
func change(before, after any) map[string]any {
	return map[string]any{"from": before, "to": after}
}

func sameJSON(a, b any) bool {
	left, errLeft := json.Marshal(a)
	right, errRight := json.Marshal(b)
	return errLeft == nil && errRight == nil && string(left) == string(right)
}

func stringOrNil(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
