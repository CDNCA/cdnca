package l4forward

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 批量添加 (添加转发 > 批量): one line per stream,
// "监听端口|IP|回源端口", e.g. "88 99/udp|1.2.3.4|8080". The first port is the
// primary listener, the others additional listeners; the origin is an IP
// address or a domain name.
const (
	BatchCreateLinesMax = 200

	BatchLineCreated = "created"
	BatchLineFailed  = "failed"
	BatchLineSkipped = "skipped" // not attempted: an earlier line failed without 忽略错误
)

// BatchCreateRequest carries the shared fields of every line (owner,
// package, site, groups, remark and the stream defaults in Template) and the
// lines. IgnoreErrors (忽略错误) skips failed lines; without it the batch is
// atomic: one failed line and nothing is written.
type BatchCreateRequest struct {
	TargetScopeID  uuid.UUID
	OwnerUserID    uuid.UUID
	Template       Fields
	GroupIDs       []uuid.UUID
	Lines          []string
	IgnoreErrors   bool
	IdempotencyKey string
	RequestID      string
}

type BatchLineError struct {
	Code string `json:"code"`
}

type BatchCreateLineResult struct {
	Line   int             `json:"line"`
	Text   string          `json:"text"`
	Status string          `json:"status"`
	Stream *Forward        `json:"stream,omitempty"`
	Error  *BatchLineError `json:"error,omitempty"`
}

type BatchCreateResult struct {
	Items     []BatchCreateLineResult `json:"items"`
	Created   int                     `json:"created"`
	Failed    int                     `json:"failed"`
	Committed bool                    `json:"committed"`
	Replayed  bool                    `json:"-"`
}

// ParseBatchLine reads one 批量添加 line into the template's fields.
func ParseBatchLine(template Fields, line string) (Fields, error) {
	parts := strings.Split(strings.TrimSpace(line), "|")
	if len(parts) != 3 {
		return Fields{}, ErrInvalidInput
	}
	ports := strings.Fields(parts[0])
	origin := strings.TrimSpace(parts[1])
	originPort, err := strconv.ParseUint(strings.TrimSpace(parts[2]), 10, 16)
	if len(ports) == 0 || len(ports) > 64 || origin == "" || err != nil || originPort == 0 {
		return Fields{}, ErrInvalidInput
	}
	fields := template
	fields.AdditionalListeners = nil
	fields.Origins = nil
	extras := make([]AdditionalListener, 0, len(ports)-1)
	// A port without /tcp or /udp takes the template's protocol (the
	// 「默认设置」 listen protocol, L4-DEFAULT-01), else TCP.
	defaultProtocol := ProtocolTCP
	if template.Protocol == ProtocolUDP {
		defaultProtocol = ProtocolUDP
	}
	for index, token := range ports {
		protocol := defaultProtocol
		if number, suffix, found := strings.Cut(token, "/"); found {
			token, protocol = number, strings.ToLower(suffix)
		}
		port, err := strconv.ParseUint(token, 10, 16)
		if err != nil || port == 0 || (protocol != ProtocolTCP && protocol != ProtocolUDP) {
			return Fields{}, ErrInvalidInput
		}
		if index == 0 {
			fields.Protocol, fields.ListenPort = protocol, uint16(port)
			continue
		}
		extras = append(extras, AdditionalListener{ID: uuid.New(), Protocol: protocol, Address: "*", Port: uint16(port)})
	}
	if len(extras) > 0 {
		fields.AdditionalListeners = &extras
	}
	fields.UpstreamAddress, fields.UpstreamHost, fields.UpstreamPort = "", "", uint16(originPort)
	fields.Origins = []Origin{{Address: origin, Weight: 1}}
	if fields.Name == "" {
		fields.Name = fmt.Sprintf("%s %d", strings.ToUpper(fields.Protocol), fields.ListenPort)
	}
	return fields, nil
}

func (s *Service) BatchCreate(ctx context.Context, actor Actor, request BatchCreateRequest) (BatchCreateResult, error) {
	if err := normalizeActorAndTarget(actor, &request.TargetScopeID, &request.OwnerUserID); err != nil {
		return BatchCreateResult{}, err
	}
	if !validWriteMetadata(request.IdempotencyKey, request.RequestID) || len(request.Lines) == 0 || len(request.Lines) > BatchCreateLinesMax {
		return BatchCreateResult{}, ErrInvalidInput
	}
	groupIDs, err := normalizeGroupIDs(request.GroupIDs)
	if err != nil {
		return BatchCreateResult{}, err
	}
	request.GroupIDs = groupIDs
	defaults, err := s.resolveFieldDefaults(ctx, actor, request.TargetScopeID, request.OwnerUserID, groupIDs)
	if err != nil {
		return BatchCreateResult{}, err
	}
	template := request.Template
	if template.Protocol == "" && defaults.Protocol != nil {
		template.Protocol = *defaults.Protocol // ports without /tcp|/udp follow it
	}
	// The whole batch is one idempotent request (digest over the input as sent).
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID   `json:"target_scope_id"`
		OwnerUserID   uuid.UUID   `json:"owner_user_id"`
		Template      Fields      `json:"template"`
		GroupIDs      []uuid.UUID `json:"group_ids"`
		Lines         []string    `json:"lines"`
		IgnoreErrors  bool        `json:"ignore_errors"`
	}{request.TargetScopeID, request.OwnerUserID, request.Template, request.GroupIDs, request.Lines, request.IgnoreErrors})
	if err != nil {
		return BatchCreateResult{}, err
	}
	creates := make([]*CreateRequest, len(request.Lines))
	parseErrors := make([]error, len(request.Lines))
	for index, line := range request.Lines {
		fields, err := ParseBatchLine(template, line)
		if err == nil {
			applyFieldDefaults(&fields, defaults)
			err = normalizeFields(&fields)
		}
		if err != nil {
			parseErrors[index] = locatedOrInvalid(err)
			continue
		}
		creates[index] = &CreateRequest{TargetScopeID: request.TargetScopeID, OwnerUserID: request.OwnerUserID,
			Fields: fields, GroupIDs: groupIDs, RequestID: request.RequestID}
	}
	result, err := s.store.BatchCreate(ctx, actor, request, creates, parseErrors, digest)
	for index := range result.Items {
		if result.Items[index].Stream != nil {
			redact(result.Items[index].Stream, actor.ScopeKind)
		}
	}
	return result, err
}

// BatchCreate writes the lines in one transaction. With IgnoreErrors each
// line runs in a savepoint and a failed line is rolled back alone; without
// it the first failure stops the batch, nothing is written, and the result
// (lines failed / skipped, Committed false) is returned with ErrBatchFailed.
func (s *Store) BatchCreate(ctx context.Context, actor Actor, request BatchCreateRequest, creates []*CreateRequest,
	parseErrors []error, digest [32]byte) (BatchCreateResult, error) {
	const operation = "stream.batch_create"
	var result BatchCreateResult
	failed := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTarget(ctx, tx, actor, request.TargetScopeID, request.OwnerUserID); err != nil {
			return err
		}
		if err := authorizeAutomaticMutation(ctx, tx, actor, request.TargetScopeID); err != nil {
			return err
		}
		write, err := s.claimWrite(ctx, tx, actor.UserID, request.TargetScopeID, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result); err != nil {
				return fmt.Errorf("decode stored stream batch create response: %w", err)
			}
			for index := range result.Items {
				if result.Items[index].Stream != nil {
					markPublicationUnknown(&result.Items[index].Stream.PublishIntent)
				}
			}
			result.Replayed = true
			return nil
		}
		result = BatchCreateResult{Items: make([]BatchCreateLineResult, len(request.Lines))}
		for index, line := range request.Lines {
			item := &result.Items[index]
			item.Line, item.Text = index+1, line
			if failed && !request.IgnoreErrors {
				item.Status = BatchLineSkipped
				continue
			}
			lineErr := parseErrors[index]
			if lineErr == nil {
				lineErr = s.batchCreateLine(ctx, tx, actor, *creates[index], item)
			}
			if lineErr != nil {
				if !isLineError(lineErr) {
					return lineErr
				}
				failed = true
				item.Status, item.Stream = BatchLineFailed, nil
				item.Error = &BatchLineError{Code: batchErrorCode(lineErr)}
				result.Failed++
				continue
			}
			result.Created++
		}
		if failed && !request.IgnoreErrors {
			for index := range result.Items {
				if result.Items[index].Status == BatchLineCreated {
					result.Items[index].Status, result.Items[index].Stream = BatchLineSkipped, nil
				}
			}
			result.Created = 0
			return errBatchRollback
		}
		result.Committed = true
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: request.TargetScopeID, ActorUserID: &actor.UserID, Action: operation,
			ResourceType: "stream", ResourceID: request.TargetScopeID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"lines": len(request.Lines), "created": result.Created, "failed": result.Failed,
				"ignore_errors": request.IgnoreErrors},
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, operation, request.IdempotencyKey, request.TargetScopeID, 200, result)
	})
	if errors.Is(err, errBatchRollback) {
		return result, ErrBatchFailed
	}
	if err != nil {
		return BatchCreateResult{}, fmt.Errorf("batch create streams: %w", err)
	}
	return result, nil
}

// ErrBatchFailed: a 批量添加 without 忽略错误 had a failed line; nothing was
// written (the API answers 422 with the per-line result).
var ErrBatchFailed = errors.New("layer-four forwarding batch had a failed line")

var errBatchRollback = errors.New("roll the batch back")

// batchCreateLine writes one line in a savepoint, so a failed line leaves
// the transaction usable for the next.
func (s *Store) batchCreateLine(ctx context.Context, tx pgx.Tx, actor Actor, create CreateRequest, item *BatchCreateLineResult) error {
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	id, err := uuid.NewV7()
	if err != nil {
		_ = savepoint.Rollback(ctx)
		return err
	}
	forward, err := s.insertForward(ctx, savepoint, actor, create, id)
	if err != nil {
		_ = savepoint.Rollback(ctx)
		return err
	}
	if err := savepoint.Commit(ctx); err != nil {
		return err
	}
	if err := refreshEligibility(ctx, tx, &forward, false); err != nil {
		return err
	}
	item.Status, item.Stream = BatchLineCreated, &forward
	return nil
}

// isLineError: errors of the line's own input (rejected, conflicting), not
// of the database or the actor.
func isLineError(err error) bool {
	var located *PortConflictError
	return errors.As(err, &located) || errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrPortConflict) ||
		errors.Is(err, ErrNameConflict) || errors.Is(err, ErrSharedPortProxyProtocol) || errors.Is(err, ErrGroupNotFound) ||
		errors.Is(err, packageaddon.ErrQuotaExceeded)
}

func batchErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrPortConflict):
		return "stream_port_conflict"
	case errors.Is(err, ErrNameConflict):
		return "stream_name_conflict"
	case errors.Is(err, ErrSharedPortProxyProtocol):
		return "stream_shared_port_proxy_protocol"
	case errors.Is(err, ErrGroupNotFound):
		return "stream_group_not_found"
	case errors.Is(err, packageaddon.ErrQuotaExceeded):
		return "package_resource_quota_exceeded"
	default:
		return "validation_error"
	}
}
