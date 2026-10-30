package qualitydiagnostics

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
	"github.com/google/uuid"
)

const (
	maximumCursorBytes       = 4096
	maximumSourceCursorBytes = 2048
	maximumRange             = 31 * 24 * time.Hour
)

type Service struct {
	reader    FinalizedLatestStateReader
	now       func() time.Time
	cursorKey []byte
}

func NewService(reader FinalizedLatestStateReader, config Config) (*Service, error) {
	if reader == nil || len(config.CursorKey) < sha256.Size || len(config.CursorKey) > 128 {
		return nil, ErrInvalidConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Service{reader: reader, now: config.Now, cursorKey: bytes.Clone(config.CursorKey)}, nil
}

func (service *Service) Read(ctx context.Context, actor Actor, query Query) (Response, error) {
	if service == nil || service.reader == nil || service.now == nil || ctx == nil {
		return Response{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	now := service.now().UTC().Truncate(time.Millisecond)
	if now.IsZero() {
		return Response{}, ErrUnavailable
	}
	scope, filter, err := normalize(actor, query, now)
	if err != nil {
		return Response{}, err
	}

	readRequest := ReadRequest{Scope: scope, Filter: filter, Limit: query.Limit}
	if query.Cursor != "" {
		cursor, decodeErr := service.decodeCursor(query.Cursor, query, scope, filter, now)
		if decodeErr != nil {
			return Response{}, decodeErr
		}
		readRequest.SourceCursor = cursor.SourceCursor
		readRequest.Snapshot = &cursor.Snapshot
	}

	page, err := service.reader.ReadFinalizedLatest(ctx, readRequest)
	if operationErr := operationError(ctx, err); operationErr != nil {
		return Response{}, operationErr
	}
	if err != nil {
		return Response{}, stableReaderError(err)
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	if !validSnapshot(page.Snapshot, filter.To, now) {
		return Response{}, ErrInvalidSnapshot
	}
	if readRequest.Snapshot != nil && !sameSnapshot(*readRequest.Snapshot, page.Snapshot) {
		return Response{}, ErrInvalidSnapshot
	}
	if len(page.Facts) > int(query.Limit) || !validSourceCursor(page.NextSourceCursor) ||
		page.NextSourceCursor != "" && len(page.Facts) == 0 {
		return Response{}, ErrInvalidResponse
	}

	response := Response{Items: make([]Item, 0, len(page.Facts)), Snapshot: page.Snapshot}
	if query.Audience == AudiencePlatform {
		tenantID := scope.TenantID.String()
		response.EffectiveTenantID = &tenantID
	}
	seen := make(map[string]struct{}, len(page.Facts))
	for index, fact := range page.Facts {
		if !validFact(fact, scope, filter) {
			return Response{}, ErrInvalidResponse
		}
		if _, duplicate := seen[fact.Log.EventID]; duplicate {
			return Response{}, ErrInvalidResponse
		}
		seen[fact.Log.EventID] = struct{}{}
		if index > 0 && !factsOrdered(page.Facts[index-1].Log, fact.Log) {
			return Response{}, ErrInvalidResponse
		}
		category, cause, action, diagnostic := classify(fact.Log)
		if !diagnostic || filter.Category != "" && category != filter.Category {
			return Response{}, ErrInvalidResponse
		}
		response.Items = append(response.Items, project(fact.Log, category, cause, action))
	}
	if page.NextSourceCursor != "" {
		next, encodeErr := service.encodeCursor(query, scope, filter, page.Snapshot, page.NextSourceCursor)
		if encodeErr != nil {
			return Response{}, encodeErr
		}
		response.NextCursor = &next
	}
	return response, nil
}

func normalize(actor Actor, query Query, now time.Time) (Scope, Filter, error) {
	scope, err := authorize(actor, query)
	if err != nil {
		return Scope{}, Filter{}, err
	}
	if !validTime(query.From) || !validTime(query.To) || !query.From.Before(query.To) || query.To.After(now) ||
		query.To.Sub(query.From) > maximumRange || query.Limit == 0 || query.Limit > MaxLimit ||
		len(query.Cursor) > maximumCursorBytes || !validOptionalUUID(query.SiteID) || !validOptionalUUID(query.NodeID) ||
		!validCategory(query.Category) {
		return Scope{}, Filter{}, ErrInvalidRequest
	}
	return scope, Filter{
		From: query.From, To: query.To, SiteID: query.SiteID, NodeID: query.NodeID, Category: query.Category,
	}, nil
}

func authorize(actor Actor, query Query) (Scope, error) {
	switch actor.ScopeKind {
	case "tenant":
		if actor.TenantID == uuid.Nil || !validUUID(actor.TenantID) || query.Audience != AudienceTenant || query.TenantID != uuid.Nil {
			return Scope{}, ErrScopeForbidden
		}
		if !slices.Contains(actor.Permissions, analyticslog.ReadPermission) {
			return Scope{}, ErrPermissionDenied
		}
		return Scope{TenantID: actor.TenantID}, nil
	case "platform":
		if actor.TenantID != uuid.Nil || query.Audience != AudiencePlatform || !validUUID(query.TenantID) {
			return Scope{}, ErrScopeForbidden
		}
		if !slices.Contains(actor.Permissions, "platform.admin") {
			return Scope{}, ErrPermissionDenied
		}
		return Scope{TenantID: query.TenantID}, nil
	default:
		return Scope{}, ErrScopeForbidden
	}
}

func validFact(fact ScopedAccessFact, scope Scope, filter Filter) bool {
	item := fact.Log
	if fact.TenantID != scope.TenantID || !validIdentity(item.EventID, 128) || !validTime(item.OccurredAt) ||
		item.OccurredAt.Before(filter.From) || !item.OccurredAt.Before(filter.To) ||
		!validUUIDString(item.SiteID) || !validUUIDString(item.NodeID) || !validUUIDString(item.ConfigVersion) ||
		!validUUIDString(item.InstallationID) || !validIdentity(item.RequestID, 128) || !validIdentity(item.TraceID, 128) ||
		item.StatusCode < 100 || item.StatusCode > 599 || len(item.Host) > 253 || strings.TrimSpace(item.Host) != item.Host ||
		!validOptionalText(item.UpstreamResult, 128) {
		return false
	}
	if item.TaskID != nil && !validUUIDString(*item.TaskID) {
		return false
	}
	if filter.SiteID != uuid.Nil && item.SiteID != filter.SiteID.String() ||
		filter.NodeID != uuid.Nil && item.NodeID != filter.NodeID.String() {
		return false
	}
	return true
}

func classify(item analyticslog.AccessLog) (Category, CauseCode, ActionCode, bool) {
	switch {
	case item.UpstreamResult == "config_mismatch":
		return CategoryConfigMismatch, CauseConfigMismatch, ActionReconcileConfig, true
	case item.Host == "":
		return CategoryNoHost, CauseHostMissing, ActionConfigureHost, true
	case item.UpstreamResult == "no_host":
		return CategoryNoHost, CauseUpstreamNoHost, ActionConfigureHost, true
	case item.StatusCode == 530:
		return CategoryEdge530, CauseStatus530, ActionInspectEdge, true
	case item.StatusCode >= 500 && item.StatusCode <= 599:
		switch item.UpstreamResult {
		case "":
			return CategoryUpstream5xx, CauseUpstreamEmpty, ActionInspectUpstream, true
		case "timeout", "connect_failed", "connection_reset", "connection_refused", "unavailable":
			return CategoryUpstream5xx, CauseUpstreamFailure, ActionInspectUpstream, true
		default:
			return CategoryUpstream5xx, CauseUpstreamUnknown, ActionInspectUpstream, true
		}
	default:
		return "", "", "", false
	}
}

func project(item analyticslog.AccessLog, category Category, cause CauseCode, action ActionCode) Item {
	var taskID *string
	if item.TaskID != nil {
		value := *item.TaskID
		taskID = &value
	}
	return Item{
		EventID: item.EventID, OccurredAt: item.OccurredAt, SiteID: item.SiteID, NodeID: item.NodeID,
		Category: category, CauseCode: cause, ActionCode: action, StatusCode: item.StatusCode,
		ConfigVersionID: item.ConfigVersion, InstallationID: item.InstallationID,
		RequestID: item.RequestID, TaskID: taskID, TraceID: item.TraceID,
	}
}

func factsOrdered(previous, current analyticslog.AccessLog) bool {
	return previous.OccurredAt.After(current.OccurredAt) ||
		previous.OccurredAt.Equal(current.OccurredAt) && previous.EventID > current.EventID
}

func stableReaderError(err error) error {
	for _, stable := range []error{ErrInvalidRequest, ErrInvalidCursor, ErrInvalidSnapshot, ErrInvalidResponse, ErrUnavailable} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	return ErrUnavailable
}

func operationError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

func validSnapshot(snapshot analyticsrealtime.Snapshot, through, now time.Time) bool {
	return validTime(snapshot.At) && validTime(snapshot.FinalizedThrough) && validTime(snapshot.ExpiresAt) &&
		snapshot.SourceWatermark > 0 && !snapshot.FinalizedThrough.Before(through) &&
		!snapshot.FinalizedThrough.After(snapshot.At) && !snapshot.At.After(now) &&
		snapshot.ExpiresAt.After(now) && snapshot.ExpiresAt.After(snapshot.At)
}

func sameSnapshot(left, right analyticsrealtime.Snapshot) bool {
	return left.SourceWatermark == right.SourceWatermark && left.At.Equal(right.At) &&
		left.FinalizedThrough.Equal(right.FinalizedThrough) && left.ExpiresAt.Equal(right.ExpiresAt)
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Equal(value.Truncate(time.Millisecond))
}

func validUUID(value uuid.UUID) bool { return value != uuid.Nil }

func validOptionalUUID(value uuid.UUID) bool { return value == uuid.Nil || validUUID(value) }

func validUUIDString(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validIdentity(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validOptionalText(value string, maximum int) bool {
	return value == "" || validIdentity(value, maximum)
}

func validCategory(value Category) bool {
	switch value {
	case "", CategoryUpstream5xx, CategoryEdge530, CategoryNoHost, CategoryConfigMismatch:
		return true
	default:
		return false
	}
}

func validSourceCursor(value string) bool {
	return value == "" || len(value) <= maximumSourceCursorBytes && validIdentity(value, maximumSourceCursorBytes)
}

type cursorPayload struct {
	Version      uint8                      `json:"v"`
	Audience     Audience                   `json:"audience"`
	TenantID     string                     `json:"tenant_id"`
	FromMS       int64                      `json:"from_ms"`
	ToMS         int64                      `json:"to_ms"`
	SiteID       string                     `json:"site_id,omitempty"`
	NodeID       string                     `json:"node_id,omitempty"`
	Category     Category                   `json:"category,omitempty"`
	Limit        uint16                     `json:"limit"`
	Snapshot     analyticsrealtime.Snapshot `json:"snapshot"`
	SourceCursor string                     `json:"source_cursor"`
}

func (service *Service) encodeCursor(
	query Query,
	scope Scope,
	filter Filter,
	snapshot analyticsrealtime.Snapshot,
	sourceCursor string,
) (string, error) {
	payload, err := json.Marshal(cursorFor(query, scope, filter, snapshot, sourceCursor))
	if err != nil {
		return "", ErrInvalidResponse
	}
	mac := hmac.New(sha256.New, service.cursorKey)
	_, _ = mac.Write(payload)
	encoded := base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
	if len(encoded) > maximumCursorBytes {
		return "", ErrInvalidResponse
	}
	return encoded, nil
}

func (service *Service) decodeCursor(raw string, query Query, scope Scope, filter Filter, now time.Time) (cursorPayload, error) {
	var result cursorPayload
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) <= sha256.Size {
		return result, ErrInvalidCursor
	}
	payload, signature := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	mac := hmac.New(sha256.New, service.cursorKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return result, ErrInvalidCursor
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return cursorPayload{}, ErrInvalidCursor
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return cursorPayload{}, ErrInvalidCursor
	}
	canonical, err := json.Marshal(result)
	want := cursorFor(query, scope, filter, result.Snapshot, result.SourceCursor)
	if err != nil || !bytes.Equal(canonical, payload) || result.Version != 1 ||
		!sameCursorFilter(result, want) || !validSourceCursor(result.SourceCursor) || result.SourceCursor == "" ||
		!validSnapshot(result.Snapshot, filter.To, now) {
		return cursorPayload{}, ErrInvalidCursor
	}
	return result, nil
}

func cursorFor(query Query, scope Scope, filter Filter, snapshot analyticsrealtime.Snapshot, sourceCursor string) cursorPayload {
	return cursorPayload{
		Version: 1, Audience: query.Audience, TenantID: scope.TenantID.String(), FromMS: filter.From.UnixMilli(),
		ToMS: filter.To.UnixMilli(), SiteID: optionalUUID(filter.SiteID), NodeID: optionalUUID(filter.NodeID),
		Category: filter.Category, Limit: query.Limit, Snapshot: snapshot, SourceCursor: sourceCursor,
	}
}

func sameCursorFilter(left, right cursorPayload) bool {
	return left.Audience == right.Audience && left.TenantID == right.TenantID && left.FromMS == right.FromMS &&
		left.ToMS == right.ToMS && left.SiteID == right.SiteID && left.NodeID == right.NodeID &&
		left.Category == right.Category && left.Limit == right.Limit
}

func optionalUUID(value uuid.UUID) string {
	if value == uuid.Nil {
		return ""
	}
	return value.String()
}

var _ Reader = (*Service)(nil)
