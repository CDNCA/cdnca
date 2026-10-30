package l4analytics

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

const maximumCursorBytes = 4096

type Service struct {
	source    Source
	now       func() time.Time
	cursorKey []byte
}

type cursorEnvelope struct {
	Version  uint8    `json:"version"`
	TenantID string   `json:"tenant_id"`
	Filter   [32]byte `json:"filter"`
	Snapshot Snapshot `json:"snapshot"`
	After    After    `json:"after"`
}

func NewService(source Source, config Config) (*Service, error) {
	if source == nil || len(config.CursorKey) < sha256.Size || len(config.CursorKey) > 128 {
		return nil, ErrInvalidConfig
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Service{source: source, now: config.Now, cursorKey: bytes.Clone(config.CursorKey)}, nil
}

func (service *Service) Read(ctx context.Context, actor Actor, query Query) (Response, error) {
	if service == nil || service.source == nil || service.now == nil || ctx == nil {
		return Response{}, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	scope, filter, err := normalize(actor, query, service.now().UTC())
	if err != nil {
		return Response{}, err
	}
	if query.Cursor != "" {
		cursor, err := service.decodeCursor(query.Cursor, scope, filter)
		if err != nil {
			return Response{}, err
		}
		filter.Snapshot, filter.After = cursor.Snapshot, &cursor.After
	}
	page, err := service.source.Read(ctx, scope, filter)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, ErrDependencyUnavailable
	}
	if !validPage(page, filter) {
		return Response{}, ErrInvalidResponse
	}
	response := Response{Version: Version, Meta: Meta{
		Range: query.Range, Timezone: filter.Timezone, From: filter.From, To: filter.To, Snapshot: page.Snapshot,
	}, Rows: append([]Row{}, page.Rows...)}
	for _, row := range page.Rows {
		if !addTotals(&response.Totals, row) {
			return Response{}, ErrInvalidResponse
		}
	}
	if page.HasMore {
		last := page.Rows[len(page.Rows)-1]
		response.NextCursor, err = service.encodeCursor(scope, filter, page.Snapshot, After{
			Bucket: last.Bucket, NodeID: last.NodeID, SiteID: last.SiteID, StreamID: last.StreamID, ListenerID: last.ListenerID,
		})
		if err != nil {
			return Response{}, err
		}
	}
	return response, nil
}

func normalize(actor Actor, query Query, now time.Time) (Scope, Filter, error) {
	scope, err := authorize(actor, query)
	if err != nil {
		return Scope{}, Filter{}, err
	}
	if now.IsZero() || query.Timezone == "" || query.Timezone == "Local" || len(query.Timezone) > 128 ||
		strings.TrimSpace(query.Timezone) != query.Timezone {
		return Scope{}, Filter{}, ErrInvalidRequest
	}
	if _, err := time.LoadLocation(query.Timezone); err != nil {
		return Scope{}, Filter{}, ErrInvalidRequest
	}
	if !optionalUUID(query.SiteID) || !optionalUUID(query.StreamID) || !optionalUUID(query.NodeID) ||
		(query.Protocol != "" && query.Protocol != "tcp" && query.Protocol != "udp") ||
		query.ListenPort > 65535 ||
		query.Limit == 0 || query.Limit > 100 || len(query.Cursor) > maximumCursorBytes {
		return Scope{}, Filter{}, ErrInvalidRequest
	}
	from, to, err := queryWindow(query, now)
	if err != nil {
		return Scope{}, Filter{}, err
	}
	return scope, Filter{From: from, To: to, Timezone: query.Timezone, SiteID: query.SiteID,
		StreamID: query.StreamID, NodeID: query.NodeID, Protocol: query.Protocol, ListenPort: query.ListenPort, Limit: query.Limit}, nil
}

func authorize(actor Actor, query Query) (Scope, error) {
	switch actor.ScopeKind {
	case "tenant":
		if !requiredUUID(actor.TenantID) || query.Audience != AudienceTenant ||
			(query.TenantID != "" && query.TenantID != actor.TenantID) || !hasPermission(actor.Permissions, ReadPermission) {
			return Scope{}, ErrPermissionDenied
		}
		return Scope{TenantID: actor.TenantID}, nil
	case "platform":
		if actor.TenantID != "" || query.Audience != AudiencePlatform || !optionalUUID(query.TenantID) ||
			!hasPermission(actor.Permissions, "platform.admin") {
			return Scope{}, ErrPermissionDenied
		}
		return Scope{TenantID: query.TenantID}, nil
	default:
		return Scope{}, ErrPermissionDenied
	}
}

func queryWindow(query Query, now time.Time) (time.Time, time.Time, error) {
	fixed := map[string]time.Duration{"1h": time.Hour, "6h": 6 * time.Hour, "12h": 12 * time.Hour, "24h": 24 * time.Hour}
	if duration, ok := fixed[query.Range]; ok {
		if !query.From.IsZero() || !query.To.IsZero() {
			return time.Time{}, time.Time{}, ErrInvalidRequest
		}
		return now.Add(-duration), now, nil
	}
	if query.Range != "custom" || query.From.IsZero() || query.To.IsZero() || !query.From.Before(query.To) ||
		query.To.Sub(query.From) > 31*24*time.Hour || query.From.Location() != time.UTC || query.To.Location() != time.UTC {
		return time.Time{}, time.Time{}, ErrInvalidRequest
	}
	return query.From, query.To, nil
}

func validPage(page Page, filter Filter) bool {
	if page.Snapshot.At.IsZero() || page.Snapshot.FinalizedThrough.IsZero() ||
		(page.Snapshot.SourceWatermark == 0 && (len(page.Rows) != 0 || page.HasMore)) ||
		page.Snapshot.FinalizedThrough.After(page.Snapshot.At) || page.Snapshot.FinalizedThrough.After(filter.To) ||
		(filter.Snapshot.SourceWatermark != 0 && page.Snapshot != filter.Snapshot) || page.HasMore && len(page.Rows) == 0 ||
		len(page.Rows) > int(filter.Limit) {
		return false
	}
	for _, row := range page.Rows {
		if row.Bucket.IsZero() || !requiredUUID(row.NodeID) || !requiredUUID(row.SiteID) || !requiredUUID(row.StreamID) ||
			!requiredUUID(row.ListenerID) || (row.Protocol != "tcp" && row.Protocol != "udp") || row.ListenPort == 0 ||
			row.Sessions == 0 || row.Errors > row.Sessions {
			return false
		}
	}
	return true
}

func addTotals(totals *Totals, row Row) bool {
	if totals.Sessions > math.MaxUint64-row.Sessions || totals.BytesUp > math.MaxUint64-row.BytesUp ||
		totals.BytesDown > math.MaxUint64-row.BytesDown || totals.Errors > math.MaxUint64-row.Errors {
		return false
	}
	totals.Sessions += row.Sessions
	totals.BytesUp += row.BytesUp
	totals.BytesDown += row.BytesDown
	totals.Errors += row.Errors
	return true
}

func (service *Service) encodeCursor(scope Scope, filter Filter, snapshot Snapshot, after After) (string, error) {
	cursor := cursorEnvelope{Version: 1, TenantID: scope.TenantID, Filter: filterDigest(filter), Snapshot: snapshot, After: after}
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", ErrInvalidCursor
	}
	mac := hmac.New(sha256.New, service.cursorKey)
	_, _ = mac.Write(payload)
	payload = append(payload, mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func (service *Service) decodeCursor(raw string, scope Scope, filter Filter) (cursorEnvelope, error) {
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(payload) <= sha256.Size || len(payload) > maximumCursorBytes {
		return cursorEnvelope{}, ErrInvalidCursor
	}
	body, signature := payload[:len(payload)-sha256.Size], payload[len(payload)-sha256.Size:]
	mac := hmac.New(sha256.New, service.cursorKey)
	_, _ = mac.Write(body)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return cursorEnvelope{}, ErrInvalidCursor
	}
	var cursor cursorEnvelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cursor) != nil || cursor.Version != 1 || cursor.TenantID != scope.TenantID ||
		cursor.Filter != filterDigest(filter) || cursor.Snapshot.SourceWatermark == 0 {
		return cursorEnvelope{}, ErrInvalidCursor
	}
	return cursor, nil
}

func filterDigest(filter Filter) [32]byte {
	filter.Snapshot, filter.After = Snapshot{}, nil
	payload, _ := json.Marshal(filter)
	return sha256.Sum256(payload)
}

func requiredUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func optionalUUID(value string) bool { return value == "" || requiredUUID(value) }

func hasPermission(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
