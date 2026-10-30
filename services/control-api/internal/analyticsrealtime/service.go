package analyticsrealtime

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maximumPoints      = 240
	maximumRankLimit   = 100
	maximumCursorBytes = 4096
	maximumCustomRange = 31 * 24 * time.Hour
)

type Service struct {
	source    Source
	now       func() time.Time
	cursorKey []byte
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
	return service.Query(ctx, actor, query)
}

func (service *Service) Query(ctx context.Context, actor Actor, query Query) (Response, error) {
	if service == nil || service.source == nil || service.now == nil || ctx == nil {
		return Response{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	now := service.now().UTC().Truncate(time.Millisecond)
	if now.IsZero() {
		return Response{}, ErrUnavailable
	}
	scope, filter, downsample, err := normalizeQuery(actor, query, now)
	if err != nil {
		return Response{}, err
	}

	var cursorSnapshot *Snapshot
	if query.Cursor != "" {
		cursor, decodeErr := service.decodeCursor(query.Cursor, query, scope, filter)
		if decodeErr != nil {
			return Response{}, decodeErr
		}
		filter.After = &cursor.After
		cursorSnapshot = &cursor.Snapshot
	}

	snapshot, err := service.source.ResolveSnapshot(ctx, scope, filter)
	if contextErr := operationContextError(ctx, err); contextErr != nil {
		return Response{}, contextErr
	}
	if err != nil {
		return Response{}, ErrUnavailable
	}
	if !validSnapshot(snapshot, filter.To, now) {
		return Response{}, ErrInvalidSnapshot
	}
	if cursorSnapshot != nil && !sameSnapshot(*cursorSnapshot, snapshot) {
		return Response{}, ErrInvalidSnapshot
	}
	filter.Snapshot = snapshot

	response := Response{Version: Version, Meta: Meta{
		Range: query.Range, Timezone: filter.Timezone, From: filter.From, To: filter.To,
		Bucket: filter.Bucket, Downsample: downsample, Snapshot: snapshot,
	}}
	if response.Basic, err = service.loadBasic(ctx, scope, filter); err != nil {
		return Response{}, err
	}
	if response.Quality, err = service.loadQuality(ctx, scope, filter); err != nil {
		return Response{}, err
	}
	if response.Origin, err = service.loadOrigin(ctx, scope, filter); err != nil {
		return Response{}, err
	}
	if response.Rank, err = service.loadRank(ctx, query, scope, filter); err != nil {
		return Response{}, err
	}
	return response, nil
}

func normalizeQuery(actor Actor, query Query, now time.Time) (Scope, Filter, bool, error) {
	scope, err := authorize(actor, query)
	if err != nil {
		return Scope{}, Filter{}, false, err
	}
	if query.Timezone == "" || len(query.Timezone) > 128 || strings.TrimSpace(query.Timezone) != query.Timezone || query.Timezone == "Local" {
		return Scope{}, Filter{}, false, ErrInvalidRequest
	}
	if _, err := time.LoadLocation(query.Timezone); err != nil {
		return Scope{}, Filter{}, false, ErrInvalidRequest
	}
	if !validOptionalUUID(query.SiteID) || !validOptionalUUID(query.NodeID) || !validDomain(query.Domain) ||
		!validRankDimension(query.RankBy) || query.Limit == 0 || query.Limit > maximumRankLimit ||
		len(query.Cursor) > maximumCursorBytes {
		return Scope{}, Filter{}, false, ErrInvalidRequest
	}

	from, to, bucket, downsample, err := queryWindow(query, now)
	if err != nil {
		return Scope{}, Filter{}, false, err
	}
	return scope, Filter{
		From: from, To: to, Timezone: query.Timezone, SiteID: query.SiteID, NodeID: query.NodeID,
		Domain: query.Domain, ListenPort: query.ListenPort, Bucket: bucket, RankBy: query.RankBy, Limit: query.Limit,
	}, downsample, nil
}

func authorize(actor Actor, query Query) (Scope, error) {
	switch actor.ScopeKind {
	case "tenant":
		if !validRequiredUUID(actor.TenantID) {
			return Scope{}, ErrScopeForbidden
		}
		if !hasPermission(actor.Permissions, ReadPermission) {
			return Scope{}, ErrPermissionDenied
		}
		if query.Audience != AudienceTenant || query.TenantID != "" && query.TenantID != actor.TenantID {
			return Scope{}, ErrScopeForbidden
		}
		return Scope{TenantID: actor.TenantID}, nil
	case "platform":
		if actor.TenantID != "" {
			return Scope{}, ErrScopeForbidden
		}
		if !hasPermission(actor.Permissions, "platform.admin") {
			return Scope{}, ErrPermissionDenied
		}
		if query.Audience != AudiencePlatform || !validRequiredUUID(query.TenantID) {
			return Scope{}, ErrScopeForbidden
		}
		return Scope{TenantID: query.TenantID}, nil
	default:
		return Scope{}, ErrScopeForbidden
	}
}

func queryWindow(query Query, now time.Time) (time.Time, time.Time, time.Duration, bool, error) {
	fixed := map[string]struct {
		duration time.Duration
		bucket   time.Duration
	}{
		"1h":  {duration: time.Hour, bucket: time.Minute},
		"6h":  {duration: 6 * time.Hour, bucket: 5 * time.Minute},
		"12h": {duration: 12 * time.Hour, bucket: 10 * time.Minute},
	}
	if window, ok := fixed[query.Range]; ok {
		from, to := query.From, query.To
		if from.IsZero() && to.IsZero() {
			to, from = now, now.Add(-window.duration)
		} else if from.IsZero() || to.IsZero() || to.Sub(from) != window.duration {
			return time.Time{}, time.Time{}, 0, false, ErrInvalidRequest
		}
		if !validQueryTime(from) || !validQueryTime(to) || !from.Before(to) {
			return time.Time{}, time.Time{}, 0, false, ErrInvalidRequest
		}
		return from.UTC(), to.UTC(), window.bucket, false, nil
	}
	if query.Range != "custom" || !validQueryTime(query.From) || !validQueryTime(query.To) ||
		!query.From.Before(query.To) || query.To.Sub(query.From) > maximumCustomRange {
		return time.Time{}, time.Time{}, 0, false, ErrInvalidRequest
	}
	duration := query.To.Sub(query.From)
	for _, bucket := range []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour} {
		if bucketCount(duration, bucket) <= maximumPoints {
			return query.From.UTC(), query.To.UTC(), bucket, bucket > time.Minute, nil
		}
	}
	// The one-hour production aggregate is the coarsest existing source. For
	// longer valid windows, use an integral number of those buckets.
	bucket := time.Duration(bucketCount(duration, maximumPoints*time.Hour)) * time.Hour
	if bucket < time.Hour {
		bucket = time.Hour
	}
	return query.From.UTC(), query.To.UTC(), bucket, true, nil
}

func bucketCount(duration, bucket time.Duration) int {
	return int((duration + bucket - 1) / bucket)
}

func validQueryTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Equal(value.Truncate(time.Millisecond))
}

func validSnapshot(snapshot Snapshot, through, now time.Time) bool {
	for _, value := range []time.Time{snapshot.At, snapshot.FinalizedThrough, snapshot.ExpiresAt} {
		if !validQueryTime(value) {
			return false
		}
	}
	return snapshot.SourceWatermark > 0 && !snapshot.FinalizedThrough.Before(through) &&
		!snapshot.FinalizedThrough.After(snapshot.At) && !snapshot.At.After(now) && snapshot.ExpiresAt.After(now)
}

func sameSnapshot(left, right Snapshot) bool {
	return left.SourceWatermark == right.SourceWatermark && left.At.Equal(right.At) &&
		left.FinalizedThrough.Equal(right.FinalizedThrough) && left.ExpiresAt.Equal(right.ExpiresAt)
}

func (service *Service) loadBasic(ctx context.Context, scope Scope, filter Filter) (Section[Basic], error) {
	value, err := service.source.LoadBasic(ctx, scope, filter)
	if section, handled, fatal := failedSection[Basic](ctx, err); handled {
		return section, fatal
	}
	if !validBasic(value, filter) {
		return Section[Basic]{}, ErrInvalidResponse
	}
	return available(value), nil
}

func (service *Service) loadQuality(ctx context.Context, scope Scope, filter Filter) (Section[Quality], error) {
	value, err := service.source.LoadQuality(ctx, scope, filter)
	if section, handled, fatal := failedSection[Quality](ctx, err); handled {
		return section, fatal
	}
	if !validQuality(value, filter) {
		return Section[Quality]{}, ErrInvalidResponse
	}
	return available(value), nil
}

func (service *Service) loadOrigin(ctx context.Context, scope Scope, filter Filter) (Section[Origin], error) {
	value, err := service.source.LoadOrigin(ctx, scope, filter)
	if section, handled, fatal := failedSection[Origin](ctx, err); handled {
		return section, fatal
	}
	if !validOrigin(value, filter) {
		return Section[Origin]{}, ErrInvalidResponse
	}
	return available(value), nil
}

func (service *Service) loadRank(ctx context.Context, query Query, scope Scope, filter Filter) (Section[Rank], error) {
	value, err := service.source.LoadRank(ctx, scope, filter)
	if section, handled, fatal := failedSection[Rank](ctx, err); handled {
		return section, fatal
	}
	if !validRank(value, filter) {
		return Section[Rank]{}, ErrInvalidResponse
	}
	rank := Rank{FactCount: value.FactCount, Dimension: string(filter.RankBy), Items: value.Items}
	if value.HasMore {
		last := value.Items[len(value.Items)-1]
		rank.NextCursor, err = service.encodeCursor(query, scope, filter, RankAfter{
			TrafficBytes: last.TrafficBytes, Requests: last.Requests, Key: last.Key,
		})
		if err != nil {
			return Section[Rank]{}, err
		}
	}
	return available(rank), nil
}

func failedSection[T any](ctx context.Context, err error) (Section[T], bool, error) {
	if err == nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Section[T]{}, true, ctxErr
		}
		return Section[T]{}, false, nil
	}
	if ctxErr := operationContextError(ctx, err); ctxErr != nil {
		return Section[T]{}, true, ctxErr
	}
	switch {
	case errors.Is(err, ErrDependencyUnavailable):
		return unavailable[T](ReasonDependencyUnavailable), true, nil
	case errors.Is(err, ErrFactsMissing):
		return unavailable[T](ReasonAuthoritativeMissing), true, nil
	default:
		return Section[T]{}, true, ErrUnavailable
	}
}

func operationContextError(ctx context.Context, err error) error {
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

func available[T any](value T) Section[T] {
	return Section[T]{Available: true, Value: &value}
}

func unavailable[T any](reason string) Section[T] {
	return Section[T]{Reason: reason}
}

func validBasic(value Basic, filter Filter) bool {
	if value.FactCount == 0 || value.Requests != value.FactCount || len(value.Series) == 0 ||
		len(value.Series) > maximumPoints || !finiteNonnegative(value.BandwidthBPS) {
		return false
	}
	var requests, traffic uint64
	for _, point := range value.Series {
		if !validPointBucket(point.Bucket, filter) || !finiteNonnegative(point.BandwidthBPS) ||
			requests > math.MaxUint64-point.Requests || traffic > math.MaxUint64-point.TrafficBytes {
			return false
		}
		requests += point.Requests
		traffic += point.TrafficBytes
	}
	return requests == value.Requests && traffic == value.TrafficBytes
}

func validQuality(value Quality, filter Filter) bool {
	if value.FactCount == 0 || len(value.Series) == 0 || len(value.Series) > maximumPoints || !finiteNonnegative(value.AverageDurationUS) ||
		value.Status2xx > math.MaxUint64-value.Status3xx ||
		value.Status2xx+value.Status3xx > math.MaxUint64-value.Status4xx ||
		value.Status2xx+value.Status3xx+value.Status4xx > math.MaxUint64-value.Status5xx {
		return false
	}
	var status2xx, status3xx, status4xx, status5xx uint64
	for _, point := range value.Series {
		if !validPointBucket(point.Bucket, filter) {
			return false
		}
		if status2xx > math.MaxUint64-point.Status2xx || status3xx > math.MaxUint64-point.Status3xx ||
			status4xx > math.MaxUint64-point.Status4xx || status5xx > math.MaxUint64-point.Status5xx {
			return false
		}
		status2xx += point.Status2xx
		status3xx += point.Status3xx
		status4xx += point.Status4xx
		status5xx += point.Status5xx
	}
	return status2xx == value.Status2xx && status3xx == value.Status3xx && status4xx == value.Status4xx &&
		status5xx == value.Status5xx && value.CacheHits <= value.FactCount && value.CacheMisses <= value.FactCount-value.CacheHits &&
		value.Errors <= value.FactCount
}

func validOrigin(value Origin, filter Filter) bool {
	if value.FactCount == 0 || len(value.Series) == 0 || len(value.Series) > maximumPoints ||
		!validDurations(value.ConnectUS, value.FirstByteUS, value.TotalUS) {
		return false
	}
	for _, point := range value.Series {
		if !validPointBucket(point.Bucket, filter) || !validDurations(point.ConnectUS, point.FirstByteUS, point.TotalUS) {
			return false
		}
	}
	return true
}

func validRank(value RankResult, filter Filter) bool {
	if value.FactCount == 0 || len(value.Items) > int(filter.Limit) || value.HasMore && len(value.Items) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(value.Items))
	for index, item := range value.Items {
		if item.Key == "" || strings.TrimSpace(item.Key) != item.Key || item.Requests == 0 {
			return false
		}
		if _, exists := seen[item.Key]; exists {
			return false
		}
		seen[item.Key] = struct{}{}
		if index > 0 {
			prior := value.Items[index-1]
			if prior.TrafficBytes < item.TrafficBytes ||
				prior.TrafficBytes == item.TrafficBytes && (prior.Requests < item.Requests ||
					prior.Requests == item.Requests && prior.Key >= item.Key) {
				return false
			}
		}
	}
	return true
}

func validPointBucket(bucket time.Time, filter Filter) bool {
	return validQueryTime(bucket) && !bucket.Before(filter.From) && bucket.Before(filter.To) &&
		bucket.Sub(filter.From)%filter.Bucket == 0
}

func validDurations(connect, firstByte, total float64) bool {
	return finiteNonnegative(connect) && finiteNonnegative(firstByte) && finiteNonnegative(total) &&
		connect <= firstByte && firstByte <= total
}

func finiteNonnegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

func validRequiredUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validOptionalUUID(value string) bool {
	return value == "" || validRequiredUUID(value)
}

func validDomain(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 253 || strings.ToLower(value) != value || strings.TrimSpace(value) != value ||
		strings.HasSuffix(value, ".") || net.ParseIP(value) != nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validRankDimension(value RankDimension) bool {
	switch value {
	case RankByHost, RankBySite, RankByNode, RankByStatusCode:
		return true
	default:
		return false
	}
}

func hasPermission(permissions []string, wanted string) bool {
	for _, permission := range permissions {
		if permission == wanted {
			return true
		}
	}
	return false
}

type cursorPayload struct {
	Version    uint8         `json:"v"`
	Audience   Audience      `json:"audience"`
	TenantID   string        `json:"tenant_id,omitempty"`
	Range      string        `json:"range"`
	FromMS     int64         `json:"from_ms"`
	ToMS       int64         `json:"to_ms"`
	Timezone   string        `json:"timezone"`
	SiteID     string        `json:"site_id,omitempty"`
	NodeID     string        `json:"node_id,omitempty"`
	Domain     string        `json:"domain,omitempty"`
	ListenPort uint16        `json:"listen_port,omitempty"`
	BucketNS   int64         `json:"bucket_ns"`
	RankBy     RankDimension `json:"rank_by"`
	Limit      uint16        `json:"limit"`
	Snapshot   Snapshot      `json:"snapshot"`
	After      RankAfter     `json:"after"`
}

func (service *Service) encodeCursor(query Query, scope Scope, filter Filter, after RankAfter) (string, error) {
	payload, err := json.Marshal(cursorFor(query, scope, filter, after))
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

func (service *Service) decodeCursor(raw string, query Query, scope Scope, filter Filter) (cursorPayload, error) {
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
	want := cursorFor(query, scope, filter, result.After)
	if err != nil || !bytes.Equal(canonical, payload) || result.Version != 1 ||
		!sameCursorFilter(result, want) || result.After.Key == "" || strings.TrimSpace(result.After.Key) != result.After.Key ||
		result.After.Requests == 0 || !validSnapshot(result.Snapshot, filter.To, service.now().UTC().Truncate(time.Millisecond)) {
		return cursorPayload{}, ErrInvalidCursor
	}
	return result, nil
}

func cursorFor(query Query, scope Scope, filter Filter, after RankAfter) cursorPayload {
	return cursorPayload{
		Version: 1, Audience: query.Audience, TenantID: scope.TenantID, Range: query.Range,
		FromMS: filter.From.UnixMilli(), ToMS: filter.To.UnixMilli(), Timezone: filter.Timezone,
		SiteID: filter.SiteID, NodeID: filter.NodeID, Domain: filter.Domain, ListenPort: filter.ListenPort,
		BucketNS: int64(filter.Bucket), RankBy: filter.RankBy, Limit: filter.Limit,
		Snapshot: filter.Snapshot, After: after,
	}
}

func sameCursorFilter(left, right cursorPayload) bool {
	return left.Audience == right.Audience && left.TenantID == right.TenantID && left.Range == right.Range &&
		left.FromMS == right.FromMS && left.ToMS == right.ToMS && left.Timezone == right.Timezone &&
		left.SiteID == right.SiteID && left.NodeID == right.NodeID && left.Domain == right.Domain &&
		left.ListenPort == right.ListenPort && left.BucketNS == right.BucketNS && left.RankBy == right.RankBy &&
		left.Limit == right.Limit
}

var _ Reader = (*Service)(nil)
