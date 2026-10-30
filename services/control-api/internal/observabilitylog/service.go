package observabilitylog

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
)

const (
	maxPageSize   = 300
	maxExportRows = 10_000
	maxExportSize = 8 << 20
)

var codePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)
var releasePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
var actorDisplayIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
var countryCodePattern = regexp.MustCompile(`^[A-Z]{2}$`)

type Service struct {
	repository Repository
	cursorKey  []byte
	now        func() time.Time
	ipIntel    analyticslog.IPIntelLookup
}

// SetIPIntelLookup makes List answer each row's region from the control
// plane's IP intelligence base library by source IP when the page is served
// (B6), so historic login rows and operation rows (whose audit payload never
// carried geo) show 国家-省-市. Nil, an unloaded library or an address not in
// it leaves the stored geo fields (unknown for operations) untouched.
func (service *Service) SetIPIntelLookup(lookup analyticslog.IPIntelLookup) {
	service.ipIntel = lookup
}

type cursorEnvelope struct {
	ScopeID              uuid.UUID `json:"scope_id"`
	UserID               uuid.UUID `json:"user_id"`
	SessionID            uuid.UUID `json:"session_id"`
	Fingerprint          string    `json:"fingerprint"`
	SnapshotAt           time.Time `json:"snapshot_at"`
	BeforeTime           time.Time `json:"before_time"`
	BeforeID             string    `json:"before_id"`
	AuditThroughPosition int64     `json:"audit_through_position,omitempty"`
	// RangeFrom/RangeTo 是首次查询解析出的有效时间范围（含默认最近 24 小时），
	// 后续页从验签后的游标恢复，避免每页按当前时间重算导致指纹漂移或下界滑动（A18）。
	RangeFrom time.Time `json:"range_from"`
	RangeTo   time.Time `json:"range_to"`
}

type auditBoundaryEnvelope struct {
	ScopeID   uuid.UUID `json:"scope_id"`
	UserID    uuid.UUID `json:"user_id"`
	SessionID uuid.UUID `json:"session_id"`
	AuditHead int64     `json:"audit_head"`
}

func NewService(repository Repository, cursorKey []byte, now func() time.Time) (*Service, error) {
	if repository == nil || len(cursorKey) < 32 || now == nil {
		return nil, ErrInvalidConfig
	}
	return &Service{repository: repository, cursorKey: append([]byte(nil), cursorKey...), now: now}, nil
}

func (service *Service) CaptureAuditBoundary(ctx context.Context, actor Actor, targetScopeID uuid.UUID) (AuditBoundary, error) {
	target, platform, err := authorize(actor, &targetScopeID)
	if err != nil {
		return AuditBoundary{}, err
	}
	if !platform || target != targetScopeID {
		return AuditBoundary{}, ErrPermissionDenied
	}
	head, err := service.repository.AuditHead(ctx, target)
	if err != nil || head < 0 {
		return AuditBoundary{}, ErrUnavailable
	}
	token, err := service.encodeAuditBoundary(auditBoundaryEnvelope{ScopeID: target, UserID: actor.UserID,
		SessionID: actor.SessionID, AuditHead: head})
	if err != nil {
		return AuditBoundary{}, ErrUnavailable
	}
	return AuditBoundary{Token: token, SnapshotAt: service.now().UTC()}, nil
}

func (service *Service) List(ctx context.Context, actor Actor, input Query) (Page, error) {
	if input.CaptureAuditBoundary {
		return Page{}, ErrInvalidInput
	}
	query, fingerprint, err := service.prepare(actor, input)
	if err != nil {
		return Page{}, err
	}
	if input.AfterAuditBoundary != "" {
		boundary, err := service.decodeAuditBoundary(input.AfterAuditBoundary)
		if err != nil || boundary.ScopeID != query.ScopeID || boundary.UserID != actor.UserID || boundary.SessionID != actor.SessionID {
			return Page{}, ErrInvalidCursor
		}
		query.AuditBound = true
		query.AuditAfterPosition = boundary.AuditHead
	}
	if input.Cursor != "" {
		cursor, err := service.decodeCursor(input.Cursor)
		if err != nil || cursor.ScopeID != query.ScopeID || cursor.UserID != actor.UserID ||
			cursor.SessionID != actor.SessionID || cursor.Fingerprint != fingerprint {
			return Page{}, ErrInvalidCursor
		}
		query.From, query.To = cursor.RangeFrom, cursor.RangeTo
		query.SnapshotAt, query.BeforeTime, query.BeforeID = cursor.SnapshotAt, cursor.BeforeTime, cursor.BeforeID
		query.AuditThroughPosition = cursor.AuditThroughPosition
	} else if query.AuditBound {
		head, err := service.repository.AuditHead(ctx, query.ScopeID)
		if err != nil || head < query.AuditAfterPosition {
			return Page{}, ErrUnavailable
		}
		query.AuditThroughPosition = head
	}
	rows, err := service.repository.ListFacts(ctx, query)
	if err != nil {
		return Page{}, ErrUnavailable
	}
	pageSize := query.Limit - 1
	hasMore := len(rows) > pageSize
	if hasMore {
		rows = rows[:pageSize]
	}
	if err := validateRows(rows, query); err != nil {
		return Page{}, err
	}
	service.attachRegions(ctx, rows)
	service.attachResourceNames(ctx, query.ScopeID, rows)
	page := Page{Items: rows, SnapshotAt: query.SnapshotAt}
	if len(rows) > 0 {
		page.TotalCount = rows[0].TotalCount
	}
	if hasMore {
		last := rows[len(rows)-1]
		page.NextCursor, err = service.encodeCursor(cursorEnvelope{ScopeID: query.ScopeID, UserID: actor.UserID,
			SessionID: actor.SessionID, Fingerprint: fingerprint, SnapshotAt: query.SnapshotAt,
			BeforeTime: last.OccurredAt, BeforeID: last.ID, AuditThroughPosition: query.AuditThroughPosition,
				RangeFrom: query.From, RangeTo: query.To})
		if err != nil {
			return Page{}, ErrUnavailable
		}
	}
	return page, nil
}

func (service *Service) Export(ctx context.Context, actor Actor, input Query) (ExportArtifact, error) {
	now := service.now().UTC()
	if input.From.IsZero() {
		input.From = now.Add(-24 * time.Hour)
	}
	if input.To.IsZero() {
		input.To = now
	}
	input.Limit, input.Cursor = maxPageSize, ""
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	_ = writer.Write([]string{"event_id", "occurred_at", "kind", "action", "reason_code", "result_code", "resource_type", "resource_id", "request_id", "source_ip", "geo_code"})
	rows := 0
	for {
		page, err := service.List(ctx, actor, input)
		if err != nil {
			return ExportArtifact{}, err
		}
		for _, fact := range page.Items {
			if rows >= maxExportRows {
				return ExportArtifact{}, ErrInvalidInput
			}
			_ = writer.Write([]string{safeCSVCell(fact.ID), fact.OccurredAt.UTC().Format(time.RFC3339Nano), string(fact.Kind), fact.Action,
				fact.ReasonCode, fact.ResultCode, fact.ResourceType, safeCSVCell(fact.ResourceID), safeCSVCell(fact.RequestID), fact.SourceIP, fact.GeoCode})
			rows++
		}
		writer.Flush()
		if writer.Error() != nil || buffer.Len() > maxExportSize {
			return ExportArtifact{}, ErrInvalidInput
		}
		if page.NextCursor == "" {
			break
		}
		input.Cursor = page.NextCursor
	}
	digest := sha256.Sum256(buffer.Bytes())
	return ExportArtifact{Content: buffer.Bytes(), SHA256: hex.EncodeToString(digest[:])}, nil
}

// attachRegions replaces a row's geo with the IP library's answer for its
// source IP. Answers that would not pass validateRows are ignored.
func (service *Service) attachRegions(ctx context.Context, rows []Fact) {
	if service.ipIntel == nil || len(rows) == 0 {
		return
	}
	addresses := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.SourceIP != "unknown" {
			addresses = append(addresses, row.SourceIP)
		}
	}
	if len(addresses) == 0 {
		return
	}
	answers := service.ipIntel.Lookup(ctx, addresses)
	for index := range rows {
		info := answers[rows[index].SourceIP]
		if info == nil || !countryCodePattern.MatchString(info.Country) ||
			!validFactText(info.ProvinceName, 128, true) || !validFactText(info.CityName, 128, true) {
			continue
		}
		rows[index].GeoCode, rows[index].GeoRegion, rows[index].GeoCity = info.Country, info.ProvinceName, info.CityName
		rows[index].GeoResolution = "matched"
	}
}

// nameableResourceTypes are the audit resource types the operation log can
// show by name (ResourceNamer answers them); others show resource_id.
var nameableResourceTypes = map[string]bool{"site": true, "node": true, "stream": true, "certificate_asset": true,
	"certificate_order": true, "dns_provider": true, "ticket": true, "user": true}

// attachResourceNames sets each row's object name with one lookup for the
// whole page (tp-b6b). A nameable object with no answer is marked deleted.
// A lookup failure leaves the page as it was (rows show resource_id).
func (service *Service) attachResourceNames(ctx context.Context, scopeID uuid.UUID, rows []Fact) {
	namer, ok := service.repository.(ResourceNamer)
	if !ok {
		return
	}
	refs := make([]ResourceRef, 0, len(rows))
	seen := map[ResourceRef]bool{}
	for _, row := range rows {
		if ref, ok := nameableRef(row); ok && !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return
	}
	names, err := namer.ResourceNames(ctx, scopeID, refs)
	if err != nil {
		return
	}
	for index := range rows {
		ref, ok := nameableRef(rows[index])
		if !ok {
			continue
		}
		if name := names[ref]; name != "" && validFactText(name, 256, false) {
			rows[index].ResourceName = name
		} else if name == "" {
			rows[index].ResourceDeleted = true
		}
	}
}

// Nameable reports whether ResourceNames answers resourceType (the admin log
// center reuses the lookup, log-merge).
func Nameable(resourceType string) bool { return nameableResourceTypes[resourceType] }

func nameableRef(row Fact) (ResourceRef, bool) {
	if row.Kind == KindNotification || !nameableResourceTypes[row.ResourceType] {
		return ResourceRef{}, false
	}
	id, err := uuid.Parse(row.ResourceID)
	if err != nil || id == uuid.Nil {
		return ResourceRef{}, false
	}
	return ResourceRef{Type: row.ResourceType, ID: id}, true
}

func safeCSVCell(value string) string {
	if value == "" {
		return ""
	}
	switch value[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}

func (service *Service) RecordFrontend(ctx context.Context, actor Actor, input FrontendInput) error {
	if _, _, err := authorize(actor, nil); err != nil {
		return err
	}
	if !map[string]bool{"route_error": true, "api_error": true, "render_error": true}[input.EventCode] ||
		!strings.HasPrefix(input.Route, "/") || len(input.Route) > 256 || strings.ContainsAny(input.Route, "?#\r\n") ||
		!codePattern.MatchString(input.ReasonCode) || !map[string]bool{"success": true, "denied": true, "failure": true}[input.ResultCode] ||
		!releasePattern.MatchString(input.Release) || !validActor(actor) {
		return ErrInvalidInput
	}
	sourceIP := actor.SourceIP
	if net.ParseIP(sourceIP) == nil {
		sourceIP = "unknown"
	}
	if err := service.repository.AppendFrontend(ctx, FrontendFact{ScopeID: actor.ScopeID, ActorID: actor.UserID,
		RequestID: actor.RequestID, SourceIP: sourceIP, EventCode: input.EventCode, Route: input.Route,
		ReasonCode: input.ReasonCode, ResultCode: input.ResultCode, Release: input.Release}); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (service *Service) prepare(actor Actor, input Query) (StoreQuery, string, error) {
	target, platform, err := authorize(actor, input.TargetScopeID)
	if err != nil {
		return StoreQuery{}, "", err
	}
	limit := input.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > maxPageSize || len(input.Cursor) > 4096 || len(input.AfterAuditBoundary) > 4096 ||
		len(input.Action) > 96 || len(input.SourceIP) > 64 || len(input.ActorUserDisplayID) > 19 || len(input.ResourceID) > 256 || len(input.Change) > 256 {
		return StoreQuery{}, "", ErrInvalidInput
	}
	now := service.now().UTC()
	from, to := input.From, input.To
	if from.IsZero() {
		from = now.Add(-24 * time.Hour)
	}
	if to.IsZero() {
		to = now
	}
	from, to = from.UTC(), to.UTC()
	if from.After(to) || to.Sub(from) > 31*24*time.Hour || to.After(now.Add(time.Minute)) {
		return StoreQuery{}, "", ErrInvalidInput
	}
	kinds := input.Kinds
	if len(kinds) == 0 {
		kinds = []Kind{KindLogin, KindOperation, KindNotification, KindFrontend}
	}
	seen := map[Kind]bool{}
	for _, kind := range kinds {
		if seen[kind] || !validKind(kind) {
			return StoreQuery{}, "", ErrInvalidInput
		}
		seen[kind] = true
	}
	auditMode := input.AfterAuditBoundary != ""
	if auditMode {
		if !platform || input.AfterAuditBoundary == "" || input.AuditActorUserID == nil || *input.AuditActorUserID == uuid.Nil {
			return StoreQuery{}, "", ErrInvalidInput
		}
		for _, kind := range kinds {
			if kind == KindNotification {
				return StoreQuery{}, "", ErrInvalidInput
			}
		}
	} else if input.AuditActorUserID != nil && (!platform || *input.AuditActorUserID == uuid.Nil) {
		return StoreQuery{}, "", ErrPermissionDenied
	}
	if input.ActorUserDisplayID != "" && (!platform || !actorDisplayIDPattern.MatchString(input.ActorUserDisplayID) || input.AuditActorUserID != nil) {
		return StoreQuery{}, "", ErrInvalidInput
	}
	resultSeen := map[string]bool{}
	for _, result := range input.ResultCodes {
		if resultSeen[result] || !codePattern.MatchString(result) {
			return StoreQuery{}, "", ErrInvalidInput
		}
		resultSeen[result] = true
	}
	if input.Action != "" && !codePattern.MatchString(input.Action) {
		return StoreQuery{}, "", ErrInvalidInput
	}
	if input.ActionVerb != "" && !map[string]bool{"create": true, "update": true, "delete": true}[input.ActionVerb] {
		return StoreQuery{}, "", ErrInvalidInput
	}
	if input.Category != "" && !audit.ValidCategory(audit.Category(input.Category)) {
		return StoreQuery{}, "", ErrInvalidInput
	}
	if input.ResourceType != "" && !codePattern.MatchString(input.ResourceType) {
		return StoreQuery{}, "", ErrInvalidInput
	}
	if !validFactText(input.ResourceID, 256, true) || !validFactText(input.Change, 256, true) {
		return StoreQuery{}, "", ErrInvalidInput
	}
	if input.SourceIP != "" && input.SourceIP != "unknown" && net.ParseIP(input.SourceIP) == nil {
		return StoreQuery{}, "", ErrInvalidInput
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	results := append([]string{}, input.ResultCodes...)
	sort.Strings(results)
	var actorUserID *uuid.UUID
	if !platform {
		value := actor.UserID
		actorUserID = &value
	}
	fingerprintRaw, _ := json.Marshal([]any{target, actorUserID, input.AuditActorUserID, input.ActorUserDisplayID, input.AfterAuditBoundary,
		kinds, results, input.Action, input.ActionVerb, input.ResourceType, input.ResourceID, input.Change,
		input.SourceIP, input.From.UTC(), input.To.UTC(), platform, input.Category})
	fingerprint := sha256.Sum256(fingerprintRaw)
	return StoreQuery{ScopeID: target, ActorUserID: actorUserID, ExactActorUserID: input.AuditActorUserID, ActorUserDisplayID: input.ActorUserDisplayID,
		Kinds: kinds, ResultCodes: results, Action: input.Action, ActionVerb: input.ActionVerb, Category: input.Category,
		ResourceType: input.ResourceType, ResourceID: input.ResourceID, Change: input.Change, SourceIP: input.SourceIP,
		From: from, To: to, SnapshotAt: minTime(now, to), Limit: limit + 1}, hex.EncodeToString(fingerprint[:]), nil
}

func authorize(actor Actor, target *uuid.UUID) (uuid.UUID, bool, error) {
	if !validActor(actor) {
		return uuid.Nil, false, ErrPermissionDenied
	}
	if actor.ScopeKind == ScopeTenant {
		if target != nil || !hasPermission(actor.Permissions, "identity.self.read") {
			return uuid.Nil, false, ErrPermissionDenied
		}
		return actor.ScopeID, false, nil
	}
	if actor.ScopeKind != ScopePlatform || !hasPermission(actor.Permissions, "platform.admin") {
		return uuid.Nil, false, ErrPermissionDenied
	}
	if target != nil {
		if *target == uuid.Nil {
			return uuid.Nil, false, ErrInvalidInput
		}
		return *target, true, nil
	}
	return actor.ScopeID, true, nil
}

func validateRows(rows []Fact, query StoreQuery) error {
	if len(rows) > query.Limit {
		return ErrUnsafeFact
	}
	seen := map[string]bool{}
	var previous Fact
	for index, row := range rows {
		if !validFactText(row.ID, 128, false) || seen[row.ID] || row.ScopeID != query.ScopeID || !validKind(row.Kind) ||
			!codePattern.MatchString(row.Action) || !codePattern.MatchString(row.ReasonCode) || !codePattern.MatchString(row.ResultCode) ||
			(row.ResourceType != "" && !codePattern.MatchString(row.ResourceType)) ||
			!validFactText(row.UserAgent, 2048, true) || !validFactText(row.ChangeSummary, 2048, true) || row.TotalCount < 0 ||
			(row.SourceIP != "unknown" && net.ParseIP(row.SourceIP) == nil) ||
			(row.GeoCode != "unknown" && !countryCodePattern.MatchString(row.GeoCode)) ||
			(row.Category != "" && !audit.ValidCategory(audit.Category(row.Category))) ||
			(query.Category != "" && row.Category != query.Category) ||
			!validFactText(row.GeoRegion, 128, true) || !validFactText(row.GeoCity, 128, true) ||
			(row.GeoResolution != "" && row.GeoResolution != "matched" && row.GeoResolution != "unknown") ||
			row.OccurredAt.Before(query.From) || row.OccurredAt.After(query.To) || row.OccurredAt.After(query.SnapshotAt) ||
			!validFactText(row.ResourceID, 256, true) || !validFactText(row.RequestID, 128, true) {
			return ErrUnsafeFact
		}
		if row.ActorUserID != nil && *row.ActorUserID == uuid.Nil {
			return ErrUnsafeFact
		}
		if row.SubjectUserID != "" {
			subject, err := uuid.Parse(row.SubjectUserID)
			if err != nil || subject.String() != row.SubjectUserID {
				return ErrUnsafeFact
			}
		}
		if query.ActorUserID != nil {
			actorMatch := row.ActorUserID != nil && *row.ActorUserID == *query.ActorUserID
			subjectMatch := row.SubjectUserID == query.ActorUserID.String()
			if !actorMatch && !subjectMatch {
				return ErrUnsafeFact
			}
		}
		if query.ExactActorUserID != nil && (row.ActorUserID == nil || *row.ActorUserID != *query.ExactActorUserID) {
			return ErrUnsafeFact
		}
		if query.ActorUserDisplayID != "" && row.ActorUserDisplayID != query.ActorUserDisplayID {
			return ErrUnsafeFact
		}
		if index > 0 && (row.OccurredAt.After(previous.OccurredAt) || row.OccurredAt.Equal(previous.OccurredAt) && row.ID >= previous.ID) {
			return ErrUnsafeFact
		}
		seen[row.ID], previous = true, row
	}
	return nil
}

func validFactText(value string, maxBytes int, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	return len(value) <= maxBytes && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func (service *Service) encodeCursor(cursor cursorEnvelope) (string, error) {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, service.cursorKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (service *Service) decodeCursor(value string) (cursorEnvelope, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return cursorEnvelope{}, ErrInvalidCursor
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return cursorEnvelope{}, ErrInvalidCursor
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return cursorEnvelope{}, ErrInvalidCursor
	}
	mac := hmac.New(sha256.New, service.cursorKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return cursorEnvelope{}, ErrInvalidCursor
	}
	var cursor cursorEnvelope
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil || cursor.ScopeID == uuid.Nil || cursor.UserID == uuid.Nil || cursor.SessionID == uuid.Nil || cursor.Fingerprint == "" || cursor.SnapshotAt.IsZero() || cursor.BeforeTime.IsZero() || cursor.BeforeID == "" || cursor.AuditThroughPosition < 0 ||
		cursor.RangeFrom.IsZero() || cursor.RangeTo.IsZero() || cursor.RangeFrom.After(cursor.RangeTo) || cursor.SnapshotAt.After(cursor.RangeTo) {
		return cursorEnvelope{}, ErrInvalidCursor
	}
	return cursor, nil
}

func (service *Service) encodeAuditBoundary(boundary auditBoundaryEnvelope) (string, error) {
	payload, err := json.Marshal(boundary)
	if err != nil {
		return "", err
	}
	key := sha256.Sum256(append([]byte("observability-audit-boundary-v1\x00"), service.cursorKey...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, payload, []byte("cdnca-observability-audit-boundary-v1"))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (service *Service) decodeAuditBoundary(value string) (auditBoundaryEnvelope, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return auditBoundaryEnvelope{}, ErrInvalidCursor
	}
	key := sha256.Sum256(append([]byte("observability-audit-boundary-v1\x00"), service.cursorKey...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return auditBoundaryEnvelope{}, ErrInvalidCursor
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(sealed) < aead.NonceSize()+aead.Overhead() {
		return auditBoundaryEnvelope{}, ErrInvalidCursor
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	payload, err := aead.Open(nil, nonce, ciphertext, []byte("cdnca-observability-audit-boundary-v1"))
	if err != nil {
		return auditBoundaryEnvelope{}, ErrInvalidCursor
	}
	var boundary auditBoundaryEnvelope
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&boundary); err != nil || boundary.ScopeID == uuid.Nil || boundary.UserID == uuid.Nil ||
		boundary.SessionID == uuid.Nil || boundary.AuditHead < 0 {
		return auditBoundaryEnvelope{}, ErrInvalidCursor
	}
	return boundary, nil
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.SessionID != uuid.Nil
}
func validKind(kind Kind) bool {
	return kind == KindLogin || kind == KindOperation || kind == KindNotification || kind == KindFrontend
}
func hasPermission(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
