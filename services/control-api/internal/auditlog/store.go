// Package auditlog reads audit_events for the log center (unified-log):
// filters, keyset pagination, display names, and server-side plain-language
// rendering through the audit event catalog.
package auditlog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/observabilitylog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	DefaultLimit = 50
	MaxLimit     = 200
	// MaxExportRows bounds one CSV export.
	MaxExportRows = 10000
)

var ErrInvalidFilter = errors.New("invalid log filter")

// Filter selects log rows. ScopeIDs empty means every scope (platform view);
// the HTTP layer always sets it for tenants.
type Filter struct {
	ScopeIDs []uuid.UUID
	Category string
	// ExcludeCategory drops one category (the log center's 操作 tab is every
	// category except auth).
	ExcludeCategory string
	Since, Until    time.Time
	ActorUserID     *uuid.UUID
	ActorName       string // username, exact match
	SourceIP        string
	ResourceType    string
	ResourceID      string
	Result          string
	Action          string
	Cursor          string
	Limit           int
}

// Page is one page of rendered rows.
type Page struct {
	Items      []audit.Rendered `json:"items"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

// resourceNamer is observabilitylog.Store.ResourceNames (tp-b6b): names of
// refs that still exist in one scope; missing keys are deleted objects.
type resourceNamer interface {
	ResourceNames(ctx context.Context, scopeID uuid.UUID, refs []observabilitylog.ResourceRef) (map[observabilitylog.ResourceRef]string, error)
}

type Store struct {
	pool    *pgxpool.Pool
	names   resourceNamer
	ipIntel analyticslog.IPIntelLookup
}

func NewStore(pool *pgxpool.Pool) *Store {
	store := &Store{pool: pool}
	if names, err := observabilitylog.NewStore(pool); err == nil {
		store.names = names
	}
	return store
}

// SetIPIntelLookup answers each row's 国家-省-市 from the control IP library
// at query time, like the B6 log query (observabilitylog.SetIPIntelLookup).
func (store *Store) SetIPIntelLookup(lookup analyticslog.IPIntelLookup) {
	store.ipIntel = lookup
}

type cursor struct {
	OccurredAt time.Time `json:"t"`
	ID         uuid.UUID `json:"i"`
}

func encodeCursor(value cursor) string {
	raw, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeCursor(text string) (cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return cursor{}, err
	}
	var value cursor
	if err := json.Unmarshal(raw, &value); err != nil || value.ID == uuid.Nil || value.OccurredAt.IsZero() {
		return cursor{}, errors.New("malformed cursor")
	}
	return value, nil
}

// Validate normalises the filter and rejects bad values.
func (filter *Filter) Validate() error {
	if filter.Category != "" && !audit.ValidCategory(audit.Category(filter.Category)) ||
		filter.ExcludeCategory != "" && !audit.ValidCategory(audit.Category(filter.ExcludeCategory)) {
		return fmt.Errorf("%w: unknown category", ErrInvalidFilter)
	}
	switch filter.Result {
	case "", "success", "denied", "failure":
	default:
		return fmt.Errorf("%w: result must be success, denied or failure", ErrInvalidFilter)
	}
	if filter.SourceIP != "" {
		address, err := netip.ParseAddr(strings.TrimSpace(filter.SourceIP))
		if err != nil {
			return fmt.Errorf("%w: source_ip is not an IP address", ErrInvalidFilter)
		}
		filter.SourceIP = address.Unmap().String()
	}
	if !filter.Since.IsZero() && !filter.Until.IsZero() && filter.Until.Before(filter.Since) {
		return fmt.Errorf("%w: until is before since", ErrInvalidFilter)
	}
	for _, value := range []*string{&filter.ActorName, &filter.ResourceType, &filter.ResourceID, &filter.Action} {
		*value = strings.TrimSpace(*value)
		if len(*value) > 256 {
			return fmt.Errorf("%w: filter value too long", ErrInvalidFilter)
		}
	}
	filter.ActorName = strings.ToLower(filter.ActorName)
	if filter.Limit <= 0 {
		filter.Limit = DefaultLimit
	}
	if filter.Limit > MaxLimit {
		filter.Limit = MaxLimit
	}
	if filter.Cursor != "" {
		if _, err := decodeCursor(filter.Cursor); err != nil {
			return fmt.Errorf("%w: cursor", ErrInvalidFilter)
		}
	}
	return nil
}

// where builds the WHERE clause; args are appended in placeholder order.
func (filter Filter) where() (string, []any) {
	var clauses []string
	var args []any
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, strings.ReplaceAll(clause, "?", "$"+strconv.Itoa(len(args))))
	}
	if len(filter.ScopeIDs) > 0 {
		add("event.scope_id = ANY(?)", filter.ScopeIDs)
	}
	if filter.Category != "" {
		add("event.category = ?", filter.Category)
	}
	if filter.ExcludeCategory != "" {
		add("event.category <> ?", filter.ExcludeCategory)
	}
	if !filter.Since.IsZero() {
		add("event.occurred_at >= ?", filter.Since)
	}
	if !filter.Until.IsZero() {
		add("event.occurred_at < ?", filter.Until)
	}
	if filter.ActorUserID != nil {
		add("event.actor_user_id = ?", *filter.ActorUserID)
	}
	if filter.ActorName != "" {
		add("actor.username = ?", filter.ActorName)
	}
	if filter.SourceIP != "" {
		add("event.source_ip = ?", filter.SourceIP)
	}
	if filter.ResourceType != "" {
		add("event.resource_type = ?", filter.ResourceType)
	}
	if filter.ResourceID != "" {
		add("event.resource_id = ?", filter.ResourceID)
	}
	if filter.Result != "" {
		add("event.result = ?", filter.Result)
	}
	if filter.Action != "" {
		add("event.action = ?", filter.Action)
	}
	if filter.Cursor != "" {
		value, _ := decodeCursor(filter.Cursor)
		args = append(args, value.OccurredAt, value.ID)
		clauses = append(clauses, fmt.Sprintf("(event.occurred_at, event.id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// selectSQL resolves display names: the actor's username and whether they
// belong to a platform scope, and the row scope's tenant name. Object names
// come from the B6b lookup afterwards (attachNames, inside the row's scope);
// platform-scope rows also carry the platform-wide site / node / user name an
// administrator's action may point at, used when the scoped lookup misses.
// log-merge: login rows take IP / UA / geo like the B6 store
// (observabilitylog): the session first, then the payload, then the 361/491
// columns; other rows read the columns (geo is answered later from the IP
// library, the stored payload geo is the fallback).
const selectSQL = `SELECT event.id, event.scope_id, event.occurred_at, event.action, event.category,
	event.actor_kind, event.actor_user_id, event.actor_ref, COALESCE(actor.username, ''),
	EXISTS (SELECT 1 FROM memberships membership JOIN access_scopes scope ON scope.id = membership.scope_id
		WHERE membership.user_id = event.actor_user_id AND scope.kind = 'platform'),
	CASE WHEN event.action = 'auth.login' THEN COALESCE(host(session.source_ip), NULLIF(event.payload->>'source_ip', ''), event.source_ip)
		ELSE event.source_ip END,
	event.resource_type, event.resource_id,
	COALESCE(CASE WHEN row_scope.kind = 'platform' AND event.resource_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
		CASE event.resource_type
			WHEN 'site' THEN (SELECT site.domain FROM sites site WHERE site.id = event.resource_id::uuid)
			WHEN 'node' THEN (SELECT node.name FROM nodes node WHERE node.id = event.resource_id::uuid)
			WHEN 'user' THEN (SELECT target.username FROM users target WHERE target.id = event.resource_id::uuid)
		END END, ''),
	event.result, event.reason_code, event.request_id, event.payload::text, event.changes::text,
	COALESCE(tenant.display_name, ''),
	CASE WHEN event.action = 'auth.login' THEN COALESCE(
		NULLIF(left(regexp_replace(session.user_agent, '[[:cntrl:]]', '', 'g'), 512), ''),
		NULLIF(left(regexp_replace(event.payload->>'user_agent', '[[:cntrl:]]', '', 'g'), 512), ''),
		event.user_agent) ELSE event.user_agent END,
	COALESCE(NULLIF(event.payload->>'geo_code', ''), ''), COALESCE(event.payload->>'geo_region', ''), COALESCE(event.payload->>'geo_city', '')
FROM audit_events event
LEFT JOIN users actor ON actor.id = event.actor_user_id
LEFT JOIN access_scopes row_scope ON row_scope.id = event.scope_id
LEFT JOIN tenants tenant ON tenant.id = row_scope.tenant_id
LEFT JOIN auth_sessions session ON event.action = 'auth.login' AND session.id::text = event.payload->>'session_id'
`

// List returns one page, newest first, rendered in locale.
func (store *Store) List(ctx context.Context, filter Filter, locale audit.Locale, location *time.Location) (Page, error) {
	if err := filter.Validate(); err != nil {
		return Page{}, err
	}
	where, args := filter.where()
	args = append(args, filter.Limit+1)
	rows, err := store.pool.Query(ctx, selectSQL+where+
		fmt.Sprintf(" ORDER BY event.occurred_at DESC, event.id DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		return Page{}, fmt.Errorf("query audit log: %w", err)
	}
	inputs, err := pgx.CollectRows(rows, scanInput)
	if err != nil {
		return Page{}, fmt.Errorf("read audit log: %w", err)
	}
	page := Page{Items: make([]audit.Rendered, 0, len(inputs))}
	if len(inputs) > filter.Limit {
		last := inputs[filter.Limit-1]
		page.NextCursor = encodeCursor(cursor{OccurredAt: last.OccurredAt, ID: last.ID})
		inputs = inputs[:filter.Limit]
	}
	store.attachRegions(ctx, inputs)
	store.attachNames(ctx, inputs)
	for _, input := range inputs {
		page.Items = append(page.Items, audit.Render(input, locale, location))
	}
	return page, nil
}

func scanInput(row pgx.CollectableRow) (audit.RenderInput, error) {
	var input audit.RenderInput
	var payload, changes string
	if err := row.Scan(&input.ID, &input.ScopeID, &input.OccurredAt, &input.Action, &input.Category,
		&input.ActorKind, &input.ActorUserID, &input.ActorRef, &input.ActorName, &input.ActorIsAdmin,
		&input.SourceIP, &input.ResourceType, &input.ResourceID, &input.ResourceName,
		&input.Result, &input.ReasonCode, &input.RequestID, &payload, &changes,
		&input.TenantName, &input.UserAgent, &input.GeoCode, &input.GeoRegion, &input.GeoCity); err != nil {
		return audit.RenderInput{}, err
	}
	if err := json.Unmarshal([]byte(payload), &input.Payload); err != nil {
		return audit.RenderInput{}, fmt.Errorf("decode payload: %w", err)
	}
	if err := json.Unmarshal([]byte(changes), &input.Changes); err != nil {
		return audit.RenderInput{}, fmt.Errorf("decode changes: %w", err)
	}
	return input, nil
}
