package nodepresence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	StatusUnknown           = "unknown"
	MaxInventorySearchRunes = 128

	FreshnessFresh = "fresh"
	FreshnessStale = "stale"
	FreshnessNever = "never"

	LeasePresent     = "present"
	LeaseAbsent      = "absent"
	LeaseUnavailable = "unavailable"
)

type Presence struct {
	Status              string     `json:"status"`
	LastHeartbeatAt     *time.Time `json:"last_heartbeat_at,omitempty"`
	AgentVersion        *string    `json:"agent_version,omitempty"`
	SessionEpoch        *int64     `json:"session_epoch,omitempty"`
	HeartbeatSequence   *int64     `json:"heartbeat_sequence,omitempty"`
	ProjectionFreshness string     `json:"projection_freshness"`
	LeaseSignal         string     `json:"lease_signal"`
	ProjectedAt         *time.Time `json:"projected_at,omitempty"`
	// MarketProbeRole is the role of the latest heartbeat (probe_only,
	// join_market, disabled); omitted when the Agent did not report it.
	MarketProbeRole *string `json:"market_probe_role,omitempty"`
	// OpenRestyVersion is the OpenResty runtime version the Agent declared
	// in the capabilities of the confirmed session (node-runtime-upgrade: a
	// native node reports the runtime it switched to); omitted when the
	// session declared none or its snapshot is unreadable.
	OpenRestyVersion *string `json:"openresty_version,omitempty"`
	// NativeRuntime* are the native runtime switch outcome of the latest
	// heartbeat (EdgeRuntimeStatus.native_runtime): switched, unchanged or
	// rolled_back, the runtime manifest sha256 it targeted, the one active
	// before and the RUNTIME_* error code of a rollback. Omitted when the node
	// is not native or did not report it.
	NativeRuntimeState           *string `json:"native_runtime_state,omitempty"`
	NativeRuntimeRelease         *string `json:"native_runtime_release,omitempty"`
	NativeRuntimePreviousRelease *string `json:"native_runtime_previous_release,omitempty"`
	NativeRuntimeErrorCode       *string `json:"native_runtime_error_code,omitempty"`
}

type InventoryItem struct {
	node.Node
	Presence         Presence                    `json:"presence"`
	NetworkInventory node.NetworkInventoryStatus `json:"network_inventory"`
}

type InventoryListRequest struct {
	ScopeID      uuid.UUID
	State        string
	Presence     string
	Search       string
	After        *uuid.UUID
	Limit        int
	Order        string
	OrderedAfter string
}

type InventoryListResult struct {
	Items             []InventoryItem
	NextCursor        *uuid.UUID
	NextOrderedCursor string
}

type Inventory struct {
	pool         *pgxpool.Pool
	leases       LeaseReader
	offlineAfter time.Duration
	now          func() time.Time
	logger       *slog.Logger
	exclusions   TelemetryExclusionReader
}

// TelemetryExclusionReader reports which scopes of a node serving several
// the node's authorization leaves out of telemetry, and why
// (nodeidentity.TelemetryScopeExclusions); it reads in the caller's
// transaction.
type TelemetryExclusionReader func(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, now time.Time) (map[uuid.UUID]string, error)

// WithTelemetryExclusions makes ConfigurationScopes report isolated scopes.
func (i *Inventory) WithTelemetryExclusions(reader TelemetryExclusionReader) *Inventory {
	i.exclusions = reader
	return i
}

func NewInventory(pool *pgxpool.Pool, leases LeaseReader, offlineAfter time.Duration, now func() time.Time, logger *slog.Logger) *Inventory {
	if offlineAfter <= 0 {
		offlineAfter = 45 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Inventory{pool: pool, leases: leases, offlineAfter: offlineAfter, now: now, logger: logger}
}

func (i *Inventory) List(ctx context.Context, request InventoryListRequest) (InventoryListResult, error) {
	if request.ScopeID == uuid.Nil || request.Limit < 1 || request.Limit > node.MaxListLimit ||
		request.State != "" && !validAdminState(request.State) ||
		request.Presence != "" && request.Presence != StatusOnline && request.Presence != StatusOffline && request.Presence != StatusUnknown ||
		!utf8.ValidString(request.Search) || utf8.RuneCountInString(request.Search) > MaxInventorySearchRunes ||
		request.Search != strings.TrimSpace(request.Search) || strings.ContainsFunc(request.Search, invalidSearchCharacter) {
		return InventoryListResult{}, node.ErrInvalidInput
	}
	position, err := validateInventoryOrder(request)
	if err != nil {
		return InventoryListResult{}, err
	}
	searchUUID := ""
	if len(request.Search) == 36 {
		if parsed, err := uuid.Parse(request.Search); err == nil {
			searchUUID = parsed.String()
		}
	}
	searchDisplayID := request.Search != "" && request.Search[0] != '0' && len(request.Search) <= 19 &&
		strings.IndexFunc(request.Search, func(character rune) bool { return character < '0' || character > '9' }) == -1
	searchIP := ""
	if address, err := netip.ParseAddr(request.Search); err == nil && address.Zone() == "" {
		searchIP = address.Unmap().String()
	}
	cutoff := i.now().UTC().Add(-i.offlineAfter)
	args := []any{request.ScopeID, request.State, request.Presence, cutoff, request.Search, searchUUID, searchDisplayID, searchIP}
	keyset := `AND ($9::uuid IS NULL OR nodes.id > $9) ORDER BY nodes.id LIMIT $10`
	if request.Order == InventoryManagementSortDesc {
		var sort *int
		var displayID *string
		var id *uuid.UUID
		if position != nil {
			sort, displayID, id = &position.LastSort, &position.LastDisplayID, &position.LastID
		}
		keyset = `AND ($9::integer IS NULL OR ((nodes.management_settings->>'sort')::integer, nodes.display_id, nodes.id) < ($9, $10::bigint, $11::uuid))
			ORDER BY (nodes.management_settings->>'sort')::integer DESC, nodes.display_id DESC, nodes.id DESC LIMIT $12`
		args = append(args, sort, displayID, id, request.Limit+1)
	} else {
		args = append(args, request.After, request.Limit+1)
	}
	rows, err := i.pool.Query(ctx, `
		SELECT nodes.id, nodes.display_id::text, nodes.name, nodes.description, nodes.region, host(nodes.ipv4), host(nodes.ipv6),
		       nodes.admin_state, nodes.management_settings, nodes.revision, nodes.created_at, nodes.updated_at,
		       node_presence.status, node_presence.last_seen_at, node_presence.confirmed_agent_version,
		       node_presence.confirmed_session_epoch, node_presence.confirmed_heartbeat_sequence,
		       node_presence.market_probe_role,
		       node_presence.native_runtime_state, node_presence.native_runtime_release,
		       node_presence.native_runtime_previous_release, node_presence.native_runtime_error_code,
		       session.capabilities_snapshot, session.capabilities_sha256,
		       CASE WHEN network.ipv4_state='verified' AND host(nodes.ipv4) IS DISTINCT FROM network.ipv4_address THEN 'address_conflict' ELSE network.ipv4_state END,
		       CASE WHEN network.ipv6_state='verified' AND host(nodes.ipv6) IS DISTINCT FROM network.ipv6_address THEN 'address_conflict' ELSE network.ipv6_state END,
		       network.received_at
		FROM nodes
		LEFT JOIN node_presence ON node_presence.node_id = nodes.id
		LEFT JOIN node_session_capabilities session ON session.node_id = nodes.id
		  AND session.session_epoch = node_presence.confirmed_session_epoch
		LEFT JOIN node_network_inventory_latest network ON network.node_id=nodes.id AND network.scope_id=nodes.scope_id
		WHERE nodes.scope_id = $1
		  AND ($2 = '' OR nodes.admin_state = $2)
		  AND (
		    $3 = '' OR
		    $3 = 'unknown' AND node_presence.confirmed_session_epoch IS NULL OR
		    $3 = 'online' AND node_presence.confirmed_session_epoch IS NOT NULL AND
		      node_presence.status = 'online' AND node_presence.last_seen_at > $4 OR
		    $3 = 'offline' AND node_presence.confirmed_session_epoch IS NOT NULL AND
		      NOT (node_presence.status = 'online' AND node_presence.last_seen_at > $4)
		  )
		  AND (
		    $5 = '' OR
		    strpos(lower(nodes.name), lower($5)) > 0 OR
		    strpos(lower(nodes.region), lower($5)) > 0 OR
		    (NULLIF($6, '')::uuid IS NOT NULL AND nodes.id = NULLIF($6, '')::uuid) OR
		    ($7 AND nodes.display_id::text LIKE $5 || '%') OR
		    (NULLIF($8, '')::inet IS NOT NULL AND
		      (nodes.ipv4 = NULLIF($8, '')::inet OR nodes.ipv6 = NULLIF($8, '')::inet))
		  )
		  `+keyset, args...)
	if err != nil {
		return InventoryListResult{}, fmt.Errorf("list node presence inventory: %w", err)
	}
	defer rows.Close()
	items := make([]InventoryItem, 0, request.Limit+1)
	for rows.Next() {
		item, err := scanInventoryItem(rows, cutoff)
		if err != nil {
			return InventoryListResult{}, fmt.Errorf("scan node presence inventory: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return InventoryListResult{}, fmt.Errorf("iterate node presence inventory: %w", err)
	}
	result := InventoryListResult{Items: items}
	if len(items) > request.Limit {
		if request.Order == InventoryManagementSortDesc {
			result.NextOrderedCursor, err = encodeInventoryOrderCursor(request, items[request.Limit-1])
			if err != nil {
				return InventoryListResult{}, fmt.Errorf("encode node inventory cursor: %w", err)
			}
		} else {
			cursor := items[request.Limit-1].ID
			result.NextCursor = &cursor
		}
		result.Items = items[:request.Limit]
	}
	i.attachLeaseSignals(ctx, result.Items)
	return result, nil
}

func invalidSearchCharacter(character rune) bool {
	return unicode.IsControl(character) || character == '\u2028' || character == '\u2029'
}

func (i *Inventory) Get(ctx context.Context, scopeID, nodeID uuid.UUID) (InventoryItem, error) {
	cutoff := i.now().UTC().Add(-i.offlineAfter)
	row := i.pool.QueryRow(ctx, `
		SELECT nodes.id, nodes.display_id::text, nodes.name, nodes.description, nodes.region, host(nodes.ipv4), host(nodes.ipv6),
		       nodes.admin_state, nodes.management_settings, nodes.revision, nodes.created_at, nodes.updated_at,
		       node_presence.status, node_presence.last_seen_at, node_presence.confirmed_agent_version,
		       node_presence.confirmed_session_epoch, node_presence.confirmed_heartbeat_sequence,
		       node_presence.market_probe_role,
		       node_presence.native_runtime_state, node_presence.native_runtime_release,
		       node_presence.native_runtime_previous_release, node_presence.native_runtime_error_code,
		       session.capabilities_snapshot, session.capabilities_sha256,
		       CASE WHEN network.ipv4_state='verified' AND host(nodes.ipv4) IS DISTINCT FROM network.ipv4_address THEN 'address_conflict' ELSE network.ipv4_state END,
		       CASE WHEN network.ipv6_state='verified' AND host(nodes.ipv6) IS DISTINCT FROM network.ipv6_address THEN 'address_conflict' ELSE network.ipv6_state END,
		       network.received_at
		FROM nodes
		LEFT JOIN node_presence ON node_presence.node_id = nodes.id
		LEFT JOIN node_session_capabilities session ON session.node_id = nodes.id
		  AND session.session_epoch = node_presence.confirmed_session_epoch
		LEFT JOIN node_network_inventory_latest network ON network.node_id=nodes.id AND network.scope_id=nodes.scope_id
		WHERE nodes.scope_id = $1 AND nodes.id = $2`, scopeID, nodeID)
	item, err := scanInventoryItem(row, cutoff)
	if errors.Is(err, pgx.ErrNoRows) {
		return InventoryItem{}, node.ErrNotFound
	}
	if err != nil {
		return InventoryItem{}, fmt.Errorf("get node presence inventory: %w", err)
	}
	items := []InventoryItem{item}
	i.attachLeaseSignals(ctx, items)
	return items[0], nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanInventoryItem(row rowScanner, cutoff time.Time) (InventoryItem, error) {
	var item InventoryItem
	var persistedStatus *string
	var lastSeen *time.Time
	var ipv4State, ipv6State *string
	var capabilitiesSnapshot, capabilitiesDigest []byte
	if err := row.Scan(
		&item.ID, &item.DisplayID, &item.Name, &item.Description, &item.Region, &item.IPv4, &item.IPv6,
		&item.AdminState, &item.ManagementSettings, &item.Revision, &item.CreatedAt, &item.UpdatedAt,
		&persistedStatus, &lastSeen, &item.Presence.AgentVersion,
		&item.Presence.SessionEpoch, &item.Presence.HeartbeatSequence, &item.Presence.MarketProbeRole,
		&item.Presence.NativeRuntimeState, &item.Presence.NativeRuntimeRelease,
		&item.Presence.NativeRuntimePreviousRelease, &item.Presence.NativeRuntimeErrorCode,
		&capabilitiesSnapshot, &capabilitiesDigest,
		&ipv4State, &ipv6State, &item.NetworkInventory.ReceivedAt,
	); err != nil {
		return InventoryItem{}, err
	}
	item.NetworkInventory.SchemaVersion = 1
	item.NetworkInventory.IPv4State, item.NetworkInventory.IPv6State = "not_reported", "not_reported"
	if ipv4State != nil && ipv6State != nil && item.NetworkInventory.ReceivedAt != nil {
		item.NetworkInventory.IPv4State, item.NetworkInventory.IPv6State = *ipv4State, *ipv6State
	} else if ipv4State != nil || ipv6State != nil || item.NetworkInventory.ReceivedAt != nil {
		return InventoryItem{}, errors.New("incomplete network inventory state")
	}
	item.Presence.LeaseSignal = LeaseUnavailable
	if item.Presence.SessionEpoch == nil || lastSeen == nil {
		item.Presence.Status = StatusUnknown
		item.Presence.ProjectionFreshness = FreshnessNever
		item.Presence.AgentVersion = nil
		item.Presence.HeartbeatSequence = nil
		item.Presence.MarketProbeRole = nil
		item.Presence.NativeRuntimeState, item.Presence.NativeRuntimeRelease = nil, nil
		item.Presence.NativeRuntimePreviousRelease, item.Presence.NativeRuntimeErrorCode = nil, nil
		return item, nil
	}
	item.Presence.OpenRestyVersion = sessionOpenRestyVersion(capabilitiesSnapshot, capabilitiesDigest)
	confirmedAt := lastSeen.UTC()
	item.Presence.LastHeartbeatAt = &confirmedAt
	item.Presence.ProjectedAt = &confirmedAt
	if persistedStatus != nil && *persistedStatus == StatusOnline && confirmedAt.After(cutoff) {
		item.Presence.Status = StatusOnline
		item.Presence.ProjectionFreshness = FreshnessFresh
	} else {
		item.Presence.Status = StatusOffline
		item.Presence.ProjectionFreshness = FreshnessStale
	}
	return item, nil
}

func (i *Inventory) attachLeaseSignals(ctx context.Context, items []InventoryItem) {
	if i.leases == nil || len(items) == 0 {
		return
	}
	ids := make([]uuid.UUID, len(items))
	for index := range items {
		ids[index] = items[index].ID
	}
	var signals map[uuid.UUID]bool
	var err error
	if redisLeases, ok := i.leases.(*RedisLeaseStore); ok {
		signals, err = redisLeases.Signals(ctx, ids)
	} else {
		signals = make(map[uuid.UUID]bool, len(ids))
		for _, nodeID := range ids {
			signals[nodeID], err = i.leases.Exists(ctx, nodeID)
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		i.logger.WarnContext(ctx, "node presence lease signal unavailable", "error", err)
		return
	}
	for index := range items {
		if signals[items[index].ID] {
			items[index].Presence.LeaseSignal = LeasePresent
		} else {
			items[index].Presence.LeaseSignal = LeaseAbsent
		}
	}
}

// validAdminState lists the states the inventory can be filtered by. Deleting
// a node removes its row, so "retired" is not a filter; a legacy retired row
// from an older release is listed unfiltered and can be deleted.
func validAdminState(value string) bool {
	switch value {
	case node.StatePending, node.StateActive, node.StateDraining, node.StateDisabled:
		return true
	default:
		return false
	}
}
