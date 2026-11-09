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

	"github.com/cdnca/cdnca/services/control-api/internal/marketsupplyguard"
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
	// Telemetry* are the telemetry pipeline degradation of the latest
	// heartbeat (EdgeRuntimeStatus.telemetry, migration 592): the error code
	// (L4_USAGE_LEDGER_FULL, L4_USAGE_ATTRIBUTION_PENDING, TELEMETRY_*, ...),
	// when the Agent first and last saw it and in how many heartbeats.
	// Omitted while the pipeline is healthy or the node did not report it.
	TelemetryErrorCode   *string    `json:"telemetry_error_code,omitempty"`
	TelemetryFirstSeenAt *time.Time `json:"telemetry_first_seen_at,omitempty"`
	TelemetryLastSeenAt  *time.Time `json:"telemetry_last_seen_at,omitempty"`
	TelemetryCount       *int64     `json:"telemetry_count,omitempty"`
	// Toolset* are the packaging toolset of the latest heartbeat
	// (EdgeRuntimeStatus.packaging_toolset, migration 647):
	// the last refresh (status none/unknown/ok/failed/skipped, version, reason,
	// time, packaging helper result) and the installed scripts / helper
	// digests. ToolsetRefreshStatus omitted: the Agent does not report it.
	ToolsetRefreshStatus  *string    `json:"toolset_refresh_status,omitempty"`
	ToolsetRefreshVersion *string    `json:"toolset_refresh_version,omitempty"`
	ToolsetRefreshReason  *string    `json:"toolset_refresh_reason,omitempty"`
	ToolsetRefreshedAt    *time.Time `json:"toolset_refreshed_at,omitempty"`
	ToolsetHelperStatus   *string    `json:"toolset_helper_status,omitempty"`
	ToolsetHelperReason   *string    `json:"toolset_helper_reason,omitempty"`
	ToolsetScriptsSHA256  *string    `json:"toolset_scripts_sha256,omitempty"`
	ToolsetHelperSHA256   *string    `json:"toolset_helper_sha256,omitempty"`
}

type InventoryItem struct {
	node.Node
	Presence         Presence                    `json:"presence"`
	NetworkInventory node.NetworkInventoryStatus `json:"network_inventory"`
	// MarketSupplyGroups are the hidden node-market supply groups whose
	// current revision lists the node (they hold it against deletion like any
	// line group, but no line group list shows them); omitted when none.
	MarketSupplyGroups []MarketSupplyGroupRef `json:"market_supply_groups,omitempty"`
	// StaleConfigurations are the tenants (configuration scopes) whose
	// latest release left the node out because its Agent predates
	// SITE_SELECTION and the key envelope did not fit: the
	// node still runs the previous configuration, so websites withheld and
	// forwards deleted since then still serve there. Omitted when none.
	StaleConfigurations []StaleConfiguration `json:"stale_configurations,omitempty"`
}

// StaleConfiguration is a scope release the node did not get
// (InventoryItem.StaleConfigurations): SourceRevision is the release it was
// left out of, LeftOutAt when.
type StaleConfiguration struct {
	ScopeID        uuid.UUID `json:"scope_id"`
	TenantName     string    `json:"tenant_name"`
	SourceRevision int64     `json:"source_revision"`
	Reason         string    `json:"reason"`
	LeftOutAt      time.Time `json:"left_out_at"`
}

// StaleReasonKeyEnvelopeOversized: the release's key document is larger
// than an Agent before SITE_SELECTION (capability 82) takes.
const StaleReasonKeyEnvelopeOversized = "key_envelope_oversized"

// MarketSupplyGroupRef names a market supply group: Name is the seller's
// name, without the hidden-group prefix.
type MarketSupplyGroupRef struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
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
		       node_presence.telemetry_error_code, node_presence.telemetry_first_seen_at,
		       node_presence.telemetry_last_seen_at, node_presence.telemetry_count,
		       node_presence.toolset_refresh_status, node_presence.toolset_refresh_version, node_presence.toolset_refresh_reason,
		       node_presence.toolset_refreshed_at, node_presence.toolset_helper_status, node_presence.toolset_helper_reason,
		       node_presence.toolset_scripts_sha256, node_presence.toolset_helper_sha256,
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
	if err := i.attachMarketSupplyGroups(ctx, result.Items); err != nil {
		return InventoryListResult{}, err
	}
	if err := i.attachStaleConfigurations(ctx, result.Items); err != nil {
		return InventoryListResult{}, err
	}
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
		       node_presence.telemetry_error_code, node_presence.telemetry_first_seen_at,
		       node_presence.telemetry_last_seen_at, node_presence.telemetry_count,
		       node_presence.toolset_refresh_status, node_presence.toolset_refresh_version, node_presence.toolset_refresh_reason,
		       node_presence.toolset_refreshed_at, node_presence.toolset_helper_status, node_presence.toolset_helper_reason,
		       node_presence.toolset_scripts_sha256, node_presence.toolset_helper_sha256,
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
	if err := i.attachMarketSupplyGroups(ctx, items); err != nil {
		return InventoryItem{}, err
	}
	if err := i.attachStaleConfigurations(ctx, items); err != nil {
		return InventoryItem{}, err
	}
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
		&item.Presence.TelemetryErrorCode, &item.Presence.TelemetryFirstSeenAt,
		&item.Presence.TelemetryLastSeenAt, &item.Presence.TelemetryCount,
		&item.Presence.ToolsetRefreshStatus, &item.Presence.ToolsetRefreshVersion, &item.Presence.ToolsetRefreshReason,
		&item.Presence.ToolsetRefreshedAt, &item.Presence.ToolsetHelperStatus, &item.Presence.ToolsetHelperReason,
		&item.Presence.ToolsetScriptsSHA256, &item.Presence.ToolsetHelperSHA256,
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
		item.Presence.TelemetryErrorCode, item.Presence.TelemetryFirstSeenAt = nil, nil
		item.Presence.TelemetryLastSeenAt, item.Presence.TelemetryCount = nil, nil
		item.Presence.ToolsetRefreshStatus, item.Presence.ToolsetRefreshVersion, item.Presence.ToolsetRefreshReason = nil, nil, nil
		item.Presence.ToolsetRefreshedAt, item.Presence.ToolsetHelperStatus, item.Presence.ToolsetHelperReason = nil, nil, nil
		item.Presence.ToolsetScriptsSHA256, item.Presence.ToolsetHelperSHA256 = nil, nil
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

// attachMarketSupplyGroups reads, in one query, the live market supply
// groups whose current revision lists each node (the membership a node
// deletion refuses on, node.ensureNodeUnreferenced).
func (i *Inventory) attachMarketSupplyGroups(ctx context.Context, items []InventoryItem) error {
	if len(items) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(items))
	for index := range items {
		ids[index] = items[index].ID
	}
	rows, err := i.pool.Query(ctx, `
		SELECT DISTINCT endpoint.node_id, line_group.id, line_group.name
		FROM node_line_groups line_group
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id = line_group.tenant_scope_id
		 AND endpoint.line_group_id = line_group.id AND endpoint.config_revision = line_group.current_revision
		WHERE line_group.purpose = 'market_supply' AND line_group.deleted_at IS NULL AND endpoint.node_id = ANY($1)
		ORDER BY endpoint.node_id, line_group.name, line_group.id`, ids)
	if err != nil {
		return fmt.Errorf("read node market supply groups: %w", err)
	}
	defer rows.Close()
	groups := make(map[uuid.UUID][]MarketSupplyGroupRef)
	for rows.Next() {
		var nodeID uuid.UUID
		var group MarketSupplyGroupRef
		if err := rows.Scan(&nodeID, &group.ID, &group.Name); err != nil {
			return fmt.Errorf("scan node market supply groups: %w", err)
		}
		group.Name = strings.TrimPrefix(group.Name, marketsupplyguard.GroupNamePrefix)
		groups[nodeID] = append(groups[nodeID], group)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read node market supply groups: %w", err)
	}
	for index := range items {
		items[index].MarketSupplyGroups = groups[items[index].ID]
	}
	return nil
}

// staleConfigurationsQuery reads the stale configurations of the nodes $1.
// The LATERAL lookup per (node, scope) is served by
// audit_events_node_key_envelope_oversized_648_idx.
const staleConfigurationsQuery = `
	SELECT state.node_id, state.configuration_scope_id, COALESCE(tenant.display_name,''),
	       left_out.source_revision, left_out.occurred_at
	FROM node_config_state state
	JOIN access_scopes scope ON scope.id=state.configuration_scope_id
	LEFT JOIN tenants tenant ON tenant.id=scope.tenant_id
	JOIN LATERAL (
		SELECT (event.payload->>'source_revision')::bigint AS source_revision, event.occurred_at
		FROM audit_events event
		WHERE event.scope_id=state.configuration_scope_id AND event.action='edge_publication.key_envelope_oversized'
		  AND event.resource_type='node' AND event.resource_id=state.node_id::text
		ORDER BY event.occurred_at DESC, event.stream_position DESC LIMIT 1
	) left_out ON true
	WHERE state.node_id=ANY($1)
	  AND NOT EXISTS (
		SELECT 1 FROM edge_config_publications running
		WHERE running.configuration_scope_id=state.configuration_scope_id
		  AND running.config_version_id=state.current_config_version_id
		  AND running.source_revision>=left_out.source_revision)
	ORDER BY state.node_id, COALESCE(tenant.display_name,''), state.configuration_scope_id`

// attachStaleConfigurations reads, in one query, the scopes whose release
// left each node out for its key envelope: the newest
// edge_publication.key_envelope_oversized row of the (scope, node) -- the
// newest row of its group, which archiving keeps (migration 331) -- names a
// revision and the node has applied no release of that revision or later
// since. It clears once the node takes a later release (the capability
// watcher republishes after it upgrades).
func (i *Inventory) attachStaleConfigurations(ctx context.Context, items []InventoryItem) error {
	if len(items) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(items))
	for index := range items {
		ids[index] = items[index].ID
	}
	rows, err := i.pool.Query(ctx, staleConfigurationsQuery, ids)
	if err != nil {
		return fmt.Errorf("read node stale configurations: %w", err)
	}
	defer rows.Close()
	stale := make(map[uuid.UUID][]StaleConfiguration)
	for rows.Next() {
		var nodeID uuid.UUID
		item := StaleConfiguration{Reason: StaleReasonKeyEnvelopeOversized}
		if err := rows.Scan(&nodeID, &item.ScopeID, &item.TenantName, &item.SourceRevision, &item.LeftOutAt); err != nil {
			return fmt.Errorf("scan node stale configurations: %w", err)
		}
		stale[nodeID] = append(stale[nodeID], item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read node stale configurations: %w", err)
	}
	for index := range items {
		items[index].StaleConfigurations = stale[items[index].ID]
	}
	return nil
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
