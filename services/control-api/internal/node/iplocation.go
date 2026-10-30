package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IP 归属 (fix-nodeipgeo, migration 547): management_settings.ip_location is
// what condition matching reads (L2 node conditions, market supply groups).
// Each field is either automatic (the control plane's IP intelligence library
// resolved it from the node's addresses, node_ip_location_resolutions) or
// manual (listed in ip_location_manual: an administrator's correction the
// resolver never overwrites).

// IPLocationFields are the ip_location keys in canonical order.
var IPLocationFields = []string{"country", "province", "city", "isp", "country_code"}

const (
	IPLocationResolved   = "resolved"
	IPLocationUnresolved = "unresolved"
	IPLocationNoLibrary  = "no_library"
)

// IPLocationLibrary is the library the resolver answers from.
type IPLocationLibrary struct {
	Revision uint64
	Version  string
}

// IPLocationSource answers addresses from the control plane's IP library
// (nil answer: not in it). ok is false when no library is loaded.
type IPLocationSource interface {
	Library(context.Context) (IPLocationLibrary, bool)
	Locate(context.Context, []string) map[string]*NodeIPLocation
}

// IPLocationResolution is a node's latest automatic resolution.
type IPLocationResolution struct {
	NodeID          uuid.UUID      `json:"node_id"`
	Outcome         string         `json:"outcome"`
	Address         string         `json:"address,omitempty"`
	Automatic       NodeIPLocation `json:"automatic"`
	LibraryRevision uint64         `json:"library_revision"`
	LibraryVersion  string         `json:"library_version"`
	ResolvedAt      time.Time      `json:"resolved_at"`
}

// IPLocationView is the 编辑节点 → IP 归属 read: the effective values, which
// are manual, and the automatic resolution (nil: not resolved yet).
type IPLocationView struct {
	NodeID     uuid.UUID             `json:"node_id"`
	Effective  NodeIPLocation        `json:"effective"`
	Manual     []string              `json:"manual_fields"`
	Resolution *IPLocationResolution `json:"resolution"`
}

func (location *NodeIPLocation) field(name string) *string {
	switch name {
	case "country":
		return &location.Country
	case "province":
		return &location.Province
	case "city":
		return &location.City
	case "isp":
		return &location.ISP
	case "country_code":
		return &location.CountryCode
	}
	return nil
}

// normalizeIPLocationManual keeps known fields once, in canonical order (nil
// stays nil: the caller did not say).
func normalizeIPLocationManual(values []string) ([]string, bool) {
	if values == nil {
		return nil, true
	}
	result := []string{}
	for _, name := range IPLocationFields {
		if slices.Contains(values, name) {
			result = append(result, name)
		}
	}
	for _, value := range values {
		if !slices.Contains(IPLocationFields, value) {
			return nil, false
		}
	}
	return result, true
}

// effectiveIPLocation is every manual field from manual, every other from
// automatic.
func effectiveIPLocation(manualFields []string, manual, automatic NodeIPLocation) NodeIPLocation {
	result := automatic
	for _, name := range manualFields {
		*result.field(name) = *manual.field(name)
	}
	return result
}

// applyIPLocationWrite settles an update's ip_location: a request naming
// ip_location_manual says which fields are manual (a field left out goes
// back to its automatic value); an older caller that does not name it makes
// every field it changed manual.
func applyIPLocationWrite(before NodeManagementSettings, after *NodeManagementSettings, automatic NodeIPLocation) {
	manual := after.IPLocationManual
	if manual == nil {
		manual = slices.Clone(before.IPLocationManual)
		for _, name := range IPLocationFields {
			if *after.IPLocation.field(name) != *before.IPLocation.field(name) && !slices.Contains(manual, name) {
				manual = append(manual, name)
			}
		}
		manual, _ = normalizeIPLocationManual(manual)
	}
	if len(manual) == 0 {
		manual = nil
	}
	after.IPLocationManual = manual
	after.IPLocation = effectiveIPLocation(manual, after.IPLocation, automatic)
}

// nodeAddresses is the resolve order: IPv4, IPv6, then secondary IPs.
func nodeAddresses(ipv4, ipv6 *string, secondary []string) []string {
	addresses := []string{}
	for _, value := range append([]string{deref(ipv4), deref(ipv6)}, secondary...) {
		if address, err := netip.ParseAddr(value); err == nil && !slices.Contains(addresses, address.String()) {
			addresses = append(addresses, address.String())
		}
	}
	return addresses
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// resolveIPLocation is the first address the library places (a country).
func resolveIPLocation(ctx context.Context, source IPLocationSource, addresses []string) (outcome, address string,
	location NodeIPLocation, library IPLocationLibrary) {
	library, ok := source.Library(ctx)
	if !ok {
		return IPLocationNoLibrary, "", NodeIPLocation{}, IPLocationLibrary{}
	}
	answers := source.Locate(ctx, addresses)
	for _, candidate := range addresses {
		if answer := answers[candidate]; answer != nil && answer.CountryCode != "" {
			return IPLocationResolved, candidate, *answer, library
		}
	}
	return IPLocationUnresolved, "", NodeIPLocation{}, library
}

func loadIPLocationResolution(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, nodeID uuid.UUID) (*IPLocationResolution, error) {
	resolution := IPLocationResolution{NodeID: nodeID}
	var address *string
	var revision int64
	err := q.QueryRow(ctx, `SELECT outcome,host(address),country,province,city,isp,country_code,
		library_revision,library_version,resolved_at FROM node_ip_location_resolutions WHERE node_id=$1`, nodeID).Scan(
		&resolution.Outcome, &address, &resolution.Automatic.Country, &resolution.Automatic.Province,
		&resolution.Automatic.City, &resolution.Automatic.ISP, &resolution.Automatic.CountryCode,
		&revision, &resolution.LibraryVersion, &resolution.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load node IP location resolution: %w", err)
	}
	resolution.Address, resolution.LibraryRevision = deref(address), uint64(revision)
	return &resolution, nil
}

// IPLocation reads a platform node's IP 归属.
func (s *Store) IPLocation(ctx context.Context, scopeID, nodeID uuid.UUID) (IPLocationView, error) {
	var view IPLocationView
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var settings NodeManagementSettings
		err := tx.QueryRow(ctx, `SELECT management_settings FROM nodes WHERE id=$1 AND scope_id=$2`, nodeID, scopeID).
			Scan(&settings)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		resolution, err := loadIPLocationResolution(ctx, tx, nodeID)
		view = IPLocationView{NodeID: nodeID, Effective: settings.IPLocation, Manual: settings.IPLocationManual,
			Resolution: resolution}
		if view.Manual == nil {
			view.Manual = []string{}
		}
		return err
	})
	return view, err
}

// IPLocationResolver writes each node's automatic IP 归属: a node never
// resolved, whose addresses (IPv4, IPv6, secondary IPs) changed, or resolved
// from another library revision is resolved again; the fields not marked
// manual follow it. A failed node is retried on the next pass; saving a node
// never waits for it.
type IPLocationResolver struct {
	pool    *pgxpool.Pool
	source  IPLocationSource
	auditor *audit.Log
	now     func() time.Time
	logger  *slog.Logger
}

func NewIPLocationResolver(pool *pgxpool.Pool, source IPLocationSource, logger *slog.Logger) *IPLocationResolver {
	if logger == nil {
		logger = slog.Default()
	}
	return &IPLocationResolver{pool: pool, source: source, auditor: audit.New(pool), now: time.Now, logger: logger}
}

// IPLocationResolveAction audits a resolution that changed a node's values.
const IPLocationResolveAction = "node.ip_location.resolve"

type ipLocationCandidate struct {
	id, scopeID uuid.UUID
	addresses   []string
}

// RunOnce resolves every node due and returns how many it wrote.
func (resolver *IPLocationResolver) RunOnce(ctx context.Context) (int, error) {
	library, hasLibrary := resolver.source.Library(ctx)
	rows, err := resolver.pool.Query(ctx, `SELECT node.id,node.scope_id,host(node.ipv4),host(node.ipv6),
		COALESCE(node.management_settings->'secondary_ips','[]'::jsonb),resolution.addresses,resolution.library_revision,
		resolution.outcome FROM nodes node LEFT JOIN node_ip_location_resolutions resolution ON resolution.node_id=node.id
		WHERE node.admin_state<>'retired' ORDER BY node.id`)
	if err != nil {
		return 0, fmt.Errorf("list nodes to resolve IP location: %w", err)
	}
	var due []ipLocationCandidate
	for rows.Next() {
		var candidate ipLocationCandidate
		var ipv4, ipv6 *string
		var secondary []string
		var resolved []string
		var revision *int64
		var outcome *string
		if err := rows.Scan(&candidate.id, &candidate.scopeID, &ipv4, &ipv6, &secondary, &resolved, &revision, &outcome); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan node to resolve IP location: %w", err)
		}
		candidate.addresses = nodeAddresses(ipv4, ipv6, secondary)
		if ipLocationDue(candidate.addresses, resolved, revision, outcome, library, hasLibrary) {
			due = append(due, candidate)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	written := 0
	var failures []error
	for _, candidate := range due {
		if err := resolver.resolveNode(ctx, candidate); err != nil {
			failures = append(failures, err)
			continue
		}
		written++
	}
	return written, errors.Join(failures...)
}

// ipLocationDue: never resolved, other addresses, or another library.
func ipLocationDue(addresses, resolved []string, revision *int64, outcome *string, library IPLocationLibrary, hasLibrary bool) bool {
	if revision == nil || outcome == nil || !slices.Equal(addresses, resolved) {
		return true
	}
	if !hasLibrary {
		return *outcome != IPLocationNoLibrary
	}
	return *outcome == IPLocationNoLibrary || uint64(*revision) != library.Revision
}

func (resolver *IPLocationResolver) resolveNode(ctx context.Context, candidate ipLocationCandidate) error {
	outcome, address, automatic, library := resolveIPLocation(ctx, resolver.source, candidate.addresses)
	return pgx.BeginFunc(ctx, resolver.pool, func(tx pgx.Tx) error {
		if err := lockNodeScope(ctx, tx, candidate.scopeID); err != nil {
			return err
		}
		current, err := lockNode(ctx, tx, candidate.scopeID, candidate.id)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !slices.Equal(nodeAddresses(current.IPv4, current.IPv6, current.ManagementSettings.SecondaryIPs), candidate.addresses) {
			return nil // changed meanwhile: the next pass resolves the new addresses
		}
		now := resolver.now().UTC()
		if _, err := tx.Exec(ctx, `INSERT INTO node_ip_location_resolutions(node_id,addresses,outcome,address,country,province,
			city,isp,country_code,library_revision,library_version,resolved_at) VALUES($1,$2,$3,NULLIF($4,'')::inet,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (node_id) DO UPDATE SET addresses=EXCLUDED.addresses,outcome=EXCLUDED.outcome,address=EXCLUDED.address,
			  country=EXCLUDED.country,province=EXCLUDED.province,city=EXCLUDED.city,isp=EXCLUDED.isp,
			  country_code=EXCLUDED.country_code,library_revision=EXCLUDED.library_revision,
			  library_version=EXCLUDED.library_version,resolved_at=EXCLUDED.resolved_at`,
			current.ID, candidate.addresses, outcome, address, automatic.Country, automatic.Province, automatic.City,
			automatic.ISP, automatic.CountryCode, int64(library.Revision), library.Version, now); err != nil {
			return fmt.Errorf("record node IP location resolution: %w", err)
		}
		before := current.ManagementSettings.IPLocation
		effective := effectiveIPLocation(current.ManagementSettings.IPLocationManual, before, automatic)
		if effective == before {
			return nil
		}
		current.ManagementSettings.IPLocation = effective
		updated, err := updateNodeRow(ctx, tx, current, current.Revision, now)
		if err != nil {
			return err
		}
		return resolver.auditor.Append(ctx, tx, audit.Event{
			ScopeID: candidate.scopeID, Action: IPLocationResolveAction, ResourceType: "node",
			ResourceID: updated.ID.String(), RequestID: "node-ip-location." + uuid.NewString(), Result: "success",
			ActorKind: "system", ActorRef: "job:node-ip-location",
			Payload: map[string]any{
				"outcome": outcome, "library_revision": library.Revision, "revision": updated.Revision,
				"changes": map[string]any{"ip_location": map[string]any{"before": before, "after": effective}},
			},
		})
	})
}

// Run resolves at once, then every interval, until ctx ends.
func (resolver *IPLocationResolver) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if written, err := resolver.RunOnce(ctx); err != nil && ctx.Err() == nil {
			resolver.logger.Warn("node IP location resolution failed", "error", err)
		} else if written > 0 {
			resolver.logger.Info("node IP location resolved", "nodes", written)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
