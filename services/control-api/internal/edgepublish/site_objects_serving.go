package edgepublish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Published serving nodes (migration 702).
// The websites and forwards a node's key document withholds follow the nodes
// serving each (siteServingNodes, streamServingNodes). A release records the
// ones it used. A release that publishes no tenant row of its own (a stop
// overlay, a node settings redelivery) takes them from the releases its
// content comes from, never from the current rows: a line group change the
// tenant has not published would otherwise stop a website on its old nodes
// while its new ones do not get the release, unavailable everywhere. Only an
// explicit stop (a traffic stop, a package out of publication) takes a
// website or a forward off the nodes before the tenant publishes: the overlay
// drops them from its content, a redelivery withholds them (releaseStops).

// releaseServing is a release's serving nodes per website and forward ID. A
// key with a nil set has no live line group to go by (served by every target
// node); an ID absent from the map was not in the release.
type releaseServing struct {
	sites, streams map[string]map[uuid.UUID]struct{}
}

type storedServing struct {
	NodeSets [][]uuid.UUID   `json:"node_sets"`
	Sites    map[string]*int `json:"sites"`
	Streams  map[string]*int `json:"streams"`
}

// releaseServingNodes is the serving nodes of a release's websites and
// forwards: from the current rows without from; else from the first of the
// from releases that recorded each, and from the current rows only for one
// none recorded (a release published before migration 702).
func releaseServingNodes(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, siteIDs []string,
	streams *edgeconfig.StreamRuntime, from []uuid.UUID) (releaseServing, error) {
	var recorded []releaseServing
	if len(from) > 0 {
		var err error
		if recorded, err = loadReleaseServing(ctx, tx, scopeID, from); err != nil {
			return releaseServing{}, err
		}
	}
	serving := releaseServing{sites: map[string]map[uuid.UUID]struct{}{}, streams: map[string]map[uuid.UUID]struct{}{}}
	take := func(id string, pick func(releaseServing) map[string]map[uuid.UUID]struct{},
		into map[string]map[uuid.UUID]struct{}) bool {
		for _, release := range recorded {
			if nodes, listed := pick(release)[id]; listed {
				into[id] = nodes
				return true
			}
		}
		return false
	}
	var missingSites []string
	for _, id := range siteIDs {
		if !take(id, func(release releaseServing) map[string]map[uuid.UUID]struct{} { return release.sites }, serving.sites) {
			missingSites = append(missingSites, id)
		}
	}
	var missingStreams *edgeconfig.StreamRuntime
	if streams != nil {
		missing := *streams
		missing.StreamsV2 = nil
		for _, stream := range streams.StreamsV2 {
			if !take(stream.StreamID, func(release releaseServing) map[string]map[uuid.UUID]struct{} { return release.streams },
				serving.streams) {
				missing.StreamsV2 = append(missing.StreamsV2, stream)
			}
		}
		missingStreams = &missing
	}
	current, err := siteServingNodes(ctx, tx, scopeID, missingSites)
	if err != nil {
		return releaseServing{}, err
	}
	for _, id := range missingSites {
		serving.sites[id] = current[id]
	}
	currentStreams, err := streamServingNodes(ctx, tx, scopeID, missingStreams)
	if err != nil {
		return releaseServing{}, err
	}
	if missingStreams != nil {
		for _, stream := range missingStreams.StreamsV2 {
			serving.streams[stream.StreamID] = currentStreams[stream.StreamID]
		}
	}
	return serving, nil
}

// resolved is the map withheldSitesFor and withheldStreamsFor take: the IDs
// with a set only.
func resolved(serving map[string]map[uuid.UUID]struct{}) map[string]map[uuid.UUID]struct{} {
	result := make(map[string]map[uuid.UUID]struct{}, len(serving))
	for id, nodes := range serving {
		if nodes != nil {
			result[id] = nodes
		}
	}
	return result
}

// withStops is serving with the stopped IDs served by no node.
func withStops(serving map[string]map[uuid.UUID]struct{}, stopped []string) map[string]map[uuid.UUID]struct{} {
	result := resolved(serving)
	for _, id := range stopped {
		if _, present := serving[id]; present {
			result[id] = map[uuid.UUID]struct{}{}
		}
	}
	return result
}

func loadReleaseServing(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, from []uuid.UUID) ([]releaseServing, error) {
	rows, err := tx.Query(ctx, `SELECT config_version_id,serving FROM edge_publication_serving_nodes
		WHERE configuration_scope_id=$1 AND config_version_id=ANY($2::uuid[])`, scopeID, from)
	if err != nil {
		return nil, fmt.Errorf("%w: read release serving nodes", ErrPersistence)
	}
	defer rows.Close()
	byConfig := map[uuid.UUID]releaseServing{}
	for rows.Next() {
		var configID uuid.UUID
		var raw []byte
		if err := rows.Scan(&configID, &raw); err != nil {
			return nil, fmt.Errorf("%w: scan release serving nodes", ErrPersistence)
		}
		var stored storedServing
		if err := json.Unmarshal(raw, &stored); err != nil {
			return nil, fmt.Errorf("%w: decode release serving nodes", ErrPersistence)
		}
		release := releaseServing{sites: map[string]map[uuid.UUID]struct{}{}, streams: map[string]map[uuid.UUID]struct{}{}}
		for into, entries := range map[*map[string]map[uuid.UUID]struct{}]map[string]*int{
			&release.sites: stored.Sites, &release.streams: stored.Streams} {
			for id, index := range entries {
				if index == nil {
					(*into)[id] = nil
					continue
				}
				if *index < 0 || *index >= len(stored.NodeSets) {
					return nil, fmt.Errorf("%w: release serving node set index", ErrPersistence)
				}
				nodes := make(map[uuid.UUID]struct{}, len(stored.NodeSets[*index]))
				for _, nodeID := range stored.NodeSets[*index] {
					nodes[nodeID] = struct{}{}
				}
				(*into)[id] = nodes
			}
		}
		byConfig[configID] = release
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate release serving nodes", ErrPersistence)
	}
	ordered := make([]releaseServing, 0, len(from))
	for _, configID := range from {
		if release, found := byConfig[configID]; found {
			ordered = append(ordered, release)
		}
	}
	return ordered, nil
}

// persistReleaseServing records serving for configID (one node set per
// distinct set of nodes).
func persistReleaseServing(ctx context.Context, tx pgx.Tx, scopeID, configID uuid.UUID, serving releaseServing,
	now time.Time) error {
	stored := storedServing{NodeSets: [][]uuid.UUID{}, Sites: map[string]*int{}, Streams: map[string]*int{}}
	indexes := map[string]int{}
	encode := func(entries map[string]map[uuid.UUID]struct{}, into map[string]*int) {
		for id, nodes := range entries {
			if nodes == nil {
				into[id] = nil
				continue
			}
			set := make([]uuid.UUID, 0, len(nodes))
			for nodeID := range nodes {
				set = append(set, nodeID)
			}
			slices.SortFunc(set, func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) })
			keys := make([]string, len(set))
			for position, nodeID := range set {
				keys[position] = nodeID.String()
			}
			key := strings.Join(keys, ",")
			index, found := indexes[key]
			if !found {
				index = len(stored.NodeSets)
				indexes[key] = index
				stored.NodeSets = append(stored.NodeSets, set)
			}
			into[id] = &index
		}
	}
	encode(serving.sites, stored.Sites)
	encode(serving.streams, stored.Streams)
	raw, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("%w: encode release serving nodes", ErrInvalidInput)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO edge_publication_serving_nodes(config_version_id,configuration_scope_id,serving,created_at)
		VALUES($1,$2,$3,$4)`, configID, scopeID, raw, now); err != nil {
		return fmt.Errorf("%w: persist release serving nodes", ErrPersistence)
	}
	return nil
}

// releaseStops are the websites and forwards of a node settings redelivery's
// base that an explicit stop holds now, withheld on every node: the base's
// content goes out as it is, a stop since it does not wait for the scope's
// next publication.
type releaseStops struct {
	sites, streams []string
}

func loadReleaseStops(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, siteIDs []string,
	streams *edgeconfig.StreamRuntime) (releaseStops, error) {
	parse := func(values []string) ([]uuid.UUID, error) {
		ids := make([]uuid.UUID, 0, len(values))
		for _, value := range values {
			id, err := uuid.Parse(value)
			if err != nil {
				return nil, fmt.Errorf("%w: release resource id", ErrInvalidInput)
			}
			ids = append(ids, id)
		}
		return ids, nil
	}
	sites, err := parse(siteIDs)
	if err != nil {
		return releaseStops{}, err
	}
	var streamIDs []string
	if streams != nil {
		for _, stream := range streams.StreamsV2 {
			streamIDs = append(streamIDs, stream.StreamID)
		}
	}
	forwards, err := parse(streamIDs)
	if err != nil {
		return releaseStops{}, err
	}
	stoppedSites, err := stoppedSiteIDs(ctx, tx, scopeID, sites)
	if err != nil {
		return releaseStops{}, err
	}
	stoppedStreams, err := stoppedStreamIDs(ctx, tx, scopeID, forwards)
	if err != nil {
		return releaseStops{}, err
	}
	var stops releaseStops
	for _, id := range stoppedSites {
		stops.sites = append(stops.sites, id.String())
	}
	for _, id := range stoppedStreams {
		stops.streams = append(stops.streams, id.String())
	}
	return stops, nil
}

// stoppedSiteIDs are the published websites a system stop holds now (traffic
// over limit, domain claim, overdue secondary verification that disabled the
// site) or whose package is no longer in effect (none, a disabled or deleted
// one; a suspended one: migration 555; a cancelled one:
// user).
func stoppedSiteIDs(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, published []uuid.UUID) ([]uuid.UUID, error) {
	if len(published) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT site.id FROM sites site WHERE site.scope_id=$1 AND site.id=ANY($2::uuid[]) AND (
		site.package_subscription_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM package_subscriptions package_subscription
		  WHERE package_subscription.tenant_scope_id=site.scope_id AND package_subscription.id=site.package_subscription_id
		    AND `+packageInEffectSQL("package_subscription")+`) OR
		EXISTS(SELECT 1 FROM package_traffic_site_suspensions open WHERE open.site_id=site.id AND open.recovered_at IS NULL) OR
		EXISTS(SELECT 1 FROM domain_claim_suspensions claim WHERE claim.site_id=site.id AND claim.released_at IS NULL) OR
		EXISTS(SELECT 1 FROM identity_secondary_verification_site_holds hold WHERE hold.site_id=site.id
		  AND hold.released_at IS NULL AND hold.disabled_site))
		ORDER BY site.id`, scopeID, published)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// stoppedStreamIDs are the published forwards an open package traffic stop
// holds (migration 508) or whose package is no longer in effect.
func stoppedStreamIDs(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, published []uuid.UUID) ([]uuid.UUID, error) {
	if len(published) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT suspension.stream_id FROM package_traffic_stream_suspensions suspension
		WHERE suspension.tenant_scope_id=$1 AND suspension.stream_id=ANY($2::uuid[]) AND suspension.recovered_at IS NULL
		UNION SELECT forward.id FROM l4_forwards forward
		WHERE forward.scope_id=$1 AND forward.id=ANY($2::uuid[]) AND forward.package_subscription_id IS NOT NULL AND NOT EXISTS(
		  SELECT 1 FROM package_subscriptions package_subscription
		  WHERE package_subscription.id=forward.package_subscription_id AND package_subscription.tenant_scope_id=forward.scope_id
		    AND `+packageInEffectSQL("package_subscription")+`)
		ORDER BY 1`, scopeID, published)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}
