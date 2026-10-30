package edgeautopublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NodeNetworksSourceID is the source resource of node_networks
// republication requests: the platform's node address set, not a row.
var NodeNetworksSourceID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("cdnca.edge.node-networks"))

// NodeNetworksRepublishAction is the audit event of a sweep that found the
// node addresses changed and queued the republications.
const NodeNetworksRepublishAction = "node.networks.republish"

// NodeNetworksWatcher republishes, through the system channel (trigger
// node_networks, due at once), every tenant scope whose latest release
// exempts other node addresses from DDoS protection than the current ones:
// a node was added, retired or deleted, or its
// IPv4/IPv6 or secondary IPs changed. It acts when the canonical address set
// differs from the one it last acted on (edge_node_network_marks).
type NodeNetworksWatcher struct {
	pool     *pgxpool.Pool
	auditor  edgepublish.AuditAppender
	interval time.Duration
	now      func() time.Time
	last     time.Time
}

func NewNodeNetworksWatcher(pool *pgxpool.Pool, auditor edgepublish.AuditAppender, interval time.Duration) (*NodeNetworksWatcher, error) {
	if pool == nil || auditor == nil || interval < 0 || interval > time.Hour {
		return nil, ErrInvalidInput
	}
	return &NodeNetworksWatcher{pool: pool, auditor: auditor, interval: interval, now: time.Now}, nil
}

// RunOnce sweeps at most once per interval (the runtime polls faster).
func (watcher *NodeNetworksWatcher) RunOnce(ctx context.Context) (bool, error) {
	if watcher == nil || ctx == nil {
		return false, ErrInvalidInput
	}
	now := watcher.now()
	if !watcher.last.IsZero() && now.Sub(watcher.last) < watcher.interval {
		return false, nil
	}
	watcher.last = now
	scopes, err := watcher.SweepOnce(ctx)
	return len(scopes) > 0, err
}

// SweepOnce returns the scopes it queued, in scope order.
func (watcher *NodeNetworksWatcher) SweepOnce(ctx context.Context) ([]uuid.UUID, error) {
	var queued []uuid.UUID
	err := pgx.BeginFunc(ctx, watcher.pool, func(tx pgx.Tx) error {
		queued = nil
		networks, err := edgepublish.CurrentNodeNetworksTx(ctx, tx)
		if err != nil {
			return err
		}
		// Node regions are part of the mark: a node changing region changes
		// its nginx base under region overrides.
		regions, err := edgepublish.NodeRegionsTx(ctx, tx)
		if err != nil {
			return err
		}
		digest := sha256.Sum256([]byte(strings.Join(networks, "\n") + "\x00" + strings.Join(regions, "\n")))
		regionDigest := sha256.Sum256([]byte(strings.Join(regions, "\n")))
		var previous, previousRegions []byte
		var previousCount int
		err = tx.QueryRow(ctx, `SELECT networks_sha256,network_count,regions_sha256 FROM edge_node_network_marks WHERE singleton FOR UPDATE`).
			Scan(&previous, &previousCount, &previousRegions)
		first := errors.Is(err, pgx.ErrNoRows)
		if err != nil && !first {
			return err
		}
		// Each node's storage settings (NODE_STORAGE) ride
		// in its key documents: a change republishes every tenant scope with
		// trigger node_storage (none recorded yet, as after migration 538:
		// the sweep only records it).
		storageDigest, err := edgepublish.NodeStorageDigestTx(ctx, tx)
		if err != nil {
			return err
		}
		var previousStorage []byte
		if !first {
			if err := tx.QueryRow(ctx, `SELECT storage_sha256 FROM edge_node_network_marks WHERE singleton`).Scan(&previousStorage); err != nil {
				return err
			}
		}
		if previousStorage != nil && !bytes.Equal(previousStorage, storageDigest) {
			storageScopes, err := watcher.republishStorage(ctx, tx, previousStorage, storageDigest)
			if err != nil {
				return err
			}
			queued = storageScopes
		}
		if !first && !bytes.Equal(previousStorage, storageDigest) {
			if _, err := tx.Exec(ctx, `UPDATE edge_node_network_marks SET storage_sha256=$1 WHERE singleton`, storageDigest); err != nil {
				return err
			}
		}
		// A node's IP 归属 (automatic or corrected) moves the
		// L2 node conditions matching it; scopes with such a condition go out
		// again (none recorded yet, as after migration 547: only recorded).
		locationsDigest, err := edgepublish.NodeLocationsDigestTx(ctx, tx)
		if err != nil {
			return err
		}
		var previousLocations []byte
		if !first {
			if err := tx.QueryRow(ctx, `SELECT locations_sha256 FROM edge_node_network_marks WHERE singleton`).Scan(&previousLocations); err != nil {
				return err
			}
		}
		if previousLocations != nil && !bytes.Equal(previousLocations, locationsDigest) {
			locationScopes, err := edgepublish.NodeLocationScopesTx(ctx, tx)
			if err != nil {
				return err
			}
			requestID := "node-locations." + uuid.NewSHA1(NodeNetworksSourceID, locationsDigest).String()
			for _, scopeID := range locationScopes {
				if _, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
					ScopeID: scopeID, Trigger: edgepublish.SystemTriggerNodeNetworks, SourceResourceID: NodeNetworksSourceID,
					SourceRequestID: requestID, Immediate: true,
				}); err != nil {
					return err
				}
			}
			queued = mergeScopeIDs(queued, locationScopes)
		}
		if !first && !bytes.Equal(previousLocations, locationsDigest) {
			if _, err := tx.Exec(ctx, `UPDATE edge_node_network_marks SET locations_sha256=$1 WHERE singleton`, locationsDigest); err != nil {
				return err
			}
		}
		if !first && bytes.Equal(previous, digest[:]) {
			return nil
		}
		scopes, err := edgepublish.StaleNodeNetworkScopesTx(ctx, tx, networks)
		if err != nil {
			return err
		}
		nginxScopes, err := edgepublish.StaleNodeNginxScopesTx(ctx, tx)
		if err != nil {
			return err
		}
		scopes = mergeScopeIDs(scopes, nginxScopes)
		// fz-x12: a node's region code rides in its key documents, so a
		// changed region assignment republishes every tenant scope (none
		// recorded yet: the first sweep only records it).
		if previousRegions != nil && !bytes.Equal(previousRegions, regionDigest[:]) {
			regionScopes, err := edgepublish.NodeRegionScopesTx(ctx, tx)
			if err != nil {
				return err
			}
			scopes = mergeScopeIDs(scopes, regionScopes)
		}
		requestID := "node-networks." + uuid.NewSHA1(NodeNetworksSourceID, digest[:]).String()
		for _, scopeID := range scopes {
			if _, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
				ScopeID: scopeID, Trigger: edgepublish.SystemTriggerNodeNetworks, SourceResourceID: NodeNetworksSourceID,
				SourceRequestID: requestID, Immediate: true,
			}); err != nil {
				return err
			}
		}
		queued = mergeScopeIDs(queued, scopes)
		if len(scopes) > 0 || !first {
			if err := watcher.audit(ctx, tx, requestID, first, previousCount, len(networks), scopes); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO edge_node_network_marks(singleton,networks_sha256,network_count,observed_at,regions_sha256,storage_sha256,locations_sha256)
			VALUES(true,$1,$2,clock_timestamp(),$3,$4,$5)
			ON CONFLICT (singleton) DO UPDATE SET networks_sha256=EXCLUDED.networks_sha256,
			  network_count=EXCLUDED.network_count,observed_at=EXCLUDED.observed_at,regions_sha256=EXCLUDED.regions_sha256`,
			digest[:], len(networks), regionDigest[:], storageDigest, locationsDigest)
		return err
	})
	return queued, err
}

// republishStorage queues every tenant scope with trigger node_storage and
// audits it (the node networks action, trigger node_storage).
func (watcher *NodeNetworksWatcher) republishStorage(ctx context.Context, tx pgx.Tx, previousDigest, storageDigest []byte) ([]uuid.UUID, error) {
	scopes, err := edgepublish.NodeRegionScopesTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	requestID := "node-storage." + uuid.NewSHA1(NodeNetworksSourceID, storageDigest).String()
	for _, scopeID := range scopes {
		if _, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
			ScopeID: scopeID, Trigger: edgepublish.SystemTriggerNodeStorage, SourceResourceID: NodeNetworksSourceID,
			SourceRequestID: requestID, Immediate: true,
		}); err != nil {
			return nil, err
		}
	}
	var platformScopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScopeID); err != nil {
		return nil, err
	}
	scopeIDs := make([]string, 0, len(scopes))
	for _, scopeID := range scopes {
		scopeIDs = append(scopeIDs, scopeID.String())
	}
	return scopes, watcher.auditor.Append(ctx, tx, audit.Event{
		ScopeID: platformScopeID, Action: NodeNetworksRepublishAction, ResourceType: "node_networks",
		ResourceID: NodeNetworksSourceID.String(), RequestID: requestID, Result: "success",
		Payload: map[string]any{
			"actor": "system", "ip": "", "trigger": edgepublish.SystemTriggerNodeStorage,
			"object_type": "node_networks", "object_id": NodeNetworksSourceID.String(),
			"scope_count": len(scopes), "scope_ids": scopeIDs,
			"changes": map[string]any{"node_storage_sha256": map[string]any{"before": hex.EncodeToString(previousDigest), "after": hex.EncodeToString(storageDigest)}},
		},
	})
}

// mergeScopeIDs is the sorted union of two scope order lists.
func mergeScopeIDs(left, right []uuid.UUID) []uuid.UUID {
	merged := append(slices.Clone(left), right...)
	slices.SortFunc(merged, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(merged)
}

func (watcher *NodeNetworksWatcher) audit(ctx context.Context, tx pgx.Tx, requestID string, first bool,
	previousCount, count int, scopes []uuid.UUID) error {
	var platformScopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScopeID); err != nil {
		return err
	}
	scopeIDs := make([]string, 0, len(scopes))
	for _, scopeID := range scopes {
		scopeIDs = append(scopeIDs, scopeID.String())
	}
	before := any(previousCount)
	if first {
		before = nil
	}
	return watcher.auditor.Append(ctx, tx, audit.Event{
		ScopeID: platformScopeID, Action: NodeNetworksRepublishAction, ResourceType: "node_networks",
		ResourceID: NodeNetworksSourceID.String(), RequestID: requestID, Result: "success",
		Payload: map[string]any{
			"actor": "system", "ip": "", "trigger": edgepublish.SystemTriggerNodeNetworks,
			"object_type": "node_networks", "object_id": NodeNetworksSourceID.String(),
			"scope_count": len(scopes), "scope_ids": scopeIDs,
			"changes": map[string]any{"node_network_count": map[string]any{"before": before, "after": count}},
		},
	})
}
