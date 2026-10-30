package edgepublish

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Node storage (NODE_STORAGE v1, fix-nodesettings): the cache directory,
// cache limit and log directory of a node's 节点设置 (nodes.
// management_settings) ride in its key documents
// (siteobject.KeyDocument.NodeStorage) to an Agent declaring the
// capability. A change republishes every tenant scope
// (edgeautopublish.NodeNetworksWatcher, trigger node_storage).

const nodeStorageSelect = `SELECT id, COALESCE(management_settings->>'cache_directory',''),
	COALESCE((management_settings->>'cache_limit_gb')::bigint,0), COALESCE(management_settings->>'log_directory','')
	FROM nodes`

func scanNodeStorage(rows pgx.Rows) (uuid.UUID, siteobject.NodeStorage, error) {
	var nodeID uuid.UUID
	var storage siteobject.NodeStorage
	var limitGB int64
	if err := rows.Scan(&nodeID, &storage.CacheDirectory, &limitGB, &storage.LogDirectory); err != nil {
		return uuid.Nil, siteobject.NodeStorage{}, err
	}
	if limitGB < 0 || limitGB > siteobject.NodeStorageMaxCacheBytes>>30 {
		limitGB = 0
	}
	storage.CacheMaxBytes = limitGB << 30
	return nodeID, storage, nil
}

// loadNodeStorage maps each node to its set storage; a node with none set,
// or with settings that are not valid (stored before this check), is absent.
func loadNodeStorage(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) (map[uuid.UUID]siteobject.NodeStorage, error) {
	rows, err := tx.Query(ctx, nodeStorageSelect+` WHERE id=ANY($1::uuid[])`, nodeIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: load node storage", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]siteobject.NodeStorage, len(nodeIDs))
	for rows.Next() {
		nodeID, storage, err := scanNodeStorage(rows)
		if err != nil {
			return nil, fmt.Errorf("%w: scan node storage", ErrPersistence)
		}
		if !storage.IsZero() && storage.Validate() {
			result[nodeID] = storage
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate node storage", ErrPersistence)
	}
	return result, nil
}

// nodeStorageFor is the storage a node's key document carries: only for an
// Agent declaring NODE_STORAGE and only when some setting is set.
func nodeStorageFor(advertised []*agentv1.Capability, storage siteobject.NodeStorage, set bool) *siteobject.NodeStorage {
	if !set {
		return nil
	}
	for _, capability := range advertised {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_NODE_STORAGE &&
			capability.GetApiVersion() >= siteobject.NodeStorageAPIVersion {
			return &storage
		}
	}
	return nil
}

// NodeStorageDigestTx digests every live node's storage settings, in node
// order: the watcher republishes when it moves.
func NodeStorageDigestTx(ctx context.Context, tx pgx.Tx) ([]byte, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, nodeStorageSelect+` WHERE admin_state<>'retired' ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("%w: load node storage", ErrPersistence)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		nodeID, storage, err := scanNodeStorage(rows)
		if err != nil {
			return nil, fmt.Errorf("%w: scan node storage", ErrPersistence)
		}
		if storage.IsZero() || !storage.Validate() {
			continue
		}
		lines = append(lines, nodeID.String()+"\x00"+storage.CacheDirectory+"\x00"+
			strconv.FormatInt(storage.CacheMaxBytes, 10)+"\x00"+storage.LogDirectory)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate node storage", ErrPersistence)
	}
	digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return digest[:], nil
}
