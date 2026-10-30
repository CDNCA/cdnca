package node

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// Node storage (NODE_STORAGE v1, fix-nodesettings): the cache directory,
// cache limit (GB) and log directory of the 节点设置 tab go to the node in
// its key documents (siteobject.KeyDocument.NodeStorage).

// MaxCacheLimitGB bounds cache_limit_gb (siteobject.NodeStorageMaxCacheBytes).
const MaxCacheLimitGB = uint64(siteobject.NodeStorageMaxCacheBytes >> 30)

// Storage is the settings' node storage (0 GB / "" = the node's default).
func (settings NodeManagementSettings) Storage() siteobject.NodeStorage {
	return siteobject.NodeStorage{CacheDirectory: settings.CacheDirectory, CacheMaxBytes: int64(settings.CacheLimitGB) << 30,
		LogDirectory: settings.LogDirectory}
}

func sameStorage(left, right NodeManagementSettings) bool {
	return left.CacheDirectory == right.CacheDirectory && left.CacheLimitGB == right.CacheLimitGB &&
		left.LogDirectory == right.LogDirectory
}

// checkStorageChange admits a change of the node storage: valid settings,
// an Agent declaring NODE_STORAGE, and a cache limit within the size of the
// disk the node last reported for the cache directory (no report: not
// checked here, the node caps it at its file system).
func checkStorageChange(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, before, after NodeManagementSettings) error {
	if sameStorage(before, after) {
		return nil
	}
	storage := after.Storage()
	if after.CacheLimitGB > MaxCacheLimitGB || !storage.Validate() {
		return ErrInvalidInput
	}
	var snapshot, telemetry []byte
	err := tx.QueryRow(ctx, `SELECT
		(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts
		 WHERE facts.node_id=$1 ORDER BY facts.session_epoch DESC LIMIT 1),
		(SELECT metric.telemetry_json FROM node_load_latest metric WHERE metric.node_id=$1)`, nodeID).Scan(&snapshot, &telemetry)
	if err != nil {
		return err
	}
	if !DeclaresStorage(snapshot) {
		return ErrStorageUnsupported
	}
	if storage.CacheMaxBytes > 0 {
		if size := cacheDiskBytes(telemetry, after.CacheDirectory); size > 0 && uint64(storage.CacheMaxBytes) > size {
			return ErrStorageExceedsDisk
		}
	}
	return nil
}

// DeclaresStorage: an AgentCapabilities snapshot declares NODE_STORAGE v1.
func DeclaresStorage(snapshot []byte) bool {
	var capabilities agentv1.AgentCapabilities
	if len(snapshot) == 0 || proto.Unmarshal(snapshot, &capabilities) != nil {
		return false
	}
	for _, capability := range capabilities.GetFeatures() {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_NODE_STORAGE &&
			capability.GetApiVersion() >= siteobject.NodeStorageAPIVersion {
			return true
		}
	}
	return false
}

// storageTelemetry is the part of a stored node telemetry sample
// (nodemetrics.Telemetry JSON) the cache limit check reads.
type storageTelemetry struct {
	Disks []struct {
		Path       string `json:"path"`
		TotalBytes uint64 `json:"total_bytes"`
	} `json:"disks"`
	Storage *struct {
		CacheDirectory string `json:"cache_directory"`
	} `json:"storage"`
}

func decodeStorageTelemetry(raw []byte) (storageTelemetry, bool) {
	var report storageTelemetry
	if len(raw) == 0 || json.Unmarshal(raw, &report) != nil {
		return storageTelemetry{}, false
	}
	return report, true
}

// cacheDiskBytes is the total size of the reported disk holding directory
// (the longest disk path prefix; "" = the cache directory the node runs),
// 0 when unknown.
func cacheDiskBytes(telemetry []byte, directory string) uint64 {
	report, ok := decodeStorageTelemetry(telemetry)
	if !ok {
		return 0
	}
	if directory == "" && report.Storage != nil {
		directory = report.Storage.CacheDirectory
	}
	if directory == "" {
		return 0
	}
	best, size := -1, uint64(0)
	for _, disk := range report.Disks {
		if (disk.Path == "/" || directory == disk.Path || strings.HasPrefix(directory, disk.Path+"/")) && len(disk.Path) > best {
			best, size = len(disk.Path), disk.TotalBytes
		}
	}
	return size
}
