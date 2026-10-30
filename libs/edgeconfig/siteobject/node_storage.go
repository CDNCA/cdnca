package siteobject

import (
	"path"
	"strings"
)

// NodeStorage (NODE_STORAGE v1) is a node's cache
// directory, cache limit and log directory as the control plane sets them,
// carried per node in KeyDocument.NodeStorage. An empty directory or a zero
// limit keeps the node's own default for that item. The node applies the
// cache directory and limit on reload and the log directory on its next
// Agent start.
type NodeStorage struct {
	CacheDirectory string `json:"cache_directory,omitempty"`
	CacheMaxBytes  int64  `json:"cache_max_bytes,omitempty"`
	LogDirectory   string `json:"log_directory,omitempty"`
}

// NodeStorageAPIVersion is the CAPABILITY_NAME_NODE_STORAGE version an Agent
// declares and control needs to write KeyDocument.NodeStorage.
const NodeStorageAPIVersion uint32 = 1

// NodeStoragePrefixes are the roots a node storage directory must lie
// strictly below: never the system, home or temp trees.
var NodeStoragePrefixes = []string{"/data", "/var/cache", "/var/lib", "/var/log", "/opt", "/srv", "/mnt"}

// NodeStorageMinCacheBytes / NodeStorageMaxCacheBytes bound a set cache
// limit: edgecache.PlanPool's 64 MiB floor and 1 PiB (the Agent's own
// cache_max_bytes bounds).
const (
	NodeStorageMinCacheBytes int64 = 64 << 20
	NodeStorageMaxCacheBytes int64 = 1 << 50
)

// ValidNodeStorageDirectory reports whether value may be a node storage
// directory: absolute, clean (no "..", no trailing slash), at most 256
// bytes of [A-Za-z0-9._/-], strictly below one of NodeStoragePrefixes.
func ValidNodeStorageDirectory(value string) bool {
	if len(value) < 2 || len(value) > 256 || path.Clean(value) != value || !strings.HasPrefix(value, "/") {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' ||
			char == '.' || char == '_' || char == '-' || char == '/') {
			return false
		}
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	for _, prefix := range NodeStoragePrefixes {
		if strings.HasPrefix(value, prefix+"/") {
			return true
		}
	}
	return false
}

// NodeStorageDirectoriesOverlap reports whether one directory is the other
// or contains it.
func NodeStorageDirectoriesOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

// Validate checks the settings as a whole: each set directory is valid, the
// two do not overlap, and a set limit is within bounds.
func (storage NodeStorage) Validate() bool {
	for _, directory := range []string{storage.CacheDirectory, storage.LogDirectory} {
		if directory != "" && !ValidNodeStorageDirectory(directory) {
			return false
		}
	}
	if storage.CacheDirectory != "" && storage.LogDirectory != "" &&
		NodeStorageDirectoriesOverlap(storage.CacheDirectory, storage.LogDirectory) {
		return false
	}
	return storage.CacheMaxBytes == 0 ||
		storage.CacheMaxBytes >= NodeStorageMinCacheBytes && storage.CacheMaxBytes <= NodeStorageMaxCacheBytes
}

// NodeStorageStates are NodeStorageV1.state's values.
var NodeStorageStates = map[string]bool{"applied": true, "default": true, "failed": true, "restart_pending": true}

// ValidNodeStorageReport checks a reported NodeStorageV1 (gateway and
// control plane): absolute clean directories (any root: a node default may
// lie outside the allowed prefixes), a known state, a reason (≤512 bytes,
// one line) exactly when failed, and a requested log directory exactly
// when restart_pending.
func ValidNodeStorageReport(cacheDirectory, logDirectory, state, reason, requestedLogDirectory string, cacheMaxBytes uint64) bool {
	for _, directory := range []string{cacheDirectory, logDirectory} {
		if directory == "" || len(directory) > 4096 || path.Clean(directory) != directory || !strings.HasPrefix(directory, "/") ||
			strings.ContainsAny(directory, "\x00\r\n") {
			return false
		}
	}
	if !NodeStorageStates[state] || (state == "failed") != (reason != "") || len(reason) > 512 ||
		strings.ContainsAny(reason, "\x00\r\n") || cacheMaxBytes > uint64(NodeStorageMaxCacheBytes) {
		return false
	}
	if state == "restart_pending" {
		return ValidNodeStorageDirectory(requestedLogDirectory)
	}
	return requestedLogDirectory == ""
}

// IsZero: nothing set, the node runs its defaults.
func (storage NodeStorage) IsZero() bool { return storage == NodeStorage{} }
