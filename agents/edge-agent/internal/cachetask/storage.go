package cachetask

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"golang.org/x/sys/unix"
)

const (
	maxTaskStateBytes               = 16 << 20
	maxTombstoneShardBytes          = 8 << 20
	tombstoneRecordBytes            = sha256.Size
	cachePolicyBindingSchemaVersion = 1
)

var errRecordCancelled = errors.New("cache task record cancelled")

type recordState string
type recordItemStatus string

const (
	recordRunning   recordState = "running"
	recordDone      recordState = "done"
	recordCancelled recordState = "cancelled"

	recordPending recordItemStatus = "pending"
	recordWorking recordItemStatus = "working"
	recordSuccess recordItemStatus = "success"
	recordSkipped recordItemStatus = "skipped"
	recordFailed  recordItemStatus = "failed"
)

type itemRecord struct {
	Index              int              `json:"index"`
	Target             string           `json:"target"`
	TargetDigest       string           `json:"target_digest"`
	Path               string           `json:"path"`
	Status             recordItemStatus `json:"status"`
	Code               string           `json:"code,omitempty"`
	CauseCode          string           `json:"cause_code,omitempty"`
	Affected           int              `json:"affected"`
	Bytes              int64            `json:"bytes"`
	ReservedBytes      int64            `json:"reserved_bytes,omitempty"`
	Attempts           int              `json:"attempts"`
	DestructiveStarted bool             `json:"destructive_started,omitempty"`
	DeleteIntent       *deleteIntent    `json:"delete_intent,omitempty"`
	NextAttemptAt      time.Time        `json:"next_attempt_at,omitempty"`
	CompletedAt        time.Time        `json:"completed_at,omitempty"`
}

type deleteIntent struct {
	// Area is empty for the site cache namespace, or "range/<identity>" for a
	// listener's Range slice cache directory.
	Area     string `json:"area,omitempty"`
	Relative string `json:"relative"`
	Size     int64  `json:"size"`
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
}

type taskMetadata struct {
	SchemaVersion   int            `json:"schema_version"`
	TaskID          string         `json:"task_id"`
	OperationID     string         `json:"operation_id"`
	TenantID        string         `json:"tenant_id"`
	SiteID          string         `json:"site_id"`
	Scope           Scope          `json:"scope"`
	ConfigVersionID string         `json:"config_version_id"`
	ConfigRevision  uint64         `json:"config_revision"`
	Deadline        time.Time      `json:"deadline"`
	Budget          ResourceBudget `json:"budget"`
	Action          Action         `json:"action"`
	ItemCount       int            `json:"item_count"`
}

type listenerBinding struct {
	Domain            string `json:"domain"`
	Scheme            string `json:"scheme"`
	ListenPort        uint16 `json:"listen_port"`
	PrewarmPort       uint16 `json:"prewarm_port"`
	PrewarmPathPrefix string `json:"prewarm_path_prefix"`
	CacheEnabled      bool   `json:"cache_enabled"`
	CacheFreshness    bool   `json:"cache_freshness,omitempty"`
}

type siteBinding struct {
	ActiveReleaseSHA256      string                         `json:"active_release_sha256,omitempty"`
	NginxSHA256              string                         `json:"nginx_sha256,omitempty"`
	CacheIdentity            string                         `json:"cache_identity"`
	CachePolicySchemaVersion int                            `json:"cache_policy_schema_version"`
	CachePolicySHA256        string                         `json:"cache_policy_sha256"`
	QueryMode                edgeconfig.CacheQueryMode      `json:"query_mode"`
	QueryNames               []string                       `json:"query_names"`
	VaryHeaders              []string                       `json:"vary_headers"`
	CacheRules               []edgeconfig.CacheRuleDocument `json:"cache_rules"`
	Listeners                []listenerBinding              `json:"listeners"`
	// Domains: SiteContext.Domains (omitted when the site serves only its key domain).
	Domains []string `json:"domains,omitempty"`
	// KeyByHost: SiteContext.KeyByHost.
	KeyByHost bool `json:"key_by_host,omitempty"`
	// CacheGeneration: SiteContext.CacheGeneration (site runtime v2).
	CacheGeneration string `json:"cache_generation,omitempty"`
}

type taskRecord struct {
	SchemaVersion          int          `json:"schema_version"`
	Digest                 string       `json:"digest"`
	Task                   taskMetadata `json:"task"`
	Binding                siteBinding  `json:"site_binding"`
	State                  recordState  `json:"state"`
	ExecutionAttempt       int          `json:"execution_attempt"`
	HighestDeliveryAttempt int          `json:"highest_delivery_attempt"`
	StartedAt              time.Time    `json:"started_at"`
	CompletedAt            time.Time    `json:"completed_at,omitempty"`
	CancelRequestedAt      time.Time    `json:"cancel_requested_at,omitempty"`
	Items                  []itemRecord `json:"items"`
}

type registryEntry struct {
	TaskID      string `json:"task_id"`
	OperationID string `json:"operation_id"`
	Digest      string `json:"digest"`
}

type registry struct {
	SchemaVersion int                      `json:"schema_version"`
	Tasks         map[string]registryEntry `json:"tasks"`
	Operations    map[string]registryEntry `json:"operations"`
}

type diskStore struct {
	stateRoot           string
	cacheRoot           string
	root                string
	tasksDir            string
	locksDir            string
	tmpDir              string
	tombstonesDir       string
	registryPath        string
	stateLock           string
	writeJSON           func(string, string, any) error
	writeBytes          func(string, string, []byte, int) error
	removeFile          func(string) error
	syncDir             func(string) error
	fsyncParent         func(int) error
	unlinkEntry         func(cacheEntry) (bool, error)
	beforeTombstoneRead func(string)
	config              Config
}

func newDiskStore(configuredRoot string, config Config) (*diskStore, error) {
	if configuredRoot == "" || !filepath.IsAbs(configuredRoot) || filepath.Clean(configuredRoot) != configuredRoot ||
		configuredRoot == string(filepath.Separator) {
		return nil, ErrInvalidState
	}
	info, err := os.Lstat(configuredRoot)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, ErrInvalidState
	}
	realRoot, err := filepath.EvalSymlinks(configuredRoot)
	if err != nil || realRoot == string(filepath.Separator) {
		return nil, ErrInvalidState
	}
	sharedRoot := filepath.Join(realRoot, "shared")
	cacheRoot := filepath.Join(sharedRoot, "cache")
	if err := ensureCacheParentDirectory(sharedRoot); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(cacheRoot); err != nil {
		return nil, err
	}
	stateDir := filepath.Join(realRoot, "state")
	if err := ensurePrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	root := filepath.Join(stateDir, "cache-tasks")
	store := &diskStore{
		stateRoot: realRoot, cacheRoot: cacheRoot, root: root,
		tasksDir: filepath.Join(root, "tasks"), locksDir: filepath.Join(root, "locks"),
		tmpDir: filepath.Join(root, "tmp"), tombstonesDir: filepath.Join(root, "tombstones"),
		registryPath: filepath.Join(root, "registry.json"), stateLock: filepath.Join(root, "state.lock"),
		writeJSON: writeStateJSON, writeBytes: writeStateBytes, removeFile: os.Remove,
		syncDir: syncDirectory, fsyncParent: unix.Fsync, config: config,
	}
	store.unlinkEntry = func(entry cacheEntry) (bool, error) {
		return unlinkCacheEntryWithFsync(entry, store.fsyncParent)
	}
	for _, directory := range []string{store.root, store.tasksDir, store.locksDir, store.tmpDir, store.tombstonesDir} {
		if err := ensurePrivateDirectory(directory); err != nil {
			return nil, err
		}
	}
	cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.withStateLock(cleanupContext, func() error {
		if err := store.cleanupTemporaryFiles(); err != nil {
			return err
		}
		if err := store.cleanupOrphanTasksContext(cleanupContext); err != nil {
			return err
		}
		return store.recoverTerminalDeleteIntentsContext(cleanupContext)
	}); err != nil {
		return nil, err
	}
	return store, nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create cache task directory: %w", err)
		}
		return syncDirectory(filepath.Dir(path))
	}
	if err != nil {
		return fmt.Errorf("inspect cache task directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return ErrInvalidState
	}
	return nil
}

func ensureCacheParentDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create cache task parent directory: %w", err)
		}
		return syncDirectory(filepath.Dir(path))
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return ErrInvalidState
	}
	return nil
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return ErrInvalidState
	}
	return nil
}

func stateName(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func (s *diskStore) taskPath(taskID string) string {
	return filepath.Join(s.tasksDir, stateName(taskID)+".json")
}

func (s *diskStore) lockPath(kind, value string) string {
	return filepath.Join(s.locksDir, kind+"-"+stateName(value)+".lock")
}

func (s *diskStore) lock(ctx context.Context, path string) (func(), error) {
	removeOnUnlock := filepath.Dir(path) == s.locksDir
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open cache task lock: %w", err)
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			_ = file.Close()
			return nil, ErrInvalidState
		}
		for {
			err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if err == nil {
				current, pathErr := os.Lstat(path)
				if pathErr == nil && os.SameFile(info, current) {
					return func() {
						if removeOnUnlock {
							current, pathErr := os.Lstat(path)
							locked, statErr := file.Stat()
							if pathErr == nil && statErr == nil && os.SameFile(locked, current) {
								_ = os.Remove(path)
							}
						}
						_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
						_ = file.Close()
					}, nil
				}
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
				if pathErr != nil && !errors.Is(pathErr, os.ErrNotExist) {
					return nil, fmt.Errorf("inspect cache task lock: %w", pathErr)
				}
				break
			}
			if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
				_ = file.Close()
				return nil, fmt.Errorf("lock cache task state: %w", err)
			}
			select {
			case <-ctx.Done():
				_ = file.Close()
				return nil, ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func (s *diskStore) withStateLock(ctx context.Context, operation func() error) error {
	unlock, err := s.lock(ctx, s.stateLock)
	if err != nil {
		return err
	}
	defer unlock()
	return operation()
}

func (s *diskStore) loadRegistry() (registry, error) {
	value := registry{}
	exists, err := readStateJSON(s.registryPath, &value)
	if err != nil {
		if errors.Is(err, ErrInvalidState) {
			return registry{}, journalCorrupt()
		}
		return registry{}, err
	}
	if !exists {
		return registry{SchemaVersion: SchemaVersion, Tasks: map[string]registryEntry{}, Operations: map[string]registryEntry{}}, nil
	}
	if value.SchemaVersion != SchemaVersion || value.Tasks == nil || value.Operations == nil ||
		len(value.Tasks) > s.config.MaxRegistryTasks || len(value.Operations) > s.config.MaxRegistryTasks {
		return registry{}, journalCorrupt()
	}
	for key, entry := range value.Tasks {
		if key != entry.TaskID || !validRegistryEntry(entry) || value.Operations[entry.OperationID] != entry {
			return registry{}, journalCorrupt()
		}
	}
	for key, entry := range value.Operations {
		if key != entry.OperationID || !validRegistryEntry(entry) || value.Tasks[entry.TaskID] != entry {
			return registry{}, journalCorrupt()
		}
	}
	return value, nil
}

func (s *diskStore) loadTask(taskID string) (*taskRecord, error) {
	value := &taskRecord{}
	exists, err := readStateJSON(s.taskPath(taskID), value)
	if err != nil {
		if errors.Is(err, ErrInvalidState) {
			return nil, journalCorrupt()
		}
		return nil, err
	}
	if !exists {
		return nil, err
	}
	if !validTaskRecord(value, taskID, s.config) {
		return nil, journalCorrupt()
	}
	return value, nil
}

func validRegistryEntry(entry registryEntry) bool {
	return idPattern.MatchString(entry.TaskID) && idPattern.MatchString(entry.OperationID) &&
		validDigest(entry.Digest)
}

func journalCorrupt() error {
	return fmt.Errorf("%w: %w", ErrJournalCorrupt, ErrInvalidState)
}

func validTaskRecord(value *taskRecord, taskID string, config Config) bool {
	if value.SchemaVersion != SchemaVersion || value.Task.TaskID != taskID || !validDigest(value.Digest) ||
		value.ExecutionAttempt < 1 || value.HighestDeliveryAttempt < 1 || value.StartedAt.IsZero() ||
		len(value.Items) == 0 || value.Task.ItemCount != len(value.Items) || !validTaskMetadata(value.Task, config) ||
		!validSiteBinding(value.Binding, value.Task) ||
		(value.State != recordRunning && value.State != recordDone && value.State != recordCancelled) {
		return false
	}
	allTerminal := true
	targetBytes := 0
	affectedTotal := 0
	bytesTotal := int64(0)
	for index, item := range value.Items {
		if len(item.Target) > maxTargetLength || targetBytes > config.MaxTaskTargetBytes-len(item.Target) {
			return false
		}
		targetBytes += len(item.Target)
		if item.Index != index || !validPublicTarget(item.Target) ||
			!validDigest(item.TargetDigest) || item.Affected < 0 || item.Bytes < 0 || item.ReservedBytes < 0 || item.Attempts < 0 ||
			item.Attempts > value.Task.Budget.MaxAttempts || !validCanonicalPath(item.Path) {
			return false
		}
		if (item.Code != "" && !validItemCode(value.Task.Action, item.Code)) ||
			(item.CauseCode != "" && !validItemCode(value.Task.Action, item.CauseCode)) {
			return false
		}
		if !recordTargetPathMatches(item.Target, item.Path, value.Task.Action) {
			return false
		}
		if item.Affected > value.Task.Budget.MaxPurgeEntries || affectedTotal > value.Task.Budget.MaxPurgeEntries-item.Affected {
			return false
		}
		affectedTotal += item.Affected
		switch item.Status {
		case recordPending:
			allTerminal = false
			if !item.CompletedAt.IsZero() || item.ReservedBytes != 0 ||
				item.Code != "" && !validRetryCause(value.Task.Action, item.Code) || item.CauseCode != "" ||
				item.Attempts >= value.Task.Budget.MaxAttempts && !validRetryCause(value.Task.Action, item.Code) ||
				(value.Task.Action == ActionPrewarm && item.DeleteIntent != nil) ||
				(item.DeleteIntent != nil && !item.DestructiveStarted) {
				return false
			}
		case recordWorking:
			allTerminal = false
			if item.Attempts < 1 || !item.CompletedAt.IsZero() ||
				item.Code != "" && !validRetryCause(value.Task.Action, item.Code) || item.CauseCode != "" ||
				(value.Task.Action == ActionPrewarm && (item.ReservedBytes < 1 || item.DeleteIntent != nil)) ||
				(value.Task.Action != ActionPrewarm && item.ReservedBytes != 0) {
				return false
			}
		case recordSuccess, recordSkipped, recordFailed:
			if item.Code == "" || item.CompletedAt.IsZero() || !item.NextAttemptAt.IsZero() || item.ReservedBytes != 0 ||
				(value.Task.Action == ActionPrewarm && (item.Affected != 0 || item.DeleteIntent != nil || item.DestructiveStarted)) ||
				(value.Task.Action != ActionPrewarm && item.Bytes != 0 && item.DeleteIntent == nil) ||
				(item.DeleteIntent != nil && (value.Task.Action == ActionPrewarm || item.Status != recordFailed || !item.DestructiveStarted)) {
				return false
			}
			if !validTerminalItem(value.Task.Action, item.Status, item.Code, item.CauseCode) {
				return false
			}
		default:
			return false
		}
		if item.DeleteIntent != nil && !validDeleteIntent(*item.DeleteIntent) {
			return false
		}
		if value.Task.Action == ActionPrewarm {
			if item.Bytes > value.Task.Budget.MaxResourceBytes || item.ReservedBytes > value.Task.Budget.MaxResourceBytes ||
				item.ReservedBytes > value.Task.Budget.MaxResourceBytes-item.Bytes ||
				bytesTotal > value.Task.Budget.MaxTotalBytes-item.Bytes {
				return false
			}
			bytesTotal += item.Bytes
			if item.ReservedBytes > value.Task.Budget.MaxTotalBytes-bytesTotal {
				return false
			}
			bytesTotal += item.ReservedBytes
		} else if item.Bytes != 0 || item.ReservedBytes != 0 {
			return false
		}
	}
	if (value.State == recordDone || value.State == recordCancelled) && (!allTerminal || value.CompletedAt.IsZero()) {
		return false
	}
	if value.State == recordRunning && !value.CompletedAt.IsZero() {
		return false
	}
	if value.State == recordCancelled && value.CancelRequestedAt.IsZero() {
		return false
	}
	return true
}

func validItemCode(action Action, code string) bool {
	switch code {
	case CodePurged, CodeCacheEntryNotFound, CodeCacheLayoutUnsafe, CodeCacheMetadataInvalid,
		CodeCacheEntryChanged, CodeCacheDeleteFailed, CodePurgeBudgetExceeded, CodePurgeScanBudgetExceeded,
		CodeSiteContextStale, CodeTaskCancelled, CodeTaskDeadlineExceeded, CodeRetryExhausted,
		CodePrewarmed, CodeAlreadyCached, CodePrewarmTimeout, CodePrewarmRedirect, CodePrewarmResponseTooLarge,
		CodePrewarmTaskBytesExceeded, CodePrewarmUpstream, CodePrewarmStatus, CodePrewarmNotCacheable:
		if action == ActionPrewarm {
			return code != CodePurged && code != CodeCacheEntryNotFound &&
				code != CodeCacheEntryChanged && code != CodeCacheDeleteFailed &&
				code != CodePurgeBudgetExceeded && code != CodePurgeScanBudgetExceeded
		}
		return code != CodePrewarmed && code != CodeAlreadyCached && code != CodePrewarmTimeout &&
			code != CodePrewarmRedirect && code != CodePrewarmResponseTooLarge && code != CodePrewarmTaskBytesExceeded &&
			code != CodePrewarmUpstream && code != CodePrewarmStatus && code != CodePrewarmNotCacheable
	default:
		return false
	}
}

func validFailureCode(action Action, code string) bool {
	if !validItemCode(action, code) {
		return false
	}
	if action == ActionPrewarm {
		switch code {
		case CodePrewarmTimeout, CodePrewarmRedirect, CodePrewarmResponseTooLarge,
			CodePrewarmTaskBytesExceeded, CodePrewarmUpstream, CodePrewarmStatus,
			CodePrewarmNotCacheable, CodeCacheLayoutUnsafe, CodeCacheMetadataInvalid,
			CodeSiteContextStale, CodeTaskCancelled,
			CodeTaskDeadlineExceeded, CodeRetryExhausted:
			return true
		default:
			return false
		}
	}
	switch code {
	case CodeCacheLayoutUnsafe, CodeCacheMetadataInvalid, CodeCacheEntryChanged,
		CodeCacheDeleteFailed, CodePurgeBudgetExceeded, CodePurgeScanBudgetExceeded,
		CodeSiteContextStale, CodeTaskCancelled, CodeTaskDeadlineExceeded, CodeRetryExhausted:
		return true
	default:
		return false
	}
}

func validTerminalItem(action Action, status recordItemStatus, code, cause string) bool {
	switch status {
	case recordSuccess:
		return cause == "" && ((action == ActionPrewarm && code == CodePrewarmed) ||
			(action != ActionPrewarm && code == CodePurged))
	case recordSkipped:
		return cause == "" && ((action == ActionPrewarm && code == CodeAlreadyCached) ||
			(action != ActionPrewarm && code == CodeCacheEntryNotFound))
	case recordFailed:
		if !validFailureCode(action, code) {
			return false
		}
		if code == CodeRetryExhausted {
			return validRetryCause(action, cause)
		}
		return cause == ""
	default:
		return false
	}
}

func validRetryCause(action Action, cause string) bool {
	if action == ActionPrewarm {
		return cause == CodePrewarmTimeout || cause == CodePrewarmUpstream || cause == CodePrewarmStatus
	}
	return cause == CodeCacheDeleteFailed || cause == CodeCacheEntryChanged
}

func validDeleteIntent(intent deleteIntent) bool {
	if intent.Size < 0 || intent.Device == 0 || intent.Inode == 0 {
		return false
	}
	if intent.Area != "" && !rangeAreaPattern.MatchString(intent.Area) {
		return false
	}
	_, valid := cacheDigestFromPath(intent.Relative)
	return valid
}

var rangeAreaPattern = regexp.MustCompile(`^range/[0-9a-f]{16}$`)

func recordHasDeleteIntent(record *taskRecord) bool {
	for _, item := range record.Items {
		if item.DeleteIntent != nil {
			return true
		}
	}
	return false
}

func validTaskMetadata(task taskMetadata, config Config) bool {
	if task.SchemaVersion != SchemaVersion || !idPattern.MatchString(task.TaskID) ||
		!idPattern.MatchString(task.OperationID) || !idPattern.MatchString(task.TenantID) ||
		!idPattern.MatchString(task.SiteID) || !idPattern.MatchString(task.ConfigVersionID) ||
		task.ConfigRevision == 0 || task.Deadline.IsZero() || task.ItemCount < 1 || task.ItemCount > config.MaxBatchItems ||
		!validActionScope(task.Action, task.Scope) {
		return false
	}
	budget := task.Budget
	if budget.MaxAttempts < 1 || budget.MaxAttempts > 20 || budget.InitialRetryBackoff < time.Millisecond ||
		budget.MaximumRetryBackoff < budget.InitialRetryBackoff || budget.MaximumRetryBackoff > 10*time.Minute {
		return false
	}
	if task.Action == ActionPrewarm {
		return budget.MaxAttempts <= config.MaxAttempts && budget.MaxConcurrency >= 1 && budget.MaxConcurrency <= config.MaxTaskConcurrency && budget.MaxPurgeEntries == 0 &&
			budget.MaxScanEntries == 0 && budget.MaxScanBytes == 0 && budget.MaxScanDuration == 0 &&
			budget.MaxResourceBytes >= 1 && budget.MaxResourceBytes <= config.MaxResponseBytes &&
			budget.MaxTotalBytes >= budget.MaxResourceBytes && budget.MaxTotalBytes <= config.MaxTaskBytes &&
			budget.RequestsPerSecond > 0 && budget.RequestsPerSecond <= config.SiteRequestsPerSecond &&
			budget.Burst >= 1 && budget.Burst <= config.SiteBurst
	}
	return budget.MaxAttempts <= config.MaxAttempts && budget.MaxConcurrency == 1 && budget.MaxPurgeEntries >= 1 && budget.MaxPurgeEntries <= config.MaxPurgeEntries &&
		budget.MaxScanEntries >= 1 && budget.MaxScanEntries <= config.MaxScanEntries &&
		budget.MaxScanBytes >= 1 && budget.MaxScanBytes <= config.MaxScanBytes &&
		budget.MaxScanDuration >= time.Millisecond && budget.MaxScanDuration <= config.MaxScanDuration &&
		budget.MaxTotalBytes == 0 && budget.MaxResourceBytes == 0 && budget.RequestsPerSecond == 0 && budget.Burst == 0
}

func recordTargetPathMatches(target, itemPath string, action Action) bool {
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	if action == ActionPurgeSite {
		return strings.HasSuffix(parsed.Path, "/*") && itemPath == "/"
	}
	if action == ActionPurgePrefix && parsed.RawQuery != "" {
		return false
	}
	pathValue := parsed.Path
	if pathValue == "" {
		pathValue = "/"
	}
	return pathValue == itemPath
}

func validPublicTarget(value string) bool {
	if value == "" || len(value) > maxTargetLength || !asciiPrintable(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	hostname := strings.ToLower(parsed.Hostname())
	// A whole-site record names the site's key domain, which may be a "*."
	// wildcard (normalizeTask); other targets name a concrete host.
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		hostname == "" || net.ParseIP(hostname) != nil || !domainPattern.MatchString(hostname) && !validSiteName(hostname) ||
		parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	return parsed.RawQuery == "" || parsed.RawQuery == "query=redacted"
}

func validDigest(value string) bool {
	return len(value) == sha256.Size*2 && lowerHex(value)
}

func (s *diskStore) cleanupTemporaryFiles() error {
	entries, err := os.ReadDir(s.tmpDir)
	if err != nil {
		return fmt.Errorf("read cache task temporary directory: %w", err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
			!strings.HasPrefix(entry.Name(), ".cache-task-") || !strings.HasSuffix(entry.Name(), ".tmp") {
			return ErrInvalidState
		}
		if err := os.Remove(filepath.Join(s.tmpDir, entry.Name())); err != nil {
			return fmt.Errorf("remove abandoned cache task state: %w", err)
		}
	}
	return syncDirectory(s.tmpDir)
}

func (s *diskStore) cleanupOrphanTasksContext(ctx context.Context) error {
	registry, err := s.loadRegistry()
	if err != nil {
		return err
	}
	expected := make(map[string]struct{}, len(registry.Tasks))
	for taskID := range registry.Tasks {
		expected[stateName(taskID)+".json"] = struct{}{}
	}
	entries, err := os.ReadDir(s.tasksDir)
	if err != nil {
		return err
	}
	changed := false
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
			len(entry.Name()) != sha256.Size*2+len(".json") || !strings.HasSuffix(entry.Name(), ".json") ||
			!lowerHex(strings.TrimSuffix(entry.Name(), ".json")) {
			return ErrInvalidState
		}
		if _, keep := expected[entry.Name()]; keep {
			continue
		}
		if err := s.removeFile(filepath.Join(s.tasksDir, entry.Name())); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.syncDir(s.tasksDir); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

func tombstoneDigest(kind, id string) [sha256.Size]byte {
	return sha256.Sum256([]byte(kind + "\x00" + id))
}

func (s *diskStore) tombstonePath(prefix byte, segment int) string {
	return filepath.Join(s.tombstonesDir, fmt.Sprintf("%02x-%04x.bin", prefix, segment))
}

func (s *diskStore) deleteEntries(ctx context.Context, entries []cacheEntry) (int, error) {
	return deleteCacheEntriesWith(ctx, entries, s.unlinkEntry)
}

func (s *diskStore) readTombstoneShard(expected tombstoneFile) ([]byte, error) {
	file, err := os.OpenFile(expected.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, journalCorrupt()
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !validTombstoneInfo(info) || info.Size() != expected.size {
		return nil, journalCorrupt()
	}
	device, inode, _ := fileIdentity(info)
	if device != expected.device || inode != expected.inode || info.ModTime().UnixNano() != expected.modTime {
		return nil, journalCorrupt()
	}
	body, err := io.ReadAll(io.LimitReader(file, maxTombstoneShardBytes+1))
	if err != nil || int64(len(body)) != info.Size() || int64(len(body))%tombstoneRecordBytes != 0 {
		return nil, journalCorrupt()
	}
	post, err := file.Stat()
	if err != nil || !sameTombstoneInfo(info, post) {
		return nil, journalCorrupt()
	}
	postDevice, postInode, _ := fileIdentity(post)
	if postDevice != expected.device || postInode != expected.inode || post.Size() != expected.size ||
		post.ModTime().UnixNano() != expected.modTime {
		return nil, journalCorrupt()
	}
	return body, nil
}

func tombstoneContains(shard []byte, digest [sha256.Size]byte) bool {
	for offset := 0; offset < len(shard); offset += tombstoneRecordBytes {
		if bytes.Equal(shard[offset:offset+tombstoneRecordBytes], digest[:]) {
			return true
		}
	}
	return false
}

type tombstoneFile struct {
	prefix  byte
	segment int
	path    string
	size    int64
	device  uint64
	inode   uint64
	modTime int64
}

type tombstoneShard struct {
	tombstoneFile
	body []byte
}

func parseTombstoneName(name string) (byte, int, bool) {
	if len(name) != len("00-0000.bin") || name[2] != '-' || !strings.HasSuffix(name, ".bin") ||
		!lowerHex(name[:2]) || !lowerHex(name[3:7]) {
		return 0, 0, false
	}
	prefix, prefixErr := strconv.ParseUint(name[:2], 16, 8)
	segment, segmentErr := strconv.ParseUint(name[3:7], 16, 16)
	return byte(prefix), int(segment), prefixErr == nil && segmentErr == nil
}

func (s *diskStore) listTombstoneFiles() ([]tombstoneFile, error) {
	return s.listTombstoneFilesContext(context.Background())
}

func (s *diskStore) listTombstoneFilesContext(ctx context.Context) ([]tombstoneFile, error) {
	entries, err := os.ReadDir(s.tombstonesDir)
	if err != nil {
		return nil, err
	}
	maxRecords := int64(s.config.MaxTombstoneTasks) * 2
	maxSegments := (maxRecords*tombstoneRecordBytes + maxTombstoneShardBytes - 1) / maxTombstoneShardBytes
	if maxRecords < 1 || maxSegments < 1 {
		return nil, journalCorrupt()
	}
	files := make([]tombstoneFile, 0, min(len(entries), int(maxRecords)))
	prefixCounts := make(map[byte]int)
	var totalRecords int64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		prefix, segment, valid := parseTombstoneName(entry.Name())
		if !valid {
			return nil, journalCorrupt()
		}
		path := filepath.Join(s.tombstonesDir, entry.Name())
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, journalCorrupt()
		}
		info, statErr := file.Stat()
		var device, inode uint64
		if statErr == nil {
			device, inode, _ = fileIdentity(info)
		}
		closeErr := file.Close()
		if statErr != nil || closeErr != nil || !validTombstoneInfo(info) {
			return nil, journalCorrupt()
		}
		if int64(segment) >= maxSegments || prefixCounts[prefix] >= int(maxSegments) {
			return nil, journalCorrupt()
		}
		prefixCounts[prefix]++
		records := info.Size() / tombstoneRecordBytes
		if records > maxRecords-totalRecords {
			return nil, journalCorrupt()
		}
		totalRecords += records
		files = append(files, tombstoneFile{
			prefix: prefix, segment: segment, path: path, size: info.Size(), device: device,
			inode: inode, modTime: info.ModTime().UnixNano(),
		})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].prefix == files[j].prefix {
			return files[i].segment < files[j].segment
		}
		return files[i].prefix < files[j].prefix
	})
	lastPrefix, nextSegment := -1, 0
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if int(file.prefix) != lastPrefix {
			lastPrefix, nextSegment = int(file.prefix), 0
		}
		if file.segment != nextSegment {
			return nil, journalCorrupt()
		}
		nextSegment++
	}
	return files, nil
}

func validTombstoneInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 &&
		info.Size() >= 0 && info.Size()%tombstoneRecordBytes == 0 && info.Size() <= maxTombstoneShardBytes
}

func sameTombstoneInfo(first, second os.FileInfo) bool {
	firstDevice, firstInode, _ := fileIdentity(first)
	secondDevice, secondInode, _ := fileIdentity(second)
	return validTombstoneInfo(second) && firstDevice == secondDevice && firstInode == secondInode &&
		first.Size() == second.Size() && first.ModTime().UnixNano() == second.ModTime().UnixNano()
}

func (s *diskStore) readTombstoneShards(prefix byte) ([]tombstoneShard, error) {
	return s.readTombstoneShardsContext(context.Background(), prefix)
}

func (s *diskStore) readTombstoneShardsContext(ctx context.Context, prefix byte) ([]tombstoneShard, error) {
	files, err := s.listTombstoneFilesContext(ctx)
	if err != nil {
		return nil, err
	}
	shards := make([]tombstoneShard, 0)
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if file.prefix != prefix {
			continue
		}
		if s.beforeTombstoneRead != nil {
			s.beforeTombstoneRead(file.path)
		}
		body, err := s.readTombstoneShard(file)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		shards = append(shards, tombstoneShard{tombstoneFile: file, body: body})
	}
	return shards, nil
}

func (s *diskStore) hasTombstone(kind, id string) (bool, error) {
	return s.hasTombstoneContext(context.Background(), kind, id)
}

func (s *diskStore) hasTombstoneContext(ctx context.Context, kind, id string) (bool, error) {
	digest := tombstoneDigest(kind, id)
	shards, err := s.readTombstoneShardsContext(ctx, digest[0])
	if err != nil {
		return false, err
	}
	for _, shard := range shards {
		if tombstoneContains(shard.body, digest) {
			return true, nil
		}
	}
	return false, nil
}

func (s *diskStore) tombstoneRecordCount() (int, error) {
	return s.tombstoneRecordCountContext(context.Background())
}

func (s *diskStore) tombstoneRecordCountContext(ctx context.Context) (int, error) {
	files, err := s.listTombstoneFilesContext(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		total += int(file.size / tombstoneRecordBytes)
	}
	return total, nil
}

func (s *diskStore) addTombstones(entries []registryEntry) error {
	return s.addTombstonesContext(context.Background(), entries)
}

func (s *diskStore) addTombstonesContext(ctx context.Context, entries []registryEntry) error {
	byPrefix := make(map[byte][][sha256.Size]byte)
	for _, entry := range entries {
		for _, identity := range []struct{ kind, id string }{{"task", entry.TaskID}, {"operation", entry.OperationID}} {
			digest := tombstoneDigest(identity.kind, identity.id)
			byPrefix[digest[0]] = append(byPrefix[digest[0]], digest)
		}
	}
	total, err := s.tombstoneRecordCountContext(ctx)
	if err != nil {
		return err
	}
	updates := make([]tombstoneShard, 0, len(byPrefix))
	additions := 0
	for prefix, digests := range byPrefix {
		if err := ctx.Err(); err != nil {
			return err
		}
		shards, err := s.readTombstoneShardsContext(ctx, prefix)
		if err != nil {
			return err
		}
		for _, digest := range digests {
			if err := ctx.Err(); err != nil {
				return err
			}
			found := false
			for _, shard := range shards {
				if tombstoneContains(shard.body, digest) {
					found = true
					break
				}
			}
			if found {
				continue
			}
			if len(shards) == 0 || len(shards[len(shards)-1].body)+tombstoneRecordBytes > maxTombstoneShardBytes {
				segment := len(shards)
				if segment > 0xffff {
					return ErrTaskCapacity
				}
				shards = append(shards, tombstoneShard{tombstoneFile: tombstoneFile{
					prefix: prefix, segment: segment, path: s.tombstonePath(prefix, segment),
				}})
			}
			last := &shards[len(shards)-1]
			last.body = append(last.body, digest[:]...)
			additions++
		}
		for _, shard := range shards {
			if int64(len(shard.body)) != shard.size {
				updates = append(updates, shard)
			}
		}
	}
	if total+additions > s.config.MaxTombstoneTasks*2 {
		return ErrTaskCapacity
	}
	sort.Slice(updates, func(i, j int) bool { return updates[i].path < updates[j].path })
	for _, update := range updates {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.writeBytes(s.tmpDir, update.path, update.body, maxTombstoneShardBytes); err != nil {
			return fmt.Errorf("%w: %v", ErrJournalWrite, err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

func (s *diskStore) compactRegistry(ctx context.Context, value *registry) error {
	if len(value.Tasks) < s.config.MaxRegistryTasks {
		return nil
	}
	if err := s.cleanupOrphanTasksContext(ctx); err != nil {
		return err
	}
	type completedEntry struct {
		entry       registryEntry
		completedAt time.Time
	}
	completed := make([]completedEntry, 0)
	for taskID, entry := range value.Tasks {
		if err := ctx.Err(); err != nil {
			return err
		}
		record, err := s.loadTask(taskID)
		if err != nil {
			return err
		}
		if record == nil || (record.State != recordDone && record.State != recordCancelled) {
			continue
		}
		if changed, err := s.settleTerminalDeleteIntents(record); err != nil {
			return err
		} else if changed {
			if err := s.saveTask(record); err != nil {
				return err
			}
		}
		if !recordHasDeleteIntent(record) {
			completed = append(completed, completedEntry{entry: entry, completedAt: record.CompletedAt})
		}
	}
	if len(completed) <= s.config.RetainCompletedTasks {
		return ErrTaskCapacity
	}
	sort.Slice(completed, func(i, j int) bool {
		if completed[i].completedAt.Equal(completed[j].completedAt) {
			return completed[i].entry.TaskID < completed[j].entry.TaskID
		}
		return completed[i].completedAt.Before(completed[j].completedAt)
	})
	expired := completed[:len(completed)-s.config.RetainCompletedTasks]
	tombstones := make([]registryEntry, len(expired))
	for index := range expired {
		tombstones[index] = expired[index].entry
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.addTombstonesContext(ctx, tombstones); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, expiredEntry := range expired {
		delete(value.Tasks, expiredEntry.entry.TaskID)
		delete(value.Operations, expiredEntry.entry.OperationID)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.writeRegistry(*value); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, expiredEntry := range expired {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.removeFile(s.taskPath(expiredEntry.entry.TaskID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.syncDir(s.tasksDir); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(value.Tasks) >= s.config.MaxRegistryTasks {
		return ErrTaskCapacity
	}
	return nil
}

func (s *diskStore) prepare(ctx context.Context, task normalizedTask, now time.Time) (*taskRecord, bool, error) {
	var prepared *taskRecord
	replayed := false
	err := s.withStateLock(ctx, func() error {
		registry, err := s.loadRegistry()
		if err != nil {
			return err
		}
		byTask, hasTask := registry.Tasks[task.TaskID]
		byOperation, hasOperation := registry.Operations[task.OperationID]
		if hasTask || hasOperation {
			if !hasTask || !hasOperation || byTask != byOperation || byTask.TaskID != task.TaskID ||
				byTask.OperationID != task.OperationID || byTask.Digest != task.Digest {
				return ErrConflict
			}
			record, err := s.loadTask(task.TaskID)
			if err != nil {
				return err
			}
			if record == nil || record.Digest != task.Digest || !recordMatches(record, task) {
				return ErrInvalidState
			}
			if task.DeliveryAttempt < record.HighestDeliveryAttempt {
				prepared, replayed = record, true
				return nil
			}
			if task.DeliveryAttempt > record.HighestDeliveryAttempt {
				record.HighestDeliveryAttempt = task.DeliveryAttempt
				if err := s.saveTask(record); err != nil {
					return err
				}
			}
			intentChanged := false
			for index := range record.Items {
				if record.Items[index].DeleteIntent == nil {
					continue
				}
				beforeAffected := record.Items[index].Affected
				if err := s.reconcileDeleteIntent(record, &record.Items[index]); err != nil {
					return err
				}
				intentChanged = intentChanged || beforeAffected != record.Items[index].Affected || record.Items[index].DeleteIntent == nil
			}
			if intentChanged {
				if err := s.saveTask(record); err != nil {
					return err
				}
			}
			if record.State != recordRunning {
				prepared, replayed = record, true
				return nil
			}
			record.ExecutionAttempt++
			record.CompletedAt = time.Time{}
			for index := range record.Items {
				if record.Items[index].Status == recordWorking {
					record.Items[index].Bytes += record.Items[index].ReservedBytes
					record.Items[index].ReservedBytes = 0
					record.Items[index].Status = recordPending
					if record.Task.Action == ActionPrewarm {
						record.Items[index].Code = CodePrewarmUpstream
					} else {
						record.Items[index].Code = CodeCacheDeleteFailed
					}
				}
			}
			if err := s.saveTask(record); err != nil {
				return err
			}
			prepared = record
			return nil
		}
		taskExpired, err := s.hasTombstoneContext(ctx, "task", task.TaskID)
		if err != nil {
			return err
		}
		operationExpired, err := s.hasTombstoneContext(ctx, "operation", task.OperationID)
		if err != nil {
			return err
		}
		if taskExpired || operationExpired {
			return ErrTaskExpired
		}
		if err := s.compactRegistry(ctx, &registry); err != nil {
			return err
		}

		record := newTaskRecord(task, now)
		if err := s.saveTask(record); err != nil {
			return err
		}
		entry := registryEntry{TaskID: task.TaskID, OperationID: task.OperationID, Digest: task.Digest}
		registry.Tasks[task.TaskID] = entry
		registry.Operations[task.OperationID] = entry
		if err := s.writeRegistry(registry); err != nil {
			return err
		}
		prepared = record
		return nil
	})
	return prepared, replayed, err
}

func (s *diskStore) journalSite(ctx context.Context, task Task) (SiteContext, bool, error) {
	var site SiteContext
	found := false
	err := s.withStateLock(ctx, func() error {
		registry, err := s.loadRegistry()
		if err != nil {
			return err
		}
		byTask, hasTask := registry.Tasks[task.TaskID]
		byOperation, hasOperation := registry.Operations[task.OperationID]
		if !hasTask && !hasOperation {
			taskExpired, taskErr := s.hasTombstoneContext(ctx, "task", task.TaskID)
			operationExpired, operationErr := s.hasTombstoneContext(ctx, "operation", task.OperationID)
			if taskErr != nil {
				return taskErr
			}
			if operationErr != nil {
				return operationErr
			}
			if taskExpired || operationExpired {
				return ErrTaskExpired
			}
			return nil
		}
		if !hasTask || !hasOperation || byTask != byOperation || byTask.TaskID != task.TaskID ||
			byTask.OperationID != task.OperationID {
			return ErrConflict
		}
		record, err := s.loadTask(task.TaskID)
		if err != nil {
			return err
		}
		if record == nil || !taskMatchesMetadata(task, record.Task) {
			return ErrConflict
		}
		site = siteContextFromBinding(record.Binding, record.Task)
		found = true
		return nil
	})
	return site, found, err
}

func (s *diskStore) recoverTerminalDeleteIntentsContext(ctx context.Context) error {
	registry, err := s.loadRegistry()
	if err != nil {
		return err
	}
	for taskID := range registry.Tasks {
		if err := ctx.Err(); err != nil {
			return err
		}
		record, err := s.loadTask(taskID)
		if err != nil {
			return err
		}
		if record == nil || (record.State != recordDone && record.State != recordCancelled) || !recordHasDeleteIntent(record) {
			continue
		}
		changed, err := s.settleTerminalDeleteIntents(record)
		if err != nil {
			return err
		}
		if changed {
			if err := s.saveTask(record); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *diskStore) settleTerminalDeleteIntents(record *taskRecord) (bool, error) {
	if record.State != recordDone && record.State != recordCancelled {
		return false, nil
	}
	changed := false
	for index := range record.Items {
		if record.Items[index].DeleteIntent == nil {
			continue
		}
		beforeAffected := record.Items[index].Affected
		if err := s.reconcileDeleteIntent(record, &record.Items[index]); err != nil {
			return false, err
		}
		changed = changed || beforeAffected != record.Items[index].Affected || record.Items[index].DeleteIntent == nil
	}
	return changed, nil
}

func newTaskRecord(task normalizedTask, now time.Time) *taskRecord {
	record := &taskRecord{
		SchemaVersion: SchemaVersion, Digest: task.Digest,
		Task: taskMetadata{
			SchemaVersion: task.SchemaVersion, TaskID: task.TaskID, OperationID: task.OperationID,
			TenantID: task.TenantID, SiteID: task.SiteID, Scope: task.Scope,
			ConfigVersionID: task.ConfigVersionID, ConfigRevision: task.ConfigRevision,
			Deadline: task.Deadline, Budget: task.Budget, Action: task.Action, ItemCount: len(task.Targets),
		},
		Binding: siteBindingFromContext(task.Site),
		State:   recordRunning, ExecutionAttempt: 1, HighestDeliveryAttempt: task.DeliveryAttempt,
		StartedAt: now, Items: make([]itemRecord, len(task.Targets)),
	}
	for index, target := range task.Targets {
		record.Items[index] = itemRecord{
			Index: index, Target: target.PublicTarget, TargetDigest: target.Digest,
			Path: target.Path, Status: recordPending,
		}
	}
	return record
}

func journalRecordFits(task normalizedTask, now time.Time) bool {
	record := newTaskRecord(task, now)
	record.State = recordCancelled
	record.CompletedAt = now
	record.CancelRequestedAt = now
	for index := range record.Items {
		item := &record.Items[index]
		item.Status = recordFailed
		item.Code = strings.Repeat("X", 64)
		item.CauseCode = strings.Repeat("X", 64)
		item.Affected = task.Budget.MaxPurgeEntries
		item.Bytes = task.Budget.MaxTotalBytes
		item.ReservedBytes = task.Budget.MaxResourceBytes
		item.Attempts = task.Budget.MaxAttempts
		item.DestructiveStarted = true
		item.DeleteIntent = &deleteIntent{Area: "range/" + strings.Repeat("d", 16), Relative: "d/dd/" + strings.Repeat("d", 32), Size: 1, Device: 1, Inode: 1}
		item.NextAttemptAt = now
		item.CompletedAt = now
	}
	encoded, err := json.Marshal(record)
	return err == nil && len(encoded) <= maxTaskStateBytes
}

func recordMatches(record *taskRecord, task normalizedTask) bool {
	metadata := newTaskRecord(task, record.StartedAt).Task
	if record.Task != metadata || !equalSiteBinding(record.Binding, siteBindingFromContext(task.Site)) ||
		len(record.Items) != len(task.Targets) {
		return false
	}
	for index, target := range task.Targets {
		item := record.Items[index]
		if item.Target != target.PublicTarget || item.TargetDigest != target.Digest || item.Path != target.Path {
			return false
		}
	}
	return true
}

func siteBindingFromContext(site SiteContext) siteBinding {
	binding := siteBinding{
		ActiveReleaseSHA256: site.ActiveReleaseSHA256, NginxSHA256: site.NginxSHA256,
		CacheIdentity: site.CacheIdentity, CachePolicySchemaVersion: cachePolicyBindingSchemaVersion,
		QueryMode: site.QueryMode, QueryNames: append([]string{}, site.QueryNames...),
		VaryHeaders: append([]string{}, site.VaryHeaders...), CacheRules: copyCacheRuleDocuments(site.CacheRules),
		Listeners: make([]listenerBinding, len(site.Listeners)), KeyByHost: site.KeyByHost,
		CacheGeneration: site.CacheGeneration,
	}
	if len(site.Domains) != 0 {
		binding.Domains = append([]string(nil), site.Domains...)
	}
	for index, listener := range site.Listeners {
		binding.Listeners[index] = listenerBinding{
			Domain: listener.Domain, Scheme: listener.Scheme, ListenPort: listener.ListenPort,
			PrewarmPort: listener.PrewarmPort, PrewarmPathPrefix: listener.PrewarmPathPrefix,
			CacheEnabled: listener.CacheEnabled, CacheFreshness: listener.CacheFreshness,
		}
	}
	binding.CachePolicySHA256 = cachePolicyBindingSHA256(binding)
	return binding
}

func siteContextFromBinding(binding siteBinding, task taskMetadata) SiteContext {
	site := SiteContext{
		TenantID: task.TenantID, SiteID: task.SiteID, ConfigVersionID: task.ConfigVersionID,
		ConfigRevision: task.ConfigRevision, ActiveReleaseSHA256: binding.ActiveReleaseSHA256,
		NginxSHA256: binding.NginxSHA256, CacheIdentity: binding.CacheIdentity,
		QueryMode: binding.QueryMode, QueryNames: append([]string{}, binding.QueryNames...),
		VaryHeaders: append([]string{}, binding.VaryHeaders...), CacheRules: copyCacheRuleDocuments(binding.CacheRules),
		Listeners: make([]ListenerContext, len(binding.Listeners)), KeyByHost: binding.KeyByHost,
		CacheGeneration: binding.CacheGeneration,
	}
	if len(binding.Domains) != 0 {
		site.Domains = append([]string(nil), binding.Domains...)
	}
	for index, listener := range binding.Listeners {
		site.Listeners[index] = ListenerContext{
			Domain: listener.Domain, Scheme: listener.Scheme, ListenPort: listener.ListenPort,
			PrewarmPort: listener.PrewarmPort, PrewarmPathPrefix: listener.PrewarmPathPrefix,
			CacheEnabled: listener.CacheEnabled, CacheFreshness: listener.CacheFreshness,
		}
	}
	return site
}

func validSiteBinding(binding siteBinding, task taskMetadata) bool {
	if binding.CachePolicySchemaVersion != cachePolicyBindingSchemaVersion || binding.QueryNames == nil ||
		binding.VaryHeaders == nil || binding.CacheRules == nil || !validDigest(binding.CachePolicySHA256) ||
		binding.CachePolicySHA256 != cachePolicyBindingSHA256(binding) {
		return false
	}
	site := siteContextFromBinding(binding, task)
	normalized, valid := normalizeSiteContext(site)
	return valid && equalSiteBinding(binding, siteBindingFromContext(normalized))
}

func equalSiteBinding(left, right siteBinding) bool {
	if left.ActiveReleaseSHA256 != right.ActiveReleaseSHA256 || left.NginxSHA256 != right.NginxSHA256 ||
		left.CacheIdentity != right.CacheIdentity || left.CachePolicySchemaVersion != right.CachePolicySchemaVersion ||
		left.CachePolicySHA256 != right.CachePolicySHA256 ||
		left.QueryMode != right.QueryMode || !slices.Equal(left.QueryNames, right.QueryNames) ||
		!slices.Equal(left.VaryHeaders, right.VaryHeaders) || !equalCacheRuleDocuments(left.CacheRules, right.CacheRules) ||
		!slices.Equal(left.Domains, right.Domains) || left.KeyByHost != right.KeyByHost ||
		left.CacheGeneration != right.CacheGeneration ||
		len(left.Listeners) != len(right.Listeners) {
		return false
	}
	for index := range left.Listeners {
		if left.Listeners[index] != right.Listeners[index] {
			return false
		}
	}
	return true
}

func cachePolicyBindingSHA256(binding siteBinding) string {
	document := binding
	document.CachePolicySHA256 = ""
	content, _ := json.Marshal(document)
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func copyCacheRuleDocuments(rules []edgeconfig.CacheRuleDocument) []edgeconfig.CacheRuleDocument {
	result := make([]edgeconfig.CacheRuleDocument, len(rules))
	for index, rule := range rules {
		rule.Extensions = append([]string{}, rule.Extensions...)
		rule.StatusCodes = append([]int{}, rule.StatusCodes...)
		result[index] = rule
	}
	return result
}

func equalCacheRuleDocuments(left, right []edgeconfig.CacheRuleDocument) bool {
	return slices.EqualFunc(left, right, func(leftRule, rightRule edgeconfig.CacheRuleDocument) bool {
		return leftRule.Order == rightRule.Order && leftRule.PathPrefix == rightRule.PathPrefix &&
			leftRule.TTLSeconds == rightRule.TTLSeconds && slices.Equal(leftRule.Extensions, rightRule.Extensions) &&
			slices.Equal(leftRule.StatusCodes, rightRule.StatusCodes)
	})
}

func taskMatchesMetadata(task Task, metadata taskMetadata) bool {
	itemCount := len(task.Targets)
	if task.Action == ActionPurgeSite {
		itemCount = 1
	}
	return task.SchemaVersion == metadata.SchemaVersion && task.TaskID == metadata.TaskID &&
		task.OperationID == metadata.OperationID && task.TenantID == metadata.TenantID &&
		task.SiteID == metadata.SiteID && task.Scope == metadata.Scope &&
		task.ConfigVersionID == metadata.ConfigVersionID && task.ConfigRevision == metadata.ConfigRevision &&
		task.Deadline.UTC().Equal(metadata.Deadline) && task.Budget == metadata.Budget &&
		task.Action == metadata.Action && itemCount == metadata.ItemCount
}

func (s *diskStore) update(ctx context.Context, record *taskRecord) error {
	return s.withStateLock(ctx, func() error {
		existing, err := s.loadTask(record.Task.TaskID)
		if err != nil {
			return err
		}
		if existing == nil || existing.Digest != record.Digest || existing.ExecutionAttempt != record.ExecutionAttempt {
			return ErrInvalidState
		}
		if existing.State == recordCancelled {
			return errRecordCancelled
		}
		if !existing.CancelRequestedAt.IsZero() {
			record.CancelRequestedAt = existing.CancelRequestedAt
		}
		return s.saveTask(record)
	})
}

func (s *diskStore) lookup(ctx context.Context, reference TaskReference) (*taskRecord, error) {
	var result *taskRecord
	err := s.withStateLock(ctx, func() error {
		registry, err := s.loadRegistry()
		if err != nil {
			return err
		}
		entry, exists := registry.Tasks[reference.TaskID]
		if !exists {
			taskExpired, taskErr := s.hasTombstoneContext(ctx, "task", reference.TaskID)
			operationExpired, operationErr := s.hasTombstoneContext(ctx, "operation", reference.OperationID)
			if taskErr != nil {
				return taskErr
			}
			if operationErr != nil {
				return operationErr
			}
			if taskExpired || operationExpired {
				return ErrTaskExpired
			}
			return ErrTaskNotFound
		}
		if entry.OperationID != reference.OperationID {
			return ErrTaskNotFound
		}
		record, err := s.loadTask(reference.TaskID)
		if err != nil {
			return err
		}
		if record == nil || record.Task.TenantID != reference.TenantID || record.Task.SiteID != reference.SiteID {
			return ErrTaskNotFound
		}
		if changed, err := s.settleTerminalDeleteIntents(record); err != nil {
			return err
		} else if changed {
			if err := s.saveTask(record); err != nil {
				return err
			}
		}
		result = record
		return nil
	})
	return result, err
}

func (s *diskStore) cancel(ctx context.Context, reference TaskReference, now time.Time) (*taskRecord, error) {
	var result *taskRecord
	err := s.withStateLock(ctx, func() error {
		registry, err := s.loadRegistry()
		if err != nil {
			return err
		}
		entry, exists := registry.Tasks[reference.TaskID]
		if !exists {
			taskExpired, taskErr := s.hasTombstoneContext(ctx, "task", reference.TaskID)
			operationExpired, operationErr := s.hasTombstoneContext(ctx, "operation", reference.OperationID)
			if taskErr != nil {
				return taskErr
			}
			if operationErr != nil {
				return operationErr
			}
			if taskExpired || operationExpired {
				return ErrTaskExpired
			}
			return ErrTaskNotFound
		}
		if entry.OperationID != reference.OperationID {
			return ErrTaskNotFound
		}
		record, err := s.loadTask(reference.TaskID)
		if err != nil {
			return err
		}
		if record == nil || record.Task.TenantID != reference.TenantID || record.Task.SiteID != reference.SiteID {
			return ErrTaskNotFound
		}
		intentChanged := false
		for index := range record.Items {
			if record.Items[index].DeleteIntent == nil {
				continue
			}
			beforeAffected := record.Items[index].Affected
			if err := s.reconcileDeleteIntent(record, &record.Items[index]); err != nil {
				return err
			}
			intentChanged = intentChanged || beforeAffected != record.Items[index].Affected || record.Items[index].DeleteIntent == nil
		}
		if record.State == recordDone || record.State == recordCancelled {
			if intentChanged {
				if err := s.saveTask(record); err != nil {
					return err
				}
			}
			result = record
			return nil
		}
		record.CancelRequestedAt = now
		for index := range record.Items {
			if record.Items[index].Status == recordSuccess || record.Items[index].Status == recordSkipped ||
				record.Items[index].Status == recordFailed {
				continue
			}
			if record.Items[index].DeleteIntent != nil {
				if err := s.reconcileDeleteIntent(record, &record.Items[index]); err != nil {
					return err
				}
			}
			record.Items[index].Bytes += record.Items[index].ReservedBytes
			record.Items[index].ReservedBytes = 0
			record.Items[index].Status = recordFailed
			record.Items[index].Code = CodeTaskCancelled
			record.Items[index].NextAttemptAt = time.Time{}
			record.Items[index].CompletedAt = now
		}
		record.State = recordCancelled
		record.CompletedAt = now
		if err := s.saveTask(record); err != nil {
			return err
		}
		result = record
		return nil
	})
	return result, err
}

func (s *diskStore) reconcileDeleteIntent(record *taskRecord, item *itemRecord) error {
	intent := item.DeleteIntent
	if intent == nil || !validDeleteIntent(*intent) {
		return ErrInvalidState
	}
	root, known := s.cacheAreaRoot(siteContextFromBinding(record.Binding, record.Task), intent.Area)
	if !known {
		return ErrInvalidState
	}
	path := filepath.Join(root, filepath.FromSlash(intent.Relative))
	if !strings.HasPrefix(path, root+string(filepath.Separator)) {
		return ErrInvalidState
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := syncCacheParent(root, intent.Relative, s.fsyncParent); err != nil {
			return &operationError{code: CodeCacheDeleteFailed, err: err}
		}
		if item.Affected >= record.Task.Budget.MaxPurgeEntries {
			return journalCorrupt()
		}
		item.Affected++
		item.DeleteIntent = nil
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ErrInvalidState
	}
	device, inode, links := fileIdentity(info)
	if links > 1 || device != intent.Device || inode != intent.Inode || info.Size() != intent.Size {
		return ErrInvalidState
	}
	deleted, err := s.unlinkEntry(cacheEntry{
		root: root, area: intent.Area, relative: intent.Relative, size: intent.Size, device: intent.Device, inode: intent.Inode,
	})
	if err != nil {
		return err
	}
	if !deleted {
		if err := syncCacheParent(root, intent.Relative, s.fsyncParent); err != nil {
			return &operationError{code: CodeCacheDeleteFailed, err: err}
		}
	}
	if item.Affected >= record.Task.Budget.MaxPurgeEntries {
		return journalCorrupt()
	}
	item.Affected++
	item.DeleteIntent = nil
	return nil
}

func (s *diskStore) saveTask(record *taskRecord) error {
	if err := s.writeJSON(s.tmpDir, s.taskPath(record.Task.TaskID), record); err != nil {
		return fmt.Errorf("%w: %v", ErrJournalWrite, err)
	}
	return nil
}

func (s *diskStore) writeRegistry(value registry) error {
	if err := s.writeJSON(s.tmpDir, s.registryPath, value); err != nil {
		return fmt.Errorf("%w: %v", ErrJournalWrite, err)
	}
	return nil
}

var readStateOpen = func(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}

func readStateJSON(path string, target any) (bool, error) {
	file, err := readStateOpen(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open cache task state: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() < 2 || info.Size() > maxTaskStateBytes {
		return false, ErrInvalidState
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxTaskStateBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false, ErrInvalidState
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return false, ErrInvalidState
	}
	return true, nil
}

func writeStateJSON(tmpDir, path string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxTaskStateBytes {
		return ErrInvalidState
	}
	return writeStateBytes(tmpDir, path, encoded, maxTaskStateBytes)
}

func writeStateBytes(tmpDir, path string, encoded []byte, maximum int) error {
	if len(encoded) == 0 || len(encoded) > maximum {
		return ErrInvalidState
	}
	file, err := os.CreateTemp(tmpDir, ".cache-task-*.tmp")
	if err != nil {
		return fmt.Errorf("create cache task state: %w", err)
	}
	temporary := file.Name()
	defer func() {
		_ = file.Close()
		_ = os.Remove(temporary)
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("protect cache task state: %w", err)
	}
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("write cache task state: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync cache task state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close cache task state: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("activate cache task state: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
