package cachetask

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	store           *diskStore
	resolver        SiteResolver
	config          Config
	now             func() time.Time
	globalSlots     chan struct{}
	globalRate      *tokenBucket
	allowedStatuses map[int]struct{}
	prewarmAttempt  func(context.Context, normalizedTask, normalizedTarget, *tokenBucket, int64) prewarmOutcome
	walkEntries     func(context.Context, SiteContext, *cacheScanBudget, func(cacheEntry) error) error
	exactEntry      func(context.Context, SiteContext, normalizedTarget, *cacheScanBudget) (*cacheEntry, error)
	deleteEntries   func(context.Context, []cacheEntry) (int, error)

	locksMu    sync.Mutex
	localLocks map[string]*lockEntry
	ratesMu    sync.Mutex
	siteRates  map[string]*siteRateEntry
	rateTick   uint64
	activeMu   sync.Mutex
	active     map[string]context.CancelFunc
}

type lockEntry struct {
	token chan struct{}
	refs  int
}

type siteRateEntry struct {
	limiter  *tokenBucket
	refs     int
	lastUsed uint64
}

type itemOutcome struct {
	status    ItemStatus
	code      string
	affected  int
	bytes     int64
	retryable bool
}

type purgePlan struct {
	entries    [][]cacheEntry
	matched    []bool
	entryCount int
}

type byteAllocator struct {
	mu        sync.Mutex
	remaining int64
	inFlight  int
	changed   chan struct{}
}

func NewManager(stateRoot string, candidate any, config Config) (*Manager, error) {
	resolver, ok := candidate.(SiteResolver)
	_, leaseOK := candidate.(activeReleaseLeaser)
	if !ok || resolver == nil || !leaseOK || !validManagerConfig(config) {
		return nil, ErrInvalidTask
	}
	store, err := newDiskStore(stateRoot, config)
	if err != nil {
		return nil, err
	}
	allowed := make(map[int]struct{}, len(config.AllowedStatuses))
	for _, status := range config.AllowedStatuses {
		allowed[status] = struct{}{}
	}
	manager := &Manager{
		store: store, resolver: resolver, config: config, now: config.Now,
		globalSlots:     make(chan struct{}, config.GlobalConcurrency),
		globalRate:      newTokenBucket(config.GlobalRequestsPerSecond, config.GlobalBurst),
		allowedStatuses: allowed, walkEntries: store.walkCacheEntries, exactEntry: store.exactCacheEntry,
		deleteEntries: store.deleteEntries,
		localLocks:    make(map[string]*lockEntry), siteRates: make(map[string]*siteRateEntry),
		active: make(map[string]context.CancelFunc),
	}
	manager.prewarmAttempt = manager.prewarm
	return manager, nil
}

func validManagerConfig(config Config) bool {
	if config.GlobalConcurrency < 1 || config.GlobalConcurrency > 128 ||
		config.GlobalRequestsPerSecond <= 0 || config.GlobalRequestsPerSecond > 100000 ||
		config.SiteRequestsPerSecond <= 0 || config.SiteRequestsPerSecond > 100000 ||
		config.GlobalBurst < 1 || config.GlobalBurst > 10000 || config.SiteBurst < 1 || config.SiteBurst > 10000 ||
		config.RequestTimeout < 10*time.Millisecond || config.RequestTimeout > time.Hour ||
		config.MaxResponseBytes < 1 || config.MaxResponseBytes > MaxPrewarmObjectBytes ||
		config.MaxTaskBytes < config.MaxResponseBytes || config.MaxTaskBytes > 1<<44 ||
		config.MaxBatchItems < 1 || config.MaxBatchItems > 500 ||
		config.MaxTaskTargetBytes < 1 || config.MaxTaskTargetBytes > 256<<10 ||
		config.MaxAttempts < 1 || config.MaxAttempts > 20 ||
		config.MaxTaskConcurrency < 1 || config.MaxTaskConcurrency > config.GlobalConcurrency ||
		config.MaxPurgeEntries < 1 || config.MaxPurgeEntries > 10_000_000 ||
		config.MaxScanEntries < 1 || config.MaxScanEntries > 10_000_000 ||
		config.MaxScanBytes < 1 || config.MaxScanBytes > 1<<40 ||
		config.MaxScanDuration < time.Millisecond || config.MaxScanDuration > time.Hour ||
		config.MaxSiteLimiters < config.GlobalConcurrency || config.MaxSiteLimiters > 100000 ||
		config.RetainCompletedTasks < 1 || config.RetainCompletedTasks > 4096 ||
		config.MaxRegistryTasks <= config.RetainCompletedTasks || config.MaxRegistryTasks > 8192 ||
		config.MaxTombstoneTasks < 1 || config.MaxTombstoneTasks > 1000000 ||
		config.CancelSettlementTimeout < 10*time.Millisecond || config.CancelSettlementTimeout > time.Minute ||
		config.MaxDeadlineHorizon < time.Minute || config.MaxDeadlineHorizon > 7*24*time.Hour ||
		!config.LoopbackAddress.IsValid() || !config.LoopbackAddress.IsLoopback() || config.LoopbackAddress.Zone() != "" ||
		len(config.AllowedStatuses) == 0 || len(config.AllowedStatuses) > 100 ||
		config.Now == nil || config.Sleep == nil || config.Jitter == nil {
		return false
	}
	seen := make(map[int]struct{}, len(config.AllowedStatuses))
	for _, status := range config.AllowedStatuses {
		if status < 200 || status > 299 {
			return false
		}
		if _, exists := seen[status]; exists {
			return false
		}
		seen[status] = struct{}{}
	}
	return true
}

func (m *Manager) Execute(ctx context.Context, task Task) (Result, error) {
	now := m.now().UTC()
	if err := validateEnvelope(task, m.config, now); err != nil {
		return Result{}, err
	}
	site, fromJournal, err := m.store.journalSite(ctx, task)
	if err != nil {
		return Result{}, err
	}
	if !fromJournal {
		site, err = m.resolver.ResolveSite(ctx, task.TenantID, task.SiteID, task.ConfigVersionID, task.ConfigRevision)
		if err != nil {
			return Result{}, err
		}
	}
	normalized, err := normalizeTask(task, site, m.config, now)
	if err != nil {
		return Result{}, err
	}

	executionContext, cancel := context.WithDeadline(ctx, normalized.Deadline)
	defer cancel()
	unlockTaskLocal, err := m.lockLocal(ctx, "task:"+normalized.TaskID)
	if err != nil {
		return Result{}, err
	}
	defer unlockTaskLocal()
	unlockTaskFile, err := m.store.lock(ctx, m.store.lockPath("task", normalized.TaskID))
	if err != nil {
		return Result{}, err
	}
	defer unlockTaskFile()
	m.registerActive(normalized.TaskID, cancel)
	defer m.unregisterActive(normalized.TaskID)

	record, replayed, err := m.store.prepare(ctx, normalized, now)
	if err != nil {
		return Result{}, err
	}
	if replayed {
		result := resultFromRecord(record)
		result.Replayed = true
		return result, nil
	}
	if fromJournal && normalized.Action == ActionPrewarm {
		if !m.activeSiteBindingMatches(executionContext, normalized) {
			m.failUnfinished(record, CodeSiteContextStale)
			m.finish(record, false)
			if err := m.persist(record); err != nil {
				return Result{}, err
			}
			return resultFromRecord(record), nil
		}
	}

	if !record.CancelRequestedAt.IsZero() || executionContext.Err() != nil {
		code := contextFailureCode(executionContext)
		m.failUnfinished(record, code)
		m.finish(record, code == CodeTaskCancelled)
		if err := m.persist(record); err != nil {
			return Result{}, err
		}
		return resultFromRecord(record), nil
	}

	unlockSiteLocal, err := m.lockLocal(executionContext, "site:"+site.CacheIdentity)
	if err != nil {
		m.failUnfinished(record, contextFailureCode(executionContext))
		m.finish(record, errors.Is(executionContext.Err(), context.Canceled))
		if persistErr := m.persist(record); persistErr != nil {
			return Result{}, persistErr
		}
		return resultFromRecord(record), nil
	}
	defer unlockSiteLocal()
	unlockSiteFile, err := m.store.lock(executionContext, m.store.lockPath("site", site.CacheIdentity))
	if err != nil {
		if executionContext.Err() == nil {
			return Result{}, err
		}
		m.failUnfinished(record, contextFailureCode(executionContext))
		m.finish(record, errors.Is(executionContext.Err(), context.Canceled))
		if persistErr := m.persist(record); persistErr != nil {
			return Result{}, persistErr
		}
		return resultFromRecord(record), nil
	}
	defer unlockSiteFile()

	if normalized.Action == ActionPrewarm {
		err = m.executePrewarm(executionContext, normalized, record)
	} else {
		err = m.executePurge(executionContext, normalized, record)
	}
	if errors.Is(err, errRecordCancelled) {
		cancelled, lookupErr := m.store.lookup(context.Background(), referenceFromTask(normalized.Task))
		if lookupErr != nil {
			return Result{}, lookupErr
		}
		return resultFromRecord(cancelled), nil
	}
	if err != nil {
		return Result{}, err
	}
	m.finish(record, errors.Is(executionContext.Err(), context.Canceled))
	if err := m.persist(record); err != nil {
		return Result{}, err
	}
	return resultFromRecord(record), nil
}

func (m *Manager) Lookup(ctx context.Context, reference TaskReference) (Result, error) {
	if !validReference(reference) {
		return Result{}, ErrInvalidTask
	}
	record, err := m.store.lookup(ctx, reference)
	if err != nil {
		return Result{}, err
	}
	return resultFromRecord(record), nil
}

func (m *Manager) Cancel(ctx context.Context, reference TaskReference) (Result, error) {
	if !validReference(reference) {
		return Result{}, ErrInvalidTask
	}
	current, err := m.store.lookup(ctx, reference)
	if err != nil {
		return Result{}, err
	}
	if current.State != recordRunning {
		return resultFromRecord(current), nil
	}
	m.activeMu.Lock()
	active := m.active[reference.TaskID]
	m.activeMu.Unlock()
	if active != nil {
		active()
	}
	settlementContext, cancel := context.WithTimeout(ctx, m.config.CancelSettlementTimeout)
	defer cancel()
	unlock, err := m.store.lock(settlementContext, m.store.lockPath("task", reference.TaskID))
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	record, err := m.store.cancel(settlementContext, reference, m.now().UTC())
	if err != nil {
		return Result{}, err
	}
	return resultFromRecord(record), nil
}

func validReference(reference TaskReference) bool {
	return reference.SchemaVersion == SchemaVersion && idPattern.MatchString(reference.TaskID) &&
		idPattern.MatchString(reference.OperationID) && idPattern.MatchString(reference.TenantID) &&
		idPattern.MatchString(reference.SiteID)
}

func referenceFromTask(task Task) TaskReference {
	return TaskReference{
		SchemaVersion: task.SchemaVersion, TaskID: task.TaskID, OperationID: task.OperationID,
		TenantID: task.TenantID, SiteID: task.SiteID,
	}
}

func (m *Manager) executePurge(ctx context.Context, task normalizedTask, record *taskRecord) error {
	for {
		for index := range record.Items {
			if terminalItem(record.Items[index].Status) || record.Items[index].NextAttemptAt.IsZero() {
				continue
			}
			if err := m.waitForRetry(ctx, record.Items[index]); err != nil {
				m.failUnfinished(record, contextFailureCode(ctx))
				return m.persist(record)
			}
			break
		}

		plan, err := m.buildPurgePlan(ctx, task, record, newCacheScanBudget(task.Budget))
		if err != nil {
			outcome, fatal := purgeOperationOutcome(ctx, err)
			if fatal != nil {
				return fatal
			}
			retrying := outcome.retryable
			allTerminal := true
			now := m.now().UTC()
			for index := range record.Items {
				if terminalItem(record.Items[index].Status) {
					continue
				}
				item := &record.Items[index]
				item.Attempts++
				if !retrying || item.Attempts >= task.Budget.MaxAttempts {
					if retrying {
						m.completeFailure(record, index, CodeRetryExhausted, outcome.code)
					} else {
						m.complete(record, index, outcome)
					}
					continue
				}
				item.Status = recordPending
				item.Code = outcome.code
				item.CauseCode = ""
				item.NextAttemptAt = now.Add(m.retryDelay(task.Budget, item.Attempts))
				allTerminal = false
			}
			if err := m.persist(record); err != nil {
				return err
			}
			if allTerminal {
				return nil
			}
			continue
		}
		for index := range record.Items {
			if terminalItem(record.Items[index].Status) {
				continue
			}
			if err := m.runPurgeItem(ctx, task, record, index, plan.entries[index], plan.matched[index]); err != nil {
				return err
			}
			if ctx.Err() != nil {
				m.failUnfinished(record, contextFailureCode(ctx))
				return m.persist(record)
			}
		}
		return nil
	}
}

func (m *Manager) buildPurgePlan(ctx context.Context, task normalizedTask, record *taskRecord,
	scanBudget *cacheScanBudget) (purgePlan, error) {
	plan := purgePlan{
		entries: make([][]cacheEntry, len(record.Items)),
		matched: make([]bool, len(record.Items)),
	}
	appendEntry := func(index int, entry cacheEntry) error {
		plan.matched[index] = true
		if purgeAffected(record)+plan.entryCount >= task.Budget.MaxPurgeEntries {
			return &operationError{code: CodePurgeBudgetExceeded, err: ErrInvalidState}
		}
		plan.entries[index] = append(plan.entries[index], entry)
		plan.entryCount++
		return nil
	}
	needsScan, err := m.store.purgeNeedsScan(task.Site)
	if err != nil {
		return purgePlan{}, err
	}
	if task.Action == ActionPurgeExact && !needsScan && !purgeTargetsNeedScan(task.Targets) {
		for index := range record.Items {
			if terminalItem(record.Items[index].Status) {
				continue
			}
			entry, err := m.exactEntry(ctx, task.Targets[index].Site, task.Targets[index], scanBudget)
			if err != nil {
				return purgePlan{}, err
			}
			if entry != nil {
				if err := appendEntry(index, *entry); err != nil {
					return purgePlan{}, err
				}
			}
		}
		return plan, nil
	}
	unfinished := 0
	for index := range record.Items {
		if !terminalItem(record.Items[index].Status) {
			unfinished++
		}
	}
	perItemCapacity := min(task.Budget.MaxPurgeEntries/max(unfinished, 1)+1, 4096)
	for index := range plan.entries {
		if !terminalItem(record.Items[index].Status) {
			plan.entries[index] = make([]cacheEntry, 0, perItemCapacity)
		}
	}
	visit := func(entry cacheEntry) error {
		for index := range record.Items {
			if terminalItem(record.Items[index].Status) || !purgeMatchPolicy(task.Action, task.Targets[index], entry) {
				continue
			}
			if err := appendEntry(index, entry); err != nil {
				return err
			}
			break
		}
		return nil
	}
	if err := m.walkEntries(ctx, task.Site, scanBudget, visit); err != nil {
		return purgePlan{}, err
	}
	return plan, nil
}

func (m *Manager) runPurgeItem(ctx context.Context, task normalizedTask, record *taskRecord, index int,
	planned []cacheEntry, matched bool) error {
	for {
		if err := m.waitForRetry(ctx, record.Items[index]); err != nil {
			m.completeFailure(record, index, contextFailureCode(ctx), "")
			return m.persist(record)
		}
		if record.Items[index].DeleteIntent != nil {
			intentArea, intentRelative := record.Items[index].DeleteIntent.Area, record.Items[index].DeleteIntent.Relative
			beforeAffected := record.Items[index].Affected
			if err := m.store.reconcileDeleteIntent(record, &record.Items[index]); err != nil {
				outcome, fatal := purgeOperationOutcome(ctx, err)
				if fatal != nil {
					return fatal
				}
				if record.Items[index].Attempts >= task.Budget.MaxAttempts {
					m.completeFailure(record, index, CodeRetryExhausted, outcome.code)
					return m.persist(record)
				}
				record.Items[index].Status = recordPending
				record.Items[index].Code = outcome.code
				record.Items[index].NextAttemptAt = m.now().UTC().Add(m.retryDelay(task.Budget, record.Items[index].Attempts))
				if persistErr := m.persist(record); persistErr != nil {
					return persistErr
				}
				continue
			}
			planned = removePlannedCacheEntry(planned, intentArea, intentRelative)
			if beforeAffected != record.Items[index].Affected {
				if err := m.persist(record); err != nil {
					return err
				}
			}
		}
		if record.Items[index].Attempts >= task.Budget.MaxAttempts {
			m.completeFailure(record, index, CodeRetryExhausted, record.Items[index].Code)
			return m.persist(record)
		}
		record.Items[index].Status = recordWorking
		record.Items[index].Attempts++
		record.Items[index].NextAttemptAt = time.Time{}
		if err := m.persist(record); err != nil {
			return err
		}
		outcome, err := m.purgeAttempt(ctx, record, index, &planned, matched)
		if err != nil {
			return err
		}
		if outcome.affected > 0 {
			record.Items[index].Affected += outcome.affected
			outcome.affected = 0
		}
		if outcome.status != ItemFailed || !outcome.retryable {
			m.complete(record, index, outcome)
			return m.persist(record)
		}
		if record.Items[index].Attempts >= task.Budget.MaxAttempts {
			m.completeFailure(record, index, CodeRetryExhausted, outcome.code)
			return m.persist(record)
		}
		record.Items[index].Status = recordPending
		record.Items[index].Code = outcome.code
		record.Items[index].CauseCode = ""
		record.Items[index].NextAttemptAt = m.now().UTC().Add(m.retryDelay(task.Budget, record.Items[index].Attempts))
		if err := m.persist(record); err != nil {
			return err
		}
	}
}

func (m *Manager) purgeAttempt(ctx context.Context, record *taskRecord, index int,
	planned *[]cacheEntry, matched bool) (itemOutcome, error) {
	if !matched {
		if record.Items[index].Affected > 0 || record.Items[index].DestructiveStarted {
			return itemOutcome{status: ItemSuccess, code: CodePurged}, nil
		}
		return itemOutcome{status: ItemSkipped, code: CodeCacheEntryNotFound}, nil
	}
	if !record.Items[index].DestructiveStarted {
		record.Items[index].DestructiveStarted = true
		if err := m.persist(record); err != nil {
			return itemOutcome{}, err
		}
	}
	for len(*planned) > 0 {
		entry := (*planned)[0]
		record.Items[index].DeleteIntent = &deleteIntent{
			Area: entry.area, Relative: filepath.ToSlash(entry.relative), Size: entry.size, Device: entry.device, Inode: entry.inode,
		}
		if err := m.persist(record); err != nil {
			return itemOutcome{}, err
		}
		deleted, err := m.deleteEntries(ctx, []cacheEntry{entry})
		if deleted > 1 {
			return itemOutcome{}, ErrInvalidState
		}
		if deleted == 1 {
			record.Items[index].Affected++
			record.Items[index].DeleteIntent = nil
			(*planned)[0] = cacheEntry{}
			*planned = (*planned)[1:]
			if persistErr := m.persist(record); persistErr != nil {
				return itemOutcome{}, persistErr
			}
			if err != nil {
				return purgeOperationOutcome(ctx, err)
			}
		} else if err != nil {
			return purgeOperationOutcome(ctx, err)
		} else {
			if reconcileErr := m.store.reconcileDeleteIntent(record, &record.Items[index]); reconcileErr != nil {
				return purgeOperationOutcome(ctx, reconcileErr)
			}
			(*planned)[0] = cacheEntry{}
			*planned = (*planned)[1:]
			if persistErr := m.persist(record); persistErr != nil {
				return itemOutcome{}, persistErr
			}
		}
	}
	return itemOutcome{status: ItemSuccess, code: CodePurged}, nil
}

// purgeTargetsNeedScan: a wildcard target, or one covering several listener
// ports, cannot be found at one computed key path.
func purgeTargetsNeedScan(targets []normalizedTarget) bool {
	for _, target := range targets {
		if target.WildcardSuffix != "" || len(target.Ports) > 1 {
			return true
		}
	}
	return false
}

func removePlannedCacheEntry(entries []cacheEntry, area, relative string) []cacheEntry {
	for index := range entries {
		if entries[index].area != area || filepath.ToSlash(entries[index].relative) != relative {
			continue
		}
		copy(entries[index:], entries[index+1:])
		entries[len(entries)-1] = cacheEntry{}
		return entries[:len(entries)-1]
	}
	return entries
}

func purgeMatchPolicy(action Action, target normalizedTarget, entry cacheEntry) bool {
	if action != ActionPurgeExact || !cachePolicyProjectedKey(target.Site) {
		return purgeMatch(action, target, entry)
	}
	if !targetKeyDomainMatches(entry.key, target) || !target.matchesPort(entry.key.port) {
		return false
	}
	queryDigest, err := cachePolicyQueryDigest(target.Site.QueryMode, target.Site.QueryNames, target.URI)
	if err != nil {
		return false
	}
	prefix := target.Path + "?~q=" + queryDigest + "&~v="
	variant := strings.TrimPrefix(entry.key.uri, prefix)
	return variant != entry.key.uri && len(variant) == sha256.Size*2 && lowerHex(variant)
}

func purgeOperationOutcome(ctx context.Context, operationErr error) (itemOutcome, error) {
	if ctx.Err() != nil && (errors.Is(operationErr, context.Canceled) || errors.Is(operationErr, context.DeadlineExceeded)) {
		return itemOutcome{status: ItemFailed, code: contextFailureCode(ctx)}, nil
	}
	var operation *operationError
	if errors.As(operationErr, &operation) {
		return itemOutcome{
			status: ItemFailed, code: operation.code,
			retryable: operation.code == CodeCacheDeleteFailed || operation.code == CodeCacheEntryChanged,
		}, nil
	}
	if errors.Is(operationErr, ErrJournalWrite) || errors.Is(operationErr, ErrInvalidState) {
		return itemOutcome{}, operationErr
	}
	return itemOutcome{status: ItemFailed, code: CodeCacheDeleteFailed, retryable: true}, nil
}

func purgeAffected(record *taskRecord) int {
	total := 0
	for _, item := range record.Items {
		if item.Affected > int(^uint(0)>>1)-total {
			return int(^uint(0) >> 1)
		}
		total += item.Affected
	}
	return total
}

func (m *Manager) executePrewarm(ctx context.Context, task normalizedTask, record *taskRecord) error {
	used := int64(0)
	for _, item := range record.Items {
		used += item.Bytes + item.ReservedBytes
	}
	allocator := &byteAllocator{remaining: task.Budget.MaxTotalBytes - used}
	if allocator.remaining < 0 {
		return ErrInvalidState
	}
	taskRate := newTokenBucket(task.Budget.RequestsPerSecond, task.Budget.Burst)
	workers := min(task.Budget.MaxConcurrency, len(record.Items))
	work := make(chan int)
	errCh := make(chan error, workers)
	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	var recordMu sync.Mutex
	var wait sync.WaitGroup
	for count := 0; count < workers; count++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := range work {
				if err := m.runPrewarmItem(workerContext, task, record, index, &recordMu, taskRate, allocator); err != nil {
					select {
					case errCh <- err:
					default:
					}
					cancel()
					return
				}
			}
		}()
	}
	for index := range record.Items {
		if terminalItem(record.Items[index].Status) {
			continue
		}
		select {
		case work <- index:
		case <-workerContext.Done():
			break
		}
	}
	close(work)
	wait.Wait()
	select {
	case err := <-errCh:
		return err
	default:
	}
	if ctx.Err() != nil {
		recordMu.Lock()
		m.failUnfinished(record, contextFailureCode(ctx))
		err := m.persist(record)
		recordMu.Unlock()
		return err
	}
	return nil
}

func (m *Manager) runPrewarmItem(ctx context.Context, task normalizedTask, record *taskRecord, index int,
	recordMu *sync.Mutex, taskRate *tokenBucket, allocator *byteAllocator) error {
	for {
		recordMu.Lock()
		item := record.Items[index]
		recordMu.Unlock()
		if err := m.waitForRetry(ctx, item); err != nil {
			recordMu.Lock()
			m.completeFailure(record, index, contextFailureCode(ctx), "")
			err := m.persist(record)
			recordMu.Unlock()
			return err
		}
		recordMu.Lock()
		if record.Items[index].Attempts >= task.Budget.MaxAttempts {
			m.completeFailure(record, index, CodeRetryExhausted, record.Items[index].Code)
			err := m.persist(record)
			recordMu.Unlock()
			return err
		}
		previousBytes := record.Items[index].Bytes
		recordMu.Unlock()
		allowance := allocator.reserveReplacing(task.Budget.MaxResourceBytes, previousBytes)
		recordMu.Lock()
		if allowance == 0 {
			m.completeFailure(record, index, CodePrewarmTaskBytesExceeded, "")
			err := m.persist(record)
			recordMu.Unlock()
			return err
		}
		record.Items[index].Status = recordWorking
		record.Items[index].Attempts++
		record.Items[index].Bytes = 0
		record.Items[index].ReservedBytes = allowance
		record.Items[index].NextAttemptAt = time.Time{}
		if err := m.persist(record); err != nil {
			allocator.settle(allowance, previousBytes)
			record.Items[index].Bytes = previousBytes
			record.Items[index].ReservedBytes = 0
			recordMu.Unlock()
			return err
		}
		recordMu.Unlock()

		if err := m.acquireSlot(ctx); err != nil {
			allocator.settle(allowance, previousBytes)
			recordMu.Lock()
			record.Items[index].Bytes = previousBytes
			record.Items[index].ReservedBytes = 0
			m.completeFailure(record, index, contextFailureCode(ctx), "")
			err := m.persist(record)
			recordMu.Unlock()
			return err
		}
		outcome := m.prewarmAttempt(ctx, task, task.Targets[index], taskRate, allowance)
		<-m.globalSlots

		recordMu.Lock()
		chargedBytes := max(previousBytes, outcome.bytes)
		record.Items[index].ReservedBytes = 0
		record.Items[index].Bytes = chargedBytes
		if outcome.status != ItemFailed || !outcome.retryable {
			m.complete(record, index, itemOutcome{
				status: outcome.status, code: outcome.code, affected: outcome.affected,
			})
			err := m.persist(record)
			recordMu.Unlock()
			allocator.settle(allowance, chargedBytes)
			return err
		}
		if record.Items[index].Attempts >= task.Budget.MaxAttempts {
			m.completeFailure(record, index, CodeRetryExhausted, outcome.code)
			err := m.persist(record)
			recordMu.Unlock()
			allocator.settle(allowance, chargedBytes)
			return err
		}
		record.Items[index].Status = recordPending
		record.Items[index].Code = outcome.code
		record.Items[index].CauseCode = ""
		now := m.now().UTC()
		delay := retryDelayWithServerHint(
			m.retryDelay(task.Budget, record.Items[index].Attempts), outcome.retryAfter,
			now, task.Budget.MaximumRetryBackoff,
		)
		record.Items[index].NextAttemptAt = now.Add(delay)
		err := m.persist(record)
		recordMu.Unlock()
		allocator.settle(allowance, chargedBytes)
		if err != nil {
			return err
		}
	}
}

func (m *Manager) activeSiteBindingMatches(ctx context.Context, task normalizedTask) bool {
	active, err := m.resolver.ResolveSite(ctx, task.TenantID, task.SiteID, task.ConfigVersionID, task.ConfigRevision)
	active, valid := normalizeSiteContext(active)
	return err == nil && valid &&
		equalSiteBinding(siteBindingFromContext(active), siteBindingFromContext(task.Site))
}

type activeReleaseLeaser interface {
	lockActiveRelease(context.Context) (func(), error)
}

func (m *Manager) lockActiveRelease(ctx context.Context) (func(), error) {
	resolver, ok := m.resolver.(activeReleaseLeaser)
	if !ok {
		return nil, ErrInvalidState
	}
	return resolver.lockActiveRelease(ctx)
}

func (a *byteAllocator) reserveReplacing(maximum, replaced int64) int64 {
	for {
		a.mu.Lock()
		available := a.remaining + replaced
		value := min(maximum, available)
		if value > 0 {
			a.remaining = available - value
			a.inFlight++
			a.mu.Unlock()
			return value
		}
		if a.inFlight == 0 {
			a.mu.Unlock()
			return 0
		}
		if a.changed == nil {
			a.changed = make(chan struct{})
		}
		changed := a.changed
		a.mu.Unlock()
		<-changed
	}
}

func (a *byteAllocator) settle(reserved, used int64) {
	a.mu.Lock()
	a.remaining += reserved - used
	a.inFlight--
	changed := a.changed
	a.changed = nil
	a.mu.Unlock()
	if changed != nil {
		close(changed)
	}
}

func (m *Manager) waitForRetry(ctx context.Context, item itemRecord) error {
	if item.NextAttemptAt.IsZero() {
		return ctx.Err()
	}
	delay := item.NextAttemptAt.Sub(m.now().UTC())
	if delay <= 0 {
		return ctx.Err()
	}
	return m.config.Sleep(ctx, delay)
}

func (m *Manager) retryDelay(budget ResourceBudget, attempts int) time.Duration {
	delay := budget.InitialRetryBackoff
	for count := 1; count < attempts && delay < budget.MaximumRetryBackoff; count++ {
		if delay > budget.MaximumRetryBackoff/2 {
			delay = budget.MaximumRetryBackoff
			break
		}
		delay *= 2
	}
	if delay > budget.MaximumRetryBackoff {
		delay = budget.MaximumRetryBackoff
	}
	delay = m.config.Jitter(delay)
	if delay < 0 {
		return 0
	}
	if delay > budget.MaximumRetryBackoff {
		return budget.MaximumRetryBackoff
	}
	return delay
}

func (m *Manager) acquireSlot(ctx context.Context) error {
	select {
	case m.globalSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) lockLocal(ctx context.Context, key string) (func(), error) {
	m.locksMu.Lock()
	entry := m.localLocks[key]
	if entry == nil {
		entry = &lockEntry{token: make(chan struct{}, 1)}
		entry.token <- struct{}{}
		m.localLocks[key] = entry
	}
	entry.refs++
	m.locksMu.Unlock()
	releaseRef := func() {
		m.locksMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(m.localLocks, key)
		}
		m.locksMu.Unlock()
	}
	if err := ctx.Err(); err != nil {
		releaseRef()
		return nil, err
	}
	select {
	case <-ctx.Done():
		releaseRef()
		return nil, ctx.Err()
	case <-entry.token:
	}
	if err := ctx.Err(); err != nil {
		entry.token <- struct{}{}
		releaseRef()
		return nil, err
	}
	return func() {
		entry.token <- struct{}{}
		releaseRef()
	}, nil
}

func (m *Manager) siteLimiter(identity string) (*tokenBucket, func(), error) {
	m.ratesMu.Lock()
	entry := m.siteRates[identity]
	if entry == nil {
		if len(m.siteRates) >= m.config.MaxSiteLimiters {
			var oldestIdentity string
			var oldestTick uint64
			for candidateIdentity, candidate := range m.siteRates {
				if candidate.refs == 0 && (oldestIdentity == "" || candidate.lastUsed < oldestTick) {
					oldestIdentity, oldestTick = candidateIdentity, candidate.lastUsed
				}
			}
			if oldestIdentity == "" {
				m.ratesMu.Unlock()
				return nil, nil, ErrTaskCapacity
			}
			delete(m.siteRates, oldestIdentity)
		}
		entry = &siteRateEntry{limiter: newTokenBucket(m.config.SiteRequestsPerSecond, m.config.SiteBurst)}
		m.siteRates[identity] = entry
	}
	m.rateTick++
	entry.refs++
	entry.lastUsed = m.rateTick
	m.ratesMu.Unlock()
	return entry.limiter, func() {
		m.ratesMu.Lock()
		entry.refs--
		m.rateTick++
		entry.lastUsed = m.rateTick
		m.ratesMu.Unlock()
	}, nil
}

func siteLimiterIdentity(site SiteContext) string {
	return site.TenantID + "\x00" + site.SiteID
}

func (m *Manager) registerActive(taskID string, cancel context.CancelFunc) {
	m.activeMu.Lock()
	m.active[taskID] = cancel
	m.activeMu.Unlock()
}

func (m *Manager) unregisterActive(taskID string) {
	m.activeMu.Lock()
	delete(m.active, taskID)
	m.activeMu.Unlock()
}

func (m *Manager) persist(record *taskRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.store.update(ctx, record)
}

func (m *Manager) complete(record *taskRecord, index int, outcome itemOutcome) {
	item := &record.Items[index]
	item.Affected += outcome.affected
	item.Status = recordItemStatus(outcome.status)
	item.Code = outcome.code
	item.CauseCode = ""
	item.NextAttemptAt = time.Time{}
	item.CompletedAt = m.now().UTC()
}

func (m *Manager) completeFailure(record *taskRecord, index int, code, cause string) {
	item := &record.Items[index]
	item.Status = recordFailed
	item.Code = code
	item.CauseCode = cause
	item.ReservedBytes = 0
	item.NextAttemptAt = time.Time{}
	item.CompletedAt = m.now().UTC()
}

func (m *Manager) failUnfinished(record *taskRecord, code string) {
	for index := range record.Items {
		if terminalItem(record.Items[index].Status) {
			continue
		}
		m.completeFailure(record, index, code, "")
	}
}

func terminalItem(status recordItemStatus) bool {
	return status == recordSuccess || status == recordSkipped || status == recordFailed
}

func (m *Manager) finish(record *taskRecord, cancelled bool) {
	if cancelled || !record.CancelRequestedAt.IsZero() {
		record.State = recordCancelled
		if record.CancelRequestedAt.IsZero() {
			record.CancelRequestedAt = m.now().UTC()
		}
	} else {
		record.State = recordDone
	}
	record.CompletedAt = m.now().UTC()
}

func resultFromRecord(record *taskRecord) Result {
	result := Result{
		SchemaVersion: record.Task.SchemaVersion, TaskID: record.Task.TaskID,
		OperationID: record.Task.OperationID, TenantID: record.Task.TenantID, SiteID: record.Task.SiteID,
		Scope: record.Task.Scope, ConfigVersionID: record.Task.ConfigVersionID,
		ConfigRevision: record.Task.ConfigRevision, Digest: record.Digest,
		Attempt: record.ExecutionAttempt, DeliveryAttempt: record.HighestDeliveryAttempt,
		StartedAt: record.StartedAt, CompletedAt: record.CompletedAt,
		Items: make([]ItemResult, len(record.Items)),
	}
	for index, item := range record.Items {
		status := ItemPending
		switch item.Status {
		case recordPending:
			status = ItemPending
		case recordWorking:
			status = ItemWorking
		case recordSuccess:
			status = ItemSuccess
			result.Progress.Succeeded++
		case recordSkipped:
			status = ItemSkipped
			result.Progress.Skipped++
		case recordFailed:
			status = ItemFailed
			result.Progress.Failed++
		}
		result.Progress.Bytes += item.Bytes
		result.Items[index] = ItemResult{
			Index: item.Index, Target: item.Target, TargetDigest: item.TargetDigest,
			Status: status, Code: item.Code, CauseCode: item.CauseCode,
			Affected: item.Affected, Bytes: item.Bytes,
			Attempts: item.Attempts, CompletedAt: item.CompletedAt,
		}
	}
	result.Progress.Total = len(result.Items)
	result.Progress.Completed = result.Progress.Succeeded + result.Progress.Skipped + result.Progress.Failed
	if record.State == recordRunning {
		result.State = StateRunning
	} else if record.State == recordCancelled {
		result.State = StateCancelled
	} else if result.Progress.Failed == 0 {
		result.State = StateSucceeded
	} else if result.Progress.Failed == result.Progress.Total {
		result.State = StateFailed
	} else {
		result.State = StatePartialFailed
	}
	return result
}
