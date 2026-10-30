package dynroute

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntls"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Rollback returns the node to the previous index generation: one step
// when the active generation came from one change set, else by activating
// the previous index file as a new generation (contract §4.3). The
// skeleton is not touched: it was rendered for a superset of ports only if
// the rolled back generation added some; such a port answers 503 (not
// ready) until the next Apply re-renders.
func (runtime *Runtime) Rollback(ctx context.Context) (uint64, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	generation, err := runtime.rollbackIndex(ctx)
	if err != nil {
		return 0, err
	}
	current, _, err := runtime.activator.Files.Current()
	if err != nil {
		return generation, err
	}
	sites, err := runtime.readSites(current)
	if err != nil {
		return generation, err
	}
	// the generation rolled back to may use ports (or WAF tiers) the
	// active skeleton no longer has: render for its sites, reload if needed
	tuning, err := runtime.prepareRulePlans(sites, runtime.lastInput)
	if err != nil {
		return generation, err
	}
	waf, err := runtime.prepareWAF(runtime.lastInput, sites, tuning)
	if err != nil {
		return generation, err
	}
	conf, err := runtime.render(sites, waf, runtime.state.System, portSet(runtime.state.L4Ports), runtime.state.L4TCP, runtime.state.NodePages)
	if err != nil {
		return generation, err
	}
	if digest := skeletonDigest(conf); digest != runtime.state.Skeleton {
		if _, _, _, err := runtime.install(ctx, conf); err != nil {
			return generation, err
		}
		runtime.state.Skeleton = digest
	}
	runtime.state.WAF, runtime.state.PrevWAF = waf.Digest, runtime.state.WAF
	runtime.sites = sites
	runtime.state.Generation = generation
	runtime.applyDDoS(ctx, runtime.state.System, sites, runtime.state.L4TCP)
	// certificates: the rolled back generation's versions are the kept
	// previous ones; keep both until the next Apply
	runtime.state.Versions, runtime.state.PrevVersions = runtime.state.PrevVersions, runtime.state.Versions
	return generation, runtime.saveRolledBack(generation)
}

// saveRolledBack persists the state after a rollback: the rolled back
// generation is already active, so a failed save is a MaintenanceError
// (activated, maintenance failed), the same as after Apply (PJ-E02).
func (runtime *Runtime) saveRolledBack(generation uint64) error {
	if err := runtime.saveState(); err != nil {
		return &MaintenanceError{Generation: generation, Step: "save_state", Err: err}
	}
	return nil
}

// ---------------------------------------------------------------- certificates

// SyncCertificates copies certificate versions that arrived in the
// certificate store after the last Apply (certificate rotation: a new
// version is delivered first, then the site object naming it). It returns
// what Sync copied; the index is not changed.
func (runtime *Runtime) SyncCertificates(ctx context.Context) (dyntls.SyncResult, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	result, err := runtime.syncCertificates(ctx, runtime.sites)
	if err == nil {
		runtime.setUnavailable(result)
	}
	return result, err
}

// RefreshOCSP fetches OCSP responses for the active generation's stapling
// versions (dyntls.Pool.RefreshOCSP).
func (runtime *Runtime) RefreshOCSP(ctx context.Context) []dyntls.OCSPStatus {
	runtime.mu.Lock()
	versions := append([]dyntls.Version(nil), runtime.state.Versions...)
	runtime.mu.Unlock()
	if runtime.config.OCSP == nil {
		return nil
	}
	return runtime.pool.RefreshOCSP(ctx, runtime.config.OCSP, versions, runtime.config.Now())
}

// ---------------------------------------------------------------- cache

// ErrSiteNotServed: the site is not in the active generation or has no
// cache.
var ErrSiteNotServed = errors.New("dynamic routing: site not served with a cache")

func (runtime *Runtime) cacheSite(tenantID, siteID string) (dyncache.Site, error) {
	for _, site := range runtime.sites {
		if site.SiteID != siteID || site.TenantID != tenantID || site.Cache == nil {
			continue
		}
		return cacheSiteOf(site), nil
	}
	return dyncache.Site{}, ErrSiteNotServed
}

func cacheSiteOf(site edgesite.Site) dyncache.Site {
	names := append([]string{site.Hosts.Primary}, site.Hosts.Aliases...)
	ports := map[int]string{}
	for _, listener := range site.Listeners {
		ports[listener.Port] = "http"
		if listener.TLS != nil {
			ports[listener.Port] = "https"
		}
	}
	policy := site.Cache.Policy
	// a rule that ignores the query keys its requests in
	// the projected form too
	projected := policy.QueryMode != edgeconfig.CacheQueryPreserve || len(policy.VaryHeaders) != 0
	// objects are slices (keys end in |slice=<range>) when the site or any
	// caching rule runs in a slice variant (edgecache.Plan.ruleSliceBytes):
	// an exact purge must then scan for every slice of the URL
	// (CACHEFLOW-E01; the whole-object key finds nothing)
	sliced := edgecache.SliceVariantBytes(policy.SliceBytes) > 0
	for _, rule := range policy.Rules {
		projected = projected || rule.IgnoreQuery
		sliced = sliced || rule.Action != edgeconfig.CacheRuleActionNoCache && rule.SliceBytes != nil &&
			edgecache.SliceVariantBytes(*rule.SliceBytes) > 0
	}
	return dyncache.Site{SiteID: site.SiteID, Prefix: site.Cache.KeyPrefix, Token: site.Cache.Generation, Domain: site.Cache.Domain,
		KeyByHost: site.Cache.KeyByHost, Names: names, Ports: ports, QuotaBytes: policy.DiskQuotaBytes,
		Projected: projected, Sliced: sliced}
}

// PurgeSite empties a site's cache: its purge generation is bumped (every
// object unreachable at once) and its old files removed.
func (runtime *Runtime) PurgeSite(ctx context.Context, tenantID, siteID string) (uint64, dyncache.Result, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	site, err := runtime.cacheSite(tenantID, siteID)
	if err != nil {
		return 0, dyncache.Result{}, err
	}
	return runtime.zones.PurgeSite(ctx, runtime.generations, site)
}

// Purge removes exact URLs or prefixes of a site.
func (runtime *Runtime) Purge(ctx context.Context, tenantID, siteID string, urls []string, prefix bool) ([]dyncache.Result, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	site, err := runtime.cacheSite(tenantID, siteID)
	if err != nil {
		return nil, err
	}
	results := make([]dyncache.Result, len(urls))
	for index, raw := range urls {
		target, err := dyncache.ParseTarget(site, raw, prefix)
		if err != nil {
			return nil, err
		}
		if results[index], err = runtime.zones.Purge(ctx, site, []dyncache.Target{target}, prefix, runtime.generations); err != nil {
			return nil, err
		}
	}
	return results, nil
}

// Prewarm fetches each URL through the node as a visitor would, within the
// task's budget (CACHEFLOW-E02).
func (runtime *Runtime) Prewarm(ctx context.Context, tenantID, siteID string, urls []string, budget dyncache.PrewarmBudget) ([]dyncache.PrewarmResult, error) {
	runtime.mu.Lock()
	site, err := runtime.cacheSite(tenantID, siteID)
	prewarmer := runtime.prewarm
	runtime.mu.Unlock()
	if err != nil {
		return nil, err
	}
	results := make([]dyncache.PrewarmResult, len(urls))
	for index, raw := range urls {
		target, err := dyncache.ParseTarget(site, raw, false)
		if err != nil {
			return nil, err
		}
		scheme := "http"
		if strings.HasPrefix(raw, "https://") {
			scheme = "https"
		}
		results[index] = prewarmer.PrewarmWithin(ctx, site, target, scheme, budget)
	}
	return results, nil
}

// CleanQuota enforces every site's soft cache quota down to 90%.
func (runtime *Runtime) CleanQuota(ctx context.Context) (dyncache.CleanResult, error) {
	runtime.mu.Lock()
	sites := map[string]dyncache.Site{}
	for _, site := range runtime.sites {
		if site.Cache != nil {
			value := cacheSiteOf(site)
			sites[value.Prefix] = value
		}
	}
	zones := runtime.zones
	runtime.mu.Unlock()
	if zones.Count == 0 || len(sites) == 0 {
		return dyncache.CleanResult{}, nil
	}
	return zones.CleanQuota(ctx, sites, 0.9)
}

// ---------------------------------------------------------------- error.log

// ErrorLogStats is the node error log summary the heartbeat carries (D12
// decision: counts and the most recent severe lines).
type ErrorLogStats struct {
	SevereTotal uint64
	NoiseTotal  uint64
	Recent      []string // newest last, each at most MaxErrorLineBytes
	LastSevere  time.Time
}

// MaxErrorLineBytes bounds one reported line.
const MaxErrorLineBytes = 512

// ReadErrorLog reads new error.log lines into the running totals.
func (runtime *Runtime) ReadErrorLog() (ErrorLogStats, error) {
	runtime.logMu.Lock()
	defer runtime.logMu.Unlock()
	summary, err := runtime.errorLog.Read()
	if err != nil {
		return runtime.logStats, err
	}
	runtime.logStats.NoiseTotal += uint64(summary.Noise)
	runtime.logStats.SevereTotal += uint64(len(summary.Severe))
	if runtime.errorLog.Dropped > 0 {
		runtime.logStats.SevereTotal += uint64(runtime.errorLog.Dropped)
		runtime.errorLog.Dropped = 0
	}
	if len(summary.Severe) > 0 {
		runtime.logStats.LastSevere = runtime.config.Now().UTC()
	}
	for _, line := range summary.Severe {
		if len(line) > MaxErrorLineBytes {
			line = line[:MaxErrorLineBytes]
		}
		runtime.logStats.Recent = append(runtime.logStats.Recent, line)
	}
	if extra := len(runtime.logStats.Recent) - runtime.config.ErrorLogRecent; extra > 0 {
		runtime.logStats.Recent = append([]string(nil), runtime.logStats.Recent[extra:]...)
	}
	return runtime.ErrorLogSnapshotLocked(), nil
}

// ErrorLogSnapshot is the current summary without reading.
func (runtime *Runtime) ErrorLogSnapshot() ErrorLogStats {
	runtime.logMu.Lock()
	defer runtime.logMu.Unlock()
	return runtime.ErrorLogSnapshotLocked()
}

func (runtime *Runtime) ErrorLogSnapshotLocked() ErrorLogStats {
	stats := runtime.logStats
	stats.Recent = append([]string(nil), stats.Recent...)
	return stats
}

// ErrorLogProto is the heartbeat form of the summary
// (agent.v1.EdgeRuntimeStatus.error_log).
func (runtime *Runtime) ErrorLogProto() *agentv1.ErrorLogSummary {
	stats := runtime.ErrorLogSnapshot()
	summary := &agentv1.ErrorLogSummary{SevereTotal: stats.SevereTotal, NoiseTotal: stats.NoiseTotal, Recent: stats.Recent}
	if !stats.LastSevere.IsZero() {
		summary.LastSevereTime = timestamppb.New(stats.LastSevere)
	}
	return summary
}
