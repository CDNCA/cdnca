package goldendyn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

func cachingSites(sites []edgesite.Site) bool {
	for _, site := range sites {
		if site.Cache != nil && site.Cache.Policy.Mode != edgeconfig.CacheDisabled {
			return true
		}
	}
	return false
}

func maxRuleTTL(sites []edgesite.Site) time.Duration {
	var maximum time.Duration
	for _, site := range sites {
		plan, err := edgecache.Build(site)
		if err == nil && plan != nil {
			maximum = max(maximum, plan.Inactive())
		}
	}
	return maximum
}

// startCache is what the agent does after OpenResty starts: push every
// site's purge generation (until then the node caches nothing) and the
// prewarm token.
func (instance *instance) startCache(ctx context.Context) error {
	control := dyncache.UnixControl{Socket: filepath.Join(instance.root, "run", "cdnca-site-admin.sock")}
	instance.generations = &dyncache.Generations{Path: filepath.Join(instance.root, "cache-generations.json"), Control: control}
	if err := instance.generations.Sync(ctx); err != nil {
		return err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	instance.prewarmer = dyncache.Prewarmer{Token: hex.EncodeToString(token), Address: "127.0.0.1", Timeout: 10 * time.Second, MaxBytes: 64 << 20}
	return dyncache.SetPrewarmToken(ctx, control, instance.prewarmer.Token)
}

// settleCache waits (bounded) until no cache fill is being written: nginx
// writes a response into a temporary file in the zone (use_temp_path=off,
// a name other than the 32 hex digits of a key) and renames it when the
// upstream finishes, which can be just after the client got the response.
// A task or entries step right after a filling request would race it (the
// object counted by the next step instead: cache purge-dir 1 / purge-site 3).
func (instance *instance) settleCache() {
	root := instance.zones().Root
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		writing := false
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err == nil && !entry.IsDir() && len(entry.Name()) != 32 {
				writing = true
				return fs.SkipAll
			}
			return nil
		})
		if !writing {
			return
		}
	}
}

func (instance *instance) zones() dyncache.Zones {
	return dyncache.Zones{Root: filepath.Join(instance.root, "shared", "cache"), Count: instance.pool.Zones}
}

func (instance *instance) cacheSite(siteID string) (dyncache.Site, error) {
	for _, site := range instance.sites {
		if site.SiteID != siteID || site.Cache == nil {
			continue
		}
		names := append([]string{site.Hosts.Primary}, site.Hosts.Aliases...)
		ports := map[int]string{}
		for _, listener := range site.Listeners {
			ports[listener.Port] = "http"
			if listener.TLS != nil {
				ports[listener.Port] = "https"
			}
		}
		policy := site.Cache.Policy
		return dyncache.Site{SiteID: site.SiteID, Prefix: site.Cache.KeyPrefix, Token: site.Cache.Generation, Domain: site.Cache.Domain,
			KeyByHost: site.Cache.KeyByHost, Names: names, Ports: ports, QuotaBytes: policy.DiskQuotaBytes,
			Projected: policy.QueryMode != edgeconfig.CacheQueryPreserve || len(policy.VaryHeaders) != 0,
			Sliced:    edgecache.SliceVariantBytes(policy.SliceBytes) > 0}, nil
	}
	return dyncache.Site{}, fmt.Errorf("site %s has no cache", siteID)
}

// CacheEntries: the KEY lines of the site's objects. Dynamic routing keys
// differ from v7's by construction (stable prefix, no config version):
// compare.json records it as a semantic change.
func (instance *instance) CacheEntries(ctx context.Context, siteID string) ([]string, error) {
	instance.settleCache()
	site, err := instance.cacheSite(siteID)
	if err != nil {
		return nil, err
	}
	keys := []string{}
	err = instance.zones().Walk(ctx, site.Prefix, func(entry dyncache.Entry) error {
		keys = append(keys, entry.Key.Host+"|"+fmt.Sprint(entry.Key.Port)+"|"+entry.Key.PolicyKey)
		return nil
	})
	sort.Strings(keys)
	return keys, err
}

// Task runs a cache task as the agent would on a dynamic routing node.
func (instance *instance) Task(ctx context.Context, spec edgegolden.TaskSpec) (*edgegolden.TaskResult, error) {
	instance.settleCache()
	site, err := instance.cacheSite(spec.SiteID)
	if err != nil {
		return &edgegolden.TaskResult{Error: err.Error()}, nil
	}
	zones := instance.zones()
	switch spec.Action {
	case "purge_exact", "purge_prefix":
		prefix := spec.Action == "purge_prefix"
		result := &edgegolden.TaskResult{State: "succeeded"}
		for _, raw := range spec.Targets {
			target, err := dyncache.ParseTarget(site, raw, prefix)
			if err != nil {
				return &edgegolden.TaskResult{Error: err.Error()}, nil
			}
			purged, err := zones.Purge(ctx, site, []dyncache.Target{target}, prefix, instance.generations)
			if err != nil {
				return nil, err
			}
			result.Items = append(result.Items, edgegolden.TaskItem{Target: raw, Status: "success", Code: "PURGED", Affected: purged.Affected})
		}
		return result, nil
	case "purge_site":
		_, purged, err := zones.PurgeSite(ctx, instance.generations, site)
		if err != nil {
			return nil, err
		}
		scheme, port := "http", 0
		for candidate, value := range site.Ports {
			if port == 0 || candidate < port {
				port, scheme = candidate, value
			}
		}
		return &edgegolden.TaskResult{State: "succeeded", Items: []edgegolden.TaskItem{{
			Target: fmt.Sprintf("%s://%s:%d/*", scheme, site.Domain, port), Status: "success", Code: "PURGED", Affected: purged.Affected}}}, nil
	case "prewarm":
		result := &edgegolden.TaskResult{State: "succeeded"}
		for _, raw := range spec.Targets {
			target, err := dyncache.ParseTarget(site, raw, false)
			if err != nil {
				return &edgegolden.TaskResult{Error: err.Error()}, nil
			}
			scheme := strings.SplitN(raw, "://", 2)[0]
			outcome := instance.prewarmer.Prewarm(ctx, site, target, scheme)
			item := edgegolden.TaskItem{Target: raw, Status: "success", Code: outcome.Code}
			switch outcome.Code {
			case "PREWARMED":
			case "ALREADY_CACHED":
				item.Status = "skipped"
			default:
				item.Status, result.State = "failed", "failed"
			}
			result.Items = append(result.Items, item)
		}
		return result, nil
	}
	return &edgegolden.TaskResult{Error: "unknown cache task action " + spec.Action}, nil
}
