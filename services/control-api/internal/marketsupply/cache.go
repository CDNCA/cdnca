package marketsupply

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
)

// defaultCacheQuota bounds the disk a market site's cache may use on each
// node when the subscriber enables caching; quotas are the leaf's to set.
const defaultCacheQuota = int64(1) << 30

// CachePolicies is the subset of cachecontrol.Store the leaf drives.
type CachePolicies interface {
	GetPolicy(ctx context.Context, actor cachecontrol.Actor, siteID uuid.UUID, revision int64) (cachecontrol.PolicyRevision, error)
	PublishPolicy(ctx context.Context, actor cachecontrol.Actor, request cachecontrol.PublishPolicyRequest) (cachecontrol.PolicyWriteResult, error)
}

// WithCache lets market sites carry a cache policy (siteconf.Cache); without
// it a cache block is refused with unsupported_cache.
func (s *Service) WithCache(policies CachePolicies) *Service {
	s.cache = policies
	return s
}

// cacheDocument maps the neutral cache block onto a local v2 policy and
// checks it with the same rules a publish applies.
func cacheDocument(cache *siteconf.Cache) (cachecontrol.PolicyDocument, error) {
	type rule struct {
		Order             int      `json:"order"`
		Extensions        []string `json:"extensions,omitempty"`
		PathPrefix        string   `json:"path_prefix,omitempty"`
		StatusCodes       []int    `json:"status_codes,omitempty"`
		Action            string   `json:"action"`
		TTLSeconds        int64    `json:"ttl_seconds"`
		BrowserTTLSeconds int64    `json:"browser_ttl_seconds"`
		PathRegex         string   `json:"path_regex,omitempty"`
		ContentTypes      []string `json:"content_types,omitempty"`
		edgeconfig.CacheRuleExtras
	}
	rules := make([]rule, len(cache.Rules))
	for i, r := range cache.Rules {
		extensions := make([]string, len(r.Extensions))
		for j, extension := range r.Extensions {
			if extension != "" && extension[0] != '.' {
				extension = "." + extension
			}
			extensions[j] = extension
		}
		extras := edgeconfig.CacheRuleExtras{PathExact: r.PathExact, IgnoreQuery: r.IgnoreQuery, SliceBytes: r.SliceBytes,
			ForceCache: r.ForceCache, IgnoreVary: r.IgnoreVary}
		for _, condition := range r.NoCache {
			extras.NoCache = append(extras.NoCache, edgeconfig.CacheNoCacheCondition{Source: condition.Source,
				Name: condition.Name, Pattern: condition.Pattern})
		}
		rules[i] = rule{Order: i + 1, Extensions: extensions, PathPrefix: r.PathPrefix, StatusCodes: r.StatusCodes,
			Action: r.Action, TTLSeconds: r.TTLSeconds, BrowserTTLSeconds: r.BrowserTTLSeconds,
			PathRegex: r.PathRegex, ContentTypes: r.ContentTypes, CacheRuleExtras: extras}
	}
	quota := int64(0)
	if cache.Mode != string(cachecontrol.PolicyDisabled) {
		quota = defaultCacheQuota
	}
	raw, err := json.Marshal(struct {
		SchemaVersion  int      `json:"schema_version"`
		Mode           string   `json:"mode"`
		Rules          []rule   `json:"rules"`
		QueryMode      string   `json:"query_mode"`
		QueryNames     []string `json:"query_names"`
		VaryHeaders    []string `json:"vary_headers"`
		DiskQuotaBytes int64    `json:"disk_quota_bytes"`
		cachecontrol.PolicyExtensions
	}{cachecontrol.PolicySchemaV2, cache.Mode, rules, cache.QueryMode, nonNilStrings(cache.QueryNames),
		nonNilStrings(cache.VaryHeaders), quota, cachecontrol.PolicyExtensions{StaleIfError: cache.StaleIfError,
			BackgroundUpdate: cache.BackgroundUpdate, MinObjectBytes: cache.MinObjectBytes,
			MaxObjectBytes: cache.MaxObjectBytes, SliceBytes: cache.SliceBytes}})
	if err != nil {
		return cachecontrol.PolicyDocument{}, err
	}
	var document cachecontrol.PolicyDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return cachecontrol.PolicyDocument{}, err
	}
	return cachecontrol.NormalizePolicyDocument(document)
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// cacheBlockers reports why the cache block cannot be honoured, if at all.
func (s *Service) cacheBlockers(c siteconf.Config) []siteconf.Blocker {
	cache, err := c.DecodeCache()
	if err != nil {
		return []siteconf.Blocker{{Code: "cache_invalid"}}
	}
	if cache == nil {
		return nil
	}
	if s.cache == nil {
		return []siteconf.Blocker{{Code: "unsupported_cache"}}
	}
	if _, err := cacheDocument(cache); err != nil {
		return []siteconf.Blocker{{Code: "cache_invalid"}}
	}
	return nil
}

// applyCache publishes the site's cache policy as the tenant owner, unless
// the config carries none or the current policy already says the same. The
// idempotency key names the revision it replaces, so a retried commit replays
// instead of stacking revisions.
func (s *Service) applyCache(ctx context.Context, tenant tenantRef, leafSiteID uuid.UUID, req siteconf.CommitRequest) error {
	cache, err := req.Config.DecodeCache()
	if err != nil || cache == nil {
		return err
	}
	if s.cache == nil {
		return errors.New("market supply: cache policies are not configured")
	}
	document, err := cacheDocument(cache)
	if err != nil {
		return err
	}
	actor := cachecontrol.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ActorScopeID: tenant.scopeID}
	current := int64(0)
	existing, err := s.cache.GetPolicy(ctx, actor, leafSiteID, 0)
	switch {
	case errors.Is(err, cachecontrol.ErrNotFound):
	case err != nil:
		return err
	default:
		current = existing.Revision
		if existing.BindingMode == cachecontrol.BindingOverride && samePolicy(existing.Document, document) {
			return nil
		}
	}
	key := "market-cache-" + req.SiteID.String() + "-" + strconv.FormatInt(req.Revision, 10) + "-r" +
		strconv.FormatInt(current, 10)
	_, err = s.cache.PublishPolicy(ctx, actor, cachecontrol.PublishPolicyRequest{SiteID: leafSiteID,
		ExpectedRevision: current, BindingMode: cachecontrol.BindingOverride, Document: document,
		IdempotencyKey: key, RequestID: key})
	return err
}

func samePolicy(a, b cachecontrol.PolicyDocument) bool {
	left, errLeft := json.Marshal(a)
	right, errRight := json.Marshal(b)
	return errLeft == nil && errRight == nil && string(left) == string(right)
}
