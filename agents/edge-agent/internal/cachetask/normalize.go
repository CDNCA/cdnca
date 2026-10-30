package cachetask

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	maxTargetLength             = 16 << 10
	cachePolicyMaxRawQueryBytes = 8192
	cachePolicyMaxQueryPairs    = 256
)

var (
	idPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	cacheIDPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	domainPattern    = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)
	queryNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.~-]{0,127}$`)
	varyNamePattern  = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$")
	targetHashMarker = "?query=redacted"
)

type normalizedTask struct {
	Task
	Site    SiteContext
	Targets []normalizedTarget
	Digest  string
}

type normalizedTarget struct {
	PublicTarget string
	RequestURL   string
	// RequestHost is the target's own host (the prewarm Host); the cache key
	// is the site's (Site.Domain).
	RequestHost string
	Digest      string
	URI         string
	Path        string
	Site        SiteContext
	// Ports (purge only, ge-cache): every cache-enabled listener port of the
	// site that serves the target's host, http and https alike: one purge
	// clears the URL whichever scheme or port stored it. The prewarm fills
	// only the target's own listener (Site.ListenPort).
	Ports []uint16
	// WildcardSuffix (purge only): the target named "*.<suffix>"; it matches
	// every host under the suffix the site serves.
	WildcardSuffix string
}

// matchesPort reports whether a key's listen port is one the target covers.
func (target normalizedTarget) matchesPort(port uint16) bool {
	if len(target.Ports) == 0 {
		return port == target.Site.ListenPort
	}
	return slices.Contains(target.Ports, port)
}

func validateEnvelope(task Task, config Config, now time.Time) error {
	if task.SchemaVersion != SchemaVersion || !idPattern.MatchString(task.TaskID) ||
		!idPattern.MatchString(task.OperationID) || task.IdempotencyKey != "" || task.ExpectedConfigVersion != "" ||
		!idPattern.MatchString(task.TenantID) || !idPattern.MatchString(task.SiteID) ||
		!idPattern.MatchString(task.ConfigVersionID) || task.ConfigRevision == 0 ||
		task.DeliveryAttempt < 1 || task.DeliveryAttempt > 1_000_000 || task.Deadline.IsZero() ||
		task.Deadline.After(now.Add(config.MaxDeadlineHorizon)) || len(task.Targets) > config.MaxBatchItems ||
		!validActionScope(task.Action, task.Scope) || !validBudget(task, config) {
		return ErrInvalidTask
	}
	targetBytes := 0
	for _, target := range task.Targets {
		targetBytes += len(target)
		if targetBytes > config.MaxTaskTargetBytes {
			return ErrInvalidTask
		}
	}
	if task.Action == ActionPurgeSite {
		if len(task.Targets) != 0 {
			return ErrInvalidTask
		}
	} else if len(task.Targets) == 0 {
		return ErrInvalidTask
	}
	return nil
}

func validActionScope(action Action, scope Scope) bool {
	return (action == ActionPurgeExact && scope == ScopeURL) ||
		(action == ActionPurgePrefix && scope == ScopeDirectory) ||
		(action == ActionPurgeSite && scope == ScopeSite) ||
		(action == ActionPrewarm && scope == ScopeURL)
}

func validBudget(task Task, config Config) bool {
	budget := task.Budget
	if budget.MaxAttempts < 1 || budget.MaxAttempts > config.MaxAttempts ||
		budget.InitialRetryBackoff < time.Millisecond || budget.InitialRetryBackoff > time.Minute ||
		budget.MaximumRetryBackoff < budget.InitialRetryBackoff || budget.MaximumRetryBackoff > 10*time.Minute {
		return false
	}
	if task.Action != ActionPrewarm {
		return budget.MaxConcurrency == 1 && budget.MaxPurgeEntries >= 1 &&
			budget.MaxPurgeEntries <= config.MaxPurgeEntries && budget.MaxTotalBytes == 0 &&
			budget.MaxScanEntries >= 1 && budget.MaxScanEntries <= config.MaxScanEntries &&
			budget.MaxScanBytes >= 1 && budget.MaxScanBytes <= config.MaxScanBytes &&
			budget.MaxScanDuration >= time.Millisecond && budget.MaxScanDuration <= config.MaxScanDuration &&
			budget.MaxResourceBytes == 0 && budget.RequestsPerSecond == 0 && budget.Burst == 0
	}
	return budget.MaxConcurrency >= 1 && budget.MaxConcurrency <= config.MaxTaskConcurrency &&
		budget.MaxPurgeEntries == 0 && budget.MaxScanEntries == 0 && budget.MaxScanBytes == 0 &&
		budget.MaxScanDuration == 0 && budget.MaxResourceBytes >= 1 &&
		budget.MaxResourceBytes <= config.MaxResponseBytes && budget.MaxTotalBytes >= budget.MaxResourceBytes &&
		budget.MaxTotalBytes <= config.MaxTaskBytes && budget.RequestsPerSecond > 0 &&
		budget.RequestsPerSecond <= config.SiteRequestsPerSecond && budget.Burst >= 1 && budget.Burst <= config.SiteBurst
}

func normalizeTask(task Task, site SiteContext, config Config, now time.Time) (normalizedTask, error) {
	if validateEnvelope(task, config, now) != nil || site.TenantID != task.TenantID || site.SiteID != task.SiteID ||
		site.ConfigVersionID != task.ConfigVersionID || site.ConfigRevision != task.ConfigRevision {
		return normalizedTask{}, ErrInvalidTask
	}
	var valid bool
	site, valid = normalizeSiteContext(site)
	if !valid || !validSiteContext(site, task.Action) {
		return normalizedTask{}, ErrInvalidTask
	}

	targets := make([]normalizedTarget, 0, max(1, len(task.Targets)))
	if task.Action == ActionPurgeSite {
		// The whole-site record names the site's key domain, a "*." wildcard
		// included (validPublicTarget accepts it).
		listener := site.Listeners[0]
		scheme := listener.Scheme
		representative := site
		representative.Domain, representative.ListenPort, representative.Scheme = listener.Domain, listener.ListenPort, scheme
		representative.CacheEnabled, representative.PrewarmPort = listener.CacheEnabled, listener.PrewarmPort
		rootURL := scheme + "://" + siteAuthority(representative) + "/"
		targets = append(targets, normalizedTarget{
			PublicTarget: strings.TrimSuffix(rootURL, "/") + "/*",
			RequestURL:   rootURL,
			Digest:       targetDigest(rootURL),
			URI:          "/",
			Path:         "/",
			Site:         site,
		})
	} else {
		seen := make(map[string]struct{}, len(task.Targets))
		for _, raw := range task.Targets {
			normalize := normalizeURL
			if task.Action != ActionPrewarm {
				normalize = normalizePurgeURL
			}
			target, err := normalize(raw, site, task.Action == ActionPurgePrefix)
			if err != nil {
				return normalizedTask{}, err
			}
			if _, exists := seen[target.RequestURL]; exists {
				return normalizedTask{}, ErrInvalidTask
			}
			seen[target.RequestURL] = struct{}{}
			targets = append(targets, target)
		}
	}

	canonicalTargets := make([]string, 0, len(targets))
	publicTargetBytes := 0
	for _, target := range targets {
		publicTargetBytes += len(target.PublicTarget)
		if publicTargetBytes > config.MaxTaskTargetBytes {
			return normalizedTask{}, ErrInvalidTask
		}
		canonicalTargets = append(canonicalTargets, target.RequestURL)
	}
	canonical := struct {
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
		Targets         []string       `json:"targets"`
		CacheIdentity   string         `json:"cache_identity"`
	}{
		task.SchemaVersion, task.TaskID, task.OperationID, task.TenantID, task.SiteID, task.Scope,
		task.ConfigVersionID, task.ConfigRevision, task.Deadline.UTC(), task.Budget, task.Action,
		canonicalTargets, site.CacheIdentity,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return normalizedTask{}, ErrInvalidTask
	}
	digest := sha256.Sum256(encoded)
	canonicalTask := task
	canonicalTask.Deadline = task.Deadline.UTC()
	canonicalTask.Targets = append([]string(nil), canonicalTargets...)
	if task.Action == ActionPurgeSite {
		canonicalTask.Targets = nil
	}
	normalized := normalizedTask{Task: canonicalTask, Site: site, Targets: targets, Digest: hex.EncodeToString(digest[:])}
	if !journalRecordFits(normalized, now) {
		return normalizedTask{}, ErrInvalidTask
	}
	return normalized, nil
}

func CacheNamespaceID(tenantID, siteID, configVersionID string) string {
	return edgeconfig.CacheNamespaceID(tenantID, siteID, configVersionID)
}

func validSiteContext(site SiteContext, action Action) bool {
	site, valid := normalizeSiteContext(site)
	if !valid {
		return false
	}
	if action != ActionPrewarm {
		return true
	}
	for _, listener := range site.Listeners {
		if listener.CacheEnabled && listener.PrewarmPort != 0 && listener.PrewarmPort != listener.ListenPort {
			return true
		}
	}
	return false
}

func normalizeSiteContext(site SiteContext) (SiteContext, bool) {
	if !idPattern.MatchString(site.TenantID) || !idPattern.MatchString(site.SiteID) ||
		!idPattern.MatchString(site.ConfigVersionID) || site.ConfigRevision == 0 ||
		!cacheIDPattern.MatchString(site.CacheIdentity) ||
		site.CacheGeneration != "" && !edgeconfig.CacheGenerationPattern.MatchString(site.CacheGeneration) ||
		site.CacheIdentity != site.expectedCacheIdentity() {
		return SiteContext{}, false
	}
	if (site.ActiveReleaseSHA256 == "") != (site.NginxSHA256 == "") ||
		site.ActiveReleaseSHA256 != "" &&
			(len(site.ActiveReleaseSHA256) != sha256.Size*2 || !lowerHex(site.ActiveReleaseSHA256) ||
				len(site.NginxSHA256) != sha256.Size*2 || !lowerHex(site.NginxSHA256)) {
		return SiteContext{}, false
	}
	if site.QueryMode == "" {
		site.QueryMode = edgeconfig.CacheQueryPreserve
	}
	if !validCachePolicyContext(site) {
		return SiteContext{}, false
	}
	site.QueryNames = append([]string(nil), site.QueryNames...)
	site.VaryHeaders = append([]string(nil), site.VaryHeaders...)
	rules := make([]edgeconfig.CacheRuleDocument, len(site.CacheRules))
	for index, rule := range site.CacheRules {
		rule.Extensions = append([]string(nil), rule.Extensions...)
		rule.StatusCodes = append([]int(nil), rule.StatusCodes...)
		rules[index] = rule
	}
	site.CacheRules = rules
	if len(site.Domains) > maxSiteDomains {
		return SiteContext{}, false
	}
	domains := make(map[string]struct{}, len(site.Domains))
	for _, domain := range site.Domains {
		if _, duplicate := domains[domain]; duplicate || !validSiteName(domain) {
			return SiteContext{}, false
		}
		domains[domain] = struct{}{}
	}
	site.Domains = append([]string(nil), site.Domains...)
	listeners := append([]ListenerContext(nil), site.Listeners...)
	if len(listeners) == 0 {
		listeners = []ListenerContext{{
			Domain: site.Domain, Scheme: site.Scheme, ListenPort: site.ListenPort, PrewarmPort: site.PrewarmPort,
			PrewarmPathPrefix: site.PrewarmPathPrefix,
			CacheEnabled:      site.CacheEnabled,
		}}
	}
	if len(listeners) > 1000 {
		return SiteContext{}, false
	}
	seen := make(map[string]struct{}, len(listeners))
	for index, listener := range listeners {
		if !validListener(listener) {
			return SiteContext{}, false
		}
		if _, served := domains[listener.Domain]; len(domains) != 0 && !served {
			return SiteContext{}, false
		}
		if listener.PrewarmPort != 0 && listener.PrewarmPathPrefix != edgeconfig.CachePrewarmPathPrefix(
			site.TenantID, site.SiteID, site.ConfigVersionID, listener.Domain, listener.ListenPort,
			edgeconfig.Protocol(listener.Scheme)) {
			return SiteContext{}, false
		}
		key := listener.Domain + "\x00" + strconv.Itoa(int(listener.ListenPort))
		if _, exists := seen[key]; exists {
			return SiteContext{}, false
		}
		seen[key] = struct{}{}
		if index > 0 {
			previous := listeners[index-1]
			if previous.ListenPort > listener.ListenPort ||
				previous.ListenPort == listener.ListenPort && previous.Domain >= listener.Domain {
				return SiteContext{}, false
			}
		}
	}
	site.Listeners = listeners
	return site, true
}

func validCachePolicyContext(site SiteContext) bool {
	if site.QueryMode != edgeconfig.CacheQueryPreserve && site.QueryMode != edgeconfig.CacheQueryIgnore &&
		site.QueryMode != edgeconfig.CacheQueryInclude && site.QueryMode != edgeconfig.CacheQueryExclude {
		return false
	}
	if (site.QueryMode == edgeconfig.CacheQueryPreserve || site.QueryMode == edgeconfig.CacheQueryIgnore) !=
		(len(site.QueryNames) == 0) || len(site.QueryNames) > 64 || len(site.VaryHeaders) > 16 || len(site.CacheRules) > 100 {
		return false
	}
	for index, name := range site.QueryNames {
		if !queryNamePattern.MatchString(name) || index > 0 && site.QueryNames[index-1] >= name {
			return false
		}
	}
	for index, name := range site.VaryHeaders {
		if !varyNamePattern.MatchString(name) || index > 0 && site.VaryHeaders[index-1] >= name {
			return false
		}
	}
	for index, rule := range site.CacheRules {
		if rule.Order != index+1 || rule.TTLSeconds < 1 || rule.TTLSeconds > 365*24*60*60 ||
			len(rule.Extensions) > 32 || len(rule.StatusCodes) > 32 ||
			rule.PathPrefix != "" && (!strings.HasPrefix(rule.PathPrefix, "/") || !strings.HasSuffix(rule.PathPrefix, "/")) {
			return false
		}
		for valueIndex, extension := range rule.Extensions {
			if valueIndex > 0 && rule.Extensions[valueIndex-1] >= extension {
				return false
			}
		}
		for valueIndex, status := range rule.StatusCodes {
			if status < 100 || status > 599 || valueIndex > 0 && rule.StatusCodes[valueIndex-1] >= status {
				return false
			}
		}
	}
	return true
}

func validListener(listener ListenerContext) bool {
	return listener.ListenPort != 0 && (listener.Scheme == "http" || listener.Scheme == "https") &&
		(listener.PrewarmPort == 0) == (listener.PrewarmPathPrefix == "") &&
		(listener.PrewarmPort == 0 || listener.PrewarmPort != listener.ListenPort) &&
		validSiteName(listener.Domain)
}

const maxSiteDomains = 100

// validHostName is a concrete lower-case DNS name (no IP literal).
func validHostName(value string) bool {
	if !domainPattern.MatchString(value) ||
		strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") ||
		strings.Contains(value, "..") || net.ParseIP(value) != nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// validSiteName is a name a site serves: a concrete host or "*." and a
// concrete suffix with at least two labels (nginx server_name).
func validSiteName(value string) bool {
	if suffix, wildcard := strings.CutPrefix(value, "*."); wildcard {
		return strings.Contains(suffix, ".") && validHostName(suffix)
	}
	return validHostName(value)
}

// siteNameCovers reports whether the concrete host is served by name: equal,
// or under a "*." wildcard (any depth, as nginx matches it; not the suffix).
func siteNameCovers(name, host string) bool {
	if suffix, wildcard := strings.CutPrefix(name, "*."); wildcard {
		return strings.HasSuffix(host, "."+suffix)
	}
	return name == host
}

// siteServes reports whether the concrete host is one the site serves: its
// Domains, or without them the listener's own domain.
func siteServes(site SiteContext, listener ListenerContext, host string) bool {
	names := site.Domains
	if len(names) == 0 {
		names = []string{listener.Domain}
	}
	for _, name := range names {
		if siteNameCovers(name, host) {
			return true
		}
	}
	return false
}

// normalizePurgeURL is normalizeURL for a purge: the host may be a "*."
// wildcard the site serves (or under one it serves), and the target covers
// every cache-enabled listener port that serves the host.
func normalizePurgeURL(raw string, site SiteContext, prefix bool) (normalizedTarget, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return normalizedTarget{}, ErrInvalidTask
	}
	hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	suffix, wildcard := strings.CutPrefix(hostname, "*.")
	if wildcard {
		if !strings.Contains(suffix, ".") || !validHostName(suffix) || !siteServesWildcard(site, suffix) {
			return normalizedTarget{}, ErrInvalidTask
		}
		// Normalize as a concrete name under the wildcard, then restore it.
		concrete := strings.Replace(raw, "*."+suffix, "cdnca-wildcard."+suffix, 1)
		if concrete == raw {
			return normalizedTarget{}, ErrInvalidTask
		}
		target, err := normalizeURL(concrete, site, prefix)
		if err != nil {
			return normalizedTarget{}, err
		}
		target.PublicTarget = strings.Replace(target.PublicTarget, "cdnca-wildcard."+suffix, "*."+suffix, 1)
		target.RequestURL = strings.Replace(target.RequestURL, "cdnca-wildcard."+suffix, "*."+suffix, 1)
		target.Digest = targetDigest(target.RequestURL)
		target.RequestHost = ""
		target.WildcardSuffix = suffix
		return target, nil
	}
	return normalizeURL(raw, site, prefix)
}

// siteServesWildcard: the site serves "*.<suffix>" itself or a wildcard
// covering every host under suffix ("*.<parent>" of suffix), or names under
// it (a host-keyed site keys each one; a purge of the wildcard clears them).
func siteServesWildcard(site SiteContext, suffix string) bool {
	names := site.Domains
	if len(names) == 0 {
		for _, listener := range site.Listeners {
			names = append(names, listener.Domain)
		}
	}
	for _, name := range names {
		if name == "*."+suffix || siteNameCovers(name, suffix) || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

// purgePorts are the cache-enabled listener ports serving host (any scheme).
func purgePorts(site SiteContext, host string) []uint16 {
	var ports []uint16
	for _, listener := range site.Listeners {
		if listener.CacheEnabled && siteServes(site, listener, host) && !slices.Contains(ports, listener.ListenPort) {
			ports = append(ports, listener.ListenPort)
		}
	}
	slices.Sort(ports)
	return ports
}

func normalizeURL(raw string, site SiteContext, prefix bool) (normalizedTarget, error) {
	if raw == "" || len(raw) > maxTargetLength || strings.TrimSpace(raw) != raw ||
		!asciiPrintable(raw) || strings.Contains(raw, "\\") {
		return normalizedTarget{}, ErrInvalidTask
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Fragment != "" ||
		parsed.Opaque != "" || parsed.Host == "" || strings.Contains(raw, "#") {
		return normalizedTarget{}, ErrInvalidTask
	}
	hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if !validHostName(hostname) {
		return normalizedTarget{}, ErrInvalidTask
	}
	listener, found := ListenerContext{}, false
	for _, candidate := range site.Listeners {
		if siteServes(site, candidate, hostname) && candidate.ListenPort == effectivePort(parsed) && candidate.Scheme == parsed.Scheme {
			if found {
				return normalizedTarget{}, ErrInvalidTask
			}
			listener, found = candidate, true
		}
	}
	if !found || !listener.CacheEnabled {
		return normalizedTarget{}, ErrInvalidTask
	}
	selected := site
	selected.Domain, selected.ListenPort, selected.Scheme = listener.Domain, listener.ListenPort, parsed.Scheme
	selected.CacheEnabled, selected.PrewarmPort = listener.CacheEnabled, listener.PrewarmPort
	selected.PrewarmPathPrefix = listener.PrewarmPathPrefix
	requestPath := parsed.Path
	if requestPath == "" {
		requestPath = "/"
	}
	escapedPath := strings.ToLower(parsed.EscapedPath())
	if strings.Contains(escapedPath, "%2f") || strings.Contains(escapedPath, "%5c") || !validCanonicalPath(requestPath) {
		return normalizedTarget{}, ErrInvalidTask
	}
	if prefix && (parsed.RawQuery != "" || parsed.ForceQuery) {
		return normalizedTarget{}, ErrInvalidTask
	}
	if !asciiPrintable(parsed.RawQuery) {
		return normalizedTarget{}, ErrInvalidTask
	}
	uri := requestPath
	if parsed.RawQuery != "" || parsed.ForceQuery {
		uri += "?" + parsed.RawQuery
	}
	if cachePolicyProjectedKey(selected) {
		if _, err := cachePolicyQueryDigest(selected.QueryMode, selected.QueryNames, uri); err != nil {
			return normalizedTarget{}, ErrInvalidTask
		}
	}
	// The URL keeps its own host; the cache key (selected.Domain) is the site's.
	requested := selected
	requested.Domain = hostname
	canonical := (&url.URL{
		Scheme: selected.Scheme, Host: siteAuthority(requested), Path: requestPath,
		RawQuery: parsed.RawQuery, ForceQuery: parsed.ForceQuery,
	}).String()
	publicTarget := (&url.URL{Scheme: selected.Scheme, Host: siteAuthority(requested), Path: requestPath}).String()
	if parsed.RawQuery != "" || parsed.ForceQuery {
		publicTarget += targetHashMarker
	}
	if len(publicTarget) > maxTargetLength {
		return normalizedTarget{}, ErrInvalidTask
	}
	return normalizedTarget{
		PublicTarget: publicTarget,
		RequestURL:   canonical,
		RequestHost:  hostname,
		Digest:       targetDigest(canonical),
		URI:          uri,
		Path:         requestPath,
		Site:         selected,
		Ports:        purgePorts(site, hostname),
	}, nil
}

func targetDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func cachePolicyProjectedKey(site SiteContext) bool {
	return site.QueryMode != edgeconfig.CacheQueryPreserve || len(site.VaryHeaders) != 0
}

func cachePolicyKeyURI(site SiteContext, uri, varyDigest string) (string, error) {
	if !cachePolicyProjectedKey(site) || len(varyDigest) != sha256.Size*2 || !lowerHex(varyDigest) {
		return "", ErrInvalidTask
	}
	queryDigest, err := cachePolicyQueryDigest(site.QueryMode, site.QueryNames, uri)
	if err != nil {
		return "", err
	}
	requestPath := uri
	if marker := strings.IndexByte(uri, '?'); marker >= 0 {
		requestPath = uri[:marker]
	}
	if !validCanonicalPath(requestPath) {
		return "", ErrInvalidTask
	}
	return requestPath + "?~q=" + queryDigest + "&~v=" + varyDigest, nil
}

func cachePolicyQueryDigest(mode edgeconfig.CacheQueryMode, names []string, uri string) (string, error) {
	present := false
	raw := ""
	if marker := strings.IndexByte(uri, '?'); marker >= 0 {
		present = true
		raw = uri[marker+1:]
	}
	if len(raw) > cachePolicyMaxRawQueryBytes || !validCachePolicyPercent(raw) {
		return "", ErrInvalidTask
	}
	var framed strings.Builder
	addCachePolicyFrame(&framed, "schema", "cdnca-cache-query-v1")
	addCachePolicyFrame(&framed, "mode", string(mode))
	if mode == edgeconfig.CacheQueryIgnore {
		addCachePolicyFrame(&framed, "state", "ignored")
		return digestCachePolicyFrames(framed.String()), nil
	}
	state := "absent"
	if present {
		state = "present"
		if raw == "" {
			state = "empty"
		}
	}
	addCachePolicyFrame(&framed, "state", state)
	if mode == edgeconfig.CacheQueryPreserve {
		if present && raw != "" {
			addCachePolicyFrame(&framed, "raw", raw)
		}
		return digestCachePolicyFrames(framed.String()), nil
	}
	if mode != edgeconfig.CacheQueryInclude && mode != edgeconfig.CacheQueryExclude {
		return "", ErrInvalidTask
	}
	if !present || raw == "" {
		return digestCachePolicyFrames(framed.String()), nil
	}
	selected := make(map[string]struct{}, len(names))
	for _, name := range names {
		selected[name] = struct{}{}
	}
	pairs := strings.Split(raw, "&")
	if len(pairs) > cachePolicyMaxQueryPairs {
		return "", ErrInvalidTask
	}
	for _, pair := range pairs {
		rawName := pair
		if equals := strings.IndexByte(pair, '='); equals >= 0 {
			rawName = pair[:equals]
		}
		name, err := decodeCachePolicyQueryName(rawName)
		if err != nil {
			return "", err
		}
		_, keep := selected[name]
		if mode == edgeconfig.CacheQueryExclude {
			keep = !keep
		}
		if keep {
			addCachePolicyFrame(&framed, "pair", pair)
		}
	}
	return digestCachePolicyFrames(framed.String()), nil
}

func addCachePolicyFrame(output *strings.Builder, tag, value string) {
	output.WriteString(tag)
	output.WriteByte(':')
	output.WriteString(strconv.Itoa(len(value)))
	output.WriteByte(':')
	output.WriteString(value)
	output.WriteByte(';')
}

func digestCachePolicyFrames(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func validCachePolicyPercent(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			continue
		}
		if index+2 >= len(value) || !hexByte(value[index+1]) || !hexByte(value[index+2]) {
			return false
		}
		index += 2
	}
	return true
}

func decodeCachePolicyQueryName(value string) (string, error) {
	var decoded strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			decoded.WriteByte(value[index])
			continue
		}
		if index+2 >= len(value) || !hexByte(value[index+1]) || !hexByte(value[index+2]) {
			return "", ErrInvalidTask
		}
		decoded.WriteByte(fromHex(value[index+1])<<4 | fromHex(value[index+2]))
		index += 2
	}
	return decoded.String(), nil
}

func hexByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func fromHex(value byte) byte {
	if value >= '0' && value <= '9' {
		return value - '0'
	}
	if value >= 'a' && value <= 'f' {
		return value - 'a' + 10
	}
	return value - 'A' + 10
}

func effectivePort(value *url.URL) uint16 {
	if raw := value.Port(); raw != "" {
		port, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || port == 0 {
			return 0
		}
		return uint16(port)
	}
	if value.Scheme == "http" {
		return 80
	}
	if value.Scheme == "https" {
		return 443
	}
	return 0
}

func siteAuthority(site SiteContext) string {
	defaultPort := (site.Scheme == "http" && site.ListenPort == 80) || (site.Scheme == "https" && site.ListenPort == 443)
	if defaultPort {
		return site.Domain
	}
	return net.JoinHostPort(site.Domain, strconv.Itoa(int(site.ListenPort)))
}

func validCanonicalPath(value string) bool {
	if value == "" || value[0] != '/' || strings.Contains(value, "//") || !utf8.ValidString(value) {
		return false
	}
	cleaned := path.Clean(value)
	if value != "/" && strings.HasSuffix(value, "/") {
		cleaned += "/"
	}
	if cleaned != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) || character == '|' ||
			character == '?' || character == '#' || character == '\\' {
			return false
		}
	}
	return true
}

func asciiPrintable(value string) bool {
	for _, character := range value {
		if character > unicode.MaxASCII || unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}
