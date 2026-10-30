package edgepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Origin forwarding in the site runtime v2 document (migration
// 367). The control plane validated the settings
// (site/origin_forwarding.go); this maps them to document fields and
// validates the document the node receives.

type siteRuntimeV2Sticky struct {
	Source string `json:"source"`
	Name   string `json:"name"`
}

type siteRuntimeV2RequestHost struct {
	Mode  string  `json:"mode"`
	Value *string `json:"value,omitempty"`
}

type siteRuntimeV2Forwarding struct {
	// TrustedProxyCIDRs: X-Forwarded-For / X-Real-IP of these peers are
	// kept; any other peer's are replaced with its address.
	TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs,omitempty"`
	// WebSocketOrigins: an upgrade whose Origin is not listed gets 403.
	WebSocketOrigins []string `json:"websocket_origins,omitempty"`
	// HTTPSPoolID: TLS listeners use this pool (follow protocol).
	HTTPSPoolID *string `json:"https_pool_id,omitempty"`
	// FollowRedirect (ge36): the node follows the origin's redirects
	// (ORIGIN_FOLLOW_REDIRECT, edgesite.FollowRedirect).
	FollowRedirect *edgesite.FollowRedirect `json:"follow_redirect,omitempty"`
	// Site edit options (site-backend6, SITE_EDGE_OPTIONS): the search
	// engine pool, ACME pass-through, unbuffered directions, default site.
	SearchEnginePoolID *string  `json:"search_engine_pool_id,omitempty"`
	ACMEPassthrough    bool     `json:"acme_passthrough,omitempty"`
	Unbuffered         []string `json:"unbuffered,omitempty"`
	DefaultSite        bool     `json:"default_site,omitempty"`
}

// siteRuntimeV2SearchEnginePoolID is the pool of 搜索引擎回源.
const siteRuntimeV2SearchEnginePoolID = "search-engine"

// usesEdgeOptions: the forwarding needs SITE_EDGE_OPTIONS.
func (forwarding *siteRuntimeV2Forwarding) usesEdgeOptions() bool {
	return forwarding != nil && (forwarding.SearchEnginePoolID != nil || forwarding.ACMEPassthrough ||
		len(forwarding.Unbuffered) != 0 || forwarding.DefaultSite)
}

// siteRuntimeV2SystemTrust names the node's own CA store as an HTTPS
// origin's trust (no bundle file).
const siteRuntimeV2SystemTrust = "system"

// siteRuntimeV2NoVerifyTrust: the pool does not verify the origin
// certificate (tls_trust none, 不校验源站证书; fix-originnoverify,
// edgesite.TrustNone). Needs ORIGIN_TLS_NO_VERIFY.
const siteRuntimeV2NoVerifyTrust = "none"

// siteRuntimeV2UsesOriginTLSNoVerify: an HTTPS origin of the site does not
// verify its certificate.
func siteRuntimeV2UsesOriginTLSNoVerify(site siteRuntimeV2Site) bool {
	for _, pool := range site.OriginPools {
		for _, origin := range pool.Origins {
			if origin.TrustRef != nil && *origin.TrustRef == siteRuntimeV2NoVerifyTrust {
				return true
			}
		}
	}
	return false
}

const siteRuntimeV2HTTPSPoolID = "primary-https"

var (
	siteRuntimeV2HashKeyPattern     = regexp.MustCompile(`^[A-Za-z0-9._:/|@=$-]{1,256}$`)
	siteRuntimeV2HashKeyToken       = regexp.MustCompile(`\$[a-z_][a-z0-9_]*`)
	siteRuntimeV2StickyNamePattern  = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)
	siteRuntimeV2HashKeyVariables   = []string{"$remote_addr", "$binary_remote_addr", "$host", "$uri", "$request_uri", "$args", "$scheme", "$request_method"}
	siteRuntimeV2HashKeyDynamicVars = regexp.MustCompile(`^\$(cookie|arg|http)_[a-z0-9_]{1,64}$`)
	siteRuntimeV2WebSocketOrigin    = regexp.MustCompile(`^https?://[a-z0-9.\-\[\]:]{1,262}$`)
)

// originForwardingFact is a site's forwarding settings as stored (367).
type originForwardingFact struct {
	hashKey, stickySource, stickyName *string
	requestHostMode                   string
	requestHost                       *string
	scheme                            string
	httpsPort                         int
	tlsSNI                            *string
	tlsTrust                          string
	tlsCASHA256                       []byte
	followPort                        bool
	websocketEnabled                  bool
	websocketOrigins                  []string
	trustedProxyCIDRs                 []string
	followRedirect                    bool
	followRedirectMaxHops             int
	followRedirectCrossOrigin         bool
	// site edit options (site-backend6, migration 466)
	searchEngineOrigin                  string
	acmePassthrough                     bool
	responseBuffering, requestBuffering bool
	l2Mode                              string
	l2ConfigID                          *uuid.UUID
	// l2Config: the custom L2 configuration (nil when deleted)
	l2Config    *L2TopologyConfig
	defaultSite bool
}

// loadOriginForwardingFacts reads the forwarding settings of sites.
func loadOriginForwardingFacts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, siteIDs []uuid.UUID) (map[uuid.UUID]originForwardingFact, error) {
	result := make(map[uuid.UUID]originForwardingFact, len(siteIDs))
	if len(siteIDs) == 0 {
		return result, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT site_id,hash_key,sticky_source,sticky_name,request_host_mode,request_host,
		       origin_scheme,https_port,tls_sni,tls_trust,tls_ca_sha256,follow_port,
		       websocket_enabled,websocket_allowed_origins,trusted_proxy_cidrs::text[],
		       follow_redirect,follow_redirect_max_hops,follow_redirect_cross_origin,
		       COALESCE(search_engine_origin,''),acme_passthrough,response_buffering,request_buffering,
		       l2_mode,l2_config_id,
		       (SELECT site.is_default FROM sites site WHERE site.id=pool.site_id)
		FROM site_origin_pools pool WHERE site_id=ANY($1::uuid[])`, siteIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: read origin forwarding", ErrPersistence)
	}
	defer rows.Close()
	for rows.Next() {
		var siteID uuid.UUID
		var fact originForwardingFact
		if err := rows.Scan(&siteID, &fact.hashKey, &fact.stickySource, &fact.stickyName, &fact.requestHostMode,
			&fact.requestHost, &fact.scheme, &fact.httpsPort, &fact.tlsSNI, &fact.tlsTrust, &fact.tlsCASHA256,
			&fact.followPort, &fact.websocketEnabled, &fact.websocketOrigins,
			&fact.trustedProxyCIDRs, &fact.followRedirect, &fact.followRedirectMaxHops,
			&fact.followRedirectCrossOrigin, &fact.searchEngineOrigin, &fact.acmePassthrough,
			&fact.responseBuffering, &fact.requestBuffering, &fact.l2Mode, &fact.l2ConfigID,
			&fact.defaultSite); err != nil {
			return nil, fmt.Errorf("%w: scan origin forwarding", ErrPersistence)
		}
		result[siteID] = fact
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate origin forwarding", ErrPersistence)
	}
	rows.Close()
	var configIDs []uuid.UUID
	for _, fact := range result {
		if fact.l2Mode == "custom" && fact.l2ConfigID != nil && !slices.Contains(configIDs, *fact.l2ConfigID) {
			configIDs = append(configIDs, *fact.l2ConfigID)
		}
	}
	configs, err := loadL2TopologyConfigs(ctx, tx, scopeID, configIDs)
	if err != nil {
		return nil, err
	}
	for siteID, fact := range result {
		if fact.l2Mode == "custom" && fact.l2ConfigID != nil {
			fact.l2Config = configs[*fact.l2ConfigID]
			result[siteID] = fact
		}
	}
	return result, nil
}

// applySiteRuntimeV2OriginForwarding sets the forwarding fields of a
// compiled site's direct origin pool (and adds the follow-protocol HTTPS
// pool). site.OriginPools holds the direct pool at index direct.
func applySiteRuntimeV2OriginForwarding(site *siteRuntimeV2Site, direct int, fact siteFact) error {
	forwarding := fact.forwarding
	if forwarding == nil {
		return nil
	}
	pool := &site.OriginPools[direct]
	if forwarding.hashKey != nil {
		key := *forwarding.hashKey
		pool.HashKey = &key
	}
	if forwarding.stickySource != nil && forwarding.stickyName != nil {
		pool.Sticky = &siteRuntimeV2Sticky{Source: *forwarding.stickySource, Name: *forwarding.stickyName}
	}
	if forwarding.requestHostMode != "" && forwarding.requestHostMode != "visitor" {
		host := &siteRuntimeV2RequestHost{Mode: forwarding.requestHostMode}
		if forwarding.requestHost != nil {
			value := *forwarding.requestHost
			host.Value = &value
		}
		pool.RequestHost = host
	}
	if forwarding.followPort {
		value := true
		pool.FollowPort = &value
	}
	for index := range pool.Origins {
		origin := &pool.Origins[index]
		if level := fact.originExtras[index].level; level > 0 {
			value := int64(level)
			origin.Level = &value
		}
		if fact.originExtras[index].maxConns != 0 {
			value := int64(fact.originExtras[index].maxConns)
			origin.MaxConns = &value
		}
	}
	if fact.activeLevel > 0 {
		value := int64(fact.activeLevel)
		pool.ActiveLevel = &value
	}
	trust := siteRuntimeV2SystemTrust
	if forwarding.tlsTrust == siteRuntimeV2NoVerifyTrust {
		trust = siteRuntimeV2NoVerifyTrust
	}
	if forwarding.tlsTrust == "custom" {
		if len(forwarding.tlsCASHA256) != sha256.Size {
			return ErrInvalidInput
		}
		trust = "sha256:" + hex.EncodeToString(forwarding.tlsCASHA256)
	}
	asHTTPS := func(target *siteRuntimeV2OriginPool, port int) {
		for index := range target.Origins {
			origin := &target.Origins[index]
			origin.Scheme = "https"
			if port != 0 {
				origin.Port = int64(port)
			}
			anchor := trust
			origin.TrustRef = &anchor
			if forwarding.tlsSNI != nil {
				sni := *forwarding.tlsSNI
				origin.SNI = &sni
			}
		}
	}
	switch forwarding.scheme {
	case "https":
		asHTTPS(pool, 0)
	case "follow":
		https := clonePool(*pool)
		https.ID = siteRuntimeV2HTTPSPoolID
		https.Position = site.OriginPools[len(site.OriginPools)-1].Position + 1
		// 跟随协议和端口 (follow + follow_port, migration 490): the HTTPS pool
		// also connects on the visitor's port (cloned FollowPort kept).
		asHTTPS(&https, forwarding.httpsPort)
		for index := range https.Origins {
			https.Origins[index].ID += "-https"
		}
		site.OriginPools = append(site.OriginPools, https)
		id := https.ID
		site.forwarding().HTTPSPoolID = &id
	}
	if !forwarding.websocketEnabled {
		value := false
		site.WebSocket = &value
	} else if len(forwarding.websocketOrigins) != 0 {
		site.forwarding().WebSocketOrigins = slices.Clone(forwarding.websocketOrigins)
	}
	if len(forwarding.trustedProxyCIDRs) != 0 {
		site.forwarding().TrustedProxyCIDRs = slices.Clone(forwarding.trustedProxyCIDRs)
	}
	if forwarding.followRedirect {
		site.forwarding().FollowRedirect = &edgesite.FollowRedirect{MaxHops: forwarding.followRedirectMaxHops,
			CrossOrigin: forwarding.followRedirectCrossOrigin}
	}
	if forwarding.searchEngineOrigin != "" {
		engine, err := siteRuntimeV2SearchEnginePool(*pool, forwarding.searchEngineOrigin,
			site.OriginPools[len(site.OriginPools)-1].Position+1)
		if err != nil {
			return err
		}
		site.OriginPools = append(site.OriginPools, engine)
		id := engine.ID
		site.forwarding().SearchEnginePoolID = &id
	}
	if forwarding.acmePassthrough {
		site.forwarding().ACMEPassthrough = true
	}
	if !forwarding.requestBuffering {
		site.forwarding().Unbuffered = append(site.forwarding().Unbuffered, edgesite.UnbufferedRequest)
	}
	if !forwarding.responseBuffering {
		site.forwarding().Unbuffered = append(site.forwarding().Unbuffered, edgesite.UnbufferedResponse)
	}
	if forwarding.defaultSite {
		site.forwarding().DefaultSite = true
	}
	return nil
}

// siteRuntimeV2SearchEnginePool: one plain HTTP origin (host[:port], port 80
// by default) with the direct pool's retry and Host settings.
func siteRuntimeV2SearchEnginePool(direct siteRuntimeV2OriginPool, origin string, position int64) (siteRuntimeV2OriginPool, error) {
	host, port := origin, int64(80)
	if parsedHost, parsedPort, err := net.SplitHostPort(origin); err == nil {
		value, err := strconv.Atoi(parsedPort)
		if err != nil || value < 1 || value > 65535 {
			return siteRuntimeV2OriginPool{}, ErrInvalidInput
		}
		host, port = parsedHost, int64(value)
	}
	if !validSiteRuntimeV2Host(host) {
		return siteRuntimeV2OriginPool{}, ErrInvalidInput
	}
	return siteRuntimeV2OriginPool{
		ID: siteRuntimeV2SearchEnginePoolID, Position: position, Kind: "origin", Algorithm: "round_robin",
		Retry: direct.Retry, KeepaliveIdleTimeoutMS: direct.KeepaliveIdleTimeoutMS, RequestHost: direct.RequestHost,
		Origins: []siteRuntimeV2Origin{{ID: "search-engine-0", Position: 0, Tier: "origin", Scheme: "http",
			Host: host, Port: port, Weight: 1}},
	}, nil
}

func (site *siteRuntimeV2Site) forwarding() *siteRuntimeV2Forwarding {
	if site.Forwarding == nil {
		site.Forwarding = &siteRuntimeV2Forwarding{}
	}
	return site.Forwarding
}

func clonePool(pool siteRuntimeV2OriginPool) siteRuntimeV2OriginPool {
	result := pool
	result.Origins = make([]siteRuntimeV2Origin, len(pool.Origins))
	for index, origin := range pool.Origins {
		result.Origins[index] = origin
		if origin.Level != nil {
			value := *origin.Level
			result.Origins[index].Level = &value
		}
		if origin.MaxConns != nil {
			value := *origin.MaxConns
			result.Origins[index].MaxConns = &value
		}
	}
	return result
}

// validateSiteRuntimeV2PoolForwarding validates a pool's forwarding fields.
func validateSiteRuntimeV2PoolForwarding(pool siteRuntimeV2OriginPool) error {
	switch pool.Algorithm {
	case "hash":
		if pool.HashKey == nil || !validSiteRuntimeV2HashKey(*pool.HashKey) || pool.Sticky != nil {
			return ErrInvalidInput
		}
	case "sticky":
		if pool.Sticky == nil || pool.HashKey != nil || !siteRuntimeV2StickyNamePattern.MatchString(pool.Sticky.Name) ||
			pool.Sticky.Source != "cookie" && pool.Sticky.Source != "header" && pool.Sticky.Source != "arg" {
			return ErrInvalidInput
		}
	default:
		if pool.HashKey != nil || pool.Sticky != nil {
			return ErrInvalidInput
		}
	}
	if pool.Kind != "origin" && (pool.HashKey != nil || pool.Sticky != nil || pool.RequestHost != nil || pool.FollowPort != nil) {
		return ErrInvalidInput
	}
	if pool.RequestHost != nil {
		switch pool.RequestHost.Mode {
		case "origin", "visitor_port":
			if pool.RequestHost.Value != nil {
				return ErrInvalidInput
			}

		case "custom":
			if pool.RequestHost.Value == nil || !validSiteRuntimeV2RequestHost(*pool.RequestHost.Value) {
				return ErrInvalidInput
			}
		default:
			return ErrInvalidInput
		}
	}
	if pool.FollowPort != nil && !*pool.FollowPort {
		return ErrInvalidInput
	}
	backups, primaries := 0, 0
	for _, origin := range pool.Origins {
		if origin.Level != nil {
			backups++
			if *origin.Level < 1 || *origin.Level > maxSiteRuntimeV2OriginLevel || pool.Kind != "origin" {
				return ErrInvalidInput
			}
		} else {
			primaries++
		}
		if origin.MaxConns != nil && (*origin.MaxConns < 1 || *origin.MaxConns > 100000) {
			return ErrInvalidInput
		}
	}
	// Any algorithm may have backup levels (dynamic routing walks them).
	if primaries == 0 || backups != 0 && pool.Kind != "origin" {
		return ErrInvalidInput
	}
	if pool.ActiveLevel != nil && (*pool.ActiveLevel < 1 || *pool.ActiveLevel > maxSiteRuntimeV2OriginLevel ||
		pool.Kind != "origin") {
		return ErrInvalidInput
	}
	return nil
}

// maxSiteRuntimeV2OriginLevel mirrors site.MaxOriginLevel.
const maxSiteRuntimeV2OriginLevel = 15

func validSiteRuntimeV2HashKey(key string) bool {
	if !siteRuntimeV2HashKeyPattern.MatchString(key) {
		return false
	}
	tokens := siteRuntimeV2HashKeyToken.FindAllString(key, -1)
	if len(tokens) == 0 || strings.Count(key, "$") != len(tokens) {
		return false
	}
	for _, token := range tokens {
		if !slices.Contains(siteRuntimeV2HashKeyVariables, token) && !siteRuntimeV2HashKeyDynamicVars.MatchString(token) {
			return false
		}
	}
	return true
}

func validSiteRuntimeV2RequestHost(value string) bool {
	host, port := value, ""
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end < 0 {
			return false
		}
		address, err := netip.ParseAddr(value[1:end])
		if err != nil || !address.Is6() || address.String() != value[1:end] {
			return false
		}
		rest := value[end+1:]
		if rest != "" && !strings.HasPrefix(rest, ":") {
			return false
		}
		port = strings.TrimPrefix(rest, ":")
		if rest == ":" {
			return false
		}
	} else {
		if index := strings.LastIndex(value, ":"); index >= 0 {
			host, port = value[:index], value[index+1:]
			if port == "" {
				return false
			}
		}
		if !validSiteRuntimeV2Host(host) {
			return false
		}
	}
	if port != "" {
		number := 0
		for _, digit := range port {
			if digit < '0' || digit > '9' {
				return false
			}
			number = number*10 + int(digit-'0')
		}
		if number < 1 || number > 65535 || port[0] == '0' {
			return false
		}
	}
	return true
}

// validateSiteRuntimeV2Forwarding validates a site's forwarding block.
func validateSiteRuntimeV2Forwarding(site siteRuntimeV2Site, pools map[string]siteRuntimeV2OriginPool) error {
	forwarding := site.Forwarding
	if forwarding == nil {
		return nil
	}
	if forwarding.TrustedProxyCIDRs == nil && forwarding.WebSocketOrigins == nil && forwarding.HTTPSPoolID == nil &&
		forwarding.FollowRedirect == nil && !forwarding.usesEdgeOptions() {
		return ErrInvalidInput
	}
	if id := forwarding.SearchEnginePoolID; id != nil {
		if pool, ok := pools[*id]; !ok || pool.Kind != "origin" || *id == site.DefaultPoolID {
			return ErrInvalidInput
		}
	}
	for index, direction := range forwarding.Unbuffered {
		if direction != edgesite.UnbufferedRequest && direction != edgesite.UnbufferedResponse ||
			index > 0 && forwarding.Unbuffered[index-1] >= direction {
			return ErrInvalidInput
		}
	}
	if forwarding.FollowRedirect != nil && forwarding.FollowRedirect.Validate() != nil {
		return ErrInvalidInput
	}
	if forwarding.TrustedProxyCIDRs != nil {
		if len(forwarding.TrustedProxyCIDRs) == 0 || len(forwarding.TrustedProxyCIDRs) > 64 {
			return ErrInvalidInput
		}
		for index, raw := range forwarding.TrustedProxyCIDRs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Masked() != prefix || prefix.String() != raw || prefix.Bits() == 0 ||
				prefix.Addr().Is4In6() || index > 0 && forwarding.TrustedProxyCIDRs[index-1] >= raw {
				return ErrInvalidInput
			}
		}
	}
	if forwarding.WebSocketOrigins != nil {
		if !*site.WebSocket || len(forwarding.WebSocketOrigins) == 0 || len(forwarding.WebSocketOrigins) > 64 {
			return ErrInvalidInput
		}
		for index, origin := range forwarding.WebSocketOrigins {
			if !siteRuntimeV2WebSocketOrigin.MatchString(origin) || index > 0 && forwarding.WebSocketOrigins[index-1] >= origin {
				return ErrInvalidInput
			}
		}
	}
	if forwarding.HTTPSPoolID != nil {
		pool, ok := pools[*forwarding.HTTPSPoolID]
		hasTLS := false
		for _, listener := range site.Listeners {
			hasTLS = hasTLS || listener.TLS != nil
		}
		// With L2 it replaces the direct fallback pool on TLS listeners.
		if !ok || pool.Kind != "origin" || pool.ID == site.DefaultPoolID || !hasTLS ||
			site.L2.DirectFallbackPoolID != nil && pool.ID == *site.L2.DirectFallbackPoolID {
			return ErrInvalidInput
		}
		for _, origin := range pool.Origins {
			if origin.Scheme != "https" {
				return ErrInvalidInput
			}
		}
	}
	return nil
}

// siteRuntimeV2TrustDigests are the custom CA bundles the document's HTTPS
// origins reference.
func siteRuntimeV2TrustDigests(document siteRuntimeV2Document) [][sha256.Size]byte {
	var digests [][sha256.Size]byte
	for _, site := range document.Sites {
		for _, pool := range site.OriginPools {
			for _, origin := range pool.Origins {
				if origin.TrustRef == nil || *origin.TrustRef == siteRuntimeV2SystemTrust || *origin.TrustRef == siteRuntimeV2NoVerifyTrust {
					continue
				}
				raw, err := hex.DecodeString(strings.TrimPrefix(*origin.TrustRef, "sha256:"))
				if err != nil || len(raw) != sha256.Size {
					continue
				}
				digest := [sha256.Size]byte(raw)
				if !slices.Contains(digests, digest) {
					digests = append(digests, digest)
				}
			}
		}
	}
	return digests
}

// loadSiteRuntimeV2TrustFiles reads the CA bundles the document references
// (site_origin_trust_bundles) as origin-trust/<hex>.pem.
func loadSiteRuntimeV2TrustFiles(ctx context.Context, tx pgx.Tx, document siteRuntimeV2Document) (map[string][]byte, error) {
	digests := siteRuntimeV2TrustDigests(document)
	if len(digests) == 0 {
		return nil, nil
	}
	keys := make([][]byte, len(digests))
	for index := range digests {
		keys[index] = digests[index][:]
	}
	rows, err := tx.Query(ctx, `SELECT sha256,pem FROM site_origin_trust_bundles WHERE sha256=ANY($1::bytea[])`, keys)
	if err != nil {
		return nil, fmt.Errorf("%w: read origin trust bundles", ErrPersistence)
	}
	defer rows.Close()
	files := make(map[string][]byte, len(digests))
	for rows.Next() {
		var digest []byte
		var content string
		if err := rows.Scan(&digest, &content); err != nil {
			return nil, fmt.Errorf("%w: scan origin trust bundle", ErrPersistence)
		}
		if sum := sha256.Sum256([]byte(content)); !bytes.Equal(sum[:], digest) || !validSiteRuntimeV2TrustPEM([]byte(content)) {
			return nil, fmt.Errorf("%w: origin trust bundle", ErrInvalidInput)
		}
		files["origin-trust/"+hex.EncodeToString(digest)+".pem"] = []byte(content)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate origin trust bundles", ErrPersistence)
	}
	if len(files) != len(digests) {
		return nil, fmt.Errorf("%w: origin trust bundle is missing", ErrInvalidInput)
	}
	return files, nil
}

func validSiteRuntimeV2TrustPEM(content []byte) bool {
	rest := content
	count := 0
	for len(bytes.TrimSpace(rest)) > 0 {
		block, remainder := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		count++
		rest = remainder
	}
	return count > 0
}
