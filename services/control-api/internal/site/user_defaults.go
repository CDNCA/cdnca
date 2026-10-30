package site

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// 网站列表 > 默认设置 (migration 490): the tenant's own defaults
// for new sites, as in the user console (设置项 / 设置值 / 生效范围
// with GET/POST/PUT/DELETE /v1/user-configs?type=site). Only fields the create
// request leaves unset take a default; existing sites are never rewritten.

const (
	SiteDefaultHTTPListenPort      = "http_listen_port"      // 端口，空格分隔
	SiteDefaultHTTPSListenPort     = "https_listen_port"     // 端口，空格分隔
	SiteDefaultBalanceWay          = "balance_way"           // round_robin / ip_hash / ...
	SiteDefaultBackendHTTPSPort    = "backend_https_port"    // 回源 HTTPS 端口
	SiteDefaultUpsKeepalive        = "ups_keepalive"         // 1 / 0
	SiteDefaultUpsKeepaliveTimeout = "ups_keepalive_timeout" // 秒
	SiteDefaultWebSocket           = "websocket_enable"      // 1 / 0
	SiteDefaultForceSSL            = "force_ssl_enable"      // 1 / 0
	SiteDefaultHSTS                = "hsts"                  // 1 / 0
	SiteDefaultOCSPStapling        = "ocsp_stapling"         // 1 / 0
	// recv_real_time「数据实时返回」= 不缓冲源站响应（proxy_buffering off），
	// send_real_time「数据实时发送」= 不缓冲请求体（proxy_request_buffering off）。fp-site4 纠正原反向映射。
	SiteDefaultRecvRealTime = "recv_real_time" // 数据实时返回 1 / 0
	SiteDefaultSendRealTime = "send_real_time" // 数据实时发送 1 / 0
	// fp-site3（迁移 513）：36 项第二批简单字段。
	SiteDefaultSSLProtocols         = "ssl_protocols"          // TLSv1.2 TLSv1.3（空格分隔，连续区间）
	SiteDefaultSSLCipherPreset      = "ssl_cipher_preset"      // modern / compatible / legacy / custom
	SiteDefaultOriginProtocol       = "origin_protocol"        // http / https / follow
	SiteDefaultBackendHTTPPort      = "backend_http_port"      // 回源 HTTP 端口
	SiteDefaultOriginConnectTimeout = "origin_connect_timeout" // 回源连接超时，秒 1–30
	SiteDefaultOriginReadTimeout    = "origin_read_timeout"    // 回源读取超时，秒 1–300
	// fp-site4（迁移 514）：36 项第三批。
	SiteDefaultCCBanSeconds  = "cc_ban_seconds"  // 黑名单时间，秒 1–86400：新建 CC 策略时带入（securitypolicy）
	SiteDefaultCCPassSeconds = "cc_pass_seconds" // 白名单时间，秒 60–604800：同上
	SiteDefaultGzip          = "gzip_enable"     // Gzip 1 / 0：建站写 site_access_settings.compression
	SiteDefaultDNSProvider   = "dns_provider"    // 默认 DNS API 账号 ID：建站未选时自动添加记录
	SiteDefaultIPv6          = "ipv6_enable"     // IPv6 1 / 0：建站请求未写 ipv6_enabled 时
	// fp-site5b（迁移 516）：复杂规则按复制快照。规则库项存本人规则库 ID，建站事务里复制成
	// 新站专用的一份并绑定（区域屏蔽、爬虫等是规则库里的规则，随库复制）；之后改原库或默认不影响已建站。
	SiteDefaultCCPolicy   = "cc_policy"       // 默认 CC 规则库 ID（#20/#29）
	SiteDefaultWAFPolicy  = "waf_policy"      // 默认 WAF 规则库 ID（#21/#22，含内置模块、区域屏蔽规则）
	SiteDefaultACLPolicy  = "acl_policy"      // 默认黑白名单 IP 规则库 ID（#32/#33）
	SiteDefaultBlockProxy = "block_proxy"     // 屏蔽透明代理 1 / 0（#26）：开时新站 WAF 复制一组代理请求头拦截规则
	SiteDefaultReqHeader  = "req_header"      // 源站请求头（#18）：每行「名称: 值」，建站写站点 HTTP 策略 request_headers（set）
	SiteDefaultPostSize   = "post_size_limit" // 上传文件大小限制 MB 1–1024（#25）：站点 HTTP 策略 max_upload_bytes
	// fp-site5a（迁移 515）：HTTPS 协议三项，建站请求未写时带入站点字段（节点按站点生效）。
	SiteDefaultHTTP2               = "http2"                     // HTTP2 1 / 0 → sites.http2_enabled
	SiteDefaultHTTP3               = "http3"                     // HTTP3 1 / 0 → sites.http3_enabled（仍需 TLSv1.3）
	SiteDefaultSSLPreferServerCiph = "ssl_prefer_server_ciphers" // 1 / 0 → sites.tls_prefer_server_ciphers
	// fp-site6（迁移 518）：独立维护的规则文档（JSON），建站同事务复制给新站。
	SiteDefaultCacheRule  = "proxy_cache" // 网站缓存（#3）：cachecontrol.PolicyDocument → 新站首个缓存策略修订（override）
	SiteDefaultCondOrigin = "cond_origin" // 条件源站（#30）：只有条件，pool_id 只能是占位 default_pool → 新站自身默认源站池
	// fp-site7（迁移 519）：区域屏蔽快捷预设（#4/#31，block_region）。取值见
	// securitypolicy.RegionBlock*；与屏蔽透明代理同路径，一条 country 规则并入新站 WAF 副本，none 不建规则。
	SiteDefaultBlockRegion = "block_region"
	// tls-custom（迁移 520）：#11 自定义套件。冒号分隔的 TLS1.2 套件名，只能取自
	// edgeconfig.TLSCustomCipherSuites；只在 ssl_cipher_preset 默认为 custom 时随它一起带入新站。
	SiteDefaultSSLCipherSuites = "ssl_cipher_suites"

	// siteDefaultGzipMinLength: 默认设置开 Gzip 时的最小压缩长度，与站点编辑页新开压缩的初值一致。
	siteDefaultGzipMinLength = 256

	SiteDefaultScopeGlobal = "global"
	SiteDefaultScopeGroup  = "group"
)

var ErrSiteDefaultConflict = errors.New("site default already exists for this setting and scope")

type SiteUserDefault struct {
	ID          uuid.UUID  `json:"id"`
	DisplayID   string     `json:"display_id"`
	ScopeID     uuid.UUID  `json:"scope_id"`
	OwnerUserID uuid.UUID  `json:"owner_user_id"`
	SettingName string     `json:"setting_name"`
	Value       string     `json:"setting_value"`
	ScopeName   string     `json:"scope_name"`
	GroupID     *uuid.UUID `json:"group_id"`
	GroupName   *string    `json:"group_name"`
	Enabled     bool       `json:"enabled"`
	Revision    int64      `json:"version"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type SiteUserDefaultFields struct {
	SettingName string     `json:"setting_name"`
	Value       string     `json:"setting_value"`
	ScopeName   string     `json:"scope_name"`
	GroupID     *uuid.UUID `json:"group_id"`
}

type SiteUserDefaultCreateRequest struct {
	TargetScopeID  uuid.UUID
	OwnerUserID    uuid.UUID
	Fields         SiteUserDefaultFields
	IdempotencyKey string
	RequestID      string
}

// SiteUserDefaultUpdateRequest changes the value and/or the enabled state
// (修改与启用 / 禁用); nil keeps the stored one.
type SiteUserDefaultUpdateRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Value            *string
	Enabled          *bool
	IdempotencyKey   string
	RequestID        string
}

type SiteUserDefaultDeleteRequest struct {
	ID             uuid.UUID
	IdempotencyKey string
	RequestID      string
}

type SiteUserDefaultListFilter struct {
	Page        int
	Limit       int
	SettingName string
	Enabled     *bool
}

type SiteUserDefaultListResult struct {
	Items []SiteUserDefault `json:"items"`
	Total int64             `json:"total"`
	Page  int               `json:"page"`
	Limit int               `json:"limit"`
}

// siteCreationUserDefaults is what applyUserDefaults reads: name → value,
// group-scoped rows over global ones.
type siteCreationUserDefaults map[string]string

func normalizeSiteUserDefaultFields(fields *SiteUserDefaultFields) bool {
	fields.SettingName = strings.TrimSpace(fields.SettingName)
	fields.ScopeName = strings.TrimSpace(fields.ScopeName)
	if fields.ScopeName == "" {
		fields.ScopeName = SiteDefaultScopeGlobal
	}
	switch fields.ScopeName {
	case SiteDefaultScopeGlobal:
		fields.GroupID = nil
	case SiteDefaultScopeGroup:
		if fields.GroupID == nil || *fields.GroupID == uuid.Nil {
			return false
		}
	default:
		return false
	}
	value, ok := normalizeSiteDefaultValue(fields.SettingName, fields.Value)
	fields.Value = value
	return ok
}

// normalizeSiteDefaultValue validates one value the way the matching site
// field is validated, so a stored default can always be applied.
func normalizeSiteDefaultValue(name, raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	switch name {
	case SiteDefaultHTTPListenPort, SiteDefaultHTTPSListenPort:
		ports, err := normalizePorts(strings.Fields(strings.ReplaceAll(value, ",", " ")))
		if err != nil || len(ports) == 0 {
			return "", false
		}
		return strings.Join(ports, " "), true
	case SiteDefaultBalanceWay:
		return value, validBalanceMethod(value) && value != BalanceHash && value != BalanceSticky
	case SiteDefaultSSLProtocols:
		protocols, err := normalizeTLSProtocols(strings.Fields(value))
		if err != nil || len(protocols) == 0 {
			return "", false
		}
		return strings.Join(protocols, " "), true
	case SiteDefaultSSLCipherPreset:
		return value, value == edgeconfig.TLSCipherModern || value == edgeconfig.TLSCipherCompatible || value == edgeconfig.TLSCipherLegacy ||
			value == edgeconfig.TLSCipherCustom
	case SiteDefaultSSLCipherSuites:
		suites := strings.FieldsFunc(value, func(r rune) bool { return r == ':' || r == ',' || r == ' ' })
		if edgeconfig.ValidateTLSCipherSuites(suites) != nil {
			return "", false
		}
		return strings.Join(suites, ":"), true
	case SiteDefaultOriginProtocol:
		return value, value == OriginSchemeHTTP || value == OriginSchemeHTTPS || value == OriginSchemeFollow
	case SiteDefaultOriginConnectTimeout:
		seconds, err := strconv.Atoi(value)
		return strconv.Itoa(seconds), err == nil && seconds >= 1 && seconds <= 30
	case SiteDefaultOriginReadTimeout:
		seconds, err := strconv.Atoi(value)
		return strconv.Itoa(seconds), err == nil && seconds >= 1 && seconds <= 300
	case SiteDefaultBackendHTTPPort, SiteDefaultBackendHTTPSPort:
		port, err := strconv.Atoi(value)
		return strconv.Itoa(port), err == nil && port >= 1 && port <= 65_535
	case SiteDefaultUpsKeepaliveTimeout:
		seconds, err := strconv.Atoi(value)
		return strconv.Itoa(seconds), err == nil && seconds >= 1 && seconds <= 300
	case SiteDefaultCCBanSeconds: // securitypolicy normalizeCCSettings 的范围
		seconds, err := strconv.Atoi(value)
		return strconv.Itoa(seconds), err == nil && seconds >= 1 && seconds <= 86_400
	case SiteDefaultCCPassSeconds:
		seconds, err := strconv.Atoi(value)
		return strconv.Itoa(seconds), err == nil && seconds >= 60 && seconds <= 7*86_400
	case SiteDefaultDNSProvider: // 归属与验证状态在存储时核对（checkSiteDefaultReference）
		id, err := uuid.Parse(value)
		return id.String(), err == nil && id != uuid.Nil
	case SiteDefaultCCPolicy, SiteDefaultWAFPolicy, SiteDefaultACLPolicy: // 归属在存储时核对
		id, err := uuid.Parse(value)
		return id.String(), err == nil && id != uuid.Nil
	case SiteDefaultPostSize:
		megabytes, err := strconv.Atoi(value)
		return strconv.Itoa(megabytes), err == nil && megabytes >= 1 && megabytes <= httppolicycontrol.MaxUploadBytes>>20
	case SiteDefaultReqHeader:
		actions, ok := parseSiteDefaultRequestHeaders(value)
		if !ok {
			return "", false
		}
		formatted := formatSiteDefaultRequestHeaders(actions)
		return formatted, utf8.RuneCountInString(formatted) <= 8192 // 迁移 516 取值上限
	case SiteDefaultBlockProxy:
		return value, value == "1" || value == "0"
	case SiteDefaultBlockRegion:
		return value, securitypolicy.ValidRegionBlockPreset(value)
	case SiteDefaultCacheRule:
		return normalizeSiteDefaultCacheRule(value)
	case SiteDefaultCondOrigin:
		return normalizeSiteDefaultCondOrigin(value)
	case SiteDefaultUpsKeepalive, SiteDefaultWebSocket, SiteDefaultForceSSL, SiteDefaultHSTS,
		SiteDefaultOCSPStapling, SiteDefaultRecvRealTime, SiteDefaultSendRealTime, SiteDefaultGzip, SiteDefaultIPv6,
		SiteDefaultHTTP2, SiteDefaultHTTP3, SiteDefaultSSLPreferServerCiph:
		return value, value == "1" || value == "0"
	}
	return "", false
}

func (s *Service) ListUserDefaults(ctx context.Context, actor Actor, filter SiteUserDefaultListFilter) (SiteUserDefaultListResult, error) {
	if !validActor(actor) || filter.Page < 1 || filter.Page > 1_000_000 || filter.Limit < 1 || filter.Limit > 100 {
		return SiteUserDefaultListResult{}, ErrInvalidInput
	}
	filter.SettingName = strings.TrimSpace(filter.SettingName)
	if filter.SettingName != "" && !slices.Contains(siteDefaultNames, filter.SettingName) {
		return SiteUserDefaultListResult{}, ErrInvalidInput
	}
	return s.store.ListUserDefaults(ctx, actor, filter)
}

var siteDefaultNames = []string{SiteDefaultHTTPListenPort, SiteDefaultHTTPSListenPort, SiteDefaultBalanceWay,
	SiteDefaultBackendHTTPSPort, SiteDefaultUpsKeepalive, SiteDefaultUpsKeepaliveTimeout, SiteDefaultWebSocket,
	SiteDefaultForceSSL, SiteDefaultHSTS, SiteDefaultOCSPStapling, SiteDefaultRecvRealTime, SiteDefaultSendRealTime,
	SiteDefaultSSLProtocols, SiteDefaultSSLCipherPreset, SiteDefaultOriginProtocol, SiteDefaultBackendHTTPPort,
	SiteDefaultOriginConnectTimeout, SiteDefaultOriginReadTimeout,
	SiteDefaultCCBanSeconds, SiteDefaultCCPassSeconds, SiteDefaultGzip, SiteDefaultDNSProvider, SiteDefaultIPv6,
	SiteDefaultCCPolicy, SiteDefaultWAFPolicy, SiteDefaultACLPolicy, SiteDefaultBlockProxy, SiteDefaultReqHeader, SiteDefaultPostSize,
	SiteDefaultHTTP2, SiteDefaultHTTP3, SiteDefaultSSLPreferServerCiph, SiteDefaultCacheRule, SiteDefaultCondOrigin, SiteDefaultBlockRegion,
	SiteDefaultSSLCipherSuites}

func (s *Service) CreateUserDefault(ctx context.Context, actor Actor, request SiteUserDefaultCreateRequest) (SiteUserDefault, error) {
	if err := normalizeActorAndTarget(actor, &request.TargetScopeID, &request.OwnerUserID); err != nil {
		return SiteUserDefault{}, err
	}
	if !normalizeSiteUserDefaultFields(&request.Fields) || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return SiteUserDefault{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID             `json:"target_scope_id"`
		OwnerUserID   uuid.UUID             `json:"owner_user_id"`
		Fields        SiteUserDefaultFields `json:"fields"`
	}{request.TargetScopeID, request.OwnerUserID, request.Fields})
	if err != nil {
		return SiteUserDefault{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return SiteUserDefault{}, err
	}
	return s.store.CreateUserDefault(ctx, actor, request, id, digest)
}

func (s *Service) UpdateUserDefault(ctx context.Context, actor Actor, request SiteUserDefaultUpdateRequest) (SiteUserDefault, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		(request.Value == nil && request.Enabled == nil) || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return SiteUserDefault{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
		Value            *string   `json:"value"`
		Enabled          *bool     `json:"enabled"`
	}{request.ID, request.ExpectedRevision, request.Value, request.Enabled})
	if err != nil {
		return SiteUserDefault{}, err
	}
	return s.store.UpdateUserDefault(ctx, actor, request, digest)
}

func (s *Service) DeleteUserDefault(ctx context.Context, actor Actor, request SiteUserDefaultDeleteRequest) error {
	if !validActor(actor) || request.ID == uuid.Nil || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		ID uuid.UUID `json:"id"`
	}{request.ID})
	if err != nil {
		return err
	}
	return s.store.DeleteUserDefault(ctx, actor, request, digest)
}

// loadCreationUserDefaults reads the owner's enabled defaults for a new
// site in group (nil: no group); group rows win over global ones.
func (s *Store) loadCreationUserDefaults(ctx context.Context, scopeID, ownerID uuid.UUID, group *uuid.UUID) (siteCreationUserDefaults, error) {
	rows, err := s.pool.Query(ctx, `SELECT setting_name, setting_value FROM site_user_defaults
		WHERE scope_id=$1 AND owner_user_id=$2 AND enabled AND (group_id IS NULL OR group_id=$3)
		ORDER BY (group_id IS NOT NULL), created_at, id`, scopeID, ownerID, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	defaults := siteCreationUserDefaults{}
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, err
		}
		defaults[name] = value
	}
	return defaults, rows.Err()
}

// applyFields fills basic fields the create request left out (nil port
// lists and pointers); runs before normalizeFields.
func (defaults siteCreationUserDefaults) applyFields(fields *SiteFields) {
	flag := func(name string) (*bool, bool) {
		value, ok := defaults[name]
		on := value == "1"
		return &on, ok
	}
	// Ports left out (or empty: a site always listens on HTTP, and HTTPS
	// on at least one port when enabled) take the default, then 80 / 443.
	if value, ok := defaults[SiteDefaultHTTPListenPort]; ok && len(fields.HTTPPorts) == 0 {
		fields.HTTPPorts = strings.Fields(value)
	}
	if fields.HTTPSEnabled && len(fields.HTTPSPorts) == 0 {
		if value, ok := defaults[SiteDefaultHTTPSListenPort]; ok {
			fields.HTTPSPorts = strings.Fields(value)
		} else {
			fields.HTTPSPorts = []string{"443"}
		}
	}
	if on, ok := flag(SiteDefaultForceSSL); ok && fields.ForceHTTPS == nil && fields.HTTPSEnabled {
		fields.ForceHTTPS = on
	}
	if on, ok := flag(SiteDefaultOCSPStapling); ok && fields.TLSOCSPStapling == nil {
		fields.TLSOCSPStapling = on
	}
	if on, ok := flag(SiteDefaultHSTS); ok {
		fields.hstsDefault = on
	}
	if value, ok := defaults[SiteDefaultSSLProtocols]; ok && fields.TLSProtocols == nil {
		fields.TLSProtocols = strings.Fields(value)
	}
	if value, ok := defaults[SiteDefaultSSLCipherPreset]; ok && fields.TLSCipherPreset == nil && fields.TLSCipherSuites == nil {
		// custom comes with its suites default; without one the preset
		// default does not apply (the system default decides)
		if value != edgeconfig.TLSCipherCustom {
			fields.TLSCipherPreset = &value
		} else if suites, ok := defaults[SiteDefaultSSLCipherSuites]; ok {
			fields.TLSCipherPreset, fields.TLSCipherSuites = &value, strings.Split(suites, ":")
		}
	}
	if on, ok := flag(SiteDefaultIPv6); ok && fields.IPv6Omitted {
		fields.IPv6Enabled = *on
	}
	if on, ok := flag(SiteDefaultGzip); ok {
		fields.gzipDefault = on
	}
	if on, ok := flag(SiteDefaultHTTP2); ok && fields.HTTP2Enabled == nil {
		fields.HTTP2Enabled = on
	}
	if on, ok := flag(SiteDefaultHTTP3); ok && fields.HTTP3Enabled == nil {
		fields.HTTP3Enabled = on
	}
	if on, ok := flag(SiteDefaultSSLPreferServerCiph); ok && fields.TLSPreferServerCiphers == nil && !fields.TLSPreferServerCiphersReset {
		fields.TLSPreferServerCiphers = on
	}
}

// applyDNSProvider fills the create's DNS API account from the default when
// the request named none and the creator may write DNS records.
func (defaults siteCreationUserDefaults) applyDNSProvider(request *CreateRequest) {
	value, ok := defaults[SiteDefaultDNSProvider]
	if !ok || request.DNSProviderID != nil || !request.DefaultDNSAllowed {
		return
	}
	if id, err := uuid.Parse(value); err == nil {
		request.DNSProviderID, request.dnsProviderDefaulted = &id, true
	}
}

// applyPool fills origin pool fields the request left out (empty balance,
// zero ports and timeouts, nil switches) before the pool is normalized, or
// with overwrite every defaulted field of the built-in pool of a request
// that named none. It reports whether the balance came from a default,
// which then wins over the platform's (系统设置 > 网站默认).
func (defaults siteCreationUserDefaults) applyPool(pool *OriginPool, overwrite bool) bool {
	flag := func(name string) (bool, bool) {
		value, ok := defaults[name]
		return value == "1", ok
	}
	balanced := false
	if value, ok := defaults[SiteDefaultBalanceWay]; ok && (overwrite || pool.BalanceMethod == "") {
		pool.BalanceMethod, balanced = value, true
	}
	// Scheme first: each scheme keeps only its own port (origin_forwarding.go),
	// so a port default applies only where the scheme uses it.
	if value, ok := defaults[SiteDefaultOriginProtocol]; ok && (overwrite || pool.Scheme == "") {
		pool.Scheme = value
	}
	scheme := pool.Scheme
	if scheme == "" {
		scheme = OriginSchemeHTTP // defaultOriginPorts
	}
	if value, ok := defaults[SiteDefaultBackendHTTPSPort]; ok && (overwrite || pool.HTTPSPort == 0) && scheme != OriginSchemeHTTP {
		pool.HTTPSPort, _ = strconv.Atoi(value)
	}
	if value, ok := defaults[SiteDefaultBackendHTTPPort]; ok && (overwrite || pool.HTTPPort == 0) && scheme != OriginSchemeHTTPS {
		pool.HTTPPort, _ = strconv.Atoi(value)
	}
	if value, ok := defaults[SiteDefaultOriginConnectTimeout]; ok && (overwrite || pool.ConnectTimeoutMS == 0) {
		seconds, _ := strconv.Atoi(value)
		pool.ConnectTimeoutMS = seconds * 1000
	}
	if value, ok := defaults[SiteDefaultOriginReadTimeout]; ok && (overwrite || pool.ReadTimeoutMS == 0) {
		seconds, _ := strconv.Atoi(value)
		pool.ReadTimeoutMS = seconds * 1000
	}
	if on, ok := flag(SiteDefaultUpsKeepalive); ok && (overwrite || pool.KeepaliveEnabled == nil) {
		pool.KeepaliveEnabled = &on
	}
	if value, ok := defaults[SiteDefaultUpsKeepaliveTimeout]; ok && (overwrite || pool.KeepaliveIdleTimeoutMS == 0) {
		seconds, _ := strconv.Atoi(value)
		pool.KeepaliveIdleTimeoutMS = seconds * 1000
	}
	if on, ok := flag(SiteDefaultWebSocket); ok && (overwrite || pool.WebSocket == nil) {
		pool.WebSocket = &OriginWebSocket{Enabled: on, AllowedOrigins: []string{}}
	}
	if on, ok := flag(SiteDefaultRecvRealTime); ok && (overwrite || pool.ResponseBuffering == nil) {
		buffering := !on
		pool.ResponseBuffering = &buffering
	}
	if on, ok := flag(SiteDefaultSendRealTime); ok && (overwrite || pool.RequestBuffering == nil) {
		buffering := !on
		pool.RequestBuffering = &buffering
	}
	return balanced
}

// canonicalGzipTypes is the platform's gzip types as site access settings
// keep them (lower case, sorted, unique: siteaccess.normalize).
func canonicalGzipTypes(values []string) []string {
	types := make([]string, 0, len(values))
	for _, value := range values {
		types = append(types, strings.ToLower(strings.TrimSpace(value)))
	}
	slices.Sort(types)
	return slices.Compact(types)
}

// parseSiteDefaultRequestHeaders reads 源站请求头: one "Name: value" per
// line, each a set action, as the site's HTTP policy accepts them.
func parseSiteDefaultRequestHeaders(value string) ([]httppolicycontrol.HeaderAction, bool) {
	actions := []httppolicycontrol.HeaderAction{}
	for _, line := range strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		name, text, found := strings.Cut(line, ":")
		if !found {
			return nil, false
		}
		actions = append(actions, httppolicycontrol.HeaderAction{Kind: httppolicycontrol.HeaderSet,
			Name: strings.ToLower(strings.TrimSpace(name)), Values: []string{strings.TrimSpace(text)}})
	}
	return actions, httppolicycontrol.ValidRequestHeaders(actions)
}

func formatSiteDefaultRequestHeaders(actions []httppolicycontrol.HeaderAction) string {
	lines := make([]string, len(actions))
	for index, action := range actions {
		lines[index] = action.Name + ": " + action.Values[0]
	}
	return strings.Join(lines, "\n")
}
