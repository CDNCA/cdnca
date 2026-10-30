package edgeconfig

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
)

// SiteRuntimeSystem is the platform system configuration (nginx base
// settings) a site runtime v2 document carries. Every publication of a scope
// carries the platform's active revision, so a node composing several scopes
// renders one node-wide main/events/http level from the highest revision
// (SelectSiteRuntimeSystem). Tenant and site settings never change these
// levels: they render inside their own server/location blocks.
type SiteRuntimeSystem struct {
	PlatformScopeID string                 `json:"platform_scope_id"`
	Revision        int64                  `json:"revision"`
	SnapshotSHA256  string                 `json:"snapshot_sha256"`
	Nginx           SiteRuntimeSystemNginx `json:"nginx"`
	// DDoS is the node-level connection protection (ddos_protection
	// category) and the platform's node networks. Control always sends it
	// once a system configuration is active, also with nothing on: the node
	// networks are what an L2 node trusts an L1's hop by.
	DDoS *SiteRuntimeDDoS `json:"ddos,omitempty"`
	// NodeNginx: nodes whose effective nginx base differs from Nginx
	// (region/node overrides), at most one group per node, groups sorted
	// by their first node. A node not listed runs Nginx (ForNode).
	NodeNginx []SiteRuntimeSystemNodeNginx `json:"node_nginx,omitempty"`
}

// SiteRuntimeSystemNginx is NginxSettings with durations in milliseconds.
type SiteRuntimeSystemNginx struct {
	WorkerProcesses         int      `json:"worker_processes"`
	WorkerRlimitNoFile      int      `json:"worker_rlimit_nofile"`
	WorkerShutdownTimeoutMS int64    `json:"worker_shutdown_timeout_ms"`
	WorkerConnections       int      `json:"worker_connections"`
	ResolverAddresses       []string `json:"resolver_addresses"`
	ResolverTimeoutMS       int64    `json:"resolver_timeout_ms"`
	GzipLevel               int      `json:"gzip_level"`
	GzipMinimumBytes        int64    `json:"gzip_minimum_bytes"`
	GzipVary                bool     `json:"gzip_vary"`
	// GzipDisabled / GzipTypes: the platform's gzip switch
	// and MIME types, omitted when gzip is on for text/html only.
	GzipDisabled           bool     `json:"gzip_disabled,omitempty"`
	GzipTypes              []string `json:"gzip_types,omitempty"`
	ProxyBuffering         bool     `json:"proxy_buffering"`
	ProxyCacheMethods      []string `json:"proxy_cache_methods"`
	ProxyCacheMaxBytes     int64    `json:"proxy_cache_max_bytes"`
	ProxyCacheZoneBytes    int64    `json:"proxy_cache_zone_bytes"`
	ProxyCacheMinFreeBytes int64    `json:"proxy_cache_min_free_bytes"`
	ProxyMaxTempFileBytes  int64    `json:"proxy_max_temp_file_bytes"`
	ProxyConnectTimeoutMS  int64    `json:"proxy_connect_timeout_ms"`
	ProxySendTimeoutMS     int64    `json:"proxy_send_timeout_ms"`
	ProxyReadTimeoutMS     int64    `json:"proxy_read_timeout_ms"`
	StreamProxyTimeoutMS   int64    `json:"stream_proxy_timeout_ms"`
	ServerHeader           string   `json:"server_header"`
	ClientMaxBodyBytes     int64    `json:"client_max_body_bytes"`
	DefaultMIMEType        string   `json:"default_mime_type"`
	KeepaliveRequests      int      `json:"keepalive_requests"`
	KeepaliveTimeoutMS     int64    `json:"keepalive_timeout_ms"`
	LogNotFound            bool     `json:"log_not_found"`
	ServerNamesHashMaxSize int      `json:"server_names_hash_max_size"`
	ServerTokens           bool     `json:"server_tokens"`
	// Omitted when unset (NginxSettings).
	GzipHTTPVersion               string   `json:"gzip_http_version,omitempty"`
	ProxyRequestBufferingDisabled bool     `json:"proxy_request_buffering_disabled,omitempty"`
	ProxyHTTPVersion              string   `json:"proxy_http_version,omitempty"`
	ProxyNextUpstream             []string `json:"proxy_next_upstream,omitempty"`
	LargeClientHeaderBufferCount  int      `json:"large_client_header_buffer_count,omitempty"`
	LargeClientHeaderBufferBytes  int64    `json:"large_client_header_buffer_bytes,omitempty"`
	ServerNamesHashBucketSize     int      `json:"server_names_hash_bucket_size,omitempty"`
	ServerAddrOutgoing            bool     `json:"server_addr_outgoing,omitempty"`
	ClientBodyBufferBytes         int64    `json:"client_body_buffer_bytes,omitempty"`
}

// SiteRuntimeSystemNodeNginx is the nginx base of the listed nodes when it
// differs from the system block's (区域及节点配置: region and node
// overrides). NodeIDs are canonical UUIDs, sorted.
type SiteRuntimeSystemNodeNginx struct {
	NodeIDs []string               `json:"node_ids"`
	Nginx   SiteRuntimeSystemNginx `json:"nginx"`
}

// MaxSiteRuntimeSystemNodeNginx bounds the per-node groups of one block.
const MaxSiteRuntimeSystemNodeNginx = 4096

var (
	siteRuntimeSystemUUIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	siteRuntimeSystemSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func NewSiteRuntimeSystemNginx(value NginxSettings) SiteRuntimeSystemNginx {
	return SiteRuntimeSystemNginx{
		WorkerProcesses: value.WorkerProcesses, WorkerRlimitNoFile: value.WorkerRlimitNoFile,
		WorkerShutdownTimeoutMS: value.WorkerShutdownTimeout.Milliseconds(), WorkerConnections: value.WorkerConnections,
		ResolverAddresses: append([]string{}, value.ResolverAddresses...), ResolverTimeoutMS: value.ResolverTimeout.Milliseconds(),
		GzipLevel: value.GzipLevel, GzipMinimumBytes: value.GzipMinimumBytes, GzipVary: value.GzipVary,
		GzipDisabled: value.GzipDisabled, GzipTypes: slices.Clone(value.GzipTypes),
		ProxyBuffering: value.ProxyBuffering, ProxyCacheMethods: append([]string{}, value.ProxyCacheMethods...),
		ProxyCacheMaxBytes: value.ProxyCacheMaxBytes, ProxyCacheZoneBytes: value.ProxyCacheZoneBytes,
		ProxyCacheMinFreeBytes: value.ProxyCacheMinFreeBytes,
		ProxyMaxTempFileBytes:  value.ProxyMaxTempFileBytes, ProxyConnectTimeoutMS: value.ProxyConnectTimeout.Milliseconds(),
		ProxySendTimeoutMS: value.ProxySendTimeout.Milliseconds(), ProxyReadTimeoutMS: value.ProxyReadTimeout.Milliseconds(),
		StreamProxyTimeoutMS: value.StreamProxyTimeout.Milliseconds(), ServerHeader: value.ServerHeader,
		ClientMaxBodyBytes: value.ClientMaxBodyBytes, DefaultMIMEType: value.DefaultMIMEType,
		KeepaliveRequests: value.KeepaliveRequests, KeepaliveTimeoutMS: value.KeepaliveTimeout.Milliseconds(),
		LogNotFound: value.LogNotFound, ServerNamesHashMaxSize: value.ServerNamesHashMaxSize, ServerTokens: value.ServerTokens,
		GzipHTTPVersion: value.GzipHTTPVersion, ProxyRequestBufferingDisabled: value.ProxyRequestBufferingDisabled,
		ProxyHTTPVersion: value.ProxyHTTPVersion, ProxyNextUpstream: slices.Clone(value.ProxyNextUpstream),
		LargeClientHeaderBufferCount: value.LargeClientHeaderBufferCount, LargeClientHeaderBufferBytes: value.LargeClientHeaderBufferBytes,
		ServerNamesHashBucketSize: value.ServerNamesHashBucketSize, ServerAddrOutgoing: value.ServerAddrOutgoing,
		ClientBodyBufferBytes: value.ClientBodyBufferBytes,
	}
}

func (value SiteRuntimeSystemNginx) Settings() NginxSettings {
	ms := func(value int64) time.Duration { return time.Duration(value) * time.Millisecond }
	return NginxSettings{
		WorkerProcesses: value.WorkerProcesses, WorkerRlimitNoFile: value.WorkerRlimitNoFile,
		WorkerShutdownTimeout: ms(value.WorkerShutdownTimeoutMS), WorkerConnections: value.WorkerConnections,
		ResolverAddresses: slices.Clone(value.ResolverAddresses), ResolverTimeout: ms(value.ResolverTimeoutMS),
		GzipLevel: value.GzipLevel, GzipMinimumBytes: value.GzipMinimumBytes, GzipVary: value.GzipVary,
		GzipDisabled: value.GzipDisabled, GzipTypes: slices.Clone(value.GzipTypes),
		ProxyBuffering: value.ProxyBuffering, ProxyCacheMethods: slices.Clone(value.ProxyCacheMethods),
		ProxyCacheMaxBytes: value.ProxyCacheMaxBytes, ProxyCacheZoneBytes: value.ProxyCacheZoneBytes,
		ProxyCacheMinFreeBytes: value.ProxyCacheMinFreeBytes,
		ProxyMaxTempFileBytes:  value.ProxyMaxTempFileBytes, ProxyConnectTimeout: ms(value.ProxyConnectTimeoutMS),
		ProxySendTimeout: ms(value.ProxySendTimeoutMS), ProxyReadTimeout: ms(value.ProxyReadTimeoutMS),
		StreamProxyTimeout: ms(value.StreamProxyTimeoutMS), ServerHeader: value.ServerHeader,
		ClientMaxBodyBytes: value.ClientMaxBodyBytes, DefaultMIMEType: value.DefaultMIMEType,
		KeepaliveRequests: value.KeepaliveRequests, KeepaliveTimeout: ms(value.KeepaliveTimeoutMS),
		LogNotFound: value.LogNotFound, ServerNamesHashMaxSize: value.ServerNamesHashMaxSize, ServerTokens: value.ServerTokens,
		GzipHTTPVersion: value.GzipHTTPVersion, ProxyRequestBufferingDisabled: value.ProxyRequestBufferingDisabled,
		ProxyHTTPVersion: value.ProxyHTTPVersion, ProxyNextUpstream: slices.Clone(value.ProxyNextUpstream),
		LargeClientHeaderBufferCount: value.LargeClientHeaderBufferCount, LargeClientHeaderBufferBytes: value.LargeClientHeaderBufferBytes,
		ServerNamesHashBucketSize: value.ServerNamesHashBucketSize, ServerAddrOutgoing: value.ServerAddrOutgoing,
		ClientBodyBufferBytes: value.ClientBodyBufferBytes,
	}
}

// validNginx checks one nginx base is in canonical form.
func (value SiteRuntimeSystemNginx) validNginx() bool {
	if value.ResolverAddresses == nil || value.ProxyCacheMethods == nil {
		return false
	}
	settings := value.Settings()
	normalized, err := normalizeNginxSettings(&settings)
	return err == nil && normalized != nil && reflect.DeepEqual(NewSiteRuntimeSystemNginx(*normalized), value)
}

// Validate applies the v1 renderer's NginxSettings bounds and requires the
// canonical (normalized) form, so control and node accept the same documents.
func (value SiteRuntimeSystem) Validate() error {
	if !siteRuntimeSystemUUIDPattern.MatchString(value.PlatformScopeID) || value.Revision < 1 || value.Revision > 1<<53-1 ||
		!siteRuntimeSystemSHA256Pattern.MatchString(value.SnapshotSHA256) || !value.Nginx.validNginx() {
		return ErrInvalidConfig
	}
	// a block with nothing on still carries the node networks
	// (an L2 node trusts an L1's hop by them)
	if value.DDoS != nil && value.DDoS.Validate() != nil {
		return ErrInvalidConfig
	}
	if value.NodeNginx != nil && len(value.NodeNginx) == 0 || len(value.NodeNginx) > MaxSiteRuntimeSystemNodeNginx {
		return ErrInvalidConfig
	}
	seen, nodes := map[string]bool{}, 0
	for index, group := range value.NodeNginx {
		if len(group.NodeIDs) == 0 || !group.Nginx.validNginx() || reflect.DeepEqual(group.Nginx, value.Nginx) ||
			index > 0 && value.NodeNginx[index-1].NodeIDs[0] >= group.NodeIDs[0] {
			return ErrInvalidConfig
		}
		for position, nodeID := range group.NodeIDs {
			if !siteRuntimeSystemUUIDPattern.MatchString(nodeID) || seen[nodeID] ||
				position > 0 && group.NodeIDs[position-1] >= nodeID {
				return ErrInvalidConfig
			}
			seen[nodeID] = true
		}
		if nodes += len(group.NodeIDs); nodes > MaxSiteRuntimeSystemNodeNginx {
			return ErrInvalidConfig
		}
	}
	return nil
}

// ForNode is the block as node nodeID runs it: its own nginx base when
// NodeNginx lists it, without the other nodes' groups.
func (value *SiteRuntimeSystem) ForNode(nodeID string) *SiteRuntimeSystem {
	if value == nil {
		return nil
	}
	result := *value
	result.NodeNginx = nil
	for _, group := range value.NodeNginx {
		if _, found := slices.BinarySearch(group.NodeIDs, nodeID); found {
			result.Nginx = group.Nginx
			break
		}
	}
	return &result
}

// WithNodeNginx returns system with the per-node bases: nodes maps a node
// ID to its effective settings; a node whose settings equal the block's
// base is left out. Settings are normalized as NewSiteRuntimeSystem does.
func (value SiteRuntimeSystem) WithNodeNginx(nodes map[string]NginxSettings) (SiteRuntimeSystem, error) {
	groups := map[string]*SiteRuntimeSystemNodeNginx{}
	for nodeID, settings := range nodes {
		normalized, err := normalizeNginxSettings(&settings)
		if err != nil || normalized == nil || !siteRuntimeSystemUUIDPattern.MatchString(nodeID) {
			return SiteRuntimeSystem{}, ErrInvalidConfig
		}
		nginx := NewSiteRuntimeSystemNginx(*normalized)
		if !reflect.DeepEqual(nginx.Settings(), *normalized) {
			return SiteRuntimeSystem{}, ErrInvalidConfig
		}
		if reflect.DeepEqual(nginx, value.Nginx) {
			continue
		}
		key := fmt.Sprintf("%#v", nginx)
		if groups[key] == nil {
			groups[key] = &SiteRuntimeSystemNodeNginx{Nginx: nginx}
		}
		groups[key].NodeIDs = append(groups[key].NodeIDs, nodeID)
	}
	value.NodeNginx = nil
	for _, group := range groups {
		slices.Sort(group.NodeIDs)
		value.NodeNginx = append(value.NodeNginx, *group)
	}
	slices.SortFunc(value.NodeNginx, func(left, right SiteRuntimeSystemNodeNginx) int {
		return strings.Compare(left.NodeIDs[0], right.NodeIDs[0])
	})
	if err := value.Validate(); err != nil {
		return SiteRuntimeSystem{}, err
	}
	return value, nil
}

// NewSiteRuntimeSystem builds the canonical system block control publishes.
func NewSiteRuntimeSystem(platformScopeID string, revision int64, snapshotSHA256 string, settings NginxSettings) (SiteRuntimeSystem, error) {
	normalized, err := normalizeNginxSettings(&settings)
	if err != nil || normalized == nil {
		return SiteRuntimeSystem{}, ErrInvalidConfig
	}
	value := SiteRuntimeSystem{PlatformScopeID: platformScopeID, Revision: revision,
		SnapshotSHA256: snapshotSHA256, Nginx: NewSiteRuntimeSystemNginx(*normalized)}
	// Sub-millisecond durations would not survive the projection.
	if value.Validate() != nil || !reflect.DeepEqual(value.Nginx.Settings(), *normalized) {
		return SiteRuntimeSystem{}, ErrInvalidConfig
	}
	return value, nil
}

// SelectSiteRuntimeSystem picks the system configuration a node renders from
// the scopes it composes: the highest platform revision wins (every scope is
// republished on activation, so a lower one is a scope not yet republished).
// Scopes without one do not vote. nil means none carries one: the node keeps
// its built-in defaults.
func SelectSiteRuntimeSystem(values []*SiteRuntimeSystem) (*SiteRuntimeSystem, error) {
	var selected *SiteRuntimeSystem
	for _, value := range values {
		if value == nil {
			continue
		}
		switch {
		case selected == nil || value.Revision > selected.Revision:
			if selected != nil && value.PlatformScopeID != selected.PlatformScopeID {
				return nil, fmt.Errorf("%w: scopes carry different platform system configurations", ErrInvalidConfig)
			}
			selected = value
		case value.PlatformScopeID != selected.PlatformScopeID:
			return nil, fmt.Errorf("%w: scopes carry different platform system configurations", ErrInvalidConfig)
		case value.Revision == selected.Revision && value.SnapshotSHA256 != selected.SnapshotSHA256:
			return nil, fmt.Errorf("%w: one system configuration revision has two snapshots", ErrInvalidConfig)
		}
	}
	return selected, nil
}

// SiteRuntimeSystemMain is the main-context directives: worker settings
// (without worker_processes when system is nil, which the caller defaults).
func SiteRuntimeSystemMain(system *SiteRuntimeSystem) string {
	if system == nil {
		return "worker_processes auto;\n"
	}
	var output strings.Builder
	if system.Nginx.WorkerProcesses == 0 {
		output.WriteString("worker_processes auto;\n")
	} else {
		fmt.Fprintf(&output, "worker_processes %d;\n", system.Nginx.WorkerProcesses)
	}
	settings := system.Nginx.Settings()
	fmt.Fprintf(&output, "worker_rlimit_nofile %d;\n", settings.WorkerRlimitNoFile)
	fmt.Fprintf(&output, "worker_shutdown_timeout %s;\n", nginxReadableDuration(settings.WorkerShutdownTimeout))
	return output.String()
}

// SiteRuntimeSystemEvents is the events{} block.
func SiteRuntimeSystemEvents(system *SiteRuntimeSystem) string {
	if system == nil {
		return "events { worker_connections 4096; }\n"
	}
	return fmt.Sprintf("events { worker_connections %d; }\n", system.Nginx.WorkerConnections)
}

// SiteRuntimeSystemHTTP is the http-level directives (server_tokens and the
// Server header included).
func SiteRuntimeSystemHTTP(system *SiteRuntimeSystem) string {
	if system == nil {
		return "  server_tokens off;\n"
	}
	var output strings.Builder
	renderGlobalNginxSettings(&output, system.Nginx.Settings())
	return output.String()
}
