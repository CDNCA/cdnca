package edgepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// TargetCapabilityError refuses a publication one target node's agent cannot
// apply because it predates a feature the release uses. The deployment would
// otherwise reach the node and fail its precheck there (older agents decode
// configuration strictly). It unwraps to ErrTargetIneligible.
type TargetCapabilityError struct {
	NodeID       uuid.UUID
	AgentVersion string
	Feature      string
	Capability   agentv1.CapabilityName
	Required     uint32
	Advertised   uint32
	// OtherNodeIDs are the further target nodes, in target order, that lack
	// the same or another gated capability.
	OtherNodeIDs []uuid.UUID
	// AutoResume: the caller recorded the refused release and publishes it
	// once the nodes declare the capability (securityactivation).
	AutoResume bool
}

func (e *TargetCapabilityError) Error() string {
	version := e.AgentVersion
	if version == "" {
		version = "unknown"
	}
	libraryPending := e.ipIntelLibraryPending()
	message := fmt.Sprintf("node %s (agent %s) does not support %s (%s v%d required, v%d declared); upgrade the node agent or remove the feature",
		e.NodeID, version, e.Feature, e.Capability, e.Required, e.Advertised)
	if e.siteRuntimeBaseline() {
		message = fmt.Sprintf("node %s (agent %s) does not have the 1.0.35 website runtime that every website release needs (节点版本低于 1.0.35，无法接收网站发布) (%s v%d required, v%d declared); upgrade the node agent to 1.0.35 or later (请把节点升级到 1.0.35 或更高版本)",
			e.NodeID, version, e.Capability, e.Required, e.Advertised)
	}
	if libraryPending {
		message = fmt.Sprintf("node %s (agent %s) has not loaded a verified IP intelligence library yet (节点尚未加载已验签的 IP 情报库), needed for %s; wait for the library to reach the node or remove the rules",
			e.NodeID, version, e.Feature)
	}
	if len(e.OtherNodeIDs) != 0 {
		others := make([]string, len(e.OtherNodeIDs))
		for index, nodeID := range e.OtherNodeIDs {
			others[index] = nodeID.String()
		}
		message += "; also unsupported on nodes " + strings.Join(others, ", ")
	}
	if e.AutoResume && libraryPending {
		message += "; the release is recorded and is published automatically once the library reaches the nodes"
	} else if e.AutoResume {
		message += "; the release is recorded and is published automatically once the nodes are upgraded"
	}
	return message
}

// NodeArtifactPending: the refusal waits for a node artifact (the IP
// library) to arrive through the node artifact set, not for an upgrade.
func (e *TargetCapabilityError) NodeArtifactPending() bool { return e.ipIntelLibraryPending() }

// ipIntelLibraryPending: the node declares IP_INTEL but is refused because it
// has not applied a verified library yet (ipIntelLibraryTargetsError).
func (e *TargetCapabilityError) ipIntelLibraryPending() bool {
	return e.Capability == agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL && e.Required != 0 && e.Advertised >= e.Required
}

// siteRuntimeBaseline: the node lacks site_runtime v6, which every site
// runtime release needs (the 1.0.35 compatibility baseline), not a feature.
func (e *TargetCapabilityError) siteRuntimeBaseline() bool {
	return e.Capability == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME && e.Required == siteRuntimeV6APIVersion
}

func (e *TargetCapabilityError) Unwrap() error { return ErrTargetIneligible }

// gatedFeature names a capability version that only newer agents implement.
// Older agents advertise a lower version (or none) and must not receive it.
func gatedFeature(capability *agentv1.Capability) (string, bool) {
	switch {
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC && capability.GetApiVersion() >= edgeconfig.CCAutoSwitchOverridesAPIVersion:
		return "CC auto switch region / node overrides (自动切换按区域、按节点覆盖，CC v8；节点版本过低，请升级节点)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC && capability.GetApiVersion() >= edgeconfig.CCMatchKeysCCAPIVersion:
		return "CC rules counting by User-Agent, Referer, a header, cookie or query argument, or matching on JA4 (CC v7；节点版本过低，请升级节点)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC && capability.GetApiVersion() >= ccV6APIVersion:
		return "CC trusted crawlers (蜘蛛白名单), the challenge cookie domain, client IP lists or exclusions, or header / User-Agent / Referer matches; upgrade the node", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC && capability.GetApiVersion() >= ccAutoSwitchAPIVersion:
		return "CC auto switch (自动切换); upgrade the node or turn the site's auto switch off", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC && capability.GetApiVersion() >= ccCountByAPIVersion:
		return "CC rules counting by network, host, URI or TLS fingerprint (统计对象); upgrade the node or count by client IP", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC && capability.GetApiVersion() >= ccProofOfWorkAPIVersion:
		return "CC verification pages with proof of work", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME &&
		capability.GetApiVersion() >= edgeconfig.DynamicRoutingSiteRuntimeVersion:
		return "the 1.0.35 dynamic routing node runtime (动态路由节点运行时，需要节点支持 site runtime v9); upgrade the node", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME &&
		capability.GetApiVersion() >= edgeconfig.LazyCertificateSiteRuntimeVersion:
		return "HTTPS sites, which use lazy certificates (HTTPS 网站使用证书懒加载，需要节点升级到支持 site runtime v7 的版本)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME && capability.GetApiVersion() >= siteRuntimeV6APIVersion:
		// The 1.0.35 baseline: every website release needs it, whatever the
		// sites use (TargetCapabilityError.siteRuntimeBaseline words it).
		return "the 1.0.35 website runtime", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE:
		return "the OWASP CRS managed WAF", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_BROTLI:
		return "Brotli compression or a site compression level (Brotli 压缩/站点压缩级别需要节点运行时编入 ngx_brotli，未声明 EDGE_BROTLI；请升级节点或关闭 Brotli 并清空压缩级别)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_WEBP:
		return "automatic WebP conversion (自动转 WebP 需要节点支持 EDGE_WEBP；请升级节点或关闭该网站的自动转 WebP)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_RESPONSE_RULES:
		return "response rules (响应规则需要节点支持 EDGE_RESPONSE_RULES；请升级节点或删除该网站的响应规则)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CACHE_RULE_MATCH:
		return "cache rule conditions or per-rule settings (缓存规则的路径正则/响应内容类型条件，以及单个路径、按规则忽略参数/分片回源/强制缓存/忽略 Vary/不缓存条件需要节点支持 CACHE_RULE_MATCH v2；请升级节点或删除这些设置)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_EDGE_OPTIONS:
		return "site edit options: default site, search engine origin, ACME pass-through to the origin or unbuffered proxying (默认站点/搜索引擎回源/源站申请证书/数据实时返回发送需要节点支持 SITE_EDGE_OPTIONS；请升级节点或关闭这些选项)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_L2_ROUTING:
		return "L2 routing: automatic publication through the line group's L2 configuration, its cache mode or L2 conditions (自动发布按线路分组的 L2 配置走 L2，以及缓存模式/L2条件，需要节点支持 L2_ROUTING v2；请升级节点，未升级的节点本次不下发)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_CUSTOM_CIPHERS:
		return "custom TLS cipher suites (网站自定义密码套件需要节点支持 SITE_TLS_CUSTOM_CIPHERS；请升级节点或改回套件预设)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_OPTIONS:
		return "per site HTTP/2 off or ssl_prefer_server_ciphers (网站关闭 HTTP/2 或单独设置服务端套件优先需要节点支持 SITE_TLS_OPTIONS（原生补丁 27）；请升级节点或恢复这些设置)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_ORIGIN_TLS_NO_VERIFY:
		return "HTTPS origins that do not verify the origin certificate (回源 HTTPS 选了「不校验源站证书」，需要节点支持 ORIGIN_TLS_NO_VERIFY（原生补丁 29），节点版本过低；请升级节点或改回校验源站证书)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_ORIGIN_FOLLOW_REDIRECT:
		return "following origin redirects (回源跟随跳转需要节点支持 ORIGIN_FOLLOW_REDIRECT；请升级节点或关闭该网站的回源跟随跳转)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SCHED302:
		return "HTTP 302 scheduling (302 调度；请升级节点或关闭该网站的 302 调度)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC:
		return "HTTP/3 over QUIC (网站开启了 HTTP/3，节点 OpenResty 未编入 HTTP/3 模块 --with-http_v3_module，未声明 SITE_QUIC；请升级节点运行时或关闭该网站的 HTTP/3)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_WAF && capability.GetApiVersion() >= edgeconfig.WAFMultipartAPIVersion:
		return "WAF rules on multipart field names, part count or field length (WAF multipart 字段名/分段数/字段长度条件，含 PHP2Shell 虚拟补丁，需要节点升级)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_WAF && capability.GetApiVersion() >= edgeconfig.WAFConditionsAPIVersion:
		return "WAF rules on the request Content-Type, HTTP version or an IP list (WAF 内容类型/HTTP 版本/IP 名单条件需要节点升级)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_WAF && capability.GetApiVersion() >= edgeconfig.WAFAdaptiveAPIVersion:
		return "the OWASP CRS managed WAF with adaptive scoring (托管 WAF 灰区挑战/自适应需要节点升级)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_WAF && capability.GetApiVersion() >= edgeconfig.WAFActionAPIVersion:
		return "WAF challenge / temporary ban actions, auto block or observe mode (WAF 挑战/临时封禁动作、自动封禁或观察模式需要节点升级)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_WAF_JA4_NEGATION:
		return "WAF rules on a JA4 fingerprint not in a list (WAF「JA4 不在列表内」条件需要节点版本支持 WAF_JA4_NEGATION，节点版本过低；请升级节点或改用“在列表内”)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC_MATCH_KEYS:
		return "CC rules counting by User-Agent, Referer, a header, cookie or query argument, or matching on JA4 (CC 统计对象 UA/Referer/请求头/Cookie/参数或 JA4 条件需要节点版本支持 CC_MATCH_KEYS，节点版本过低；请升级节点)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_JA4:
		return "WAF rules on the TLS fingerprint (JA4; the node runtime must compute it)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL:
		return "rules on carrier, IDC, ASN or region (运营商/IDC/ASN/地区规则需要节点 IP 情报库)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SUBSCRIPTION_LIMITS:
		return "market supply limits per subscription (节点市场订阅限额：TCP 连接数/每秒新建连接/QPS/停止服务，需要节点升级)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION:
		return "L4 forwards on a package, whose traffic the node attributes to that package (套餐下的四层转发需要节点支持 L4_PACKAGE_ATTRIBUTION，按发生时刻的套餐记流量；请升级节点)", true
	case capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA:
		return "L4 client address via TOA (节点内核不支持 TOA，可以改用 PROXY protocol（源站需要支持），或者升级节点系统)", true
	case (capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY ||
		capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY) && capability.GetApiVersion() >= 12:
		return "1.0.35 L4 forwards, which belong to no website (四层转发不再挂网站，需要节点 tcp/udp v12；请升级节点)", true
	case (capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY ||
		capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY) && capability.GetApiVersion() >= 10:
		return "L4 guard rules (四层防护规则)", true
	case (capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY ||
		capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY) && capability.GetApiVersion() >= 9:
		return "an L4 port range or follow-port origin (四层端口范围 / 跟随端口回源)", true
	case (capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY ||
		capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY) && capability.GetApiVersion() >= 8:
		return "an L4 stream with TOA (回源携带客户端 IP = TOA)", true
	case (capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY ||
		capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY) && capability.GetApiVersion() >= 7:
		return "an L4 session log (四层会话日志)", true
	case (capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY ||
		capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY) && capability.GetApiVersion() >= 6:
		return "an L4 per-client new connection rate (单 IP 新建连接速率)", true
	case (capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY ||
		capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY) && capability.GetApiVersion() >= 5:
		return "an L4 old-connection drain limit other than 24 hours (系统设置 > 其它配置)", true
	case (capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY ||
		capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY) && capability.GetApiVersion() >= 4:
		return "L4 TLS passthrough by SNI or ports shared with websites", true
	case (capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY ||
		capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY) && capability.GetApiVersion() >= 3:
		return "L4 additional listeners", true
	}
	return "", false
}

// listenerCCAPIVersion is ccAPIVersionForSites for one site runtime v2
// listener's CC binding.
func listenerCCAPIVersion(security *edgeconfig.ListenerSecurity) uint32 {
	if security != nil && security.CC != nil {
		return edgeconfig.CCV2PolicyAPIVersion(security.CC.Policy)
	}
	return 2
}

// ja4APIVersion is CAPABILITY_NAME_JA4 v1: the node runtime computes the
// JA4 TLS client fingerprint into $cdnca_ja4 (native OpenResty with
// ngx_http_cdnca_ja4_module). No earlier agent declared JA4, so v1 is the
// first that really collects it.
const ja4APIVersion uint32 = 1

// ccProofOfWorkAPIVersion is CC API v3: verification pages with proof of
// work and bound, rotated pass cookies (edgeconfig.CCV2PolicyNeedsProofOfWork).
// v2 agents decode challenges strictly and refuse those fields.
const ccProofOfWorkAPIVersion uint32 = 3

// ccCountByAPIVersion is CC API v4: rules counting by client network, host,
// URI or TLS fingerprint (edgeconfig.CCV2PolicyCountsByKey). Earlier agents
// accept dimension client_ip only and refuse the whole policy (503).
const ccCountByAPIVersion uint32 = 4

// ccAutoSwitchAPIVersion is CC API v5: the policy's auto switch
// (edgeconfig.CCV2AutoSwitch). Earlier agents decode policies strictly and
// refuse it.
const ccAutoSwitchAPIVersion uint32 = 5

// ccV6APIVersion is CC API v6: trusted crawlers, the pass cookie domain,
// client IP lists and header matches (edgeconfig.CCV2PolicyNeedsV6). Earlier
// agents decode policies strictly and refuse them.
const ccV6APIVersion uint32 = 6

// targetCapabilityError returns the readable refusal for the first gated
// capability a node does not declare, or nil.
func targetCapabilityError(nodeID uuid.UUID, agentVersion string, required, advertised []*agentv1.Capability) error {
	have := make(map[agentv1.CapabilityName]uint32, len(advertised))
	for _, capability := range advertised {
		have[capability.GetName()] = max(have[capability.GetName()], capability.GetApiVersion())
	}
	for _, capability := range required {
		feature, gated := gatedFeature(capability)
		if gated && have[capability.GetName()] < capability.GetApiVersion() {
			return &TargetCapabilityError{NodeID: nodeID, AgentVersion: agentVersion, Feature: feature,
				Capability: capability.GetName(), Required: capability.GetApiVersion(), Advertised: have[capability.GetName()]}
		}
	}
	return nil
}

// validateFeatureCapabilityTargets refuses, before anything is persisted, a
// release that needs a gated capability one of its target nodes lacks. Nodes
// whose capabilities are unknown are left to the deployment command's
// required_capabilities, which every agent checks itself, except for
// IP_INTEL: every target must also have applied an IP intelligence library.
func validateFeatureCapabilityTargets(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID, required []*agentv1.Capability) error {
	gated := false
	for _, capability := range required {
		if _, ok := gatedFeature(capability); ok {
			gated = true
		}
	}
	if !gated || len(nodeIDs) == 0 {
		return nil
	}
	sessions, err := loadSessionCapabilities(ctx, tx, nodeIDs)
	if err != nil {
		return err
	}
	if err := capabilityTargetsError(nodeIDs, required, sessions); err != nil {
		return err
	}
	if !requiresIPIntel(required) {
		return nil
	}
	ready, err := loadIPIntelLibraryNodes(ctx, tx, nodeIDs)
	if err != nil {
		return err
	}
	return ipIntelLibraryTargetsError(nodeIDs, required, sessions, ready)
}

// IPIntelAPIVersion is CAPABILITY_NAME_IP_INTEL v2 (signed library format
// v2 applied as a node artifact set item).
const IPIntelAPIVersion = edgeconfig.IPIntelCapabilityVersion

func requiresIPIntel(required []*agentv1.Capability) bool {
	for _, capability := range required {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL {
			return true
		}
	}
	return false
}

// ipIntelLibraryTargetsError refuses carrier / IDC / ASN / region rules for
// target nodes that have never applied a verified IP intelligence library
// (库未就绪拒绝发布并提示，库就绪后自动发布). Without a library the
// rules never match, so the release would silently not protect the site.
// Nodes without a readable session are refused too: nothing shows they
// have a library. ready holds the nodes that have one.
func ipIntelLibraryTargetsError(nodeIDs []uuid.UUID, required []*agentv1.Capability,
	sessions map[uuid.UUID]*agentv1.AgentCapabilities, ready map[uuid.UUID]bool) error {
	var capability *agentv1.Capability
	for _, item := range required {
		if item.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL {
			capability = item
		}
	}
	if capability == nil {
		return nil
	}
	feature, _ := gatedFeature(capability)
	var refusal *TargetCapabilityError
	for _, nodeID := range nodeIDs {
		if ready[nodeID] {
			continue
		}
		if refusal != nil {
			refusal.OtherNodeIDs = append(refusal.OtherNodeIDs, nodeID)
			continue
		}
		refusal = &TargetCapabilityError{NodeID: nodeID, Feature: feature, Capability: capability.GetName(),
			Required: capability.GetApiVersion(), Advertised: capability.GetApiVersion()}
		if session, ok := sessions[nodeID]; ok {
			refusal.AgentVersion = session.GetAgentVersion()
		}
	}
	if refusal == nil {
		return nil
	}
	return refusal
}

// loadIPIntelLibraryNodes returns the nodes, of nodeIDs, whose applied node
// artifact set holds an IP intelligence library (PA-01, ADR 0007 section 4.5):
// node_artifact_applied_items is written from the node's own receipt
// (edgestatus) after it verified, prechecked and switched the whole set, so a
// later rejected set does not take back the library it keeps as its last
// known good, and a set without the library does.
func loadIPIntelLibraryNodes(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) (map[uuid.UUID]bool, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT node_id FROM node_artifact_applied_items
		WHERE node_id=ANY($1::uuid[]) AND media_type=$2`, nodeIDs, artifactset.MediaTypeIPIntel)
	if err != nil {
		return nil, fmt.Errorf("%w: read node IP intelligence libraries", ErrPersistence)
	}
	defer rows.Close()
	ready := make(map[uuid.UUID]bool, len(nodeIDs))
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil {
			return nil, fmt.Errorf("%w: scan node IP intelligence libraries", ErrPersistence)
		}
		ready[nodeID] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate node IP intelligence libraries", ErrPersistence)
	}
	return ready, nil
}

// capabilityTargetsError is the refusal for the first target whose session
// lacks a gated capability, naming every other such target too.
func capabilityTargetsError(nodeIDs []uuid.UUID, required []*agentv1.Capability,
	sessions map[uuid.UUID]*agentv1.AgentCapabilities) error {
	var refusal *TargetCapabilityError
	for _, nodeID := range nodeIDs {
		capabilities, ok := sessions[nodeID]
		if !ok {
			continue
		}
		err := targetCapabilityError(nodeID, capabilities.GetAgentVersion(), required, capabilities.GetFeatures())
		if err == nil {
			continue
		}
		if refusal == nil {
			refusal = err.(*TargetCapabilityError)
		} else {
			refusal.OtherNodeIDs = append(refusal.OtherNodeIDs, nodeID)
		}
	}
	if refusal == nil {
		return nil
	}
	return refusal
}

// ValidateFeatureCapabilityTargets is validateFeatureCapabilityTargets for
// callers outside the package that roll out a release themselves
// (securityactivation).
func ValidateFeatureCapabilityTargets(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID, required []*agentv1.Capability) error {
	if ctx == nil || tx == nil {
		return ErrInvalidInput
	}
	return validateFeatureCapabilityTargets(ctx, tx, nodeIDs, required)
}

// loadSessionCapabilities returns what each node declared on its latest
// Connect session. Enrollment capabilities are frozen at first enrollment
// (certificate renewal does not refresh them), so after an in-place agent
// upgrade only the session reflects what the node runs. A node without a
// readable session row is absent from the result.
func loadSessionCapabilities(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) (map[uuid.UUID]*agentv1.AgentCapabilities, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (node_id) node_id,capabilities_snapshot,capabilities_sha256
		FROM node_session_capabilities WHERE node_id=ANY($1::uuid[])
		ORDER BY node_id,session_epoch DESC`, nodeIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: read node session capabilities", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]*agentv1.AgentCapabilities, len(nodeIDs))
	for rows.Next() {
		var nodeID uuid.UUID
		var snapshot, digest []byte
		if err := rows.Scan(&nodeID, &snapshot, &digest); err != nil {
			return nil, fmt.Errorf("%w: scan node session capabilities", ErrPersistence)
		}
		actual := sha256.Sum256(snapshot)
		capabilities := new(agentv1.AgentCapabilities)
		if !bytes.Equal(actual[:], digest) || proto.Unmarshal(snapshot, capabilities) != nil {
			continue
		}
		result[nodeID] = capabilities
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate node session capabilities", ErrPersistence)
	}
	return result, nil
}

// readableTargetCapabilityError turns a generic ineligible-target refusal
// into a TargetCapabilityError when a gated feature is what a node lacks,
// judged on advertised (what the refused validation saw: the latest session,
// else the enrollment snapshot), so a node without a session row is named too.
func readableTargetCapabilityError(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID,
	required []*agentv1.Capability, advertised map[uuid.UUID][]*agentv1.Capability, refusal error) error {
	if !errors.Is(refusal, ErrTargetIneligible) {
		return refusal
	}
	sessions, err := loadSessionCapabilities(ctx, tx, nodeIDs)
	if err != nil {
		return err
	}
	if err := siteRuntimeV2CapabilityRefusal(nodeIDs, required, advertised, sessions); err != nil {
		return err
	}
	return refusal
}

// siteRuntimeV2CapabilityRefusal is capabilityTargetsError over advertised,
// with the agent version from the session where there is one.
func siteRuntimeV2CapabilityRefusal(nodeIDs []uuid.UUID, required []*agentv1.Capability,
	advertised map[uuid.UUID][]*agentv1.Capability, sessions map[uuid.UUID]*agentv1.AgentCapabilities) error {
	known := make(map[uuid.UUID]*agentv1.AgentCapabilities, len(advertised))
	for nodeID, features := range advertised {
		known[nodeID] = &agentv1.AgentCapabilities{AgentVersion: sessions[nodeID].GetAgentVersion(), Features: features}
	}
	return capabilityTargetsError(nodeIDs, required, known)
}

// preferSessionCapabilities replaces enrollment capabilities with the latest
// session's where one exists (see loadSessionCapabilities).
func preferSessionCapabilities(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID,
	enrolled map[uuid.UUID][]*agentv1.Capability) (map[uuid.UUID][]*agentv1.Capability, error) {
	sessions, err := loadSessionCapabilities(ctx, tx, nodeIDs)
	if err != nil {
		return nil, err
	}
	for nodeID, capabilities := range sessions {
		if _, target := enrolled[nodeID]; target && len(capabilities.GetFeatures()) != 0 {
			enrolled[nodeID] = cloneSiteRuntimeV2AdvertisedCapabilities(capabilities.GetFeatures())
		}
	}
	return enrolled, nil
}
