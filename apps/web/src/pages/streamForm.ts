import type { TFunction } from 'i18next'
import { ApiError, type ScopeKind } from '../api/auth'
import {
  streamPortConflict, type Stream, type StreamFields, type StreamGeoRegionCIDRs, type StreamGuardAction, type StreamGuardGeo,
  type StreamACLAction, type StreamGuardMatch, type StreamGuardRule, type StreamOrigin,
} from '../api/streams'
import { useSessionStore } from '../auth/session'
import { localizedUnknownApiError } from '../i18n/apiError'

export interface StreamFormValues extends StreamFields {
  target_scope_id?: string
  owner_id?: string
  group_ids?: string[]
  upstream_mode: 'address' | 'host'
  geo_trusted_proxy_cidrs: string
  geo_blocked_regions: string
  geo_region_cidrs: string
  // 防护规则的编辑行（guardRuleFromRow 转为 guard_rules）；未挂载时为 undefined。
  guard_rule_rows?: GuardRuleRow[]
  // 添加转发弹窗的单行输入（parseListenPorts / parseOrigin），提交前展开为协议、端口与上游字段。
  listen_ports_text?: string
  origin_text?: string
  // 详情页「IP 访问控制」的编辑值，提交时组装成 acl（默认允许且无规则时不带）。
  acl_default?: StreamACLAction
  acl_rules?: Array<{ cidr: string; action: StreamACLAction }>
}

// GuardRuleRow is one guard rule as the form edits it: list inputs are text
// (one item per line or comma), the carrier/IDC tags and countries are the
// geo conditions the form shows; other geo conditions (ASN, province, city)
// set through the API are kept as they are.
export interface GuardRuleRow {
  id: string
  action: StreamGuardAction
  first_packet_match?: StreamGuardMatch
  first_packet_value?: string
  server_names?: string[]
  client_cidrs?: string
  client_negate?: boolean
  tags?: string[]
  tags_negate?: boolean
  countries?: string
  countries_negate?: boolean
  geo_other?: StreamGuardGeo[]
  ban_seconds?: number
  threshold?: number
  window_seconds?: number
}

// The carrier / IDC tags of the node IP library (edgeconfig.IPIntelTagNames).
export const streamGuardTags = [
  'carrier:cn-telecom', 'carrier:cn-unicom', 'carrier:cn-mobile', 'carrier:cn-cernet', 'carrier:cn-cstnet',
  'carrier:cn-drpeng', 'carrier:cn-cbn', 'idc:cn', 'idc:global',
] as const

export function newGuardRuleID(): string {
  return globalThis.crypto.randomUUID()
}

export function guardRuleRow(rule: StreamGuardRule): GuardRuleRow {
  const tags = rule.geo?.find((condition) => condition.field === 'tag')
  const countries = rule.geo?.find((condition) => condition.field === 'country')
  const other = rule.geo?.filter((condition) => condition !== tags && condition !== countries) ?? []
  return {
    id: rule.id, action: rule.action,
    first_packet_match: rule.first_packet?.match, first_packet_value: rule.first_packet?.value,
    server_names: rule.server_names ? [...rule.server_names] : undefined,
    client_cidrs: rule.client_ip?.cidrs.join('\n'), client_negate: Boolean(rule.client_ip?.negate),
    tags: tags ? [...tags.values] : undefined, tags_negate: Boolean(tags?.negate),
    countries: countries?.values.join(', '), countries_negate: Boolean(countries?.negate),
    ...(other.length ? { geo_other: other } : {}),
    ban_seconds: rule.ban_seconds, threshold: rule.threshold, window_seconds: rule.window_seconds,
  }
}

export function guardRuleFromRow(row: GuardRuleRow, tlsPassthrough: boolean): StreamGuardRule {
  const rule: StreamGuardRule = { id: row.id, action: row.action }
  const value = row.first_packet_match === 'contains' ? row.first_packet_value ?? '' : (row.first_packet_value ?? '').trim()
  if (row.first_packet_match && value) {
    rule.first_packet = { match: row.first_packet_match, value: row.first_packet_match === 'prefix_hex' ? value.replace(/\s+/gu, '').toLowerCase() : value }
  }
  const names = normalizeServerNames(row.server_names)
  if (tlsPassthrough && names.length) rule.server_names = names
  const cidrs = splitInput(row.client_cidrs)
  if (cidrs.length) rule.client_ip = { cidrs, ...(row.client_negate ? { negate: true } : {}) }
  const geo: StreamGuardGeo[] = []
  if (row.tags?.length) geo.push({ field: 'tag', ...(row.tags_negate ? { negate: true } : {}), values: [...row.tags] })
  const countries = splitInput(row.countries).map((country) => country.toUpperCase())
  if (countries.length) geo.push({ field: 'country', ...(row.countries_negate ? { negate: true } : {}), values: countries })
  geo.push(...(row.geo_other ?? []))
  if (geo.length) rule.geo = geo
  if (row.action === 'ban') {
    const threshold = row.threshold ?? 1
    rule.ban_seconds = row.ban_seconds ?? 0
    rule.threshold = threshold
    if (threshold > 1) rule.window_seconds = row.window_seconds ?? 0
  }
  return rule
}

const hexPattern = /^(?:[0-9a-f]{2})+$/u

// guardRuleProblem returns the i18n key (guard.*) of what makes row invalid,
// or null; the server checks the rest (CIDR masks, regex syntax).
export function guardRuleProblem(row: GuardRuleRow, tlsPassthrough: boolean): string | null {
  const rule = guardRuleFromRow(row, tlsPassthrough)
  if (!tlsPassthrough && normalizeServerNames(row.server_names).length) return 'sniNeedsPassthrough'
  if (!rule.first_packet && !rule.server_names && !rule.client_ip && !rule.geo) return 'noCondition'
  if (rule.first_packet) {
    const { match, value } = rule.first_packet
    if (match === 'prefix_hex' && (!hexPattern.test(value) || value.length > 512)) return 'hexInvalid'
    // Regex syntax is RE2 / PCRE (the server checks it), not the browser's.
    if (match !== 'prefix_hex' && new TextEncoder().encode(value).length > 256) return 'patternTooLong'
  }
  if (rule.client_ip && (rule.client_ip.cidrs.length > 1024 || !rule.client_ip.cidrs.every(validCIDR))) return 'cidrInvalid'
  if (rule.server_names && rule.server_names.length > 32) return 'sniTooMany'
  if (countryInputInvalid(row.countries)) return 'countryInvalid'
  if (rule.action === 'ban') {
    if (!Number.isInteger(rule.ban_seconds) || rule.ban_seconds! < 1 || rule.ban_seconds! > 86400) return 'banSecondsRange'
    if (!Number.isInteger(rule.threshold) || rule.threshold! < 1 || rule.threshold! > 10000) return 'thresholdRange'
    if (rule.threshold! > 1 && (!Number.isInteger(rule.window_seconds) || rule.window_seconds! < 1 || rule.window_seconds! > 3600)) return 'windowRange'
  }
  return null
}

function countryInputInvalid(value: string | undefined): boolean {
  return splitInput(value).some((country) => !/^[A-Za-z]{2}$/u.test(country))
}

export function validCIDR(value: string): boolean {
  const separator = value.lastIndexOf('/')
  if (separator < 1) return false
  const address = value.slice(0, separator)
  const bits = value.slice(separator + 1)
  if (!/^\d{1,3}$/u.test(bits) || !isIPAddress(address)) return false
  return Number(bits) <= (address.includes(':') ? 128 : 32)
}

export function guardRulesFromRows(rows: GuardRuleRow[] | undefined, tlsPassthrough: boolean): StreamGuardRule[] {
  return (rows ?? []).map((row) => guardRuleFromRow(row, tlsPassthrough))
}

// 防护规则：没有规则时不出现在请求里（与旧请求体逐字节一致）。
export function guardRulesField(rules: StreamGuardRule[] | undefined): Pick<StreamFields, 'guard_rules'> {
  return rules?.length ? { guard_rules: rules.map((rule) => structuredClone(rule)) } : {}
}

export const staleStreamRead = new Error('stale stream read')

export function writeKey(operation: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `${operation}-${suffix}`
}

export function writeOutcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500
}

export function hasStreamManagePermission(permissions?: readonly string[]): boolean {
  return Boolean(permissions?.includes('streams.manage') || permissions?.includes('platform.admin'))
}

export function hasStreamReadPermission(scopeKind: ScopeKind, permissions: readonly string[]): boolean {
  if (scopeKind === 'tenant') return permissions.includes('streams.read')
  return permissions.some((permission) => [
    'streams.read',
    'platform.admin',
    'edge_publications.read',
    'edge_publications.manage',
  ].includes(permission))
}

export function streamSessionMatches(scopeKind: ScopeKind, scopeID: string, sessionEpoch: number): boolean {
  const current = useSessionStore.getState()
  return current.sessionEpoch === sessionEpoch &&
    current.principal?.scope_kind === scopeKind &&
    current.principal.scope_id === scopeID
}

export function currentPrincipalCanManageStreams(
  scopeKind: ScopeKind,
  scopeID: string,
  sessionEpoch: number,
): boolean {
  return streamSessionMatches(scopeKind, scopeID, sessionEpoch) &&
    hasStreamManagePermission(useSessionStore.getState().principal?.permissions)
}

export function currentPrincipalCanReadStreams(
  scopeKind: ScopeKind,
  scopeID: string,
  sessionEpoch: number,
): boolean {
  const current = useSessionStore.getState()
  return streamSessionMatches(scopeKind, scopeID, sessionEpoch) &&
    Boolean(current.principal && hasStreamReadPermission(scopeKind, current.principal.permissions))
}

export const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export function isIPAddress(value: string): boolean {
  const candidate = value.trim()
  if (!candidate.includes(':')) {
    const ipv4 = candidate.split('.')
    if (ipv4.length !== 4) return false
    return ipv4.every((part) => /^\d{1,3}$/.test(part) &&
      Number(part) <= 255 &&
      (part === '0' || !part.startsWith('0')))
  }
  try {
    return new URL(`http://[${candidate}]/`).hostname.startsWith('[')
  } catch {
    return false
  }
}

const knownStreamErrorCodes = ['version_conflict', 'stream_shared_port_proxy_protocol'] as const

// L4-006：服务端 validation_error 的 details.field（l4forward.FieldError）→ 中文字段说明。
const streamErrorFields = [
  'name', 'remark', 'upstream_address', 'upstream_host', 'dns_policy',
  'origins', 'geo_policy', 'guard_rules', 'acl', 'balance_way',
] as const

// 组合校验（字段 + 原因）：PROXY/可信代理配对、UDP 与 PROXY、TOA、跟随端口与多源站。
const streamErrorFieldReasons = [
  'proxy_protocol_inbound.trusted_proxy_required', 'proxy_protocol_inbound.required_by_trusted_proxy',
  'proxy_protocol_inbound.udp_unsupported', 'proxy_protocol_v1.udp_unsupported',
  'toa.tcp_only', 'toa.proxy_protocol_conflict', 'upstream_follow_port.origins_conflict',
] as const

// 新建弹窗里对应的表单项（源地址类都落在「源地址:端口」一个输入框）。
export const streamErrorFormField: Partial<Record<string, keyof StreamFormValues>> = {
  name: 'name', remark: 'remark',
  upstream_address: 'origin_text', upstream_host: 'origin_text', origins: 'origin_text',
}

export function errorMessage(error: ApiError, t: TFunction<'streams'>): string {
  const combination = error.code === 'validation_error' && error.fieldReason
    ? streamErrorFieldReasons.find((known) => known === `${error.field}.${error.fieldReason}`) : undefined
  if (combination) return t(`errors.fieldReason.${combination.replace('.', '__')}`)
  const field = error.code === 'validation_error' ? streamErrorFields.find((known) => known === error.field) : undefined
  if (field) return t(`errors.field.${field}`)
  const conflict = error.code === 'stream_port_conflict' ? streamPortConflict(error) : undefined
  if (conflict) {
    const ports = conflict.port_end && conflict.port_end > conflict.port ? `${conflict.port}-${conflict.port_end}` : String(conflict.port)
    const name = conflict.name ? t('errors.portConflict.named', { name: conflict.name }) : ''
    return t(`errors.portConflict.${conflict.with}`, { protocol: conflict.protocol.toUpperCase(), ports, name })
  }
  const code = knownStreamErrorCodes.find((known) => known === error.code)
  return code ? t(`errors.${code}`) : localizedUnknownApiError(error, t('errors.operationFailed'))
}

export function emptyDNSPolicy() {
  return {
    positive_min_ttl_seconds: 0,
    positive_max_ttl_seconds: 0,
    negative_ttl_seconds: 0,
    stale_if_error_seconds: 0,
    allow_private_addresses: false,
  }
}

export function defaultDomainDNSPolicy() {
  return {
    positive_min_ttl_seconds: 30,
    positive_max_ttl_seconds: 300,
    negative_ttl_seconds: 60,
    stale_if_error_seconds: 900,
    allow_private_addresses: false,
  }
}

export function emptyGeoPolicy() {
  return {
    enabled: false,
    unknown_region_action: 'allow' as const,
    trusted_proxy_cidrs: [] as string[],
    blocked_regions: [] as string[],
    region_cidrs: [] as StreamGeoRegionCIDRs[],
  }
}

export function splitInput(value: string | undefined): string[] {
  return (value ?? '').split(/[\s,，]+/u).map((item) => item.trim()).filter(Boolean)
}

export function regionCIDRsInput(value: StreamGeoRegionCIDRs[]): string {
  return value.map((item) => `${item.region}=${item.cidrs.join(',')}`).join('\n')
}

export function parseRegionCIDRs(value: string): StreamGeoRegionCIDRs[] {
  return value.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean).map((line) => {
    const separator = line.indexOf('=')
    return {
      region: line.slice(0, separator).trim().toUpperCase(),
      cidrs: splitInput(line.slice(separator + 1)),
    }
  })
}

export function validRegionCIDRs(value: string): boolean {
  const lines = value.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean)
  return lines.length > 0 && lines.every((line) => {
    const separator = line.indexOf('=')
    return separator > 0 && /^[A-Z0-9][A-Z0-9-]{0,31}$/u.test(line.slice(0, separator).trim().toUpperCase()) &&
      splitInput(line.slice(separator + 1)).length > 0
  })
}

export function isDomainName(value: string): boolean {
  const candidate = value.trim()
  if (candidate !== value || candidate === '' || isIPAddress(candidate)) return false
  try {
    const parsed = new URL(`http://${candidate}/`)
    const hostname = parsed.hostname.toLowerCase().replace(/\.$/u, '')
    return parsed.username === '' && parsed.password === '' && parsed.port === '' && parsed.pathname === '/' &&
      parsed.search === '' && parsed.hash === '' && hostname.includes('.') && hostname !== 'localhost' &&
      !hostname.endsWith('.localhost')
  } catch {
    return false
  }
}

// 「监听端口」单行输入：88、99/udp 或 88/tcp，多个端口空格分隔；我方另支持 20000-20010 端口范围。
// 第一项是主监听，其余为附加监听（最多 63 个）。不带协议后缀为 TCP。返回 i18n 键（form.*）表示错误。
export interface ParsedListenPort { protocol: 'tcp' | 'udp'; port: number; port_end?: number }
// 未写 /tcp|/udp 的端口取 defaultProtocol（新建时为「默认设置」的监听协议，L4-DEFAULT-01）。
export function parseListenPorts(text: string | undefined, defaultProtocol: 'tcp' | 'udp' = 'tcp'): { entries: ParsedListenPort[] } | { problem: string } {
  const tokens = (text ?? '').split(/[\s,，、]+/u).filter(Boolean)
  if (tokens.length === 0) return { problem: 'listenPortRequired' }
  if (tokens.length > 64) return { problem: 'listenPortsTooMany' }
  const entries: ParsedListenPort[] = []
  const seen = new Set<string>()
  for (const token of tokens) {
    const match = /^(\d{1,5})(?:-(\d{1,5}))?(?:\/(tcp|udp))?$/iu.exec(token)
    if (!match) return { problem: 'listenPortsInvalid' }
    const port = Number(match[1])
    // L4-004：写了「-结束端口」就是范围，按文本是否存在判断；20000-0 不能被当成单端口 20000。
    const end = match[2] === undefined ? undefined : Number(match[2])
    if (port < 1 || port > 65535) return { problem: 'listenPortRange' }
    if (end !== undefined && (end <= port || end > 65535)) return { problem: 'listenPortEndRange' }
    const protocol = (match[3]?.toLowerCase() ?? defaultProtocol) as 'tcp' | 'udp'
    if (seen.has(`${protocol}:${port}`)) return { problem: 'listenPortsDuplicate' }
    seen.add(`${protocol}:${port}`)
    entries.push({ protocol, port, ...(end !== undefined ? { port_end: end } : {}) })
  }
  return { entries }
}

// 「源地址:端口」单行输入：1.1.1.1:99、www.abc.com:99；IPv6 写成 [2001:db8::1]:99。
// 跟随端口回源时可以不写端口。返回 i18n 键（form.*）表示错误。
export function parseOrigin(text: string | undefined, followPort: boolean):
  { mode: 'address' | 'host'; host: string; port?: number } | { problem: string } {
  const value = (text ?? '').trim()
  if (!value) return { problem: 'originRequired' }
  const bracket = /^\[([^\]]+)\](?::(\d{1,5}))?$/u.exec(value)
  const plain = bracket ? null : /^([^:\s]+)(?::(\d{1,5}))?$/u.exec(value)
  const host = bracket?.[1] ?? plain?.[1]
  const portText = bracket ? bracket[2] : plain?.[2]
  if (!host) return { problem: value.includes(':') ? 'invalidUpstream' : 'originInvalid' }
  const mode = bracket || isIPAddress(host) ? 'address' : 'host'
  if (mode === 'address' && !isIPAddress(host)) return { problem: 'invalidUpstream' }
  if (mode === 'host' && !isDomainName(host)) return { problem: /^[\d.]+$/u.test(host) ? 'invalidUpstream' : 'invalidUpstreamHost' }
  if (!portText) return followPort ? { mode, host } : { problem: 'originPortRequired' }
  const port = Number(portText)
  if (port < 1 || port > 65535) return { problem: 'upstreamPortRange' }
  return { mode, host, port }
}

// 只做 trim + 小写，不去重：重复项交给校验报错。
export function normalizeServerNames(value: readonly string[] | undefined): string[] {
  return (value ?? []).map((name) => name.trim().toLowerCase()).filter(Boolean)
}

export function streamFields(item: Stream): StreamFields {
  return {
    name: item.name,
    remark: item.remark,
    protocol: item.protocol,
    listen_address: item.listen_address,
    listen_port: item.listen_port,
    ...(item.additional_listeners ? { additional_listeners: item.additional_listeners.map((listener) => ({ ...listener })) } : {}),
    upstream_address: item.upstream_address,
    upstream_host: item.upstream_host,
    upstream_port: item.upstream_port,
    dns_policy: item.dns_policy,
    geo_policy: item.geo_policy,
    connect_timeout_ms: item.connect_timeout_ms,
    response_timeout_ms: item.response_timeout_ms,
    max_connections_per_client: item.max_connections_per_client,
    proxy_protocol_inbound: item.proxy_protocol_inbound,
    proxy_protocol_v1: item.proxy_protocol_v1,
    balance_way: item.balance_way,
    enabled: item.enabled,
    tls_passthrough: item.tls_passthrough,
    server_names: [...item.server_names],
    max_new_connections_per_client_per_second: item.max_new_connections_per_client_per_second,
    new_connection_burst: item.new_connection_burst,
    new_connection_ban_seconds: item.new_connection_ban_seconds,
    toa: item.toa,
    session_log_enabled: item.session_log_enabled,
    ...portRangeFields(item.listen_port_end, item.upstream_follow_port),
    ...guardRulesField(item.guard_rules),
    ...originPoolFields(item),
  }
}

// 源站列表 / IPv6开启 / 访问控制：只在用到时出现在请求里（单源站、默认允许无规则时与旧请求体一致）。
export function originPoolFields(item: Pick<Stream, 'origins' | 'listen_ipv6' | 'acl'>): Pick<StreamFields, 'origins' | 'listen_ipv6' | 'acl'> {
  const origins = item.origins ?? []
  const pool = origins.length > 1 || origins.some((origin) => origin.down || origin.weight !== 1)
  const acl = item.acl && (item.acl.default_action === 'deny' || item.acl.rules.length > 0)
  return {
    ...(pool ? { origins: origins.map((origin) => ({ ...origin })) } : {}),
    ...(item.listen_ipv6 ? { listen_ipv6: true } : {}),
    ...(acl ? { acl: { default_action: item.acl.default_action, rules: item.acl.rules.map((rule) => ({ ...rule })) } } : {}),
  }
}

// 批量添加「转发数据」：每行一条，去掉首尾空白与空行。
export function batchLines(text: string | undefined): string[] {
  return (text ?? '').split(/\r?\n/u).map((line) => line.trim()).filter(Boolean)
}

// 源站列显示用：「1.1.1.1 / 端口 88 · 权重 1 · 上线」，单源站也按列表显示。
export function originRows(item: Pick<Stream, 'origins' | 'upstream_address' | 'upstream_host'>): StreamOrigin[] {
  if (item.origins?.length) return item.origins
  const address = item.upstream_host || item.upstream_address
  return address ? [{ address, weight: 1, down: false }] : []
}

// 端口范围 / 跟随端口回源：未使用时不出现在请求里（与旧请求体逐字节一致）。
export function portRangeFields(listenPortEnd: number | null | undefined, followPort: boolean | undefined): Pick<StreamFields, 'listen_port_end' | 'upstream_follow_port'> {
  return {
    ...(listenPortEnd ? { listen_port_end: listenPortEnd } : {}),
    ...(followPort ? { upstream_follow_port: true } : {}),
  }
}

// 端口显示：范围为“起始-结束”。
export function portLabel(port: number, end?: number | null): string {
  return end && end > port ? `${port}-${end}` : String(port)
}

// 节点自身端口，端口范围不能覆盖（edgeconfig.L4RangeProtectedPorts）。
export const streamRangeProtectedPorts = [80, 443, 18080, 18443] as const

// 端口范围校验：返回 i18n 键（form.*），合法时返回 null。
export function portRangeProblem(port: number | null | undefined, end: number | null | undefined, tlsPassthrough: boolean): string | null {
  if (!end) return null
  if (!port || !Number.isInteger(end) || end <= port || end > 65535) return 'listenPortEndRange'
  if (end - port >= 1000) return 'listenPortEndTooMany'
  if (streamRangeProtectedPorts.some((protected_) => protected_ >= port && protected_ <= end)) return 'listenPortEndProtected'
  if (tlsPassthrough) return 'listenPortEndTLSPassthrough'
  return null
}

export function streamFormFields(values: StreamFormValues): StreamFields {
  const domainUpstream = values.upstream_mode === 'host'
  const geoPolicyValues = values.geo_policy ?? emptyGeoPolicy()
  const geoEnabled = Boolean(geoPolicyValues.enabled)
  const geoPolicy = geoEnabled ? {
    enabled: true,
    unknown_region_action: geoPolicyValues.unknown_region_action,
    trusted_proxy_cidrs: splitInput(values.geo_trusted_proxy_cidrs),
    blocked_regions: splitInput(values.geo_blocked_regions).map((region) => region.toUpperCase()),
    region_cidrs: parseRegionCIDRs(values.geo_region_cidrs),
  } : emptyGeoPolicy()
  const hasUDP = values.protocol === 'udp' || values.additional_listeners?.some((listener) => listener.protocol === 'udp')
  if (hasUDP) geoPolicy.trusted_proxy_cidrs = []
  return {
    name: values.name?.trim() || `${values.protocol.toUpperCase()} ${values.listen_port}`,
    remark: values.remark.trim(),
    protocol: values.protocol,
    listen_address: '*',
    listen_port: values.listen_port,
    ...(values.additional_listeners ? { additional_listeners: values.additional_listeners.map((listener) => ({ ...listener })) } : {}),
    upstream_address: domainUpstream ? '' : values.upstream_address.trim(),
    upstream_host: domainUpstream ? values.upstream_host.trim() : '',
    upstream_port: values.upstream_follow_port ? values.listen_port : values.upstream_port,
    dns_policy: domainUpstream ? { ...(values.dns_policy ?? defaultDomainDNSPolicy()), allow_private_addresses: false } : emptyDNSPolicy(),
    geo_policy: geoPolicy,
    connect_timeout_ms: values.connect_timeout_ms,
    response_timeout_ms: values.response_timeout_ms,
    max_connections_per_client: values.max_connections_per_client,
    proxy_protocol_inbound: !hasUDP && geoEnabled && Boolean(values.proxy_protocol_inbound),
    // 回源携带客户端 IP 三选一：TOA 与 PROXY（入站/出站）互斥，均只用于 TCP。
    proxy_protocol_v1: !hasUDP && !values.toa && Boolean(values.proxy_protocol_v1),
    toa: !hasUDP && !(geoEnabled && values.proxy_protocol_inbound) && Boolean(values.toa),
    balance_way: values.balance_way ?? 'rr',
    enabled: values.enabled ?? true,
    tls_passthrough: Boolean(values.tls_passthrough),
    server_names: values.tls_passthrough ? normalizeServerNames(values.server_names) : [],
    ...newConnectionRateFields(values),
    session_log_enabled: Boolean(values.session_log_enabled),
    ...portRangeFields(values.listen_port_end, values.upstream_follow_port),
    // 编辑行未挂载（新建抽屉）时沿用已有规则。
    ...guardRulesField(values.guard_rule_rows ? guardRulesFromRows(values.guard_rule_rows, Boolean(values.tls_passthrough)) : values.guard_rules),
  }
}

// Unlimited (0) carries no burst or ban, as the server requires.
function newConnectionRateFields(values: StreamFormValues) {
  const rate = values.max_new_connections_per_client_per_second ?? 0
  return {
    max_new_connections_per_client_per_second: rate,
    new_connection_burst: rate > 0 ? values.new_connection_burst ?? 0 : 0,
    new_connection_ban_seconds: rate > 0 ? values.new_connection_ban_seconds ?? 0 : 0,
  }
}
