import { useMemo, useState } from 'react'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Checkbox,
  Form,
  Input,
  Modal,
  Popconfirm,
  Radio,
  Select,
  Space,
  Table,
  Tag,
  type FormInstance,
} from 'antd'
import { Plus, Trash2 } from 'lucide-react'
import type { TFunction } from 'i18next'

import type {
  DefaultConfiguration,
  NginxConfiguration,
  ScopedDefaultOverride,
  ScopedNginxOverride,
} from '../../api/systemConfiguration'
import { nodesApi, regionsApi, type NodeInventoryItem, type RegionRecord } from '../../api/nodes'
import { useSessionStore } from '../../auth/session'
import {
  formatByteSize,
  formatDuration,
  formatHeaderBuffers,
  parseByteSize,
  parseDuration,
  parseHeaderBuffers,
} from './nginxDirectiveValues'

export type SystemConfigurationFormValues = {
  nginx?: NginxConfiguration
  defaults?: DefaultConfiguration
}

type EditableCategory = keyof SystemConfigurationFormValues
type AnyOverride = ScopedNginxOverride | ScopedDefaultOverride
type ScopeKind = 'region' | 'node'
type SettingKind =
  | 'number'
  | 'boolean'
  | 'text'
  | 'select'
  | 'multi'
  | 'string-list'
  | 'byte-size'
  | 'duration'
  | 'header-buffers'
type Path = readonly string[]

type SettingDefinition = {
  key: string
  labelKey: string
  kind: SettingKind
  overridePath: Path
  sourcePath: Path
  minimum?: number
  maximum?: number
  options?: readonly string[]
  booleanLabels?: 'onOff' | 'yesNo'
  presentation?: 'radio' | 'checkboxes'
  seed?: { overridePath: Path; sourcePath: Path }
  /** nginx 指令名，作为中文名称的副标题显示（例如「工作进程数（worker_processes）」）。 */
  directive?: string
  /** 与服务端 validateNginxCore 一致的额外校验，返回 false 即“设置值无效”。 */
  accept?: (value: unknown) => boolean
}

// 与 services/control-api/internal/systemconfig/schema.go 的校验保持一致。
const powerOfTwo = (value: unknown) => typeof value === 'number' && value > 0 && (value & (value - 1)) === 0
const serverHeaderPattern = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/u
const mimeTypePattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+\/[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u

type EditorDraft = {
  index: number | null
  scope: ScopeKind
  scopeId: string
  settingKeys: string[]
  values: Record<string, unknown>
}

type OverrideTableRow = {
  key: string
  index: number
  item: AnyOverride
}

type OverridesEditorProps = {
  category: EditableCategory
  form: FormInstance<SystemConfigurationFormValues>
  t: TFunction<'systemSettings'>
  editable: boolean
  onChange: () => void
}

const proxyNextUpstreamOptions = [
  'error', 'timeout', 'invalid_header', 'http_500', 'http_502', 'http_503', 'http_504',
  'http_403', 'http_404', 'http_429', 'non_idempotent', 'off',
] as const

const nginxSettings: readonly SettingDefinition[] = [
  { key: 'worker.worker_rlimit_nofile', directive: 'worker_rlimit_nofile', labelKey: 'parity.overrides.nginx.settings.workerRlimit', kind: 'number', overridePath: ['worker', 'worker_rlimit_nofile'], sourcePath: ['worker', 'worker_rlimit_nofile'], minimum: 1_024, maximum: 1_048_576 },
  { key: 'worker.worker_shutdown_timeout_ms', directive: 'worker_shutdown_timeout', labelKey: 'parity.overrides.nginx.settings.workerShutdown', kind: 'duration', overridePath: ['worker', 'worker_shutdown_timeout_ms'], sourcePath: ['worker', 'worker_shutdown_timeout_ms'], minimum: 1_000, maximum: 300_000 },
  { key: 'worker.worker_connections', directive: 'worker_connections', labelKey: 'parity.overrides.nginx.settings.workerConnections', kind: 'number', overridePath: ['worker', 'worker_connections'], sourcePath: ['worker', 'worker_connections'], minimum: 128, maximum: 1_048_576 },
  { key: 'worker.worker_processes', directive: 'worker_processes', labelKey: 'parity.overrides.nginx.settings.workerProcesses', kind: 'number', overridePath: ['worker', 'worker_processes'], sourcePath: ['worker', 'worker_processes'], minimum: 0, maximum: 256 },
  { key: 'http.gzip_comp_level', directive: 'gzip_comp_level', labelKey: 'parity.overrides.nginx.settings.gzipLevel', kind: 'number', overridePath: ['http', 'gzip_comp_level'], sourcePath: ['http', 'gzip_comp_level'], minimum: 1, maximum: 9 },
  { key: 'http.gzip_http_version', directive: 'gzip_http_version', labelKey: 'parity.overrides.nginx.settings.gzipHttpVersion', kind: 'select', overridePath: ['http', 'gzip_http_version'], sourcePath: ['http', 'gzip_http_version'], options: ['1.0', '1.1'], presentation: 'radio' },
  { key: 'http.gzip_min_length_bytes', directive: 'gzip_min_length', labelKey: 'parity.overrides.nginx.settings.gzipMinLength', kind: 'byte-size', overridePath: ['http', 'gzip_min_length_bytes'], sourcePath: ['http', 'gzip_min_length_bytes'], minimum: 0, maximum: 2 ** 30 },
  { key: 'http.gzip_vary', directive: 'gzip_vary', labelKey: 'parity.overrides.nginx.settings.gzipVary', kind: 'boolean', overridePath: ['http', 'gzip_vary'], sourcePath: ['http', 'gzip_vary'], booleanLabels: 'onOff' },
  { key: 'http.server_addr_outgoing', labelKey: 'parity.overrides.nginx.settings.entryOrigin', kind: 'boolean', overridePath: ['http', 'server_addr_outgoing'], sourcePath: ['http', 'server_addr_outgoing'] },
  { key: 'http.proxy_request_buffering', directive: 'proxy_request_buffering', labelKey: 'parity.overrides.nginx.settings.proxyRequestBuffering', kind: 'boolean', overridePath: ['http', 'proxy_request_buffering'], sourcePath: ['http', 'proxy_request_buffering'], booleanLabels: 'onOff' },
  { key: 'http.proxy_buffering', directive: 'proxy_buffering', labelKey: 'parity.overrides.nginx.settings.proxyBuffering', kind: 'boolean', overridePath: ['http', 'proxy_buffering'], sourcePath: ['http', 'proxy_buffering'], booleanLabels: 'onOff' },
  { key: 'http.proxy_cache_max_size_bytes', directive: 'proxy_cache_max_size', labelKey: 'parity.overrides.nginx.settings.cacheMaxSize', kind: 'byte-size', overridePath: ['http', 'proxy_cache_max_size_bytes'], sourcePath: ['http', 'proxy_cache_max_size_bytes'], minimum: 0, maximum: 2 ** 50 },
  { key: 'http.proxy_cache_min_free_bytes', directive: 'min_free', labelKey: 'parity.overrides.nginx.settings.cacheMinFree', kind: 'byte-size', overridePath: ['http', 'proxy_cache_min_free_bytes'], sourcePath: ['http', 'proxy_cache_min_free_bytes'], minimum: 0, maximum: 16 * 2 ** 40, accept: (value) => typeof value === 'number' && value % 2 ** 20 === 0 },
  { key: 'http.proxy_cache_methods', directive: 'proxy_cache_methods', labelKey: 'parity.overrides.nginx.settings.cacheMethods', kind: 'multi', overridePath: ['http', 'proxy_cache_methods'], sourcePath: ['http', 'proxy_cache_methods'], options: ['GET', 'HEAD'], presentation: 'checkboxes' },
  { key: 'http.proxy_http_version', directive: 'proxy_http_version', labelKey: 'parity.overrides.nginx.settings.proxyHttpVersion', kind: 'select', overridePath: ['http', 'proxy_http_version'], sourcePath: ['http', 'proxy_http_version'], options: ['1.0', '1.1'], presentation: 'radio' },
  { key: 'http.proxy_max_temp_file_size_bytes', directive: 'proxy_max_temp_file_size', labelKey: 'parity.overrides.nginx.settings.proxyMaxTempFileSize', kind: 'byte-size', overridePath: ['http', 'proxy_max_temp_file_size_bytes'], sourcePath: ['http', 'proxy_max_temp_file_size_bytes'], minimum: 0, maximum: 2 ** 40 },
  { key: 'http.proxy_next_upstream', directive: 'proxy_next_upstream', labelKey: 'parity.overrides.nginx.settings.proxyNextUpstream', kind: 'multi', overridePath: ['http', 'proxy_next_upstream'], sourcePath: ['http', 'proxy_next_upstream'], options: proxyNextUpstreamOptions, accept: (value) => !Array.isArray(value) || !value.includes('off') || value.length === 1 },
  { key: 'http.proxy_connect_timeout_ms', directive: 'proxy_connect_timeout', labelKey: 'parity.overrides.nginx.settings.proxyConnectTimeout', kind: 'duration', overridePath: ['http', 'proxy_connect_timeout_ms'], sourcePath: ['http', 'proxy_connect_timeout_ms'], minimum: 100, maximum: 75_000 },
  { key: 'http.proxy_send_timeout_ms', directive: 'proxy_send_timeout', labelKey: 'parity.overrides.nginx.settings.proxySendTimeout', kind: 'duration', overridePath: ['http', 'proxy_send_timeout_ms'], sourcePath: ['http', 'proxy_send_timeout_ms'], minimum: 100, maximum: 3_600_000 },
  { key: 'http.proxy_read_timeout_ms', directive: 'proxy_read_timeout', labelKey: 'parity.overrides.nginx.settings.proxyReadTimeout', kind: 'duration', overridePath: ['http', 'proxy_read_timeout_ms'], sourcePath: ['http', 'proxy_read_timeout_ms'], minimum: 100, maximum: 3_600_000 },
  { key: 'http.server', directive: 'server', labelKey: 'parity.overrides.nginx.settings.serverHeader', kind: 'text', overridePath: ['http', 'server'], sourcePath: ['http', 'server'], accept: (value) => typeof value === 'string' && serverHeaderPattern.test(value) },
  { key: 'http.client_max_body_size_bytes', directive: 'client_max_body_size', labelKey: 'parity.overrides.nginx.settings.clientMaxBodySize', kind: 'byte-size', overridePath: ['http', 'client_max_body_size_bytes'], sourcePath: ['http', 'client_max_body_size_bytes'], minimum: 1_024, maximum: 10 * 2 ** 30 },
  { key: 'http.default_type', directive: 'default_type', labelKey: 'parity.overrides.nginx.settings.defaultType', kind: 'text', overridePath: ['http', 'default_type'], sourcePath: ['http', 'default_type'], accept: (value) => typeof value === 'string' && value.length <= 128 && mimeTypePattern.test(value) },
  { key: 'http.keepalive_requests', directive: 'keepalive_requests', labelKey: 'parity.overrides.nginx.settings.keepaliveRequests', kind: 'number', overridePath: ['http', 'keepalive_requests'], sourcePath: ['http', 'keepalive_requests'], minimum: 1, maximum: 1_000_000 },
  { key: 'http.keepalive_timeout_ms', directive: 'keepalive_timeout', labelKey: 'parity.overrides.nginx.settings.keepaliveTimeout', kind: 'duration', overridePath: ['http', 'keepalive_timeout_ms'], sourcePath: ['http', 'keepalive_timeout_ms'], minimum: 100, maximum: 3_600_000 },
  { key: 'http.log_not_found', directive: 'log_not_found', labelKey: 'parity.overrides.nginx.settings.logNotFound', kind: 'boolean', overridePath: ['http', 'log_not_found'], sourcePath: ['http', 'log_not_found'], booleanLabels: 'onOff' },
  { key: 'http.server_tokens', directive: 'server_tokens', labelKey: 'parity.overrides.nginx.settings.serverTokens', kind: 'boolean', overridePath: ['http', 'server_tokens'], sourcePath: ['http', 'server_tokens'], booleanLabels: 'onOff' },
  { key: 'http.large_client_header_buffers', directive: 'large_client_header_buffers', labelKey: 'parity.overrides.nginx.settings.largeClientHeaderBuffers', kind: 'header-buffers', overridePath: ['http', 'large_client_header_buffers'], sourcePath: ['http', 'large_client_header_buffers'], accept: (value) => isRecord(value) && Number(value.count) <= 32 && Number(value.size_bytes) >= 1_024 },
  { key: 'http.server_names_hash_max_size', directive: 'server_names_hash_max_size', labelKey: 'parity.overrides.nginx.settings.serverNamesHashMaxSize', kind: 'number', overridePath: ['http', 'server_names_hash_max_size'], sourcePath: ['http', 'server_names_hash_max_size'], minimum: 512, maximum: 65_536, accept: powerOfTwo },
  { key: 'http.server_names_hash_bucket_size', directive: 'server_names_hash_bucket_size', labelKey: 'parity.overrides.nginx.settings.serverNamesHashBucketSize', kind: 'number', overridePath: ['http', 'server_names_hash_bucket_size'], sourcePath: ['http', 'server_names_hash_bucket_size'], minimum: 32, maximum: 1_024, accept: powerOfTwo },
]

const otherSeed = { overridePath: ['website', 'other'], sourcePath: ['website', 'other'] } as const

// 区域覆盖只保留节点按节点渲染的项：默认配置里只有 GZIP 开关与压缩类型；
// 监听端口、HSTS、回源、证书等在建站/建转发/签证书时取值，站点没有唯一区域，服务端一律拒绝。
const defaultSettings: readonly SettingDefinition[] = [
  { key: 'website.other.gzip_enabled', labelKey: 'parity.overrides.defaults.settings.gzip', kind: 'boolean', overridePath: ['website', 'other', 'gzip_enabled'], sourcePath: ['website', 'other', 'gzip_enabled'], seed: otherSeed },
  { key: 'website.other.gzip_types', labelKey: 'parity.overrides.defaults.settings.gzipTypes', kind: 'string-list', overridePath: ['website', 'other', 'gzip_types'], sourcePath: ['website', 'other', 'gzip_types'], seed: otherSeed },
]

const settingsByCategory: Record<EditableCategory, readonly SettingDefinition[]> = {
  nginx: nginxSettings,
  defaults: defaultSettings,
}

function cloneValue<T>(value: T): T {
  return typeof structuredClone === 'function'
    ? structuredClone(value)
    : JSON.parse(JSON.stringify(value)) as T
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function getPath(value: unknown, path: Path): unknown {
  let current = value
  for (const segment of path) {
    if (!isRecord(current) || !(segment in current)) return undefined
    current = current[segment]
  }
  return current
}

function setPath(target: Record<string, unknown>, path: Path, value: unknown): void {
  let current = target
  path.forEach((segment, index) => {
    if (index === path.length - 1) {
      current[segment] = value
      return
    }
    const next = current[segment]
    if (!isRecord(next)) current[segment] = {}
    current = current[segment] as Record<string, unknown>
  })
}

function parseStringList(value: string, options?: readonly string[]): string[] | null {
  const parsed = [...new Set(value.split(/[\s,]+/u).map((item) => item.trim()).filter(Boolean))]
  if (parsed.length === 0 || options && parsed.some((item) => !options.includes(item))) return null
  return parsed
}

function draftValue(definition: SettingDefinition, value: unknown): unknown {
  if (definition.key === 'worker.worker_processes' && value === 0) return 'auto'
  if (definition.kind === 'string-list') return Array.isArray(value) ? value.join(' ') : ''
  if (definition.kind === 'byte-size') return typeof value === 'number' ? formatByteSize(value) : ''
  if (definition.kind === 'duration') return typeof value === 'number' ? formatDuration(value) : ''
  if (definition.kind === 'header-buffers' && isRecord(value) && typeof value.count === 'number' && typeof value.size_bytes === 'number') {
    return formatHeaderBuffers({ count: value.count, size_bytes: value.size_bytes })
  }
  return cloneValue(value)
}

function parseDraftValue(definition: SettingDefinition, value: unknown): unknown {
  switch (definition.kind) {
    case 'number': {
      if (definition.key === 'worker.worker_processes' && String(value).trim().toLowerCase() === 'auto') return 0
      const number = typeof value === 'number' ? value : Number(value)
      if (!Number.isSafeInteger(number) || number < (definition.minimum ?? Number.MIN_SAFE_INTEGER) || number > (definition.maximum ?? Number.MAX_SAFE_INTEGER)) throw new Error('invalid')
      return number
    }
    case 'boolean':
      if (typeof value !== 'boolean') throw new Error('invalid')
      return value
    case 'text':
      if (typeof value !== 'string' || !value.trim()) throw new Error('invalid')
      return value.trim()
    case 'select':
      if (typeof value !== 'string' || !definition.options?.includes(value)) throw new Error('invalid')
      return value
    case 'multi':
      if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== 'string' || !definition.options?.includes(item))) throw new Error('invalid')
      return value
    case 'string-list': {
      const parsed = parseStringList(String(value ?? ''), definition.options)
      if (!parsed) throw new Error('invalid')
      return parsed
    }
    case 'byte-size': {
      const parsed = parseByteSize(String(value ?? ''), definition.minimum, definition.maximum)
      if (parsed === null) throw new Error('invalid')
      return parsed
    }
    case 'duration': {
      const parsed = parseDuration(String(value ?? ''), definition.minimum, definition.maximum)
      if (parsed === null) throw new Error('invalid')
      return parsed
    }
    case 'header-buffers': {
      const parsed = parseHeaderBuffers(String(value ?? ''))
      if (!parsed) throw new Error('invalid')
      return parsed
    }
  }
}

/** 中文名称；有 nginx 指令名时作副标题：「工作进程数（worker_processes）」。 */
function settingLabel(definition: SettingDefinition, t: TFunction<'systemSettings'>): string {
  const name = t(definition.labelKey)
  return definition.directive ? t('parity.overrides.settingWithDirective', { name, directive: definition.directive, interpolation: { escapeValue: false } }) : name
}

function settingHelp(definition: SettingDefinition, t: TFunction<'systemSettings'>): string | null {
  if (!definition.labelKey.startsWith('parity.overrides.nginx.settings.')) return null
  return t(definition.labelKey.replace('.settings.', '.help.'))
}

const targetPageSize = 20

function nodeLabel(node: Pick<NodeInventoryItem, 'name' | 'display_id' | 'ipv4' | 'ipv6'>): string {
  const address = node.ipv4 ?? node.ipv6
  return `${node.name}${address ? ` (${address})` : ''} #${node.display_id}`
}

function useTargetDirectory(scope: ScopeKind | null, search: string) {
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const query = search.trim()
  // 节点：本主控（平台作用域）的节点清单，服务端按 nodes.scope_id 过滤，搜索匹配名称、区域、ID、IP。
  const nodes = useInfiniteQuery({
    queryKey: ['configuration-override-targets', sessionEpoch, 'node', query],
    enabled: Boolean(accessToken && scope === 'node'),
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => nodesApi.list(accessToken!, { limit: targetPageSize, search: query || undefined, cursor: pageParam }),
    getNextPageParam: (last) => last.next_cursor,
    retry: false,
  })
  // 区域：与节点管理 > 区域管理同一个区域目录（region_catalog），值为区域 ID。
  const regions = useInfiniteQuery({
    queryKey: ['configuration-override-targets', sessionEpoch, 'region', query],
    enabled: Boolean(accessToken && scope === 'region'),
    initialPageParam: 1,
    queryFn: ({ pageParam }) => regionsApi.list(accessToken!, { page: pageParam, page_size: targetPageSize, search: query || undefined }),
    getNextPageParam: (last, pages) => pages.length * targetPageSize < last.count ? pages.length + 1 : undefined,
    retry: false,
  })
  const active = scope === 'node' ? nodes : regions
  const options = scope === 'node'
    ? (nodes.data?.pages.flatMap((page) => page.items) ?? [])
        // 已退役节点不能作为覆盖目标（服务端 configurationReferencesAvailable 拒绝）。
        .filter((node) => node.admin_state !== 'retired')
        .map((node) => ({ value: node.id, label: nodeLabel(node) }))
    : (regions.data?.pages.flatMap((page) => page.data) ?? []).map((region: RegionRecord) => ({ value: region.id, label: region.name }))
  return {
    options,
    loading: active.isFetching,
    error: active.isError,
    hasMore: Boolean(active.hasNextPage),
    loadMore: () => { if (active.hasNextPage && !active.isFetchingNextPage) void active.fetchNextPage() },
  }
}

/** 表格里把节点 UUID / 区域 ID 显示成名称；取不到时原样显示。 */
function useTargetNames(enabled: boolean) {
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  return useQuery({
    queryKey: ['configuration-override-target-names', sessionEpoch],
    enabled: Boolean(accessToken && enabled),
    queryFn: async () => {
      const names = new Map<string, string>()
      const [nodes, regions] = await Promise.allSettled([
        nodesApi.list(accessToken!, { limit: 100 }),
        regionsApi.list(accessToken!, { page: 1, page_size: 300 }),
      ])
      if (nodes.status === 'fulfilled') for (const node of nodes.value.items) names.set(`node:${node.id}`, nodeLabel(node))
      if (regions.status === 'fulfilled') for (const region of regions.value.data) names.set(`region:${region.id}`, region.name)
      return names
    },
    retry: false,
  })
}

function settingDefinitionsForOverride(category: EditableCategory, values: unknown): SettingDefinition[] {
  return settingsByCategory[category].filter((definition) => getPath(values, definition.overridePath) !== undefined)
}

function settingValueText(definition: SettingDefinition, value: unknown, t: TFunction<'systemSettings'>): string {
  if (definition.kind === 'boolean') {
    const labels = definition.booleanLabels === 'onOff' ? ['parity.overrides.on', 'parity.overrides.off'] : ['parity.overrides.yes', 'parity.overrides.no']
    return t(value ? labels[0] : labels[1])
  }
  if (definition.kind === 'multi') return Array.isArray(value) ? value.join(', ') : ''
  if (definition.kind === 'string-list') return Array.isArray(value) ? value.join(' ') : ''
  if (definition.kind === 'byte-size' && typeof value === 'number') return formatByteSize(value)
  if (definition.kind === 'duration' && typeof value === 'number') return formatDuration(value)
  if (definition.kind === 'header-buffers' && isRecord(value) && typeof value.count === 'number' && typeof value.size_bytes === 'number') {
    return formatHeaderBuffers({ count: value.count, size_bytes: value.size_bytes })
  }
  if (value === null || value === '') return t('parity.overrides.closed')
  if (definition.key === 'worker.worker_processes' && value === 0) return 'auto'
  return String(value)
}

function SettingsTags({ category, values, t }: { category: EditableCategory; values: unknown; t: TFunction<'systemSettings'> }) {
  const definitions = settingDefinitionsForOverride(category, values)
  return <Space size={[4, 4]} wrap>{definitions.map((definition) => <Tag key={definition.key}>{settingLabel(definition, t)}</Tag>)}</Space>
}

function SettingsValues({ category, values, t }: { category: EditableCategory; values: unknown; t: TFunction<'systemSettings'> }) {
  const definitions = settingDefinitionsForOverride(category, values)
  return <div className="configuration-overrides-values">{definitions.map((definition) => <span key={definition.key}>{settingValueText(definition, getPath(values, definition.overridePath), t)}</span>)}</div>
}

function SettingValueControl({ definition, value, onChange, onRemove, t }: {
  definition: SettingDefinition
  value: unknown
  onChange: (value: unknown) => void
  onRemove: () => void
  t: TFunction<'systemSettings'>
}) {
  const label = settingLabel(definition, t)
  const help = settingHelp(definition, t)
  const options = definition.options?.map((item) => ({ value: item, label: item })) ?? []
  let control
  switch (definition.kind) {
    case 'number':
      control = <Input aria-label={label} inputMode="numeric" value={typeof value === 'string' || typeof value === 'number' ? value : ''} onChange={(event) => onChange(event.target.value)} />
      break
    case 'boolean': {
      const labels = definition.booleanLabels === 'onOff'
        ? [{ value: true, label: t('parity.overrides.on') }, { value: false, label: t('parity.overrides.off') }]
        : [{ value: true, label: t('parity.overrides.yes') }, { value: false, label: t('parity.overrides.no') }]
      control = <Radio.Group aria-label={label} value={Boolean(value)} options={labels} onChange={(event) => onChange(event.target.value as boolean)} />
      break
    }
    case 'select':
      if (definition.presentation === 'radio') {
        control = <Radio.Group aria-label={label} value={value} options={options} onChange={(event) => onChange(event.target.value)} />
      } else {
        control = <Select aria-label={label} value={typeof value === 'string' ? value : undefined} options={options} virtual={false} classNames={{ popup: { root: 'configuration-select-popup' } }} onChange={onChange} />
      }
      break
    case 'multi':
      control = definition.presentation === 'checkboxes'
        ? <Checkbox.Group aria-label={label} value={Array.isArray(value) ? value as string[] : []} options={options} onChange={onChange} />
        : <Select aria-label={label} mode="multiple" value={Array.isArray(value) ? value as string[] : []} options={options} virtual={false} tokenSeparators={[',', ' ']} classNames={{ popup: { root: 'configuration-select-popup' } }} onChange={onChange} />
      break
    default:
      control = <Input aria-label={label} value={typeof value === 'string' ? value : ''} onChange={(event) => onChange(event.target.value)} />
  }
  return <div className="configuration-override-value-field configuration-override-modal-row">
    <label>
      <span>{t(definition.labelKey)}：</span>
      {definition.directive ? <span className="configuration-override-directive">{definition.directive}</span> : null}
    </label>
    <div className="configuration-override-modal-control">
      {control}
      {help ? <div className="configuration-override-help">{help}</div> : null}
    </div>
    <Button className="configuration-override-remove" type="text" danger icon={<Trash2 size={15} />} aria-label={t('parity.overrides.removeSetting', { setting: label })} onClick={onRemove} />
  </div>
}
export default function ConfigurationOverridesEditor({ category, form, t, editable, onChange }: OverridesEditorProps) {
  const settings = settingsByCategory[category]
  const [draft, setDraft] = useState<EditorDraft | null>(null)
  const [editorError, setEditorError] = useState('')
  const [targetQuery, setTargetQuery] = useState('')
  const watched = Form.useWatch([category, 'overrides'], { form, preserve: true }) as AnyOverride[] | undefined
  const rows = useMemo<OverrideTableRow[]>(() => (watched ?? []).map((item, index) => ({ key: item.id, index, item })), [watched])
  const directory = useTargetDirectory(draft?.scope ?? null, targetQuery)
  const targetNames = useTargetNames(rows.length > 0 || Boolean(draft))
  const targetName = (scope: ScopeKind, id: string) => targetNames.data?.get(`${scope}:${id}`)
  const targetOptions = [...directory.options]
  // 编辑已有记录时，目标可能不在当前搜索页里：补一条，名称取不到则标“已不存在”。
  if (draft?.scopeId && !targetOptions.some((item) => item.value === draft.scopeId)) {
    targetOptions.unshift({ value: draft.scopeId, label: targetName(draft.scope, draft.scopeId) ?? t('parity.overrides.targetUnknown', { id: draft.scopeId }) })
  }

  const openEditor = (row?: OverrideTableRow) => {
    const source = form.getFieldValue(category)
    if (!row) {
      setDraft({ index: null, scope: category === 'nginx' ? 'node' : 'region', scopeId: '', settingKeys: [], values: {} })
      setTargetQuery('')
      setEditorError('')
      return
    }
    const selected = settingDefinitionsForOverride(category, row.item.values)
    setDraft({
      index: row.index,
      scope: row.item.scope,
      scopeId: row.item.scope_id,
      settingKeys: selected.map((definition) => definition.key),
      values: Object.fromEntries(selected.map((definition) => [
        definition.key,
        draftValue(definition, getPath(row.item.values, definition.overridePath) ?? getPath(source, definition.sourcePath)),
      ])),
    })
    setTargetQuery('')
    setEditorError('')
  }

  const updateSettingKeys = (settingKeys: string[]) => {
    if (!draft) return
    const source = form.getFieldValue(category)
    const values = { ...draft.values }
    for (const key of Object.keys(values)) if (!settingKeys.includes(key)) delete values[key]
    for (const key of settingKeys) {
      if (key in values) continue
      const definition = settings.find((item) => item.key === key)
      if (definition) values[key] = draftValue(definition, getPath(source, definition.sourcePath))
    }
    setDraft({ ...draft, settingKeys, values })
    setEditorError('')
  }

  const commit = () => {
    if (!draft) return
    const scopeId = draft.scopeId.trim()
    if (!scopeId || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u.test(scopeId)) {
      setEditorError(t('parity.overrides.validation.target'))
      return
    }
    if (draft.settingKeys.length === 0) {
      setEditorError(t('parity.overrides.validation.setting'))
      return
    }
    const definitions = draft.settingKeys.map((key) => settings.find((item) => item.key === key)).filter((item): item is SettingDefinition => Boolean(item))
    const duplicate = rows.some((row) => row.index !== draft.index && row.item.scope === draft.scope && row.item.scope_id === scopeId)
    if (duplicate) {
      setEditorError(t('parity.overrides.validation.duplicate'))
      return
    }
    const source = form.getFieldValue(category)
    const values: Record<string, unknown> = {}
    try {
      for (const definition of definitions) {
        if (definition.seed && getPath(values, definition.seed.overridePath) === undefined) {
          setPath(values, definition.seed.overridePath, cloneValue(getPath(source, definition.seed.sourcePath)))
        }
        const parsed = parseDraftValue(definition, draft.values[definition.key])
        if (definition.accept && !definition.accept(parsed)) throw new Error('invalid')
        setPath(values, definition.overridePath, parsed)
      }
    } catch {
      setEditorError(t('parity.overrides.validation.value'))
      return
    }
    const current = [...(form.getFieldValue([category, 'overrides']) as AnyOverride[] | undefined ?? [])]
    const item = {
      id: draft.index === null ? `${category.slice(0, 7)}_${Date.now().toString(36)}` : current[draft.index].id,
      scope: draft.scope,
      scope_id: scopeId,
      values,
    } as AnyOverride
    if (draft.index === null) current.push(item)
    else current[draft.index] = item
    form.setFieldValue([category, 'overrides'], current)
    onChange()
    setDraft(null)
    setTargetQuery('')
    setEditorError('')
  }

  const remove = (row: OverrideTableRow) => {
    const current = [...(form.getFieldValue([category, 'overrides']) as AnyOverride[] | undefined ?? [])]
    current.splice(row.index, 1)
    form.setFieldValue([category, 'overrides'], current)
    onChange()
  }

  const actionsColumn = {
    title: t('parity.overrides.actions'),
    key: 'actions',
    width: category === 'nginx' ? 277 : 233,
    render: (_value: unknown, row: OverrideTableRow) => editable ? <Space size={4}>
      <Button type="link" size="small" onClick={() => openEditor(row)}>{t('parity.overrides.edit')}</Button>
      <Popconfirm title={t('parity.overrides.deleteConfirm')} okText={t('parity.overrides.confirm')} cancelText={t('parity.overrides.cancel')} onConfirm={() => remove(row)}>
        <Button type="link" size="small" danger>{t('actions.delete')}</Button>
      </Popconfirm>
    </Space> : null,
  }

  const settingLabelKey = category === 'nginx' ? 'parity.overrides.setting' : 'parity.overrides.settingItem'
  const valueLabelKey = category === 'nginx' ? 'parity.overrides.value' : 'parity.overrides.valueItem'
  const settingPlaceholderKey = category === 'nginx' ? 'parity.overrides.settingPlaceholder' : 'parity.overrides.settingItemPlaceholder'

  const columns = category === 'nginx' ? [
    {
      title: t('parity.overrides.scope'),
      key: 'scope',
      width: 336,
      render: (_value: unknown, row: OverrideTableRow) => <div className="configuration-overrides-scope"><strong>{t(`parity.overrides.${row.item.scope}`)}</strong><span>{targetName(row.item.scope, row.item.scope_id) ?? row.item.scope_id}</span></div>,
    },
    { title: t('parity.overrides.setting'), key: 'setting', width: 417, render: (_value: unknown, row: OverrideTableRow) => <SettingsTags category={category} values={row.item.values} t={t} /> },
    actionsColumn,
  ] : [
    { title: t('parity.overrides.region'), key: 'region', width: 232, render: (_value: unknown, row: OverrideTableRow) => targetName('region', row.item.scope_id) ?? row.item.scope_id },
    { title: t(settingLabelKey), key: 'setting', width: 282, render: (_value: unknown, row: OverrideTableRow) => <SettingsTags category={category} values={row.item.values} t={t} /> },
    { title: t(valueLabelKey), key: 'value', width: 283, render: (_value: unknown, row: OverrideTableRow) => <SettingsValues category={category} values={row.item.values} t={t} /> },
    actionsColumn,
  ]

  const introKey = category === 'nginx' ? 'nginx' : null
  return <div className={`configuration-overrides-panel configuration-overrides-panel--${category}`}>
    {introKey ? <div className="configuration-overrides-heading">
      <div className="configuration-section-intro">
        <h2>{t(`parity.overrides.${introKey}.title`)}</h2>
        <p>{t(`parity.overrides.${introKey}.description`)}</p>
      </div>
      {editable ? <Button type="primary" icon={<Plus size={14} />} onClick={() => openEditor()}>{t('parity.overrides.add')}</Button> : null}
    </div> : editable ? <div className="configuration-default-overrides-toolbar"><Button type="primary" onClick={() => openEditor()}>{t('parity.overrides.add')}</Button></div> : null}
    <Table<OverrideTableRow>
      className="configuration-overrides-table"
      size="small"
      rowKey="key"
      rowSelection={{ columnWidth: 70 }}
      pagination={false}
      dataSource={rows}
      columns={columns}
      tableLayout="fixed"
      locale={{ emptyText: t(`parity.overrides.${category}.empty`) }}
    />
    <Modal
      className={`configuration-override-modal configuration-override-modal--${category}`}
      width={category === 'nginx' ? 720 : 520}
      open={Boolean(draft)}
      title={t(draft?.index === null ? 'parity.overrides.add' : 'parity.overrides.editTitle')}
      okText={t('parity.overrides.confirm')}
      cancelText={t('parity.overrides.cancel')}
      footer={(_, { OkBtn, CancelBtn }) => <><CancelBtn /><OkBtn /></>}
      onOk={commit}
      onCancel={() => {
        setDraft(null)
        setTargetQuery('')
        setEditorError('')
      }}
      destroyOnHidden
    >
      {draft ? <div className="configuration-override-modal-form">
        {category === 'nginx' ? <div className="configuration-override-modal-row">
          <label>{t('parity.overrides.scopeLabel')}</label>
          <div className="configuration-override-modal-control">
            <Radio.Group
              optionType="button"
              value={draft.scope}
              options={[{ value: 'node', label: t('parity.overrides.node') }, { value: 'region', label: t('parity.overrides.region') }]}
              onChange={(event) => {
                setDraft({ ...draft, scope: event.target.value as ScopeKind, scopeId: '' })
                setTargetQuery('')
                setEditorError('')
              }}
            />
          </div>
        </div> : null}
        <div className="configuration-override-modal-row">
          <label>{t(draft.scope === 'node' ? 'parity.overrides.nodeSelect' : 'parity.overrides.regionSelect')}</label>
          <div className="configuration-override-modal-control">
            <Select
              aria-label={t(draft.scope === 'node' ? 'parity.overrides.nodeSelect' : 'parity.overrides.regionSelect')}
              value={draft.scopeId || undefined}
              showSearch
              allowClear
              filterOption={false}
              loading={directory.loading}
              placeholder={t(draft.scope === 'node' ? 'parity.overrides.nodePlaceholder' : 'parity.overrides.regionPlaceholder')}
              options={targetOptions}
              virtual={false}
              classNames={{ popup: { root: 'configuration-select-popup' } }}
              notFoundContent={t(directory.loading ? 'parity.overrides.targetLoading' : directory.error ? 'parity.overrides.targetLoadError' : 'parity.overrides.targetEmpty')}
              popupRender={(menu) => <>
                {menu}
                {directory.hasMore ? <Button type="link" size="small" block loading={directory.loading} onMouseDown={(event) => event.preventDefault()} onClick={directory.loadMore}>{t('parity.overrides.targetLoadMore')}</Button> : null}
              </>}
              onPopupScroll={(event) => {
                const target = event.currentTarget
                if (target.scrollTop + target.clientHeight >= target.scrollHeight - 10) directory.loadMore()
              }}
              onSearch={setTargetQuery}
              onChange={(value) => {
                setDraft({ ...draft, scopeId: value ?? '' })
                setTargetQuery('')
                setEditorError('')
              }}
            />
          </div>
        </div>
        <div className="configuration-override-modal-row">
          <label>{t(category === 'nginx' ? 'parity.overrides.settings' : 'parity.overrides.settingItem')}</label>
          <div className="configuration-override-modal-control">
            <Select
              aria-label={t(category === 'nginx' ? 'parity.overrides.settings' : 'parity.overrides.settingItem')}
              // 追加模式：每选一项后按已选数量重挂载，下拉框回到占位文字
              key={`append-${draft.settingKeys.length}`}
              value={undefined}
              placeholder={t(settingPlaceholderKey)}
              showSearch
              optionFilterProp="label"
              options={settings.map((definition) => ({ value: definition.key, label: settingLabel(definition, t), disabled: draft.settingKeys.includes(definition.key) }))}
              virtual={false}
              classNames={{ popup: { root: 'configuration-select-popup' } }}
              onChange={(value) => updateSettingKeys(value ? [...draft.settingKeys, value] : draft.settingKeys)}
            />
          </div>
        </div>
        {draft.settingKeys.map((key) => {
          const definition = settings.find((item) => item.key === key)
          return definition ? <SettingValueControl
            key={key}
            definition={definition}
            value={draft.values[key]}
            t={t}
            onChange={(value) => {
              setDraft({ ...draft, values: { ...draft.values, [key]: value } })
              setEditorError('')
            }}
            onRemove={() => updateSettingKeys(draft.settingKeys.filter((item) => item !== key))}
          /> : null
        })}
        {editorError ? <Alert type="error" showIcon message={editorError} /> : null}
      </div> : null}
    </Modal>
  </div>
}
