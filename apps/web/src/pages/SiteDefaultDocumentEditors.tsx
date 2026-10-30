// 网站默认设置 #3 网站缓存 / #30 条件源站的可视化编辑：值仍是后端收的
// JSON 文本（表单项 setting_value），规则用站点编辑页同一套弹窗编辑——缓存规则
// CacheRuleDialog、条件规则 ConditionalOriginRouteDialog。
import { useState } from 'react'
import { Alert, Button, Space, Table, Tooltip, type TableColumnsType } from 'antd'
import { ArrowDown, ArrowUp, Pencil, Plus, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { cachePolicySchemaV2, ruleExtraFields, type CachePolicyDocument, type CachePolicyRule } from '../api/cachePolicies'
import { siteDefaultCondOriginPool } from '../api/siteDefaults'
import type { OriginRoute } from '../api/siteOriginRouting'
import CacheRuleDialog from './site-edit/CacheRuleDialog'
import ConditionalOriginRouteDialog from './site-edit/ConditionalOriginRouteDialog'
import { ruleScope } from './site-edit/cacheRuleScope'
import '../i18n/cachePolicy'
import '../i18n/siteOriginRouting'
import '../i18n/siteListTabs'

interface DocumentEditorProps {
  value?: string
  onChange?: (value: string) => void
  disabled?: boolean
}

const day = 86_400
const newCacheRule: CachePolicyRule = {
  order: 0, extensions: [], path_prefix: '/', status_codes: [], action: 'cache', ttl_seconds: day, browser_ttl_seconds: 0,
}
// 规则只在「自定义规则」（override）模式下生效；其余字段沿用已存的值或此默认
const baseCacheDocument: CachePolicyDocument = {
  mode: 'override', rules: [], query_mode: 'preserve', query_names: [], vary_headers: [], disk_quota_bytes: 1_073_741_824,
}

function parse<T>(value: string | undefined): T | null {
  try {
    const parsed = JSON.parse(value ?? '') as unknown
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) ? parsed as T : null
  } catch { return null }
}

// 规则用到 v2 字段（不缓存、浏览器缓存、单条规则设置）时文档须声明 schema_version 2，同站点缓存页。
function withRules(document: CachePolicyDocument, rules: CachePolicyRule[]): CachePolicyDocument {
  const ordered = rules.map((rule, index) => ({ ...rule, order: index + 1 }))
  const v2 = document.schema_version === cachePolicySchemaV2 || ordered.some((rule) => rule.action === 'no_cache' ||
    (rule.browser_ttl_seconds ?? 0) !== 0 || Object.keys(ruleExtraFields(rule)).length > 0)
  return { ...document, ...(v2 ? { schema_version: cachePolicySchemaV2 } : {}), mode: 'override', rules: ordered }
}

export function CacheRulesDefaultEditor({ value, onChange, disabled = false }: DocumentEditorProps) {
  const { t } = useTranslation('cachePolicy')
  const { t: tl } = useTranslation('siteListTabs')
  const [dialog, setDialog] = useState<{ index: number | null; rule: CachePolicyRule } | null>(null)
  const parsed = parse<CachePolicyDocument>(value)
  const document = parsed && Array.isArray(parsed.rules) ? parsed : null
  const current = document ?? baseCacheDocument
  const rules = current.rules
  const write = (next: CachePolicyRule[]) => onChange?.(JSON.stringify(withRules(current, next)))

  const scopeText = (rule: CachePolicyRule) => {
    const scope = ruleScope(rule)
    const label = t(`dialog.scopes.${scope}`)
    if (scope === 'dir') return `${label} ${rule.path_prefix}`
    if (scope === 'path') return `${label} ${rule.path_exact}`
    if (scope === 'suffix') return `${label} ${(rule.extensions ?? []).map((item) => item.replace(/^\./, '')).join('|')}`
    return label
  }
  const ttlText = (rule: CachePolicyRule) => {
    if (rule.action === 'no_cache') return t('table.noCacheRule')
    const seconds = rule.ttl_seconds
    if (seconds % day === 0) return `${seconds / day}${t('dialog.units.d')}`
    if (seconds % 3600 === 0) return `${seconds / 3600}${t('dialog.units.h')}`
    return `${seconds}${t('dialog.units.s')}`
  }
  const move = (index: number, direction: -1 | 1) => {
    const next = [...rules]
    const [moved] = next.splice(index, 1)
    next.splice(index + direction, 0, moved!)
    write(next)
  }
  const columns: TableColumnsType<CachePolicyRule> = [
    { title: t('fields.order'), key: 'order', width: 56, render: (_: unknown, __: CachePolicyRule, index) => index + 1 },
    { title: t('table.scope'), key: 'scope', render: (_: unknown, rule) => scopeText(rule) },
    { title: t('table.expire'), key: 'expire', width: 110, render: (_: unknown, rule) => ttlText(rule) },
    {
      title: t('table.actions'), key: 'actions', width: 140,
      render: (_: unknown, rule, index) => (
        <Space size={2}>
          <Tooltip title={t('table.edit')}><Button type="text" size="small" aria-label={`${t('table.edit')} ${index + 1}`} icon={<Pencil size={14} aria-hidden="true" />}
            disabled={disabled} onClick={() => setDialog({ index, rule })} /></Tooltip>
          <Tooltip title={t('actions.moveUp')}><Button type="text" size="small" aria-label={t('actions.moveUp')} icon={<ArrowUp size={14} aria-hidden="true" />}
            disabled={disabled || index === 0} onClick={() => move(index, -1)} /></Tooltip>
          <Tooltip title={t('actions.moveDown')}><Button type="text" size="small" aria-label={t('actions.moveDown')} icon={<ArrowDown size={14} aria-hidden="true" />}
            disabled={disabled || index === rules.length - 1} onClick={() => move(index, 1)} /></Tooltip>
          <Tooltip title={t('actions.removeRule')}><Button danger type="text" size="small" aria-label={t('actions.removeRule')} icon={<Trash2 size={14} aria-hidden="true" />}
            disabled={disabled} onClick={() => write(rules.filter((_, position) => position !== index))} /></Tooltip>
        </Space>
      ),
    },
  ]
  return (
    <div className="site-default-document-editor">
      {value && !document ? <Alert type="warning" showIcon message={tl('defaults.form.documentReset')} /> : null}
      <Table<CachePolicyRule> size="small" rowKey="order" pagination={false} columns={columns} dataSource={rules}
        locale={{ emptyText: t('empty.title') }} />
      <Button icon={<Plus size={14} aria-hidden="true" />} disabled={disabled} onClick={() => setDialog({ index: null, rule: newCacheRule })}>
        {t('actions.addRule')}
      </Button>
      {dialog ? (
        <CacheRuleDialog open rule={dialog.rule} editing={dialog.index !== null}
          inheritedIgnoreQuery={current.query_mode === 'ignore'} inheritedSliceBytes={current.slice_bytes ?? 0} disabled={disabled}
          onCancel={() => setDialog(null)}
          onSubmit={(rule) => {
            const index = dialog.index
            setDialog(null)
            write(index === null ? [...rules, rule] : rules.map((item, position) => position === index ? rule : item))
          }} />
      ) : null}
    </div>
  )
}

export function CondOriginDefaultEditor({ value, onChange, disabled = false }: DocumentEditorProps) {
  const { t } = useTranslation('siteOriginRouting')
  const { t: tl } = useTranslation('siteListTabs')
  const [editing, setEditing] = useState<{ originalId: string | null } | null>(null)
  const parsed = parse<{ routes?: OriginRoute[] }>(value)
  const valid = parsed !== null && Array.isArray(parsed.routes)
  const routes = valid ? parsed.routes! : []
  // 默认设置只有「新站默认源站池」这一个占位池，规则一律回源到它
  const write = (next: OriginRoute[]) => onChange?.(JSON.stringify({ routes: next.map((route) => ({ ...route, pool_id: siteDefaultCondOriginPool })) }))
  const columns: TableColumnsType<OriginRoute> = [
    { title: t('fields.routeId'), dataIndex: 'id', width: 140 },
    {
      title: t('columns.conditions'),
      render: (_, route) => <div className="site-origin-routing-conditions">
        {route.path_prefix ? <span>{t('labels.path', { value: route.path_prefix })}</span> : null}
        {route.node_regions?.length ? <span>{t('labels.regions', { value: route.node_regions.join(', ') })}</span> : null}
        {route.client_cidrs?.length ? <span>{t('labels.cidrs', { value: route.client_cidrs.join(', ') })}</span> : null}
      </div>,
    },
    { title: t('fields.priority'), dataIndex: 'priority', width: 80 },
    {
      title: t('columns.actions'), width: 96,
      render: (_, route) => (
        <Space size={2}>
          <Button type="text" size="small" aria-label={t('actions.editRoute', { id: route.id })} icon={<Pencil size={14} aria-hidden="true" />}
            disabled={disabled} onClick={() => setEditing({ originalId: route.id })} />
          <Button danger type="text" size="small" aria-label={t('actions.confirmDeleteRoute', { id: route.id })} icon={<Trash2 size={14} aria-hidden="true" />}
            disabled={disabled} onClick={() => write(routes.filter((item) => item.id !== route.id))} />
        </Space>
      ),
    },
  ]
  return (
    <div className="site-default-document-editor">
      {value && !valid ? <Alert type="warning" showIcon message={tl('defaults.form.documentReset')} /> : null}
      <Table<OriginRoute> size="small" rowKey="id" pagination={false} columns={columns} dataSource={routes}
        locale={{ emptyText: tl('defaults.form.condOriginEmpty') }} />
      <Button icon={<Plus size={14} aria-hidden="true" />} disabled={disabled} onClick={() => setEditing({ originalId: null })}>
        {t('actions.addRoute')}
      </Button>
      {editing ? (
        <ConditionalOriginRouteDialog
          route={editing.originalId === null ? undefined : routes.find((item) => item.id === editing.originalId)}
          poolIds={[siteDefaultCondOriginPool]} defaultPoolId={siteDefaultCondOriginPool}
          takenIds={routes.map((item) => item.id).filter((id) => id !== editing.originalId)}
          allowFallback={false} disabled={disabled}
          onCancel={() => setEditing(null)}
          onApply={(route) => {
            const originalId = editing.originalId
            setEditing(null)
            write(originalId === null ? [...routes, route] : routes.map((item) => item.id === originalId ? route : item))
          }} />
      ) : null}
    </div>
  )
}
