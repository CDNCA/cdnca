import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, Button, Card, Descriptions, Input, InputNumber, Modal, Popconfirm, Segmented, Select, Space, Switch, Table, Tag,
  Tooltip, Typography, type TableColumnsType,
} from 'antd'
import { useFeedbackMessage, useFeedback } from '@cdnca/ui'
import { Upload } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { ApiError } from '../api/auth'
import {
  adjustableAt, rowState, rulePacksApi,
  type LevelRef, type OverrideInput, type RulePack, type RulePackLevel, type RulePackOverride, type RulePackState,
} from '../api/rulePacks'
import { sitesApi } from '../api/sites'
import { useSessionStore } from '../auth/session'
import { localizedUnknownApiError } from '../i18n/apiError'
import '../i18n/rulePacks'
import RulePackSitePanel from './security/RulePackSitePanel'
import WAFSubscriptionSection from './security/WAFSubscriptionSection'

const states: RulePackState[] = ['inherit', 'enabled', 'disabled']

// RulePacksPage: the rule packs of one level (platform or own tenant, or a
// site), their inherited state and source, this level's settings, and for a
// site the final execution order, conflicts and publication. ?site_id=
// opens a site (the "去发布" of a subscription pack waiting to be published).
// A tenant also subscribes to WAF rule library subscriptions here.
export default function RulePacksPage() {
  const { t } = useTranslation('rulePacks')
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const accessToken = useSessionStore((state) => state.accessToken) ?? ''
  const principal = useSessionStore((state) => state.principal)
  const isPlatform = principal?.scope_kind === 'platform'
  const canManage = Boolean(principal?.permissions.some((item) => item === 'security_policies.manage' || item === 'platform.admin'))
  const ownLevel: RulePackLevel = isPlatform ? 'platform' : 'tenant'
  const [searchParams] = useSearchParams()
  const linkedSite = searchParams.get('site_id')
  const [mode, setMode] = useState<'own' | 'site'>(linkedSite ? 'site' : 'own')
  const [siteID, setSiteID] = useState<string | null>(linkedSite)
  const [siteSearch, setSiteSearch] = useState('')
  const [importing, setImporting] = useState(false)
  const [importText, setImportText] = useState('')
  const level: RulePackLevel = mode === 'site' ? 'site' : ownLevel
  const objectID = mode === 'site' ? siteID : isPlatform ? null : principal?.scope_id ?? null
  const levelRef: LevelRef = { level, ...(objectID ? { object_id: objectID } : {}) }
  const ready = Boolean(accessToken) && (mode === 'own' || Boolean(siteID))

  const view = useQuery({
    queryKey: ['rule-packs', level, objectID],
    enabled: ready,
    queryFn: () => rulePacksApi.view(accessToken, level, objectID),
  })
  const sites = useQuery({
    queryKey: ['rule-pack-sites', siteSearch],
    enabled: Boolean(accessToken) && mode === 'site',
    queryFn: () => sitesApi.list(accessToken, { page: 1, limit: 100, ...(siteSearch ? { domain: siteSearch } : {}) }),
  })
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['rule-packs'] })
    void queryClient.invalidateQueries({ queryKey: ['rule-pack-site'] })
  }
  const failure = (error: unknown) => {
    const code = error instanceof ApiError ? error.code : ''
    const text = code === 'rule_pack_locked' ? t('notices.locked') : code === 'rule_pack_in_use' ? t('notices.inUse')
      : code === 'rule_pack_version_exists' ? t('notices.exists')
        : error instanceof ApiError && error.status === 400 ? t('notices.invalid') : t('notices.failed')
    void feedback.error(localizedUnknownApiError(error, text))
  }
  const put = useMutation({
    mutationFn: (input: OverrideInput) => rulePacksApi.putOverride(accessToken, input),
    onSuccess: () => { void messageApi.success(t('notices.saved')); refresh() },
    onError: failure,
  })
  const importPack = useMutation({
    mutationFn: (content: string) => rulePacksApi.importPack(accessToken, content),
    onSuccess: () => { void messageApi.success(t('notices.imported')); setImporting(false); setImportText(''); refresh() },
    onError: failure,
  })
  const updatePack = useMutation({
    mutationFn: (input: { packID: string; current_version?: string; update_policy?: 'auto' | 'manual' }) =>
      rulePacksApi.update(accessToken, input.packID, input),
    onSuccess: () => { void messageApi.success(t('notices.saved')); refresh() },
    onError: failure,
  })
  const removeVersion = useMutation({
    mutationFn: (input: { packID: string; version: string }) => rulePacksApi.removeVersion(accessToken, input.packID, input.version),
    onSuccess: () => { void messageApi.success(t('notices.removed')); refresh() },
    onError: failure,
  })

  const overrides = view.data?.overrides ?? []
  // A change keeps the row's other fields (state, allow_lower, priority, params).
  const write = (pack: RulePack, change: Partial<OverrideInput>, ruleID = '') => {
    const row = rowState(overrides, pack.pack_id, ruleID)
    put.mutate({
      level, level_object_id: objectID, pack_id: pack.pack_id, rule_id: ruleID,
      state: row?.state ?? 'inherit',
      allow_lower: ruleID ? false : row?.allow_lower ?? false,
      priority: ruleID ? null : row?.priority ?? null,
      params: ruleID ? null : row?.params ?? null,
      ...change,
    })
  }
  const ownsPack = (pack: RulePack) => pack.layer === 'user' ? !isPlatform && pack.owner_scope_id === principal?.scope_id : isPlatform
  // A customer's own account is the bottom of the chain: no "租户" wording,
  // and "inherit" reads as "follow <the level above> (now: on / off)".
  const endUser = !isPlatform
  const levelName = (value: string) => t(`${endUser ? 'tenantLevels' : 'levels'}.${value}`)
  const stateLabel = (pack: RulePack, value: RulePackState) => {
    if (value === 'inherit') {
      if (level === 'platform') return t('systemDefault')
      // The level directly above: a site follows the account, the account the platform.
      return t('follow', { level: levelName(level === 'site' ? 'tenant' : 'platform'),
        state: t(pack.effect?.inherited ? 'tenantStates.enabled' : 'tenantStates.disabled') })
    }
    return endUser ? t(`tenantStates.${value}`) : t(`states.${value}`)
  }
  const titled = (title: string, hint: string) => <Tooltip title={hint}><span>{title}</span></Tooltip>
  const hereTitle = titled(endUser ? t('tenantColumns.here') : t('columns.here'),
    level === 'platform' ? t('columnHints.platformHere') : t('columnHints.here'))

  const columns: TableColumnsType<RulePack> = [
    { title: t('columns.pack'), dataIndex: 'pack_id', render: (_, pack) => <span>
      <strong>{pack.name || pack.pack_id}</strong><br /><small><code>{pack.pack_id}</code></small>
    </span> },
    { title: titled(t('columns.layer'), t('layerHint')), dataIndex: 'layer', width: 90, render: (value: string) => <Tag>{t(`layers.${value}`)}</Tag> },
    { title: t('columns.engine'), dataIndex: 'engine', width: 110 },
    { title: t('columns.version'), dataIndex: 'current_version', width: 110, render: (value: string) => value || t('values.noVersion') },
    { title: t('columns.effective'), key: 'effective', width: 150, render: (_, pack) => pack.effect
      ? <span><Tag color={pack.effect.enabled ? 'success' : 'default'}>{t(pack.effect.enabled ? 'values.on' : 'values.off')}</Tag>
        <small>{t('values.from', { level: levelName(pack.effect.enabled_at.level) })}</small></span>
      : '—' },
    { title: hereTitle, key: 'here', width: 300, render: (_, pack) => {
      const locked = !adjustableAt(pack, levelRef)
      const control = <Segmented size="small" value={rowState(overrides, pack.pack_id)?.state ?? 'inherit'}
        disabled={!canManage || locked || put.isPending}
        options={states.map((value) => ({ value, label: stateLabel(pack, value) }))}
        onChange={(value) => write(pack, { state: value as RulePackState })} />
      return locked ? <Tooltip title={t('values.locked')}>{control}</Tooltip> : control
    } },
    ...(level === 'site' ? [] : [{ title: endUser ? titled(t('tenantColumns.allowLower'), t('columnHints.tenantAllowLower'))
      : titled(t('columns.allowLower'), t('columnHints.allowLower')), key: 'allowLower', width: 150, render: (_: unknown, pack: RulePack) =>
      <Switch size="small" checked={rowState(overrides, pack.pack_id)?.allow_lower ?? false}
        disabled={!canManage || !adjustableAt(pack, levelRef) || put.isPending}
        onChange={(checked) => write(pack, { allow_lower: checked })} /> }]),
    { title: titled(t('columns.priority'), t('columnHints.priority')), key: 'priority', width: 150, render: (_, pack) =>
      <InputNumber size="small" min={0} max={1000} precision={0} placeholder={t('values.priorityDefault')}
        defaultValue={rowState(overrides, pack.pack_id)?.priority ?? undefined}
        disabled={!canManage || !adjustableAt(pack, levelRef)}
        onBlur={(event) => {
          const raw = event.target.value.trim()
          const next = raw === '' ? null : Number(raw)
          if (next !== (rowState(overrides, pack.pack_id)?.priority ?? null)) write(pack, { priority: next })
        }} /> },
  ]

  const expanded = (pack: RulePack) => <Space direction="vertical" style={{ width: '100%' }}>
    <Descriptions size="small" column={1}>
      <Descriptions.Item label={t('values.cost', pack.cost)}>{pack.description || '—'}</Descriptions.Item>
      {pack.requires.length ? <Descriptions.Item label={t('values.requires', { items: pack.requires.join(', ') })}>{''}</Descriptions.Item> : null}
      {pack.effect && pack.effect.ignored_overrides > 0
        ? <Descriptions.Item label={t('values.ignored', { count: pack.effect.ignored_overrides })}>{''}</Descriptions.Item> : null}
    </Descriptions>
    <Typography.Text strong>{t('rules.title')}</Typography.Text>
    {pack.exports.length === 0 ? <Typography.Text type="secondary">{t('rules.none')}</Typography.Text>
      : <Table rowKey="rule_id" size="small" pagination={false} dataSource={pack.exports} columns={[
        { title: t('site.rule'), dataIndex: 'rule_id', render: (value: string, rule) => <span>{rule.name} <small><code>{value}</code></small></span> },
        { title: t('columns.effective'), key: 'effective', render: (_, rule) => {
          const state = pack.effect?.rule_states[rule.rule_id]
          const source = pack.effect?.rule_source[rule.rule_id]
          return state === undefined ? t('states.inherit') : t('rules.ruleState', {
            state: t(state ? 'values.on' : 'values.off'), source: source ? levelName(source.level) : '',
          })
        } },
        { title: t('columns.here'), key: 'here', render: (_, rule) => <Segmented size="small"
          value={rowState(overrides, pack.pack_id, rule.rule_id)?.state ?? 'inherit'}
          disabled={!canManage || !adjustableAt(pack, levelRef) || put.isPending}
          options={states.map((value) => ({ value, label: value === 'inherit' ? t('states.inherit') : stateLabel(pack, value) }))}
          onChange={(value) => write(pack, { state: value as RulePackState }, rule.rule_id)} /> },
      ]} />}
    <ParamsEditor pack={pack} row={rowState(overrides, pack.pack_id)} disabled={!canManage || !adjustableAt(pack, levelRef) || put.isPending}
      onSave={(params) => write(pack, { params })} />
    {ownsPack(pack) && canManage ? <Space wrap>
      <Typography.Text>{t('version.policy')}</Typography.Text>
      <Segmented size="small" value={pack.update_policy} options={[{ value: 'auto', label: t('values.auto') }, { value: 'manual', label: t('values.manual') }]}
        onChange={(value) => updatePack.mutate({ packID: pack.pack_id, update_policy: value as 'auto' | 'manual' })} />
      {pack.versions.map((version) => <Tag key={version.version} color={version.version === pack.current_version ? 'blue' : 'default'}>
        {version.version} <small>{version.sha256.slice(0, 12)}</small>
        {version.version !== pack.current_version && version.state === 'downloaded'
          ? <Button type="link" size="small" onClick={() => updatePack.mutate({ packID: pack.pack_id, current_version: version.version })}>{t('version.use')}</Button> : null}
        <Popconfirm title={t('version.removeConfirm')} onConfirm={() => removeVersion.mutate({ packID: pack.pack_id, version: version.version })}>
          <Button type="link" size="small" danger>{t('version.remove')}</Button>
        </Popconfirm>
      </Tag>)}
    </Space> : null}
  </Space>

  return <Space direction="vertical" style={{ width: '100%' }} className="rule-packs-page">
    {messageContext}
    <Typography.Title level={4}>{t('title')}</Typography.Title>
    <Alert className="density-note" type="info" showIcon message={t(endUser ? 'tenantIntro' : 'intro')} />
    <Space wrap>
      <Segmented value={mode} onChange={(value) => setMode(value as 'own' | 'site')}
        options={endUser ? [{ value: 'own', label: t('modes.own') }, { value: 'site', label: t('modes.site') }]
          : [{ value: 'own', label: levelName(ownLevel) }, { value: 'site', label: levelName('site') }]} />
      {mode === 'site' ? <Select showSearch style={{ width: 320 }} placeholder={t('site.placeholder')} aria-label={t('site.select')}
        value={siteID ?? undefined} filterOption={false} onSearch={setSiteSearch} onChange={(value: string) => setSiteID(value)}
        loading={sites.isFetching} options={(sites.data?.items ?? []).map((item) => ({ value: item.id, label: item.domain }))} /> : null}
      {canManage ? <Button icon={<Upload size={14} />} onClick={() => setImporting(true)}>{t('import.open')}</Button> : null}
    </Space>
    {!ready ? <Alert type="warning" message={t('site.none')} /> : <Card size="small">
      <Table rowKey="pack_id" size="small" columns={columns} dataSource={view.data?.packs ?? []} loading={view.isPending}
        pagination={false} expandable={{ expandedRowRender: expanded }} />
    </Card>}
    {mode === 'site' && siteID ? <RulePackSitePanel accessToken={accessToken} siteID={siteID} canManage={canManage} onChanged={refresh}
      endUser={endUser} /> : null}
    {!isPlatform && mode === 'own' && accessToken ? <WAFSubscriptionSection accessToken={accessToken} canManage={canManage}
      onChanged={refresh} onOpenSite={(id) => { setSiteID(id); setMode('site') }} /> : null}
    <Modal title={t('import.title')} open={importing} onCancel={() => setImporting(false)} confirmLoading={importPack.isPending}
      okText={t('import.submit')} okButtonProps={{ disabled: importText.trim() === '' }} onOk={() => importPack.mutate(importText)} destroyOnHidden>
      <Typography.Paragraph type="secondary">{t(endUser ? 'import.tenantHint' : 'import.hint')}</Typography.Paragraph>
      <input type="file" accept="application/json,.json" aria-label={t('import.file')}
        onChange={(event) => { const file = event.target.files?.[0]; if (file) void file.text().then(setImportText) }} />
      <Input.TextArea rows={12} value={importText} onChange={(event) => setImportText(event.target.value)} style={{ marginTop: 8, fontFamily: 'monospace' }} />
    </Modal>
  </Space>
}

// ParamsEditor edits this level's parameter overrides of a pack within its
// params_schema (the server validates again).
function ParamsEditor({ pack, row, disabled, onSave }: {
  pack: RulePack
  row: RulePackOverride | null
  disabled: boolean
  onSave: (params: Record<string, unknown> | null) => void
}) {
  const { t } = useTranslation('rulePacks')
  const schema = pack.params_schema ?? {}
  const names = Object.keys(schema).sort()
  const [values, setValues] = useState<Record<string, unknown>>(row?.params ?? {})
  if (names.length === 0) return null
  const effective = (name: string) => values[name] ?? pack.effect?.params[name] ?? pack.defaults?.[name]
  return <Space direction="vertical">
    <Typography.Text strong>{t('params.title')}</Typography.Text>
    {names.map((name) => {
      const spec = schema[name]
      const set = (value: unknown) => setValues((current) => ({ ...current, [name]: value }))
      const control = spec.type === 'integer'
        ? <InputNumber size="small" min={spec.minimum} max={spec.maximum} precision={0} value={effective(name) as number}
          disabled={disabled} onChange={(value) => set(value)} aria-label={name} />
        : spec.type === 'string'
          ? <Select size="small" style={{ width: 160 }} value={effective(name) as string} disabled={disabled} aria-label={name}
            options={(spec.enum ?? []).map((value) => ({ value, label: t(`params.values.${value}`, { defaultValue: value }) }))} onChange={set} />
          : <Switch size="small" checked={Boolean(effective(name))} disabled={disabled} onChange={set} aria-label={name} />
      return <Space key={name}><code>{name}</code>{control}<small>{spec.bind.target}</small></Space>
    })}
    <Button size="small" disabled={disabled} onClick={() => onSave(Object.keys(values).length ? values : null)}>{t('params.save')}</Button>
  </Space>
}
