import { useMemo, useState } from 'react'
import type { TFunction } from 'i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Drawer, Grid, Input, InputNumber, Radio, Select, Switch, Tabs, Tag } from 'antd'
import { FeedbackWhen, useFeedbackMessage } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import type { NodeLineGroup, NodeSchedulingScope } from '../../api/nodeScheduling'
import {
  smartScheduleApi,
  smartScheduleLimits,
  type LatencyMatrixRow,
  type SmartSchedule,
  type SmartScheduleLine,
  type SmartScheduleSettings,
} from '../../api/smartSchedule'
import { formatDateTime } from '../../i18n/formatters'
import { provinceNames } from '../analyticsRankLabels'
import { schedulingError } from './shared'
import './SmartScheduleDrawer.css'

const carrierOrder = ['telecom', 'unicom', 'mobile', 'overseas', 'default']
const matrixWindows = [5, 15, 30, 60]
const allValue = '__all__'
// GB/T 2260 顺序，省份显示名中英文对照（延迟表里的省份是规范中文短名，如「广东」）。
const provinceOrder = Object.values(provinceNames).map((name) => name.zh)

type TFn = TFunction<'nodeScheduling'>

function provinceLabel(province: string, language: string): string {
  if (language !== 'en-US') return province
  return Object.values(provinceNames).find((name) => name.zh === province)?.en ?? province
}

function carrierLabel(carrier: string, t: TFn): string {
  if (carrier === 'default') return t('values.defaultRegion')
  return carrierOrder.includes(carrier) ? t(`smartSchedule.scopes.${carrier}`) : carrier
}

/** 线路 scope 的显示名：运营商线路（telecom）或省份运营商线路（广东:mobile）。 */
function smartScopeLabel(scope: string, t: TFn, language: string): string {
  const separator = scope.indexOf(':')
  if (separator < 0) return carrierLabel(scope, t)
  return t('smartSchedule.scopes.provinceCarrier', {
    province: provinceLabel(scope.slice(0, separator), language),
    carrier: carrierLabel(scope.slice(separator + 1), t),
  })
}

/**
 * fallback_from 是没有合格节点的级别（province_carrier / carrier），按后端回退规则换成实际回答的线路：
 * 省份运营商线路不写、由同运营商全国线路回答；运营商线路不写、由默认线路回答。
 */
function fallbackTarget(line: SmartScheduleLine): string {
  if (line.fallback_from === 'province_carrier') {
    const separator = line.scope.indexOf(':')
    return separator < 0 ? 'default' : line.scope.slice(separator + 1)
  }
  return line.fallback_from ? 'default' : ''
}

function scopeSortKey(scope: string): [number, number] {
  const separator = scope.indexOf(':')
  const carrier = separator < 0 ? scope : scope.slice(separator + 1)
  const province = separator < 0 ? -1 : provinceOrder.indexOf(scope.slice(0, separator))
  const carrierIndex = carrierOrder.indexOf(carrier)
  return [province < 0 && separator >= 0 ? provinceOrder.length : province, carrierIndex < 0 ? carrierOrder.length : carrierIndex]
}

function sortedLines(lines: SmartScheduleLine[]): SmartScheduleLine[] {
  return [...lines].sort((left, right) => {
    const [lp, lc] = scopeSortKey(left.scope)
    const [rp, rc] = scopeSortKey(right.scope)
    return lp - rp || lc - rc || left.scope.localeCompare(right.scope)
  })
}

function latencyTier(ms: number): 'fast' | 'medium' | 'slow' {
  if (ms < 50) return 'fast'
  if (ms < 120) return 'medium'
  return 'slow'
}

export default function SmartScheduleDrawer({ group, scope, accessToken, canManage, onClose }: {
  group: NodeLineGroup
  scope: NodeSchedulingScope
  accessToken: (permission: 'read' | 'manage') => string | null
  canManage: boolean
  onClose: () => void
}) {
  const { t } = useTranslation('nodeScheduling')
  const narrow = Grid.useBreakpoint().md === false
  const [messageApi, messageContext] = useFeedbackMessage()
  const [tab, setTab] = useState('selected')
  const queryKey = ['smart-schedule', group.id, scope.kind === 'platform' ? scope.targetScopeId : ''] as const

  const scheduleQuery = useQuery({
    queryKey,
    queryFn: () => {
      const token = accessToken('read')
      if (!token) throw new Error('session changed')
      return smartScheduleApi.get(token, scope, group.id)
    },
    retry: false,
    refetchOnWindowFocus: false,
  })

  return (
    <Drawer
      className="smart-schedule-drawer"
      title={t('smartSchedule.title', { name: group.name })}
      width={narrow ? '100%' : 760}
      open
      closable={{ 'aria-label': t('smartSchedule.close') }}
      onClose={onClose}
      destroyOnHidden
    >
      {messageContext}
      <p className="smart-schedule-intro">{t('smartSchedule.intro')}</p>
      {scheduleQuery.error ? (
        <FeedbackWhen
          title={t('smartSchedule.errors.loadFailed')}
          detail={schedulingError(scheduleQuery.error, t)}
          action={<Button onClick={() => void scheduleQuery.refetch()}>{t('actions.retry')}</Button>}
        />
      ) : scheduleQuery.data ? (
        <>
          <ProbeSourceNotice schedule={scheduleQuery.data} />
          <SmartScheduleForm
            key={JSON.stringify([scheduleQuery.data.enabled, scheduleQuery.data.top_n, scheduleQuery.data.granularity,
              scheduleQuery.data.latency_window_minutes, scheduleQuery.data.max_load_percent])}
            schedule={scheduleQuery.data}
            canManage={canManage}
            save={async (input) => {
              const token = accessToken('manage')
              if (!token) throw new Error('session changed')
              await smartScheduleApi.save(token, scope, group.id, input)
            }}
            queryKey={queryKey}
            onSaved={() => messageApi.success(t('smartSchedule.form.saved'))}
          />
          <Tabs
            className="smart-schedule-tabs"
            activeKey={tab}
            onChange={setTab}
            items={[
              { key: 'selected', label: t('smartSchedule.tabs.selected'), children: <SelectedLines schedule={scheduleQuery.data} /> },
              {
                key: 'matrix',
                label: t('smartSchedule.tabs.matrix'),
                children: tab === 'matrix' ? (
                  <LatencyMatrix
                    groupID={group.id}
                    scope={scope}
                    accessToken={accessToken}
                    defaultWindow={scheduleQuery.data.latency_window_minutes}
                  />
                ) : null,
              },
            ]}
          />
        </>
      ) : (
        <div className="smart-schedule-loading" role="status">{t('states.loading')}</div>
      )}
    </Drawer>
  )
}

function ProbeSourceNotice({ schedule }: { schedule: SmartSchedule }) {
  const { t } = useTranslation('nodeScheduling')
  const sources = [
    schedule.probe_source.dnspup ? t('smartSchedule.probe.dnspup') : '',
    schedule.probe_source.peer_nodes ? t('smartSchedule.probe.peerNodes') : '',
  ].filter(Boolean)
  if (sources.length === 0) {
    return (
      <Alert
        className="smart-schedule-probe"
        type="warning"
        showIcon
        data-testid="smart-schedule-no-probe"
        message={t('smartSchedule.probe.none')}
        description={t('smartSchedule.probe.noneDetail')}
      />
    )
  }
  return (
    <p className="smart-schedule-probe-sources" data-testid="smart-schedule-probe-sources">
      {t('smartSchedule.probe.sources', { sources: sources.join(t('smartSchedule.probe.separator')) })}
    </p>
  )
}

function SmartScheduleForm({ schedule, canManage, save, queryKey, onSaved }: {
  schedule: SmartSchedule
  canManage: boolean
  save: (input: SmartScheduleSettings) => Promise<void>
  queryKey: readonly unknown[]
  onSaved: () => void
}) {
  const { t } = useTranslation('nodeScheduling')
  const queryClient = useQueryClient()
  const provinceSupported = schedule.province_lines_supported !== false
  const [draft, setDraft] = useState<SmartScheduleSettings>(() => ({
    enabled: schedule.enabled,
    top_n: schedule.top_n,
    granularity: provinceSupported ? schedule.granularity : 'carrier',
    latency_window_minutes: schedule.latency_window_minutes,
    max_load_percent: schedule.max_load_percent,
  }))
  const mutation = useMutation({
    mutationFn: save,
    onSuccess: async () => {
      onSaved()
      await queryClient.invalidateQueries({ queryKey })
    },
    retry: false,
  })
  const disabled = !canManage || mutation.isPending
  const update = (patch: Partial<SmartScheduleSettings>) => {
    mutation.reset()
    setDraft((current) => ({ ...current, ...patch }))
  }
  const numberField = (
    id: string,
    label: string,
    help: string,
    value: number,
    limits: { min: number; max: number },
    suffix: string,
    onChange: (value: number) => void,
  ) => (
    <div className="smart-schedule-field">
      <label htmlFor={id}>{label}</label>
      <InputNumber
        id={id}
        min={limits.min}
        max={limits.max}
        precision={0}
        value={value}
        disabled={disabled}
        addonAfter={suffix || undefined}
        aria-describedby={`${id}-help`}
        onChange={(next) => { if (typeof next === 'number') onChange(next) }}
      />
      <span id={`${id}-help`} className="smart-schedule-help">{help}</span>
    </div>
  )

  return (
    <section className="smart-schedule-settings" aria-labelledby="smart-schedule-settings-title">
      <h2 id="smart-schedule-settings-title">{t('smartSchedule.form.section')}</h2>
      {!canManage ? <p className="smart-schedule-help">{t('smartSchedule.form.readOnly')}</p> : null}
      <div className="smart-schedule-switch">
        <Switch
          id="smart-schedule-enabled"
          checked={draft.enabled}
          disabled={disabled}
          onChange={(enabled) => update({ enabled })}
        />
        <label htmlFor="smart-schedule-enabled">{t('smartSchedule.form.enabled')}</label>
      </div>
      <div className="smart-schedule-grid">
        {numberField('smart-schedule-top-n', t('smartSchedule.form.topN'), t('smartSchedule.form.topNHelp'),
          draft.top_n, smartScheduleLimits.topN, '', (top_n) => update({ top_n }))}
        {numberField('smart-schedule-window', t('smartSchedule.form.window'), t('smartSchedule.form.windowHelp'),
          draft.latency_window_minutes, smartScheduleLimits.windowMinutes, t('smartSchedule.form.minutes'),
          (latency_window_minutes) => update({ latency_window_minutes }))}
        {numberField('smart-schedule-max-load', t('smartSchedule.form.maxLoad'), t('smartSchedule.form.maxLoadHelp'),
          draft.max_load_percent, smartScheduleLimits.maxLoadPercent, '%', (max_load_percent) => update({ max_load_percent }))}
      </div>
      <div className="smart-schedule-field" role="radiogroup" aria-labelledby="smart-schedule-granularity-label" aria-describedby="smart-schedule-granularity-help">
        <span id="smart-schedule-granularity-label" className="smart-schedule-label">{t('smartSchedule.form.granularity')}</span>
        <Radio.Group
          optionType="button"
          value={draft.granularity}
          disabled={disabled}
          onChange={(event) => update({ granularity: event.target.value })}
          options={[
            { value: 'carrier', label: t('smartSchedule.form.carrier') },
            { value: 'province_carrier', label: t('smartSchedule.form.provinceCarrier'), disabled: !provinceSupported },
          ]}
        />
        <span id="smart-schedule-granularity-help" className="smart-schedule-help" data-testid="smart-schedule-granularity-help">
          {provinceSupported ? t('smartSchedule.form.granularityHelp') : t('smartSchedule.form.provinceUnsupported')}
        </span>
      </div>
      {mutation.error ? (
        <FeedbackWhen title={t('smartSchedule.errors.saveFailed')} detail={schedulingError(mutation.error, t)} />
      ) : null}
      {canManage ? (
        <div className="smart-schedule-actions">
          <Button type="primary" loading={mutation.isPending} onClick={() => mutation.mutate(draft)}>
            {t('actions.save')}
          </Button>
        </div>
      ) : null}
    </section>
  )
}

function SelectedLines({ schedule }: { schedule: SmartSchedule }) {
  const { t, i18n } = useTranslation('nodeScheduling')
  const lines = useMemo(() => sortedLines(schedule.lines), [schedule.lines])
  if (!schedule.enabled) return <p className="smart-schedule-empty">{t('smartSchedule.lines.disabled')}</p>
  if (lines.length === 0) return <p className="smart-schedule-empty">{t('smartSchedule.lines.empty')}</p>
  return (
    <ul className="smart-schedule-lines" aria-label={t('smartSchedule.tabs.selected')}>
      {lines.map((line) => {
        const label = smartScopeLabel(line.scope, t, i18n.language)
        const target = line.source === 'fallback' || line.fallback_from ? fallbackTarget(line) : ''
        const fallback = target ? smartScopeLabel(target, t, i18n.language) : ''
        return (
          <li key={line.scope} className="smart-schedule-line" data-testid="smart-schedule-line">
            <div className="smart-schedule-line-head">
              <strong>{label}</strong>
              {line.dns_line ? <code title={t('smartSchedule.lines.dnsLine')}>{line.dns_line}</code> : null}
              {fallback ? (
                <Tag color="warning" title={t('smartSchedule.lines.fallbackHelp', { line: fallback })}>
                  {t('smartSchedule.lines.fallbackFrom', { line: fallback })}
                </Tag>
              ) : null}
              {line.source === 'static' ? (
                <Tag title={t('smartSchedule.lines.staticHelp')}>{t('smartSchedule.lines.static')}</Tag>
              ) : null}
              {line.updated_at ? (
                <span className="smart-schedule-line-time">
                  {t('smartSchedule.lines.updatedAt')} {formatDateTime(line.updated_at, i18n.language) || line.updated_at}
                </span>
              ) : null}
            </div>
            {line.selected.length === 0 ? (
              <p className="smart-schedule-help">{t('smartSchedule.lines.noNode')}</p>
            ) : (
              <ol className="smart-schedule-nodes">
                {line.selected.map((node) => (
                  <li key={node.endpoint_id || node.address}>
                    <code className="smart-schedule-address">{node.address}</code>
                    <span
                      className={node.latency_ms === null ? 'smart-schedule-muted' : `smart-schedule-latency smart-schedule-latency-${latencyTier(node.latency_ms)}`}
                      {...(node.latency_ms === null ? { title: t('smartSchedule.lines.latencyUnknownLabel'), 'aria-label': t('smartSchedule.lines.latencyUnknownLabel') } : {})}
                    >
                      {node.latency_ms === null ? t('smartSchedule.lines.latencyUnknown') : t('smartSchedule.lines.latency', { value: Math.round(node.latency_ms) })}
                    </span>
                    <Tag color={node.healthy ? 'success' : 'error'}>
                      {node.healthy ? t('values.healthy') : t('values.unhealthy')}
                    </Tag>
                    <span
                      className="smart-schedule-muted"
                      {...(node.load_percent === null ? { title: t('smartSchedule.lines.loadUnknownLabel'), 'aria-label': t('smartSchedule.lines.loadUnknownLabel') } : {})}
                    >
                      {node.load_percent === null ? t('smartSchedule.lines.loadUnknown') : t('smartSchedule.lines.load', { value: Math.round(node.load_percent) })}
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </li>
        )
      })}
    </ul>
  )
}

function LatencyMatrix({ groupID, scope, accessToken, defaultWindow }: {
  groupID: string
  scope: NodeSchedulingScope
  accessToken: (permission: 'read' | 'manage') => string | null
  defaultWindow: number
}) {
  const { t, i18n } = useTranslation('nodeScheduling')
  const [windowMinutes, setWindowMinutes] = useState(defaultWindow)
  const [province, setProvince] = useState('')
  const [carrier, setCarrier] = useState('')
  const [address, setAddress] = useState('')
  const matrixQuery = useQuery({
    queryKey: ['smart-schedule-latency', groupID, scope.kind === 'platform' ? scope.targetScopeId : '', windowMinutes],
    queryFn: () => {
      const token = accessToken('read')
      if (!token) throw new Error('session changed')
      return smartScheduleApi.latencyMatrix(token, scope, groupID, windowMinutes)
    },
    retry: false,
    refetchOnWindowFocus: false,
  })
  const rows = useMemo(() => matrixQuery.data ?? [], [matrixQuery.data])
  const provinces = useMemo(() => [...new Set(rows.map((row) => row.province))].sort((left, right) => {
    const li = provinceOrder.indexOf(left)
    const ri = provinceOrder.indexOf(right)
    return (li < 0 ? provinceOrder.length : li) - (ri < 0 ? provinceOrder.length : ri) || left.localeCompare(right)
  }), [rows])
  const carriers = useMemo(() => [...new Set(rows.map((row) => row.carrier))].sort((left, right) => {
    const li = carrierOrder.indexOf(left)
    const ri = carrierOrder.indexOf(right)
    return (li < 0 ? carrierOrder.length : li) - (ri < 0 ? carrierOrder.length : ri) || left.localeCompare(right)
  }), [rows])
  const needle = address.trim()
  const filtered = rows.filter((row) => (!province || row.province === province) && (!carrier || row.carrier === carrier) &&
    (!needle || row.address.includes(needle)))
  const shownProvinces = provinces.filter((value) => filtered.some((row) => row.province === value))
  const shownCarriers = carrier ? [carrier] : carriers
  const cells = new Map<string, LatencyMatrixRow[]>()
  for (const row of filtered) {
    const key = `${row.province}\u0000${row.carrier}`
    cells.set(key, [...(cells.get(key) ?? []), row])
  }
  for (const list of cells.values()) list.sort((left, right) => left.p50_ms - right.p50_ms)
  const windows = [...new Set([...matrixWindows, defaultWindow])].sort((left, right) => left - right)

  return (
    <div className="smart-schedule-matrix">
      <p className="smart-schedule-help">{t('smartSchedule.matrix.hint')}</p>
      <div className="smart-schedule-matrix-filters" role="search" aria-label={t('smartSchedule.tabs.matrix')}>
        <Select
          aria-label={t('smartSchedule.matrix.window')}
          value={windowMinutes}
          options={windows.map((count) => ({ value: count, label: t('smartSchedule.matrix.windowOption', { count }) }))}
          onChange={setWindowMinutes}
        />
        <Select
          aria-label={t('smartSchedule.matrix.province')}
          value={province || allValue}
          showSearch
          optionFilterProp="label"
          options={[{ value: allValue, label: t('smartSchedule.matrix.allProvinces') },
            ...provinces.map((value) => ({ value, label: provinceLabel(value, i18n.language) }))]}
          onChange={(value) => setProvince(value === allValue ? '' : value)}
        />
        <Select
          aria-label={t('columns.carrier')}
          value={carrier || allValue}
          options={[{ value: allValue, label: t('smartSchedule.matrix.allCarriers') },
            ...carriers.map((value) => ({ value, label: carrierLabel(value, t) }))]}
          onChange={(value) => setCarrier(value === allValue ? '' : value)}
        />
        <Input
          aria-label={t('smartSchedule.matrix.node')}
          placeholder={t('smartSchedule.matrix.nodePlaceholder')}
          allowClear
          value={address}
          onChange={(event) => setAddress(event.target.value)}
        />
      </div>
      {matrixQuery.error ? (
        <FeedbackWhen
          title={t('smartSchedule.errors.matrixFailed')}
          detail={schedulingError(matrixQuery.error, t)}
          action={<Button onClick={() => void matrixQuery.refetch()}>{t('actions.retry')}</Button>}
        />
      ) : matrixQuery.isLoading ? (
        <div className="smart-schedule-loading" role="status">{t('states.loading')}</div>
      ) : rows.length === 0 ? (
        <p className="smart-schedule-empty">{t('smartSchedule.matrix.empty')}</p>
      ) : shownProvinces.length === 0 ? (
        <p className="smart-schedule-empty">{t('smartSchedule.matrix.filteredEmpty')}</p>
      ) : (
        <div className="smart-schedule-matrix-scroll" tabIndex={0} aria-label={t('smartSchedule.tabs.matrix')}>
          <table className="smart-schedule-matrix-table" data-testid="smart-schedule-matrix">
            <thead>
              <tr>
                <th scope="col">{t('smartSchedule.matrix.province')}</th>
                {shownCarriers.map((value) => <th key={value} scope="col">{carrierLabel(value, t)}</th>)}
              </tr>
            </thead>
            <tbody>
              {shownProvinces.map((provinceValue) => (
                <tr key={provinceValue}>
                  <th scope="row">{provinceLabel(provinceValue, i18n.language)}</th>
                  {shownCarriers.map((carrierValue) => {
                    const list = cells.get(`${provinceValue}\u0000${carrierValue}`) ?? []
                    return (
                      <td key={carrierValue}>
                        {list.length === 0 ? <span className="smart-schedule-muted">{t('smartSchedule.matrix.cellEmpty')}</span> : (
                          <ol className="smart-schedule-cell">
                            {list.map((row) => (
                              <li
                                key={row.endpoint_id || row.address}
                                title={`${t('smartSchedule.matrix.samples', { count: row.samples })} · ${t('smartSchedule.matrix.lastAt', {
                                  time: formatDateTime(row.last_at, i18n.language) || row.last_at,
                                })}`}
                              >
                                <code>{row.address}</code>
                                <span className="smart-schedule-cell-meta">
                                  <span className={`smart-schedule-latency smart-schedule-latency-${latencyTier(row.p50_ms)}`}>
                                    {t('smartSchedule.lines.latency', { value: Math.round(row.p50_ms) })}
                                  </span>
                                  <span className="smart-schedule-muted">{t('smartSchedule.matrix.samples', { count: row.samples })}</span>
                                </span>
                              </li>
                            ))}
                          </ol>
                        )}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
