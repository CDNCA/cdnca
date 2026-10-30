import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Checkbox, Input, InputNumber, Modal, Radio, Select, Space, Switch } from 'antd'
import { Plus, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  hstsPreloadMinimum,
  siteAccessApi,
  type HostRedirect,
  type RedirectStatus,
  type SiteAccessSettings,
  type CompressionEncoding,
  type SiteAccessState,
  type SiteCompression,
  type SiteMaintenance,
} from '../../api/siteAccess'
import '../../i18n/siteAccess'
import { FormRow, SettingGroup, SettingSection } from './SiteEditFields'
import SiteResponseRulesEditor from './SiteResponseRulesEditor'
import { cleanRule, formatStatuses, parseStatuses } from './siteResponseRules'
import { FeedbackWhen, MODAL_WIDTH } from '@cdnca/ui'
import SiteEditState from './SiteEditState'
import { useInstantDraft, useInstantFeedback } from './instantSave'

const statuses: RedirectStatus[] = [301, 302, 307, 308]
const knownErrors = ['validation_error', 'site_access_https_required', 'version_conflict', 'idempotency_conflict', 'site_locked']

type CompressionMode = 'inherit' | 'on' | 'off'

interface Draft {
  settings: SiteAccessSettings
  compressionMode: CompressionMode
  compressionTypes: string
  excludePrefixes: string
  allowedCIDRs: string
  hstsOn: boolean
  limitsOn: boolean
  authOn: boolean
  maintenanceOn: boolean
  webpOn: boolean
  /** response rule status fields as typed */
  statusTexts: string[]
}

const lines = (value: string) => value.split('\n').map((line) => line.trim()).filter(Boolean)
const defaultMaintenance = (): SiteMaintenance => ({ status: 503, content_type: 'text/html', body: '' })
const encodingOrder: CompressionEncoding[] = ['br', 'gzip']
const encodingsOf = (compression: SiteCompression | null): CompressionEncoding[] => compression?.encodings ?? ['gzip']

function draftFrom(state: SiteAccessState): Draft {
  const settings = state.settings
  return {
    settings: {
      ...settings,
      host_redirects: [...settings.host_redirects],
      basic_auth: settings.basic_auth ? { ...settings.basic_auth, users: settings.basic_auth.users.map((user) => ({ username: user.username })) } : null,
    },
    compressionMode: settings.compression === null ? 'inherit' : settings.compression.enabled ? 'on' : 'off',
    compressionTypes: (settings.compression?.types ?? []).join('\n'),
    excludePrefixes: (settings.basic_auth?.exclude_path_prefixes ?? []).join('\n'),
    allowedCIDRs: (settings.maintenance?.allowed_cidrs ?? []).join('\n'),
    hstsOn: settings.hsts !== null,
    limitsOn: settings.limits !== null,
    authOn: settings.basic_auth !== null,
    maintenanceOn: settings.maintenance !== null,
    webpOn: Boolean(settings.webp),
    statusTexts: (settings.response_rules ?? []).map((rule) => formatStatuses(rule.statuses)),
  }
}

/** The request body of a draft: switched-off sections are null. */
function settingsFrom(draft: Draft): SiteAccessSettings {
  const settings = draft.settings
  const maintenance = settings.maintenance ?? defaultMaintenance()
  const cidrs = lines(draft.allowedCIDRs)
  const encodings = encodingsOf(settings.compression)
  const gzipLevel = encodings.includes('gzip') ? settings.compression?.gzip_level ?? 0 : 0
  const brotliLevel = encodings.includes('br') ? settings.compression?.brotli_level ?? 0 : 0
  return {
    host_redirects: settings.host_redirects,
    hsts: draft.hstsOn ? settings.hsts ?? { max_age_seconds: 31536000, include_subdomains: false, preload: false } : null,
    compression: draft.compressionMode === 'inherit' ? null : {
      enabled: draft.compressionMode === 'on',
      types: draft.compressionMode === 'on' ? lines(draft.compressionTypes).map((value) => value.toLowerCase()) : [],
      min_length_bytes: settings.compression?.min_length_bytes ?? 256,
      ...(draft.compressionMode === 'on' && (encodings.length !== 1 || encodings[0] !== 'gzip') ? { encodings } : {}),
      ...(draft.compressionMode === 'on' && gzipLevel ? { gzip_level: gzipLevel } : {}),
      ...(draft.compressionMode === 'on' && brotliLevel ? { brotli_level: brotliLevel } : {}),
    },
    limits: draft.limitsOn ? settings.limits ?? {} : null,
    basic_auth: draft.authOn && settings.basic_auth ? {
      ...settings.basic_auth,
      users: settings.basic_auth.users.map((user) => user.password ? user : { username: user.username }),
      exclude_path_prefixes: lines(draft.excludePrefixes),
    } : null,
    maintenance: draft.maintenanceOn ? {
      ...maintenance,
      ...(cidrs.length ? { allowed_cidrs: cidrs } : { allowed_cidrs: undefined }),
      ...(maintenance.retry_after_seconds ? {} : { retry_after_seconds: undefined }),
    } : null,
    webp: draft.webpOn ? { enabled: true, ...(settings.webp?.quality ? { quality: settings.webp.quality } : {}) } : null,
    response_rules: (settings.response_rules ?? []).map(cleanRule),
    force_https: settings.force_https,
  }
}

/** The feature cards of the panel, one per settings key. */
export type SiteAccessPart = 'forceHttps' | 'hostRedirects' | 'hsts' | 'compression' | 'webp' | 'responseRules' | 'limits' | 'basicAuth' | 'maintenance'
const partKeys: Record<SiteAccessPart, keyof SiteAccessSettings> = {
  forceHttps: 'force_https', hostRedirects: 'host_redirects', hsts: 'hsts', compression: 'compression', webp: 'webp',
  responseRules: 'response_rules', limits: 'limits', basicAuth: 'basic_auth', maintenance: 'maintenance',
}
const allParts = Object.keys(partKeys) as SiteAccessPart[]

/**
 * The PUT body: the cards this panel shows come from the draft, the others
 * from the stored state (the same body an untouched panel sends), so two
 * panels splitting the cards (tp-b3c: Gzip sits in 性能与协议) never undo
 * each other.
 */
function bodyFrom(state: SiteAccessState, draft: Draft, parts: readonly SiteAccessPart[]): SiteAccessSettings {
  const stored = settingsFrom(draftFrom(state))
  const edited = settingsFrom(draft)
  const owned = new Set(parts.map((part) => partKeys[part]))
  return Object.fromEntries((Object.keys(stored) as (keyof SiteAccessSettings)[])
    .map((key) => [key, owned.has(key) ? edited[key] : stored[key]])) as unknown as SiteAccessSettings
}

/** Rows still being filled in (a new redirect / user) are not sent; the server would refuse them. */
function draftComplete(state: SiteAccessState, draft: Draft): boolean {
  const settings = draft.settings
  const hsts = settings.hsts
  if (draft.hstsOn && hsts?.preload && (!hsts.include_subdomains || hsts.max_age_seconds < hstsPreloadMinimum)) return false
  if (settings.host_redirects.some((redirect) => !redirect.source_host || !redirect.target_host)) return false
  if (draft.authOn) {
    const users = settings.basic_auth?.users ?? []
    const known = new Set(state.settings.basic_auth?.users.map((user) => user.username) ?? [])
    if (users.some((user) => !user.username || !user.password && !known.has(user.username))) return false
  }
  return true
}

/**
 * 站点“访问控制”页的访问处理设置：只改本站，
 * 保存推进站点版本，自动发布范围随即发布。`parts` 只渲染其中几张卡片（不带区块标题）。
 */
export default function SiteAccessPanel({ siteId, accessToken, canManage, locked, parts }: {
  siteId: string
  accessToken: string
  canManage: boolean
  locked: boolean
  parts?: readonly SiteAccessPart[]
}) {
  const { t } = useTranslation('siteAccess')
  const stateQuery = useQuery({
    queryKey: ['site-access', siteId],
    retry: false,
    queryFn: ({ signal }) => siteAccessApi.get(accessToken, siteId, signal),
  })
  const state = stateQuery.data
  if (stateQuery.isPending) return <SiteEditState status="loading" label={t('loading')} />
  if (stateQuery.isError || !state) {
    return <SiteEditState status="error" title={t('loadFailed')} onRetry={() => void stateQuery.refetch()} />
  }
  return <SiteAccessForm siteId={siteId} accessToken={accessToken} canManage={canManage} locked={locked} parts={parts}
    state={state} refetching={stateQuery.isFetching} refetch={() => void stateQuery.refetch()} />
}

function SiteAccessForm({ siteId, accessToken, canManage, locked, parts, state, refetching, refetch }: {
  siteId: string
  accessToken: string
  canManage: boolean
  locked: boolean
  parts?: readonly SiteAccessPart[]
  state: SiteAccessState
  refetching: boolean
  refetch: () => void
}) {
  const { t } = useTranslation('siteAccess')
  const queryClient = useQueryClient()
  const feedback = useInstantFeedback()
  const [compressionOpen, setCompressionOpen] = useState(false)
  const shown = parts ?? allParts
  const has = (part: SiteAccessPart) => shown.includes(part)
  const save = useMutation({
    mutationFn: (draft: Draft) => siteAccessApi.put(accessToken, siteId, state.version, bodyFrom(state, draft, shown),
      `site-access-${siteId}-${state.version}-${crypto.randomUUID()}`),
    onSuccess: (updated) => {
      feedback.success()
      queryClient.setQueryData(['site-access', siteId], updated)
    },
    onError: (error) => {
      // 失败：控件回滚到服务端值，下方就地显示原因；版本冲突重读最新值。
      instant.revert()
      if (error instanceof ApiError && error.code === 'version_conflict') refetch()
    },
  })
  // 改动即保存（开关/单选/下拉立即，文本与数字失焦或回车）；
  // 没填完的新行（跳转、用户）等填完再发。
  const instant = useInstantDraft(useMemo(() => draftFrom(state), [state]), {
    busy: save.isPending || refetching,
    isChanged: (value, stored) => JSON.stringify(bodyFrom(state, value, shown)) !== JSON.stringify(bodyFrom(state, stored, shown)),
    isValid: (value) => draftComplete(state, value),
    submit: (value) => save.mutate(value),
  })
  const draft = instant.draft
  const disabled = !canManage || locked
  const set = (patch: Partial<Draft>) => { save.reset(); instant.set(patch) }
  const setSettings = (patch: Partial<SiteAccessSettings>) =>
    set({ settings: { ...draft.settings, ...patch } })
  // compression fields besides mode and types (kept across edits; types come from the draft text)
  const setCompression = (patch: Partial<SiteCompression>) =>
    setSettings({ compression: { enabled: true, types: [], min_length_bytes: 256, ...draft.settings.compression, ...patch } })
  const plainDomains = state.domains.filter((domain) => !domain.startsWith('*.'))
  const redirects = draft.settings.host_redirects
  const updateRedirect = (index: number, patch: Partial<HostRedirect>) =>
    setSettings({ host_redirects: redirects.map((redirect, position) => position === index ? { ...redirect, ...patch } : redirect) })
  const hsts = draft.settings.hsts ?? { max_age_seconds: 31536000, include_subdomains: false, preload: false }
  const limits = draft.settings.limits ?? {}
  const auth = draft.settings.basic_auth ?? { realm: 'restricted', users: [], exclude_path_prefixes: [] }
  const maintenance = draft.settings.maintenance ?? defaultMaintenance()
  const preloadInvalid = draft.hstsOn && hsts.preload && (!hsts.include_subdomains || hsts.max_age_seconds < hstsPreloadMinimum)
  const errorCode = save.error instanceof ApiError ? save.error.code : ''
  const errorMessage = save.isError
    ? knownErrors.includes(errorCode) ? t(`errors.${errorCode}`) : t('errors.unknown', { code: errorCode || (save.error as Error).message })
    : null

  const content = <>
      {!parts && !canManage ? <Alert type="info" showIcon message={t('readOnly')} /> : null}
      {!parts && locked ? <Alert type="warning" showIcon message={t('locked')} /> : null}

      {has('forceHttps') ? <>
      <SettingGroup title={t('forceHttps.title')} status={!state.force_https ? t('inactive') : undefined}
        help={!state.force_https ? t('forceHttps.notEnabled') : undefined}>
      <FormRow label={t('forceHttps.status')} help={t('forceHttps.statusHint')}>
        <Radio.Group aria-label={t('forceHttps.status')} optionType="button" value={draft.settings.force_https.status}
          disabled={disabled || !state.https_enabled}
          options={statuses.map((value) => ({ value, label: String(value) }))}
          onChange={(event) => setSettings({ force_https: { ...draft.settings.force_https, status: event.target.value as RedirectStatus } })} />
      </FormRow>
      <FormRow label={t('forceHttps.exclude')} help={t('forceHttps.excludeHint')}>
        <Select mode="multiple" aria-label={t('forceHttps.exclude')} style={{ width: '100%', maxWidth: 520 }}
          value={draft.settings.force_https.exclude_hosts} disabled={disabled || !state.https_enabled}
          options={plainDomains.map((value) => ({ value, label: value }))}
          onChange={(value: string[]) => setSettings({ force_https: { ...draft.settings.force_https, exclude_hosts: value } })} />
      </FormRow>
      </SettingGroup>
      </> : null}

      {has('hostRedirects') ? <>
      <SettingGroup title={t('hostRedirects.title')} help={t('hostRedirects.hint')}>
      {redirects.map((redirect, index) => <Space key={index} wrap>
        <Select aria-label={`${t('hostRedirects.source')} ${index + 1}`} style={{ width: 220 }} value={redirect.source_host || undefined}
          placeholder={t('hostRedirects.source')} disabled={disabled} options={plainDomains.map((value) => ({ value, label: value }))}
          onChange={(value: string) => updateRedirect(index, { source_host: value })} />
        <Input aria-label={`${t('hostRedirects.target')} ${index + 1}`} style={{ width: 220 }} value={redirect.target_host}
          placeholder={t('hostRedirects.target')} disabled={disabled} onChange={(event) => updateRedirect(index, { target_host: event.target.value.trim().toLowerCase() })} />
        <Select aria-label={`${t('hostRedirects.scheme')} ${index + 1}`} style={{ width: 130 }} value={redirect.target_scheme} disabled={disabled}
          options={(['follow', 'https', 'http'] as const).map((value) => ({ value, label: t(`hostRedirects.schemes.${value}`) }))}
          onChange={(value) => updateRedirect(index, { target_scheme: value })} />
        <InputNumber aria-label={`${t('hostRedirects.port')} ${index + 1}`} min={1} max={65535} placeholder={t('hostRedirects.port')}
          value={redirect.target_port} disabled={disabled} onChange={(value) => updateRedirect(index, { target_port: value ?? undefined })} />
        <Select aria-label={`${t('hostRedirects.status')} ${index + 1}`} style={{ width: 90 }} value={redirect.status} disabled={disabled}
          options={statuses.map((value) => ({ value, label: String(value) }))} onChange={(value) => updateRedirect(index, { status: value })} />
        <Checkbox checked={redirect.preserve_uri} disabled={disabled} onChange={(event) => updateRedirect(index, { preserve_uri: event.target.checked })}>
          {t('hostRedirects.preserveUri')}</Checkbox>
        {canManage ? <Button danger icon={<Trash2 size={15} />} disabled={disabled}
          onClick={() => setSettings({ host_redirects: redirects.filter((_, position) => position !== index) })}>{t('hostRedirects.remove')}</Button> : null}
      </Space>)}
      {canManage ? <Button icon={<Plus size={15} />} disabled={disabled || redirects.length >= 100}
        onClick={() => setSettings({ host_redirects: [...redirects, { source_host: '', target_host: '', target_scheme: 'follow', status: 301, preserve_uri: true }] })}>
        {t('hostRedirects.add')}</Button> : null}
      </SettingGroup>
      </> : null}

      {has('hsts') ? <>
      <SettingGroup title={t('hsts.title')} status={!state.https_enabled ? t('inactive') : undefined}
        help={!state.https_enabled ? t('hsts.needsHttps') : t('hsts.hint')} tip={!state.https_enabled ? t('hsts.hint') : undefined}>
      <FormRow label={t('enabled')}>
        <Switch aria-label={t('hsts.title')} checked={draft.hstsOn} disabled={disabled || !state.https_enabled} onChange={(value) => set({ hstsOn: value })} />
      </FormRow>
      {draft.hstsOn ? <>
        <FormRow label={t('hsts.maxAge')}>
          <InputNumber aria-label={t('hsts.maxAge')} min={0} max={63072000} value={hsts.max_age_seconds} disabled={disabled}
            onChange={(value) => setSettings({ hsts: { ...hsts, max_age_seconds: value ?? 0 } })} />
        </FormRow>
        <FormRow label={t('hsts.includeSubdomains')}>
          <Switch aria-label={t('hsts.includeSubdomains')} checked={hsts.include_subdomains} disabled={disabled}
            onChange={(value) => setSettings({ hsts: { ...hsts, include_subdomains: value } })} />
        </FormRow>
        <FormRow label={t('hsts.preload')} help={t('hsts.preloadHint')}>
          <Switch aria-label={t('hsts.preload')} checked={hsts.preload} disabled={disabled}
            onChange={(value) => setSettings({ hsts: { ...hsts, preload: value } })} />
        </FormRow>
        {preloadInvalid ? <FeedbackWhen type="warning" title={t('hsts.preloadHint')} /> : null}
      </> : null}
      </SettingGroup>
      </> : null}

      {has('compression') ? (() => {
        const modeControl = (size?: 'small') => (
          <Radio.Group aria-label={t('compression.mode')} optionType="button" size={size} value={draft.compressionMode} disabled={disabled}
            options={(['inherit', 'on', 'off'] as const).map((value) => ({ value, label: t(`compression.modes.${value}`) }))}
            onChange={(event) => {
              const mode = event.target.value as CompressionMode
              set({ compressionMode: mode })
              // site-parity3a：卡片里只放三态；选「本站开启」时弹出压缩方式设置
              if (parts && mode === 'on') setCompressionOpen(true)
            }} />
        )
        const detailFields = <>
        <FormRow label={t('compression.types')} help={t('compression.typesHint')}>
          <Input.TextArea aria-label={t('compression.types')} rows={4} value={draft.compressionTypes} disabled={disabled}
            onChange={(event) => set({ compressionTypes: event.target.value })} />
        </FormRow>
        <FormRow label={t('compression.minLength')}>
          <InputNumber aria-label={t('compression.minLength')} min={0} value={draft.settings.compression?.min_length_bytes ?? 256} disabled={disabled}
            onChange={(value) => setCompression({ min_length_bytes: value ?? 0 })} />
        </FormRow>
        <FormRow label={t('compression.encodings')} help={t('compression.encodingsHint')}>
          <Checkbox.Group aria-label={t('compression.encodings')} disabled={disabled}
            value={encodingsOf(draft.settings.compression)}
            options={encodingOrder.map((value) => ({ value, label: t(`compression.encoding.${value}`) }))}
            onChange={(values) => {
              const picked = encodingOrder.filter((value) => (values as CompressionEncoding[]).includes(value))
              if (picked.length) setCompression({ encodings: picked })
            }} />
        </FormRow>
        {encodingsOf(draft.settings.compression).includes('gzip') ? (
          <FormRow label={t('compression.gzipLevel')} help={t('compression.levelHint')}>
            <InputNumber aria-label={t('compression.gzipLevel')} min={0} max={9} disabled={disabled}
              value={draft.settings.compression?.gzip_level ?? 0}
              onChange={(value) => setCompression({ gzip_level: value ?? 0 })} />
          </FormRow>
        ) : null}
        {encodingsOf(draft.settings.compression).includes('br') ? (
          <FormRow label={t('compression.brotliLevel')} help={t('compression.levelHint')}>
            <InputNumber aria-label={t('compression.brotliLevel')} min={0} max={11} disabled={disabled}
              value={draft.settings.compression?.brotli_level ?? 0}
              onChange={(value) => setCompression({ brotli_level: value ?? 0 })} />
          </FormRow>
        ) : null}
        {encodingsOf(draft.settings.compression).includes('br') || draft.settings.compression?.gzip_level
          ? <Alert type="info" showIcon message={t('compression.nodeHint')} /> : null}
</>
        // 高级设置的性能与协议按三张等宽卡片排，三态选择放卡片右上；
        // 「本站开启」的类型/算法/级别放进「压缩方式」弹层用正常宽度表单，不在窄卡片里挤成多行。
        if (parts) return (
          <SettingGroup title={t('compression.title')} help={t('compression.hint')} extra={modeControl('small')}>
            {draft.compressionMode === 'on' ? (
              <Button type="link" size="small" className="site-compression-detail-link" onClick={() => setCompressionOpen(true)}>
                {t('compression.detailOpen')}
              </Button>
            ) : null}
            <Modal title={t('compression.mode')} open={compressionOpen} width={MODAL_WIDTH.M} onCancel={() => setCompressionOpen(false)}
              footer={<div className="cdnca-modal-footer"><Button type="primary" onClick={() => setCompressionOpen(false)}>{t('compression.detailDone')}</Button></div>}>
              <div className="site-compression-modal">{detailFields}</div>
            </Modal>
          </SettingGroup>
        )
        return (
          <SettingGroup title={t('compression.title')} help={t('compression.hint')}>
          <FormRow label={t('compression.mode')}>{modeControl()}</FormRow>
          {draft.compressionMode === 'on' ? detailFields : null}
          </SettingGroup>
        )
      })() : null}

      {has('webp') ? <>
      <SettingGroup title={t('webp.title')} tip={t('webp.hint')}>
      <FormRow label={t('enabled')}>
        <Switch aria-label={t('webp.title')} checked={draft.webpOn} disabled={disabled} onChange={(value) => set({ webpOn: value })} />
      </FormRow>
      {draft.webpOn ? (
        <FormRow label={t('webp.quality')} help={t('webp.qualityHint')}>
          <InputNumber aria-label={t('webp.quality')} min={0} max={100} disabled={disabled}
            value={draft.settings.webp?.quality ?? 0}
            onChange={(value) => setSettings({ webp: { enabled: true, ...(value ? { quality: value } : {}) } })} />
        </FormRow>
      ) : null}
      </SettingGroup>
      </> : null}

      {has('responseRules') ? <SiteResponseRulesEditor rules={draft.settings.response_rules ?? []} statusTexts={draft.statusTexts} disabled={disabled}
        onChange={(rules, statusTexts) => set({ statusTexts, settings: { ...draft.settings, response_rules: rules } })}
        onStatusText={(index, text) => set({
          statusTexts: draft.statusTexts.map((value, position) => position === index ? text : value),
          settings: { ...draft.settings, response_rules: (draft.settings.response_rules ?? []).map((rule, position) =>
            position === index ? { ...rule, statuses: parseStatuses(text) } : rule) },
        })} /> : null}

      {has('limits') ? <>
      <SettingGroup title={t('limits.title')} help={t('limits.hint')}>
      <FormRow label={t('enabled')}>
        <Switch aria-label={t('limits.title')} checked={draft.limitsOn} disabled={disabled} onChange={(value) => set({ limitsOn: value })} />
      </FormRow>
      {draft.limitsOn ? <>
        <FormRow label={t('limits.connections')} help={t('limits.connectionsHint')}>
          <InputNumber aria-label={t('limits.connections')} min={0} max={65535} value={limits.connections_per_ip ?? 0} disabled={disabled}
            onChange={(value) => setSettings({ limits: { ...limits, connections_per_ip: value || undefined } })} />
        </FormRow>
        <FormRow label={t('limits.rate')} help={t('limits.rateHint')}>
          <InputNumber aria-label={t('limits.rate')} min={0} value={Math.round((limits.rate_bytes_per_second ?? 0) / 1024)} disabled={disabled}
            onChange={(value) => setSettings({ limits: { ...limits, rate_bytes_per_second: value ? value * 1024 : undefined } })} />
        </FormRow>
        <FormRow label={t('limits.rateAfter')}>
          <InputNumber aria-label={t('limits.rateAfter')} min={0} value={Math.round((limits.rate_after_bytes ?? 0) / 1024)}
            disabled={disabled || !limits.rate_bytes_per_second}
            onChange={(value) => setSettings({ limits: { ...limits, rate_after_bytes: value ? value * 1024 : undefined } })} />
        </FormRow>
      </> : null}
      </SettingGroup>
      </> : null}

      {has('basicAuth') ? <>
      <SettingGroup title={t('basicAuth.title')} help={t('basicAuth.hint')}>
      <FormRow label={t('enabled')}>
        <Switch aria-label={t('basicAuth.title')} checked={draft.authOn} disabled={disabled}
          onChange={(value) => set({ authOn: value, settings: { ...draft.settings, basic_auth: draft.settings.basic_auth ?? auth } })} />
      </FormRow>
      {draft.authOn ? <>
        <FormRow label={t('basicAuth.realm')}>
          <Input aria-label={t('basicAuth.realm')} style={{ maxWidth: 320 }} value={auth.realm} disabled={disabled}
            onChange={(event) => setSettings({ basic_auth: { ...auth, realm: event.target.value } })} />
        </FormRow>
        {auth.users.map((user, index) => <Space key={index} wrap>
          <Input aria-label={`${t('basicAuth.username')} ${index + 1}`} style={{ width: 200 }} value={user.username} disabled={disabled}
            placeholder={t('basicAuth.username')} onChange={(event) => setSettings({ basic_auth: { ...auth,
              users: auth.users.map((item, position) => position === index ? { ...item, username: event.target.value.trim() } : item) } })} />
          <Input.Password aria-label={`${t('basicAuth.password')} ${index + 1}`} style={{ width: 220 }} value={user.password ?? ''}
            disabled={disabled} autoComplete="new-password"
            placeholder={state.settings.basic_auth?.users.some((stored) => stored.username === user.username) ? t('basicAuth.passwordKeep') : t('basicAuth.passwordNew')}
            onChange={(event) => setSettings({ basic_auth: { ...auth,
              users: auth.users.map((item, position) => position === index ? { ...item, password: event.target.value || undefined } : item) } })} />
          {canManage ? <Button danger icon={<Trash2 size={15} />} disabled={disabled}
            onClick={() => setSettings({ basic_auth: { ...auth, users: auth.users.filter((_, position) => position !== index) } })}>
            {t('basicAuth.remove')}</Button> : null}
        </Space>)}
        {canManage ? <Button icon={<Plus size={15} />} disabled={disabled || auth.users.length >= 64}
          onClick={() => setSettings({ basic_auth: { ...auth, users: [...auth.users, { username: '' }] } })}>{t('basicAuth.add')}</Button> : null}
        <FormRow label={t('basicAuth.exclude')} help={t('basicAuth.excludeHint')}>
          <Input.TextArea aria-label={t('basicAuth.exclude')} rows={2} value={draft.excludePrefixes} disabled={disabled}
            onChange={(event) => set({ excludePrefixes: event.target.value })} />
        </FormRow>
      </> : null}
      </SettingGroup>
      </> : null}

      {has('maintenance') ? <>
      <SettingGroup title={t('maintenance.title')} help={t('maintenance.hint')}>
      <FormRow label={t('enabled')}>
        <Switch aria-label={t('maintenance.title')} checked={draft.maintenanceOn} disabled={disabled}
          onChange={(value) => set({ maintenanceOn: value, settings: { ...draft.settings, maintenance: draft.settings.maintenance ?? maintenance } })} />
      </FormRow>
      {draft.maintenanceOn ? <>
        <FormRow label={t('maintenance.status')}>
          <InputNumber aria-label={t('maintenance.status')} min={200} max={599} value={maintenance.status} disabled={disabled}
            onChange={(value) => setSettings({ maintenance: { ...maintenance, status: value ?? 503 } })} />
        </FormRow>
        <FormRow label={t('maintenance.contentType')}>
          <Select aria-label={t('maintenance.contentType')} style={{ width: 200 }} value={maintenance.content_type} disabled={disabled}
            options={(['text/html', 'text/plain', 'application/json'] as const).map((value) => ({ value, label: value }))}
            onChange={(value) => setSettings({ maintenance: { ...maintenance, content_type: value } })} />
        </FormRow>
        <FormRow label={t('maintenance.body')}>
          <Input.TextArea aria-label={t('maintenance.body')} rows={4} value={maintenance.body} disabled={disabled} maxLength={65536}
            onChange={(event) => setSettings({ maintenance: { ...maintenance, body: event.target.value } })} />
        </FormRow>
        <FormRow label={t('maintenance.retryAfter')}>
          <InputNumber aria-label={t('maintenance.retryAfter')} min={0} max={604800} value={maintenance.retry_after_seconds} disabled={disabled}
            onChange={(value) => setSettings({ maintenance: { ...maintenance, retry_after_seconds: value ?? undefined } })} />
        </FormRow>
        <FormRow label={t('maintenance.allowed')} help={t('maintenance.allowedHint')}>
          <Input.TextArea aria-label={t('maintenance.allowed')} rows={2} value={draft.allowedCIDRs} disabled={disabled}
            onChange={(event) => set({ allowedCIDRs: event.target.value })} />
        </FormRow>
      </> : null}
      </SettingGroup>
      </> : null}

      {errorMessage ? <FeedbackWhen title={errorMessage} /> : null}
  </>
  return parts ? <div className="site-setting-parts" aria-busy={save.isPending} {...instant.typingProps}>{content}</div>
    : <SettingSection title={t('title')} help={t('hint')} tip={t('streamingHint')}>
      <div aria-busy={save.isPending} {...instant.typingProps}>{content}</div>
    </SettingSection>
}
