import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Input, InputNumber, Select, Space, Switch, Tag } from 'antd'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { siteTrafficLimitApi, type SiteTrafficLimitSetting, type SiteTrafficLimitState } from '../../api/siteTrafficLimit'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/siteTrafficLimit'
import { FormRow } from './SiteEditFields'
import { useInstantDraft, useInstantFeedback } from './instantSave'
import { FeedbackWhen } from '@cdnca/ui'

const gib = 1024 ** 3
const maxNoticeBytes = 64 * 1024
const timeZones = ['Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Tokyo', 'Asia/Singapore', 'Europe/London', 'America/New_York', 'UTC']

interface Draft {
  enabled: boolean
  daily: number | null
  monthly: number | null
  total: number | null
  timeZone: string
  notice: string
}

const toGiB = (value: number | null) => value === null ? null : Math.round(value / gib * 1000) / 1000
const toBytes = (value: number | null) => value === null ? null : Math.round(value * gib)

function draftFrom(state: SiteTrafficLimitState | undefined): Draft {
  const setting = state?.setting
  return {
    enabled: setting?.enabled ?? false,
    daily: toGiB(setting?.daily_bytes ?? null),
    monthly: toGiB(setting?.monthly_bytes ?? null),
    total: toGiB(setting?.total_bytes ?? null),
    timeZone: setting?.time_zone || 'Asia/Shanghai',
    notice: setting?.notice_html ?? '',
  }
}

const knownErrors = ['validation_error', 'version_conflict', 'site_locked', 'idempotency_conflict'] as const

/**
 * 网站“高级”页“网站流量上限”（ge-analytics）：本站每日 / 每月 / 总流量上限与
 * 超限提示页。Saving advances the site version (an automatic scope publishes
 * it); the control plane measures usage and switches the nodes to the notice
 * page (509) once a cap is reached.
 */
export function SiteTrafficLimitCard({ siteId, accessToken, canManage }: {
  siteId: string
  accessToken: string
  canManage: boolean
}) {
  const { t, i18n } = useTranslation('siteTrafficLimit')
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const queryClient = useQueryClient()
  const queryKey = ['site-traffic-limit', siteId]
  const stateQuery = useQuery({
    queryKey,
    retry: false,
    queryFn: ({ signal }) => siteTrafficLimitApi.get(accessToken, siteId, signal),
  })
  const state = stateQuery.data
  const feedback = useInstantFeedback()
  const save = useMutation({
    mutationFn: (draft: Draft) => {
      if (!state) throw new Error('site traffic limit not loaded')
      const setting: SiteTrafficLimitSetting = {
        enabled: draft.enabled, daily_bytes: toBytes(draft.daily), monthly_bytes: toBytes(draft.monthly),
        total_bytes: toBytes(draft.total), time_zone: draft.timeZone, notice_html: draft.notice,
      }
      return siteTrafficLimitApi.put(accessToken, siteId, state.version, setting,
        `site-traffic-limit-${siteId}-${state.version}-${crypto.randomUUID()}`)
    },
    onSuccess: (updated) => {
      feedback.success()
      queryClient.setQueryData(queryKey, updated)
      void queryClient.invalidateQueries({ queryKey: ['site'] })
    },
    onError: (error) => {
      // 失败：控件回滚到服务端值，下方就地显示原因。
      instant.revert()
      if (error instanceof ApiError && error.code === 'version_conflict') void stateQuery.refetch()
    },
  })

  // fix-siteinstant：改动即保存（开关/下拉立即，数字与提示页失焦或回车）。
  const instant = useInstantDraft(useMemo(() => draftFrom(state), [state]), {
    busy: save.isPending || stateQuery.isFetching,
    isValid: (value) => !(value.enabled && value.daily === null && value.monthly === null && value.total === null) &&
      new TextEncoder().encode(value.notice).length <= maxNoticeBytes,
    submit: (value) => save.mutate(value),
  })
  const draft = instant.draft
  const noticeBytes = useMemo(() => new TextEncoder().encode(draft.notice).length, [draft.notice])
  const noCap = draft.enabled && draft.daily === null && draft.monthly === null && draft.total === null
  const tooLarge = noticeBytes > maxNoticeBytes
  if (stateQuery.isPending) return null
  if (stateQuery.isError || !state) {
    return <FeedbackWhen title={t('loadFailed')} action={<Button size="small" onClick={() => void stateQuery.refetch()}>{t('retry')}</Button>} />
  }
  const set = (patch: Partial<Draft>) => { save.reset(); instant.set(patch) }
  const disabled = !canManage
  const errorCode = save.error instanceof ApiError ? save.error.code : ''
  const errorMessage = save.isError
    ? (knownErrors as readonly string[]).includes(errorCode) ? t(`errors.${errorCode}`)
      : t('errors.unknown', { code: errorCode || (save.error as Error).message })
    : null
  const exceeded = state.exceeded_period
  const cap = (key: 'daily' | 'monthly' | 'total') => {
    const id = `site-traffic-limit-${key}`
    return <FormRow label={<label htmlFor={id}>{t(key)}</label>}>
      <InputNumber id={id} min={0.001} step={1} precision={3} value={draft[key]}
        placeholder={t('capPlaceholder')} disabled={disabled} onChange={(value) => set({ [key]: value ?? null } as Partial<Draft>)} />
    </FormRow>
  }

  return <section className="site-setting-section site-traffic-limit" aria-labelledby="site-traffic-limit-title" aria-busy={save.isPending} {...instant.typingProps}>
    <div className="site-basic-title-line"><h2 id="site-traffic-limit-title">{t('title')}{' '}
      <Tag color={exceeded ? 'error' : 'default'}>{exceeded ? t(`status.${exceeded}`) : t('status.within')}</Tag></h2></div>
    <p className="site-setting-section-help">{t('hint')}</p>
    <FormRow label={t('enabled')}>
      <Switch aria-label={t('enabled')} checked={draft.enabled} disabled={disabled} onChange={(enabled) => set({ enabled })} />
    </FormRow>
    {cap('daily')}{cap('monthly')}{cap('total')}
    <FormRow label={<label htmlFor="site-traffic-limit-zone">{t('timeZone')}</label>}>
      <Select id="site-traffic-limit-zone" aria-label={t('timeZone')} value={draft.timeZone} disabled={disabled}
        options={[...new Set([draft.timeZone, ...timeZones])].map((value) => ({ value, label: value }))}
        onChange={(timeZone) => set({ timeZone })} />
    </FormRow>
    <FormRow label={<label htmlFor="site-traffic-limit-notice">{t('notice')}</label>}>
      <Input.TextArea id="site-traffic-limit-notice" rows={5} value={draft.notice} disabled={disabled}
        placeholder={t('noticePlaceholder')} status={tooLarge ? 'error' : undefined} onChange={(event) => set({ notice: event.target.value })} />
    </FormRow>
    {tooLarge ? <Alert type="error" showIcon message={t('noticeTooLarge')} /> : null}
    {noCap ? <Alert type="warning" showIcon message={t('needCap')} /> : null}
    {state.evaluated_at || state.total_since ? <FormRow label="" help={<Space wrap>
      {state.evaluated_at ? <span>{t('status.evaluated', { time: formatDateTime(state.evaluated_at, language) })}</span> : null}
      {state.total_since ? <span>{t('status.totalSince', { time: formatDateTime(state.total_since, language) })}</span> : null}
    </Space>}>{null}</FormRow> : null}
    {errorMessage ? <FeedbackWhen title={errorMessage} /> : null}
  </section>
}
