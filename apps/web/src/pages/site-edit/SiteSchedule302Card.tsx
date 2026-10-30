import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Checkbox, Input, InputNumber, Radio, Space, Switch } from 'antd'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  SCHEDULE302_TTL_MAX, SCHEDULE302_TTL_MIN, siteSchedule302Api, splitList,
  type Schedule302Settings, type Schedule302State, type Schedule302Target,
} from '../../api/siteSchedule302'
import '../../i18n/siteSchedule302'
import { FormRow } from './SiteEditFields'
import { useInstantDraft, useInstantFeedback } from './instantSave'
import { FeedbackWhen } from '@cdnca/ui'

interface Draft {
  enabled: boolean
  target: Schedule302Target
  keepPath: boolean
  keepQuery: boolean
  ttl: number | null
  httpsToHttp: boolean
  extensions: string
  pathPrefixes: string
  minSizeMB: number | null
}

const MB = 1024 * 1024

function draftFrom(state: Schedule302State | undefined): Draft {
  const settings = state?.settings
  return {
    enabled: settings?.enabled ?? false, target: settings?.target ?? 'address',
    keepPath: settings?.keep_path ?? true, keepQuery: settings?.keep_query ?? true,
    ttl: settings?.signature_ttl_seconds ?? 60, httpsToHttp: settings?.https_to_http ?? false,
    extensions: (settings?.extensions ?? []).join(', '), pathPrefixes: (settings?.path_prefixes ?? []).join(' '),
    minSizeMB: settings ? settings.min_size_bytes / MB : 0,
  }
}

const ttlBad = (draft: Draft) => draft.enabled && (draft.ttl === null || !Number.isInteger(draft.ttl) ||
  draft.ttl < SCHEDULE302_TTL_MIN || draft.ttl > SCHEDULE302_TTL_MAX)
const sizeBad = (draft: Draft) => draft.enabled && (draft.minSizeMB === null || draft.minSizeMB < 0)

const knownErrors = ['schedule302_no_plain_http', 'version_conflict', 'idempotency_conflict', 'site_locked', 'validation_error'] as const

/**
 * 网站“高级”页“302 调度”：开关、跳转目标、保留路径/参数、签名有效期、
 * HTTPS 是否也跳转、只对大文件跳转的过滤（扩展名 / 路径前缀 / 学习到的大小）。
 * Saving advances the site version; an automatic scope publishes it.
 */
export function SiteSchedule302Card({ siteId, accessToken, canManage }: {
  siteId: string
  accessToken: string
  canManage: boolean
}) {
  const { t } = useTranslation('siteSchedule302')
  const queryClient = useQueryClient()
  const queryKey = ['site-schedule302', siteId]
  const stateQuery = useQuery({
    queryKey, retry: false,
    queryFn: ({ signal }) => siteSchedule302Api.get(accessToken, siteId, signal),
  })
  const state = stateQuery.data
  const feedback = useInstantFeedback()
  const save = useMutation({
    mutationFn: (draft: Draft) => {
      if (!state) throw new Error('302 scheduling not loaded')
      const settings: Schedule302Settings = {
        enabled: draft.enabled, target: draft.target, keep_path: draft.keepPath, keep_query: draft.keepQuery,
        signature_ttl_seconds: draft.ttl ?? 60, https_to_http: draft.httpsToHttp,
        extensions: splitList(draft.extensions), path_prefixes: splitList(draft.pathPrefixes),
        min_size_bytes: Math.round((draft.minSizeMB ?? 0) * MB),
      }
      return siteSchedule302Api.replace(accessToken, siteId, state.version, settings,
        `site-schedule302-${siteId}-${state.version}-${crypto.randomUUID()}`)
    },
    onSuccess: (updated) => {
      feedback.success()
      queryClient.setQueryData(queryKey, updated)
    },
    onError: (error) => {
      // 失败：控件回滚到服务端值，下方就地显示原因；版本冲突重读最新值。
      instant.revert()
      if (error instanceof ApiError && error.code === 'version_conflict') void stateQuery.refetch()
    },
  })
  // 改动即保存（开关/单选/勾选立即，文本与数字失焦或回车）。
  const instant = useInstantDraft(useMemo(() => draftFrom(state), [state]), {
    busy: save.isPending || stateQuery.isFetching,
    isValid: (value) => !ttlBad(value) && !sizeBad(value) && !(value.enabled && !state?.plain_http),
    submit: (value) => save.mutate(value),
  })
  const draft = instant.draft

  if (stateQuery.isPending) return null
  if (stateQuery.isError || !state) {
    return <FeedbackWhen title={t('loadFailed')} action={<Button size="small" onClick={() => void stateQuery.refetch()}>{t('retry')}</Button>} />
  }
  const disabled = !canManage
  const set = (patch: Partial<Draft>) => { save.reset(); instant.set(patch) }
  const ttlInvalid = ttlBad(draft)
  const sizeInvalid = sizeBad(draft)
  const errorCode = save.error instanceof ApiError ? save.error.code : ''
  const errorMessage = save.isError
    ? (knownErrors as readonly string[]).includes(errorCode) ? t(`errors.${errorCode}`)
      : t('errors.unknown', { code: errorCode || (save.error as Error).message })
    : null
  const blocked = draft.enabled && !state.plain_http

  return <section className="site-setting-section site-schedule302" aria-labelledby="site-schedule302-title" aria-busy={save.isPending} {...instant.typingProps}>
    <div className="site-basic-title-line"><h2 id="site-schedule302-title">{t('title')}</h2></div>
    <p className="site-setting-section-help">{t('hint')}</p>
    <Alert type="warning" showIcon message={t('warning')} />
    <FormRow label={t('enabled')}>
      <Switch checked={draft.enabled} disabled={disabled} aria-label={t('enabled')} onChange={(enabled) => set({ enabled })} />
    </FormRow>
    {blocked ? <Alert type="error" showIcon message={t('noPlainHTTP')} /> : null}
    {draft.enabled ? <>
      <FormRow label={t('target')} labelId="site-schedule302-target-label">
        <Radio.Group name="site-schedule302-target" aria-labelledby="site-schedule302-target-label" value={draft.target} disabled={disabled}
          onChange={(event) => set({ target: event.target.value as Schedule302Target })}
          options={[{ value: 'address', label: t('targetAddress') }, { value: 'hostname', label: t('targetHostname') }]} />
      </FormRow>
      <FormRow label={t('keepLabel')}>
        <Space>
          <Checkbox checked={draft.keepPath} disabled={disabled} onChange={(event) => set({ keepPath: event.target.checked })}>{t('keepPath')}</Checkbox>
          <Checkbox checked={draft.keepQuery} disabled={disabled} onChange={(event) => set({ keepQuery: event.target.checked })}>{t('keepQuery')}</Checkbox>
        </Space>
      </FormRow>
      <FormRow label={t('ttl')} help={ttlInvalid ? t('ttlInvalid') : undefined} tip={t('ttlHint')}>
        <InputNumber aria-label={t('ttl')} min={SCHEDULE302_TTL_MIN} max={SCHEDULE302_TTL_MAX} precision={0} value={draft.ttl}
          disabled={disabled} status={ttlInvalid ? 'error' : undefined} onChange={(ttl) => set({ ttl })} />
      </FormRow>
      <FormRow label={t('httpsToHttp')} tip={t('httpsToHttpHint')}>
        <Checkbox checked={draft.httpsToHttp} disabled={disabled} onChange={(event) => set({ httpsToHttp: event.target.checked })}>{t('httpsToHttp')}</Checkbox>
      </FormRow>
      <h3 className="site-setting-subtitle">{t('filters')}</h3>
      <p className="site-setting-section-help">{t('filtersHint')}</p>
      <FormRow label={t('extensions')}>
        <Input aria-label={t('extensions')} value={draft.extensions} disabled={disabled} placeholder={t('extensionsPlaceholder')}
          onChange={(event) => set({ extensions: event.target.value })} />
      </FormRow>
      <FormRow label={t('pathPrefixes')}>
        <Input aria-label={t('pathPrefixes')} value={draft.pathPrefixes} disabled={disabled} placeholder={t('pathPrefixesPlaceholder')}
          onChange={(event) => set({ pathPrefixes: event.target.value })} />
      </FormRow>
      <FormRow label={t('minSize')} help={sizeInvalid ? t('sizeInvalid') : undefined} tip={t('minSizeHint')}>
        <InputNumber aria-label={t('minSize')} min={0} value={draft.minSizeMB} disabled={disabled}
          status={sizeInvalid ? 'error' : undefined} onChange={(minSizeMB) => set({ minSizeMB })} />
      </FormRow>
    </> : null}
    {errorMessage ? <FeedbackWhen title={errorMessage} /> : null}
  </section>
}
