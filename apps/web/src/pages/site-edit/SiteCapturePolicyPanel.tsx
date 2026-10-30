import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Input, InputNumber, Select, Switch } from 'antd'
import { RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { siteCapturePolicyApi, type SiteCapturePolicy, type SiteCapturePolicyDocument, type SiteCapturePolicyUnconfigured, type SiteCapturePolicyUpdate } from '../../api/siteCapturePolicy'
import '../../i18n/siteCapturePolicy'
import { FormRow, SettingSection } from './SiteEditFields'
import { FeedbackWhen } from '@cdnca/ui'
import SiteEditState from './SiteEditState'
import { useInstantDraft, useInstantFeedback } from './instantSave'

interface Props {
  siteId: string
  scopeId: string
  accessToken: string
  ownerKey: string
  sessionEpoch: number
  permissions: readonly string[]
  canManage: boolean
  lockedForTenant: boolean
}

const methods = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
const emptyDocument: SiteCapturePolicyDocument = {
  enabled: false, methods: [], uri_prefixes: [], request_header_allowlist: [], response_header_allowlist: [],
  request_body_field_allowlist: [], response_body_field_allowlist: [], max_value_bytes: 4096,
  max_body_bytes: 64 * 1024, max_event_bytes: 1024 * 1024,
}

interface Draft extends Omit<SiteCapturePolicyDocument, 'uri_prefixes' | 'request_header_allowlist' | 'response_header_allowlist' | 'request_body_field_allowlist' | 'response_body_field_allowlist'> {
  uriPrefixes: string
  requestHeaders: string
  responseHeaders: string
  requestBody: string
  responseBody: string
}

interface Attempt {
  input: SiteCapturePolicyUpdate
  metadata: { idempotencyKey: string; requestID: string; traceID: string }
}

function draftFrom(document: SiteCapturePolicyDocument): Draft {
  return { ...document, uriPrefixes: document.uri_prefixes.join('\n'), requestHeaders: document.request_header_allowlist.join('\n'),
    responseHeaders: document.response_header_allowlist.join('\n'), requestBody: document.request_body_field_allowlist.join('\n'),
    responseBody: document.response_body_field_allowlist.join('\n') }
}

function lines(value: string): string[] {
  return value.split('\n').map((item) => item.trim()).filter(Boolean)
}

function capturedOf(draft: Draft): number {
  return lines(draft.requestHeaders).length + lines(draft.responseHeaders).length + lines(draft.requestBody).length + lines(draft.responseBody).length
}

function documentFrom(draft: Draft): SiteCapturePolicyDocument {
  if (!draft.enabled) return { ...emptyDocument, max_value_bytes: draft.max_value_bytes, max_body_bytes: draft.max_body_bytes, max_event_bytes: draft.max_event_bytes }
  return { enabled: true, methods: draft.methods, uri_prefixes: lines(draft.uriPrefixes),
    request_header_allowlist: lines(draft.requestHeaders), response_header_allowlist: lines(draft.responseHeaders),
    request_body_field_allowlist: lines(draft.requestBody), response_body_field_allowlist: lines(draft.responseBody),
    max_value_bytes: draft.max_value_bytes, max_body_bytes: draft.max_body_bytes, max_event_bytes: draft.max_event_bytes }
}

function errorKey(error: unknown): string {
  return error instanceof ApiError ? error.code : 'unknown'
}

function requestMetadata(): Attempt['metadata'] {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}`
  return { idempotencyKey: `capture-${suffix}`, requestID: `request-${suffix}`, traceID: `trace-${suffix}` }
}

export default function SiteCapturePolicyPanel({ siteId, scopeId, accessToken, ownerKey, sessionEpoch, permissions, canManage, lockedForTenant }: Props) {
  const { t } = useTranslation('siteCapturePolicy')
  const queryClient = useQueryClient()
  const queryKey = useMemo(() => ['site-capture-policy', scopeId, siteId, ownerKey, sessionEpoch], [ownerKey, scopeId, sessionEpoch, siteId])
  const platform = permissions.includes('platform.admin')
  const canRead = platform || permissions.includes('site_capture.read')
  const canWrite = canManage && !lockedForTenant && (platform || permissions.includes('site_capture.manage'))
  // A site that never saved a policy answers state=unconfigured (revision 0,
  // default document); 404 means the site itself is missing or not visible and
  // stays a read failure.
  const query = useQuery({ queryKey, enabled: canRead, retry: false, queryFn: ({ signal }) => siteCapturePolicyApi.get(accessToken, scopeId, siteId, signal) })
  const unconfigured = query.data !== undefined && 'state' in query.data
  const [attempt, setAttempt] = useState<Attempt | null>(null)
  const [saved, setSaved] = useState(false)
  const feedback = useInstantFeedback()

  const mutation = useMutation({
    retry: false,
    mutationFn: (value: Attempt) => siteCapturePolicyApi.update(accessToken, scopeId, siteId, value.input, value.metadata),
    onSuccess: (result) => {
      queryClient.setQueryData<SiteCapturePolicy | SiteCapturePolicyUnconfigured>(queryKey, result.policy)
      setAttempt(null)
      setSaved(true)
      feedback.success()
    },
    onError: (error) => {
      // 未知结果（网络）保留草稿与原请求供重试；明确拒绝回滚到服务端值。
      if (!(error instanceof ApiError) || error.status === 0) return
      setAttempt(null)
      instant.revert()
      if (error.status === 409 || error.status === 412) void query.refetch()
    },
  })
	const resetMutation = mutation.reset
  // fix-siteinstant：改动即保存（开关/方法立即，多行名单与数字失焦或回车）。
  const instant = useInstantDraft(useMemo(() => draftFrom(query.data?.document ?? emptyDocument), [query.data]), {
    busy: mutation.isPending || attempt !== null || query.isFetching,
    isChanged: (value, stored) => JSON.stringify(documentFrom(value)) !== JSON.stringify(documentFrom(stored)),
    isValid: (value) => canWrite && (!value.enabled || capturedOf(value) > 0),
    submit: (value) => {
      const next: Attempt = { input: { expected_revision: query.data?.revision ?? 0, document: documentFrom(value) }, metadata: requestMetadata() }
      setAttempt(next)
      mutation.mutate(next)
    },
  })
  const draft = instant.draft
  const revertDraft = instant.revert

  useEffect(() => {
    revertDraft()
    setAttempt(null)
    setSaved(false)
    resetMutation()
  }, [ownerKey, resetMutation, revertDraft, sessionEpoch])

  if (!canRead) return <SiteEditState status="forbidden" title={t('errors.permission_denied')} />
  if (query.isPending) return <SiteEditState status="loading" label={t('states.loading')} />
  if (query.isError) {
    return (
      <SettingSection title={t('title')}>
        <SiteEditState status="error" title={t('errors.load')} detail={t(`errors.${errorKey(query.error)}`, { defaultValue: '' }) || undefined}
          onRetry={() => void query.refetch()} />
      </SettingSection>
    )
  }

  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => { setSaved(false); instant.set({ [key]: value } as unknown as Partial<Draft>) }
  const valid = !draft.enabled || capturedOf(draft) > 0

  return (
    <SettingSection title={t('title')} tip={t('description')}>
      <div aria-busy={mutation.isPending} {...instant.typingProps}>
      {!canWrite ? <Alert type="info" message={t('states.readOnly')} /> : null}
      {unconfigured && !saved ? <Alert type="info" message={t('states.unconfigured')} /> : null}
      {mutation.isError ? <FeedbackWhen title={t(`errors.${errorKey(mutation.error)}`, { defaultValue: t('errors.unknown') })} action={attempt ? <Button onClick={() => mutation.mutate(attempt)}>{t('actions.retry')}</Button> : undefined} /> : null}
      {!valid ? <Alert type="warning" message={t('help.explicit')} /> : null}
      <FormRow label={t('fields.enabled')} help={draft.enabled ? t('help.explicit') : t('states.disabled')}>
        <Switch aria-label={t('fields.enabled')} checked={draft.enabled} disabled={!canWrite} onChange={(checked) => set('enabled', checked)} />
      </FormRow>
      {draft.enabled ? <>
      <FormRow label={t('fields.methods')}>
        <Select aria-label={t('fields.methods')} mode="multiple" value={draft.methods} options={methods.map((value) => ({ value, label: value }))} disabled={!canWrite || !draft.enabled} onChange={(value) => set('methods', value)} />
      </FormRow>
      {([
        ['uriPrefixes', 'uriPrefixes'], ['requestHeaders', 'requestHeaders'], ['responseHeaders', 'responseHeaders'],
        ['requestBody', 'requestBody'], ['responseBody', 'responseBody'],
      ] as const).map(([key, label]) => (
        <FormRow key={key} label={t(`fields.${label}`)} help={t('help.lines')}>
          <Input.TextArea aria-label={t(`fields.${label}`)} value={draft[key]} autoSize={{ minRows: 2, maxRows: 5 }} disabled={!canWrite || !draft.enabled} onChange={(event) => set(key, event.target.value)} />
        </FormRow>
      ))}
      </> : null}
      {([
        ['max_value_bytes', 'maxValueBytes', 1, 16 * 1024], ['max_body_bytes', 'maxBodyBytes', 1, 1024 * 1024],
        ['max_event_bytes', 'maxEventBytes', 256, 1024 * 1024],
      ] as const).map(([key, label, min, max]) => (
        <FormRow key={key} label={t(`fields.${label}`)}>
          <InputNumber aria-label={t(`fields.${label}`)} min={min} max={max} value={draft[key]} disabled={!canWrite} onChange={(value) => value !== null && set(key, value)} />
        </FormRow>
      ))}
      <div className="site-setting-actions">
        <Button icon={<RefreshCw size={15} />} disabled={mutation.isPending} onClick={() => void query.refetch()}>{t('actions.refresh')}</Button>
      </div>
      </div>
    </SettingSection>
  )
}
