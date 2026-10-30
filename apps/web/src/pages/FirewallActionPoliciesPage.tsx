import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Alert, Button, Input, InputNumber, Result, Select, Space, Spin, Typography } from 'antd'
import { Plus, RotateCcw, Save, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { firewallActionApi, type FirewallActionPolicyInput } from '../api/firewallAction'
import { ApiError } from '../api/auth'
import { useSessionStore } from '../auth/session'
import '../i18n/firewallAction'
import { useFeedback } from '@cdnca/ui'

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

const defaultPolicy: FirewallActionPolicyInput = {
  normal_action: 'return_page', escalated_action: 'nftables', engage_threshold: 100, recover_threshold: 20,
  recovery_windows: 3, block_networks: ['198.51.100.0/24'], trusted_proxies: [], trusted_crawlers: [],
  return_page: { status: 429, content_type: 'text/plain; charset=utf-8', body: 'Request limited' },
}

type FirewallActionDraft = Omit<FirewallActionPolicyInput, 'engage_threshold' | 'recover_threshold' | 'recovery_windows' | 'return_page'> & {
  engage_threshold: number | null
  recover_threshold: number | null
  recovery_windows: number | null
  return_page: Omit<FirewallActionPolicyInput['return_page'], 'status'> & { status: number | null }
}

function completePolicy(draft: FirewallActionDraft): FirewallActionPolicyInput | null {
  if (draft.engage_threshold === null || draft.recover_threshold === null || draft.recovery_windows === null || draft.return_page.status === null) return null
  return {
    ...draft,
    engage_threshold: draft.engage_threshold,
    recover_threshold: draft.recover_threshold,
    recovery_windows: draft.recovery_windows,
    return_page: { ...draft.return_page, status: draft.return_page.status },
  }
}

function lines(value: string): string[] {
  return value.split(/\r?\n/u).map((item) => item.trim()).filter(Boolean)
}

export default function FirewallActionPoliciesPage() {
  const { t } = useTranslation('firewallAction')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const queryClient = useQueryClient()
  const token = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const [searchParams, setSearchParams] = useSearchParams()
  const isPlatform = principal?.scope_kind === 'platform'
  const queryScope = (searchParams.get('target_scope_id') ?? '').trim().toLowerCase()
  const querySite = (searchParams.get('site_id') ?? '').trim().toLowerCase()
  const scopeId = isPlatform ? (uuidPattern.test(queryScope) ? queryScope : '') : principal?.scope_id ?? ''
  const siteId = uuidPattern.test(querySite) ? querySite : ''
  const [scopeDraft, setScopeDraft] = useState(queryScope)
  const [siteDraft, setSiteDraft] = useState(querySite)
  const [targetError, setTargetError] = useState(Boolean(querySite && !siteId || isPlatform && queryScope && !scopeId))
  const canRead = Boolean(principal?.permissions.includes('firewall.read') || principal?.permissions.includes('platform.admin'))
  const canManage = Boolean(principal?.permissions.includes('firewall.manage') || principal?.permissions.includes('platform.admin'))
  const query = useQuery({
    queryKey: ['firewall-action-policy', scopeId, siteId], enabled: Boolean(token && scopeId && siteId && canRead),
    queryFn: async () => {
      try { return await firewallActionApi.get(token!, scopeId, siteId) }
      catch (error) {
        if (error instanceof ApiError && error.code === 'firewall_action_not_found') return null
        throw error
      }
    },
  })
  const [draft, setDraft] = useState<FirewallActionDraft | null>(null)
  const saveMetadata = useRef<{ fingerprint: string; idempotencyKey: string; requestId: string } | null>(null)
  const recoverMetadata = useRef<{ fingerprint: string; idempotencyKey: string; requestId: string } | null>(null)
  useEffect(() => {
    if (query.data !== undefined) setDraft(query.data ? {
      normal_action: query.data.normal_action, escalated_action: query.data.escalated_action,
      engage_threshold: query.data.engage_threshold, recover_threshold: query.data.recover_threshold, recovery_windows: query.data.recovery_windows,
      block_networks: query.data.block_networks, trusted_proxies: query.data.trusted_proxies, trusted_crawlers: query.data.trusted_crawlers,
      return_page: query.data.return_page,
    } : defaultPolicy)
  }, [query.data])

  const save = useMutation({
    mutationFn: () => {
      const expectedRevision = query.data?.revision ?? 0
      const policy = completePolicy(draft!)
      if (!policy) return Promise.reject(new ApiError('Invalid firewall action policy', 0, 'invalid_request'))
      const fingerprint = JSON.stringify({ scopeId, siteId, expectedRevision, policy })
      let metadata = saveMetadata.current
      if (metadata?.fingerprint !== fingerprint) metadata = { fingerprint, idempotencyKey: crypto.randomUUID(), requestId: crypto.randomUUID() }
      saveMetadata.current = metadata
      const { idempotencyKey, requestId } = metadata
      return firewallActionApi.put(token!, { scopeId, siteId, expectedRevision, policy, idempotencyKey, requestId })
    },
    onSuccess: (policy) => { saveMetadata.current = null; queryClient.setQueryData(['firewall-action-policy', scopeId, siteId], policy); void message.success(t('notices.saved')) },
    onError: () => { void feedback.error(t('errors.save')) },
  })
  const recover = useMutation({
    mutationFn: () => {
      const expectedRevision = query.data!.revision
      const fingerprint = `${scopeId}\x00${siteId}\x00${expectedRevision}`
      let metadata = recoverMetadata.current
      if (metadata?.fingerprint !== fingerprint) metadata = { fingerprint, idempotencyKey: crypto.randomUUID(), requestId: crypto.randomUUID() }
      recoverMetadata.current = metadata
      const { idempotencyKey, requestId } = metadata
      return firewallActionApi.recover(token!, { scopeId, siteId, expectedRevision, idempotencyKey, requestId })
    },
    onSuccess: (policy) => { recoverMetadata.current = null; queryClient.setQueryData(['firewall-action-policy', scopeId, siteId], policy); void message.success(t('notices.recovered')) },
    onError: () => { void feedback.error(t('errors.recover')) },
  })

  const applyTarget = () => {
    const scope = isPlatform ? scopeDraft.trim().toLowerCase() : principal?.scope_id ?? ''
    const site = siteDraft.trim().toLowerCase()
    if (!uuidPattern.test(scope) || !uuidPattern.test(site)) {
      setTargetError(true)
      return
    }
    setTargetError(false)
    setSearchParams(isPlatform ? { target_scope_id: scope, site_id: site } : { site_id: site }, { replace: true })
  }

  if (!canRead) return <Result status="403" title={t('errors.forbidden')} />
  if (!scopeId || !siteId) return <Space direction="vertical" size={12} style={{ width: '100%', minWidth: 0 }}>
    <Typography.Title level={3} style={{ margin: 0 }}>{t('title')}</Typography.Title>
    {isPlatform ? <Input aria-label={t('target.scope')} placeholder={t('target.scope')} value={scopeDraft} onChange={(event) => setScopeDraft(event.target.value)} /> : null}
    <Input aria-label={t('target.site')} placeholder={t('target.site')} value={siteDraft} onChange={(event) => setSiteDraft(event.target.value)} onPressEnter={applyTarget} />
    <Button type="primary" onClick={applyTarget}>{t('target.apply')}</Button>
    {targetError ? <Typography.Text type="danger">{t('target.invalid')}</Typography.Text> : null}
  </Space>
  if (query.isLoading) return <Spin />
  if (query.isError || !draft) return <Result status="error" title={t('loadFailed')} />

  const current = query.data
  const updateCrawler = (index: number, patch: Partial<FirewallActionPolicyInput['trusted_crawlers'][number]>) => setDraft({ ...draft,
    trusted_crawlers: draft.trusted_crawlers.map((crawler, candidate) => candidate === index ? { ...crawler, ...patch } : crawler),
  })
  const inputNumber = (field: 'engage_threshold' | 'recover_threshold' | 'recovery_windows', min: number, max?: number) =>
    <InputNumber aria-label={t(field === 'engage_threshold' ? 'engageThreshold' : field === 'recover_threshold' ? 'recoverThreshold' : 'recoveryWindows')}
      min={min} max={max} value={draft[field]} disabled={!canManage} onChange={(value) => setDraft({ ...draft, [field]: value })} />

  return <Space direction="vertical" size={16} style={{ width: '100%', minWidth: 0 }}>
    <Space wrap style={{ width: '100%', justifyContent: 'space-between' }}>
      <Typography.Title level={3} style={{ margin: 0 }}>{t('title')}</Typography.Title>
      <Space wrap>
        <Button icon={<RotateCcw size={16} />} disabled={!canManage || !current || current.lkg_revision < 1 || recover.isPending}
          onClick={() => recover.mutate()}>{t('recover')}</Button>
        <Button type="primary" icon={<Save size={16} />} disabled={!canManage || save.isPending || !completePolicy(draft)} onClick={() => save.mutate()}>{t('save')}</Button>
      </Space>
    </Space>
    <Alert type={current?.deployment_state === 'failed' ? 'warning' : 'info'} message={t(`states.${current?.deployment_state ?? 'pending'}`)} />
    <Space wrap>
      <Typography.Text>{t('currentActive', { revision: current?.active_revision ?? 0 })}</Typography.Text>
      <Typography.Text>{t('currentLKG', { revision: current?.lkg_revision ?? 0 })}</Typography.Text>
    </Space>
    <Space wrap>
      <Typography.Text>{t('normalAction')}</Typography.Text>
      <Select value={draft.normal_action} disabled={!canManage} style={{ width: 180 }} options={(['disconnect', 'return_page'] as const).map((value) => ({ value, label: t(`actions.${value}`) }))}
        onChange={(normal_action) => setDraft({ ...draft, normal_action })} />
      {/* A08: the nftables escalation exists only on nodes the tenant owns
          (server host_escalation); elsewhere it is not offered at all. */}
      {current?.host_escalation === 'owned' ? <>
        <Typography.Text>{t('escalatedAction')}</Typography.Text><Select value="nftables" disabled style={{ width: 190 }} options={[{ value: 'nftables', label: t('actions.nftables') }]} />
      </> : null}
    </Space>
    <Space wrap>
      <Typography.Text>{t('engageThreshold')}</Typography.Text>{inputNumber('engage_threshold', 1)}
      <Typography.Text>{t('recoverThreshold')}</Typography.Text>{inputNumber('recover_threshold', 0)}
      <Typography.Text>{t('recoveryWindows')}</Typography.Text>{inputNumber('recovery_windows', 1, 60)}
    </Space>
    <Typography.Text strong>{t('blockNetworks')}</Typography.Text>
    <Input.TextArea value={draft.block_networks.join('\n')} autoSize={{ minRows: 2, maxRows: 6 }} disabled={!canManage}
      onChange={(event) => setDraft({ ...draft, block_networks: lines(event.target.value) })} />
    <Typography.Text strong>{t('trustedProxies')}</Typography.Text>
    <Input.TextArea value={draft.trusted_proxies.join('\n')} autoSize={{ minRows: 1, maxRows: 4 }} disabled={!canManage}
      onChange={(event) => setDraft({ ...draft, trusted_proxies: lines(event.target.value) })} />
    <Typography.Text strong>{t('trustedCrawler')}</Typography.Text>
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      {draft.trusted_crawlers.map((crawler, index) => <Space key={index} align="start" wrap style={{ width: '100%' }}>
        <Input aria-label={`${t('crawlerName')} ${index + 1}`} placeholder={t('crawlerName')} value={crawler.name} disabled={!canManage}
          onChange={(event) => updateCrawler(index, { name: event.target.value })} />
        <Input.TextArea aria-label={`${t('crawlerNetworks')} ${index + 1}`} placeholder={t('crawlerNetworks')} value={crawler.networks.join('\n')} disabled={!canManage}
          autoSize={{ minRows: 1, maxRows: 4 }} onChange={(event) => updateCrawler(index, { networks: lines(event.target.value) })} />
        <Input.TextArea aria-label={`${t('crawlerPrefixes')} ${index + 1}`} placeholder={t('crawlerPrefixes')} value={crawler.user_agent_prefixes.join('\n')} disabled={!canManage}
          autoSize={{ minRows: 1, maxRows: 4 }} onChange={(event) => updateCrawler(index, { user_agent_prefixes: lines(event.target.value) })} />
        <Button type="text" danger icon={<Trash2 size={16} />} aria-label={t('removeCrawler')} disabled={!canManage}
          onClick={() => setDraft({ ...draft, trusted_crawlers: draft.trusted_crawlers.filter((_, candidate) => candidate !== index) })} />
      </Space>)}
      <Button icon={<Plus size={16} />} disabled={!canManage || draft.trusted_crawlers.length >= 64}
        onClick={() => setDraft({ ...draft, trusted_crawlers: [...draft.trusted_crawlers, { name: '', networks: [], user_agent_prefixes: [] }] })}>{t('addCrawler')}</Button>
    </Space>
    <Typography.Text strong>{t('returnPage')}</Typography.Text>
    <Space wrap>
      <InputNumber aria-label={t('statusCode')} min={400} max={599} value={draft.return_page.status} disabled={!canManage}
        onChange={(status) => setDraft({ ...draft, return_page: { ...draft.return_page, status } })} />
      <Select aria-label={t('contentType')} value={draft.return_page.content_type} disabled={!canManage} style={{ width: 230 }}
        options={['text/plain; charset=utf-8', 'text/html; charset=utf-8'].map((value) => ({ value, label: value }))}
        onChange={(content_type) => setDraft({ ...draft, return_page: { ...draft.return_page, content_type } })} />
    </Space>
    <Input.TextArea aria-label={t('body')} value={draft.return_page.body} autoSize={{ minRows: 2, maxRows: 8 }} disabled={!canManage}
      onChange={(event) => setDraft({ ...draft, return_page: { ...draft.return_page, body: event.target.value } })} />
  </Space>
}
