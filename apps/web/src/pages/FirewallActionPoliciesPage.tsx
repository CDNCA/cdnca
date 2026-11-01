import { useEffect, useRef, useState, type ReactNode } from 'react'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Alert, Button, Card, Input, InputNumber, Result, Select, Space, Spin, Tag, Typography, type TableColumnsType } from 'antd'
import { ArrowLeft, Plus, RotateCcw, Save, Settings2, Trash2, Undo2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { firewallActionApi, policyInputOf, type FirewallActionPolicyInput } from '../api/firewallAction'
import { ApiError } from '../api/auth'
import { sitesApi, type SiteListItem } from '../api/sites'
import { useSessionStore } from '../auth/session'
import TenantScopeSelect from '../components/TenantScopeSelect'
import '../i18n/firewallAction'
import { DataTable, FormGrid, PageSection, StatusTag, TableToolbar, useFeedback } from '@cdnca/ui'
import './FirewallActionPoliciesPage.css'

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const pageSize = 20

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

function draftOf(policy: FirewallActionPolicyInput): FirewallActionDraft {
  return policyInputOf(policy)
}

function lines(value: string): string[] {
  return value.split(/\r?\n/u).map((item) => item.trim()).filter(Boolean)
}

/**
 * A labelled field in the shared horizontal form row of the site edit pages
 * (label column, then the control with its help line; stacks at ≤720px).
 */
function Field({ label, help, htmlFor, children }: { label: string; help?: string; htmlFor?: string; children: ReactNode }) {
  return <div className="site-form-row">
    <div className="site-form-row-label"><label htmlFor={htmlFor}>{label}</label></div>
    <div className="site-form-row-control">
      {children}
      {help ? <p className="site-form-row-help">{help}</p> : null}
    </div>
  </div>
}

export default function FirewallActionPoliciesPage() {
  const { t } = useTranslation('firewallAction')
  const principal = useSessionStore((state) => state.principal)
  const [searchParams, setSearchParams] = useSearchParams()
  const isPlatform = principal?.scope_kind === 'platform'
  const queryScope = (searchParams.get('target_scope_id') ?? '').trim().toLowerCase()
  const querySite = (searchParams.get('site_id') ?? '').trim().toLowerCase()
  const scopeId = isPlatform ? (uuidPattern.test(queryScope) ? queryScope : '') : principal?.scope_id ?? ''
  const siteId = uuidPattern.test(querySite) ? querySite : ''
  const canRead = Boolean(principal?.permissions.includes('firewall.read') || principal?.permissions.includes('platform.admin'))

  if (!canRead) return <Result status="403" title={t('errors.forbidden')} />
  if (!scopeId || !siteId) return <SitePicker isPlatform={isPlatform} scopeId={scopeId} onPick={(site, scope) =>
    setSearchParams(isPlatform ? { target_scope_id: scope, site_id: site } : { site_id: site })}
    onPickScope={(scope) => setSearchParams(scope ? { target_scope_id: scope } : {})} />
  return <PolicyEditor key={`${scopeId}:${siteId}`} scopeId={scopeId} siteId={siteId} onBack={() => setSearchParams({})} />
}

/**
 * 策略按网站各一份（接口只有按站读写，无列表）：入口列出网站，选中后进入该站的策略。
 * 平台管理员的目标租户作用域取自网站详情的 scope_id，不再要求手填 UUID。
 * 列表上方是本租户的默认设置，没有自定义的网站都用它。
 * 平台管理员先在上方选择用户（target_scope_id），再显示该用户的默认设置。
 */
function SitePicker({ isPlatform, scopeId, onPick, onPickScope }: { isPlatform: boolean; scopeId: string;
  onPick: (siteId: string, scopeId: string) => void; onPickScope: (scopeId: string) => void }) {
  const { t } = useTranslation('firewallAction')
  const feedback = useFeedback()
  const token = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const canListTenants = Boolean(principal?.permissions.includes('platform.admin') || principal?.permissions.includes('identity.users.manage'))
  const [search, setSearch] = useState('')
  const [domain, setDomain] = useState('')
  const [page, setPage] = useState(1)
  const [opening, setOpening] = useState<string | null>(null)
  const sites = useQuery({
    queryKey: ['firewall-action-sites', domain, page], enabled: Boolean(token), placeholderData: keepPreviousData,
    queryFn: () => sitesApi.list(token!, { page, limit: pageSize, ...(domain ? { domain } : {}) }),
  })
  const open = async (site: SiteListItem) => {
    if (!isPlatform) return onPick(site.id, '')
    setOpening(site.id)
    try {
      const detail = await sitesApi.detail(token!, site.id)
      if (!detail?.scope_id || !uuidPattern.test(detail.scope_id)) throw new ApiError('Invalid site scope', 0, 'invalid_response')
      onPick(site.id, detail.scope_id)
    } catch {
      void feedback.error(t('picker.openFailed'))
    } finally {
      setOpening(null)
    }
  }
  const columns: TableColumnsType<SiteListItem> = [
    { title: t('picker.columns.domain'), dataIndex: 'domain', render: (value: string, site) => <Space direction="vertical" size={0}>
      <Typography.Text strong>{value}</Typography.Text>
      <Typography.Text type="secondary">{site.display_id}</Typography.Text>
    </Space> },
    ...(isPlatform ? [{ title: t('picker.columns.owner'), key: 'owner', render: (_: unknown, site: SiteListItem) => site.owner?.display_name ?? '—' }] : []),
    { title: t('picker.columns.action'), key: 'action', width: 160, render: (_: unknown, site: SiteListItem) =>
      <Button type="link" icon={<Settings2 size={16} />} loading={opening === site.id} disabled={opening !== null && opening !== site.id}
        aria-label={t('picker.configureSite', { domain: site.domain })} onClick={() => void open(site)}>{t('picker.configure')}</Button> },
  ]
  return <PageSection>
    <Space direction="vertical" size={16} style={{ width: '100%', minWidth: 0 }}>
      <div>
        <Typography.Title level={3} style={{ margin: 0 }}>{t('title')}</Typography.Title>
        <Typography.Paragraph type="secondary" style={{ margin: '4px 0 0' }}>{t('description')}</Typography.Paragraph>
      </div>
      {isPlatform ? <Space wrap size={8} className="firewall-action-default-tenant">
        <Typography.Text>{t('defaults.tenant')}</Typography.Text>
        <TenantScopeSelect accessToken={token} ownerKey={principal?.user_id ?? ''} canList={canListTenants}
          queryKeyPrefix="firewall-action-default-tenants" ariaLabel={t('defaults.tenant')} placeholder={t('defaults.tenantPlaceholder')}
          emptyText={t('defaults.tenantEmpty')} value={scopeId} onChange={onPickScope} />
      </Space> : null}
      {scopeId ? <DefaultEditor key={scopeId} scopeId={scopeId} /> : null}
      <TableToolbar filters={<Input.Search allowClear aria-label={t('picker.search')} placeholder={t('picker.search')} value={search} style={{ width: 280 }}
        onChange={(event) => { setSearch(event.target.value); if (!event.target.value) { setDomain(''); setPage(1) } }}
        onSearch={(value) => { setDomain(value.trim()); setPage(1) }} />} />
      {sites.isError ? <Alert type="error" showIcon message={t('picker.loadFailed')} action={<Button size="small" onClick={() => void sites.refetch()}>{t('picker.retry')}</Button>} /> : null}
      <DataTable<SiteListItem> rowKey="id" loading={sites.isLoading} columns={columns} dataSource={sites.data?.items ?? []}
        locale={{ emptyText: t('picker.empty') }}
        pagination={{ current: page, pageSize, total: sites.data?.total ?? 0, showSizeChanger: false, onChange: setPage }} />
    </Space>
  </PageSection>
}

const stateTag = { pending: 'processing', active: 'success', failed: 'warning', inherited: 'default' } as const

function PolicyEditor({ scopeId, siteId, onBack }: { scopeId: string; siteId: string; onBack: () => void }) {
  const { t } = useTranslation('firewallAction')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const queryClient = useQueryClient()
  const token = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const canManage = Boolean(principal?.permissions.includes('firewall.manage') || principal?.permissions.includes('platform.admin'))
  const site = useQuery({
    queryKey: ['firewall-action-site', siteId], enabled: Boolean(token), retry: false,
    queryFn: () => sitesApi.detail(token!, siteId),
  })
  // 站点存在即 200（没有自有策略时为继承视图，inherited=true）。
  const query = useQuery({
    queryKey: ['firewall-action-policy', scopeId, siteId], enabled: Boolean(token),
    queryFn: () => firewallActionApi.get(token!, scopeId, siteId),
  })
  const [draft, setDraft] = useState<FirewallActionDraft | null>(null)
  const saveMetadata = useRef<{ fingerprint: string; idempotencyKey: string; requestId: string } | null>(null)
  const recoverMetadata = useRef<{ fingerprint: string; idempotencyKey: string; requestId: string } | null>(null)
  useEffect(() => {
    if (query.data) setDraft(draftOf(query.data))
  }, [query.data])

  const save = useMutation({
    mutationFn: () => {
      // The site's own revision counter (an inherited view carries it too): the first own save is "0".
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
  // 恢复继承（DELETE）：本站自有策略作废，改用默认设置。
  const inherit = useMutation({
    mutationFn: () => firewallActionApi.inherit(token!, { scopeId, siteId, expectedRevision: query.data!.revision }),
    onSuccess: (policy) => {
      queryClient.setQueryData(['firewall-action-policy', scopeId, siteId], policy)
      void queryClient.invalidateQueries({ queryKey: ['firewall-action-default', scopeId] })
      void message.success(t('notices.inherited'))
    },
    onError: () => { void feedback.error(t('errors.inherit')) },
  })

  const back = <Button icon={<ArrowLeft size={16} />} onClick={onBack}>{t('back')}</Button>
  if (query.isLoading) return <PageSection><Spin /></PageSection>
  if (query.isError || !draft) return <PageSection><Result status="error" title={t('loadFailed')} extra={back} /></PageSection>

  const current = query.data
  const domain = site.data?.basic.domains[0]
  const state = current?.deployment_state
  const inherited = Boolean(current?.inherited)

  return <PageSection className="firewall-action-page">
    <Space direction="vertical" size={16} style={{ width: '100%', minWidth: 0 }}>
      <div className="firewall-action-head">
        <div style={{ minWidth: 0 }}>
          <Typography.Title level={3} style={{ margin: 0 }}>{t('title')}</Typography.Title>
          <Typography.Text type="secondary">{domain ? t('siteLabel', { domain }) : t('siteIdLabel', { id: siteId })}</Typography.Text>
          {current ? <Tag className="firewall-action-source" color={inherited ? 'default' : 'blue'}>{t(`source.${current.source}`)}</Tag> : null}
        </div>
        <Space wrap>
          {back}
          {current && !inherited ? <Button icon={<Undo2 size={16} />} loading={inherit.isPending} disabled={!canManage || inherit.isPending}
            onClick={() => inherit.mutate()}>{t('inherit')}</Button> : null}
          <Button icon={<RotateCcw size={16} />} disabled={!canManage || !current || inherited || current.lkg_revision < 1 || recover.isPending}
            onClick={() => recover.mutate()}>{t('recover')}</Button>
          <Button type="primary" icon={<Save size={16} />} loading={save.isPending} disabled={!canManage || save.isPending || !completePolicy(draft)} onClick={() => save.mutate()}>{t('save')}</Button>
        </Space>
      </div>
      {inherited ? <Alert type="info" showIcon message={t(current!.source === 'system_default' ? 'inheritedSystem' : 'inheritedTenant')}
        description={t('inheritedHint')} />
        : current ? <Alert type={state === 'failed' || !current.enabled ? 'warning' : 'info'} showIcon message={<Space wrap>
          <StatusTag status={stateTag[current.deployment_state]}>{t(`stateTags.${current.deployment_state}`)}</StatusTag>
          <span>{t(current.enabled ? `states.${current.deployment_state}` : 'disabled')}</span>
        </Space>} description={<Space wrap size={16}>
          <span>{t('currentActive', { revision: current.active_revision })}</span>
          <span>{t('currentLKG', { revision: current.lkg_revision })}</span>
        </Space>} /> : null}
      <PolicyFields draft={draft} setDraft={setDraft} canManage={canManage} showEscalation={current?.host_escalation === 'owned'} />
    </Space>
  </PageSection>
}

/**
 * 租户默认设置（GET/PUT /v1/firewall-actions/default）：折叠显示摘要，展开编辑；只影响继承中的网站。
 * 从未保存时为系统内置默认（不下发到节点），保存后才对继承中的网站生效。
 */
function DefaultEditor({ scopeId }: { scopeId: string }) {
  const { t } = useTranslation('firewallAction')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const queryClient = useQueryClient()
  const token = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const canManage = Boolean(principal?.permissions.includes('firewall.manage') || principal?.permissions.includes('platform.admin'))
  const [open, setOpen] = useState(false)
  const query = useQuery({
    queryKey: ['firewall-action-default', scopeId], enabled: Boolean(token), retry: false,
    queryFn: () => firewallActionApi.getDefault(token!, scopeId),
  })
  const [draft, setDraft] = useState<FirewallActionDraft | null>(null)
  useEffect(() => { if (query.data) setDraft(draftOf(query.data)) }, [query.data])
  const saveMetadata = useRef<{ fingerprint: string; idempotencyKey: string; requestId: string } | null>(null)
  const save = useMutation({
    mutationFn: () => {
      const policy = completePolicy(draft!)
      if (!policy) return Promise.reject(new ApiError('Invalid firewall action policy', 0, 'invalid_request'))
      const expectedRevision = query.data!.revision
      const fingerprint = JSON.stringify({ scopeId, expectedRevision, policy })
      let metadata = saveMetadata.current
      if (metadata?.fingerprint !== fingerprint) metadata = { fingerprint, idempotencyKey: crypto.randomUUID(), requestId: crypto.randomUUID() }
      saveMetadata.current = metadata
      return firewallActionApi.putDefault(token!, { scopeId, expectedRevision, policy, idempotencyKey: metadata.idempotencyKey, requestId: metadata.requestId })
    },
    onSuccess: (saved) => {
      saveMetadata.current = null
      queryClient.setQueryData(['firewall-action-default', scopeId], saved)
      void queryClient.invalidateQueries({ queryKey: ['firewall-action-policy', scopeId] })
      void message.success(t('defaults.saved', { count: saved.inheriting_site_count }))
    },
    onError: () => { void feedback.error(t('defaults.saveFailed')) },
  })
  const current = query.data
  const headingId = 'firewall-action-default-title'
  return <Card size="small" className="firewall-action-default" role="region" aria-labelledby={headingId}
    title={<Space wrap size={8}><span id={headingId}>{t('defaults.title')}</span>
      {current ? <Tag color={current.source === 'tenant_default' ? 'blue' : 'default'}>{t(`source.${current.source}`)}</Tag> : null}</Space>}
    extra={current ? <Button size="small" aria-expanded={open} aria-controls="firewall-action-default-body" onClick={() => setOpen(!open)}>
      {t(open ? 'defaults.collapse' : 'defaults.edit')}</Button> : null}>
    {query.isLoading ? <Spin size="small" /> : query.isError || !current
      ? <Alert type="error" showIcon message={t('defaults.loadFailed')} action={<Button size="small" onClick={() => void query.refetch()}>{t('picker.retry')}</Button>} />
      : <Space direction="vertical" size={12} style={{ width: '100%', minWidth: 0 }}>
        <Typography.Paragraph type="secondary" style={{ margin: 0 }}>
          {t(current.source === 'tenant_default' ? 'defaults.hintSaved' : 'defaults.hintSystem', { count: current.inheriting_site_count })}
        </Typography.Paragraph>
        <Space wrap size={16}>
          <span>{t('engageThreshold')}：{current.engage_threshold}</span>
          <span>{t('recoverThreshold')}：{current.recover_threshold}</span>
          <span>{t('recoveryWindows')}：{current.recovery_windows}</span>
          <span>{t('normalAction')}：{t(`actions.${current.normal_action}`)}</span>
        </Space>
        {open && draft ? <div id="firewall-action-default-body" className="firewall-action-default-body">
          <PolicyFields draft={draft} setDraft={setDraft} canManage={canManage} showEscalation={false} />
          <Space wrap>
            <Button type="primary" icon={<Save size={16} />} loading={save.isPending} disabled={!canManage || save.isPending || !completePolicy(draft)}
              onClick={() => save.mutate()}>{t('defaults.save')}</Button>
            {!canManage ? <Typography.Text type="secondary">{t('defaults.readOnly')}</Typography.Text> : null}
          </Space>
        </div> : null}
      </Space>}
  </Card>
}

/** The policy fields (site policy and tenant default share them; same validation server side). */
function PolicyFields({ draft, setDraft, canManage, showEscalation }: {
  draft: FirewallActionDraft
  setDraft: (draft: FirewallActionDraft) => void
  canManage: boolean
  showEscalation: boolean
}) {
  const { t } = useTranslation('firewallAction')
  const updateCrawler = (index: number, patch: Partial<FirewallActionPolicyInput['trusted_crawlers'][number]>) => setDraft({ ...draft,
    trusted_crawlers: draft.trusted_crawlers.map((crawler, candidate) => candidate === index ? { ...crawler, ...patch } : crawler),
  })
  const inputNumber = (field: 'engage_threshold' | 'recover_threshold' | 'recovery_windows', min: number, max?: number) =>
    <InputNumber id={`firewall-action-${field}`} style={{ width: '100%' }}
      aria-label={t(field === 'engage_threshold' ? 'engageThreshold' : field === 'recover_threshold' ? 'recoverThreshold' : 'recoveryWindows')}
      min={min} max={max} value={draft[field]} disabled={!canManage} onChange={(value) => setDraft({ ...draft, [field]: value })} />
  return <>
  <Card size="small" title={t('sections.trigger')}>
    <FormGrid columns={3}>
      <Field label={t('normalAction')} help={t('help.normalAction')} htmlFor="firewall-action-normal">
        <Select id="firewall-action-normal" aria-label={t('normalAction')} value={draft.normal_action} disabled={!canManage}
          options={(['disconnect', 'return_page'] as const).map((value) => ({ value, label: t(`actions.${value}`) }))}
          onChange={(normal_action) => setDraft({ ...draft, normal_action })} />
      </Field>
      {/* A08: the nftables escalation exists only on nodes the tenant owns
          (server host_escalation); elsewhere it is not offered at all. */}
      {showEscalation ? <Field label={t('escalatedAction')} help={t('help.escalatedAction')}>
        <Select aria-label={t('escalatedAction')} value="nftables" disabled options={[{ value: 'nftables', label: t('actions.nftables') }]} />
      </Field> : null}
    </FormGrid>
    <FormGrid columns={3}>
      <Field label={t('engageThreshold')} help={t('help.engageThreshold')} htmlFor="firewall-action-engage_threshold">{inputNumber('engage_threshold', 1)}</Field>
      <Field label={t('recoverThreshold')} help={t('help.recoverThreshold')} htmlFor="firewall-action-recover_threshold">{inputNumber('recover_threshold', 0)}</Field>
      <Field label={t('recoveryWindows')} help={t('help.recoveryWindows')} htmlFor="firewall-action-recovery_windows">{inputNumber('recovery_windows', 1, 60)}</Field>
    </FormGrid>
  </Card>
  <Card size="small" title={t('sections.networks')}>
    <FormGrid columns={2}>
      <Field label={t('blockNetworks')} help={t('help.blockNetworks')} htmlFor="firewall-action-block">
        <Input.TextArea id="firewall-action-block" aria-label={t('blockNetworks')} value={draft.block_networks.join('\n')} autoSize={{ minRows: 3, maxRows: 8 }} disabled={!canManage}
          onChange={(event) => setDraft({ ...draft, block_networks: lines(event.target.value) })} />
      </Field>
      <Field label={t('trustedProxies')} help={t('help.trustedProxies')} htmlFor="firewall-action-proxies">
        <Input.TextArea id="firewall-action-proxies" aria-label={t('trustedProxies')} value={draft.trusted_proxies.join('\n')} autoSize={{ minRows: 3, maxRows: 8 }} disabled={!canManage}
          onChange={(event) => setDraft({ ...draft, trusted_proxies: lines(event.target.value) })} />
      </Field>
    </FormGrid>
  </Card>
  <Card size="small" title={t('trustedCrawler')} extra={<Button icon={<Plus size={16} />} disabled={!canManage || draft.trusted_crawlers.length >= 64}
    onClick={() => setDraft({ ...draft, trusted_crawlers: [...draft.trusted_crawlers, { name: '', networks: [], user_agent_prefixes: [] }] })}>{t('addCrawler')}</Button>}>
    <Typography.Paragraph type="secondary" style={{ margin: 0 }}>{t('help.trustedCrawler')}</Typography.Paragraph>
    {draft.trusted_crawlers.length === 0 ? <Typography.Text type="secondary">{t('noCrawler')}</Typography.Text> : null}
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      {draft.trusted_crawlers.map((crawler, index) => <div key={index} className="firewall-action-crawler">
        <FormGrid columns={3}>
          <Field label={t('crawlerName')}>
            <Input aria-label={`${t('crawlerName')} ${index + 1}`} value={crawler.name} disabled={!canManage}
              onChange={(event) => updateCrawler(index, { name: event.target.value })} />
          </Field>
          <Field label={t('crawlerNetworks')}>
            <Input.TextArea aria-label={`${t('crawlerNetworks')} ${index + 1}`} value={crawler.networks.join('\n')} disabled={!canManage}
              autoSize={{ minRows: 1, maxRows: 4 }} onChange={(event) => updateCrawler(index, { networks: lines(event.target.value) })} />
          </Field>
          <Field label={t('crawlerPrefixes')}>
            <Input.TextArea aria-label={`${t('crawlerPrefixes')} ${index + 1}`} value={crawler.user_agent_prefixes.join('\n')} disabled={!canManage}
              autoSize={{ minRows: 1, maxRows: 4 }} onChange={(event) => updateCrawler(index, { user_agent_prefixes: lines(event.target.value) })} />
          </Field>
        </FormGrid>
        <Button type="text" danger icon={<Trash2 size={16} />} aria-label={`${t('removeCrawler')} ${index + 1}`} disabled={!canManage}
          onClick={() => setDraft({ ...draft, trusted_crawlers: draft.trusted_crawlers.filter((_, candidate) => candidate !== index) })} />
      </div>)}
    </Space>
  </Card>
  <Card size="small" title={t('returnPage')}>
    <Typography.Paragraph type="secondary" style={{ margin: 0 }}>{t('help.returnPage')}</Typography.Paragraph>
    <FormGrid columns={3}>
      <Field label={t('statusCode')} htmlFor="firewall-action-status">
        <InputNumber id="firewall-action-status" style={{ width: '100%' }} aria-label={t('statusCode')} min={400} max={599} value={draft.return_page.status} disabled={!canManage}
          onChange={(status) => setDraft({ ...draft, return_page: { ...draft.return_page, status } })} />
      </Field>
      <Field label={t('contentType')} htmlFor="firewall-action-content-type">
        <Select id="firewall-action-content-type" aria-label={t('contentType')} value={draft.return_page.content_type} disabled={!canManage}
          options={['text/plain; charset=utf-8', 'text/html; charset=utf-8'].map((value) => ({ value, label: value }))}
          onChange={(content_type) => setDraft({ ...draft, return_page: { ...draft.return_page, content_type } })} />
      </Field>
      <FormGrid.Full>
        <Field label={t('body')} htmlFor="firewall-action-body">
          <Input.TextArea id="firewall-action-body" aria-label={t('body')} value={draft.return_page.body} autoSize={{ minRows: 3, maxRows: 8 }} disabled={!canManage}
            onChange={(event) => setDraft({ ...draft, return_page: { ...draft.return_page, body: event.target.value } })} />
        </Field>
      </FormGrid.Full>
    </FormGrid>
  </Card>
  </>
}
