import { useId, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Input, Select, Switch, Table, Tag, Tooltip, type TableColumnsType } from 'antd'
import { useSearchParams } from 'react-router-dom'
import { useFeedbackMessage, useFeedback } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { securitySystemRulesApi, type SystemRule, type SystemRuleGroupEntry, type SystemRuleKind } from '../../api/securitySystemRules'
import { listTenantScopes } from '../../api/tenantScopes'
import { canonicalScopeUUIDPattern } from '../../components/TenantScopeSelect'
import { localizedUnknownApiError } from '../../i18n/apiError'
import '../../i18n/securitySystemRules'
import '../../i18n/crsRepublish'
import { explainRule, type ExplainBody } from './ruleExplain'

export function systemRuleSummary(rule: SystemRule, t: (key: string, options?: Record<string, unknown>) => string): string {
  const body = rule.body
  if (body.cc_filter) {
    return t('systemRules.filterSummary', {
      type: t(`systemRules.filterTypes.${body.cc_filter.type}`, { defaultValue: body.cc_filter.type }),
      window: body.cc_filter.within_second, max: body.cc_filter.max_req,
      perUri: body.cc_filter.max_req_per_uri ? t('systemRules.perUri', { value: body.cc_filter.max_req_per_uri }) : '',
    })
  }
  if (body.cc_matcher) {
    return body.cc_matcher.conditions.length
      ? body.cc_matcher.conditions.map((condition) => `${condition.field}${condition.key ? `[${condition.key}]` : ''} ${condition.operator} ${condition.values.join(' | ')}`).join('；')
      : t('systemRules.values.matchAll')
  }
  if (body.cc_rule_group) return t('systemRules.values.entries', { count: body.cc_rule_group.entries.length })
  if (body.waf_rule_set?.engine) return `OWASP CRS ${[...body.waf_rule_set.engine.files, ...body.waf_rule_set.engine.include_ids.map(String)].join(' ')} · PL${body.waf_rule_set.engine.paranoia} · ${body.waf_rule_set.engine.threshold}`
  if (body.waf_rule_set?.settings) return `${body.waf_rule_set.settings.request_body_limit} / ${body.waf_rule_set.settings.request_body_no_files_limit}`
  if (body.waf_rule_set?.bundle) return `OWASP CRS ${body.waf_rule_set.bundle.version} · ${body.waf_rule_set.bundle.files.length}`
  if (body.waf_rule_set) return t('systemRules.values.rules', { count: body.waf_rule_set.rules?.length ?? 0 })
  return ''
}

/** Shared query so the page can tell whether the signed catalog has synced
 * (and then hide the legacy per-tenant system copies) without a second fetch. */
export function useSystemRules(accessToken: string, kind: SystemRuleKind, cacheKey: string) {
  const tokenRef = useRef(accessToken)
  tokenRef.current = accessToken
  return useQuery({
    queryKey: ['security-system-rules', cacheKey, kind],
    queryFn: () => securitySystemRulesApi.list(tokenRef.current, kind),
    retry: false,
  })
}

// CCWAF-09: the catalog is folded by default; the open state lives in the URL
// (survives a refresh, can be linked) instead of local storage.
const catalogParam = 'system_rules'
const pageSize = 10

/**
 * Show-to picker for platform admins: searches tenants by name (or display
 * ID), shows picked tenants by name, and still submits scope IDs. A scope the
 * list does not return (or a failed read) stays visible as its ID; a pasted
 * canonical scope UUID is offered as-is.
 */
function ShowToSelect({ accessToken, cacheKey, value, disabled, ariaLabel, onChange }: {
  accessToken: string
  cacheKey: string
  value: string[]
  disabled: boolean
  ariaLabel: string
  onChange: (showTo: string[]) => void
}) {
  const { t } = useTranslation('securityPolicies')
  const tokenRef = useRef(accessToken)
  tokenRef.current = accessToken
  const [search, setSearch] = useState('')
  const term = search.trim()
  const scopes = useQuery({
    queryKey: ['security-system-rules', cacheKey, 'tenant-scopes', term],
    queryFn: () => listTenantScopes(tokenRef.current, { search: term || undefined, limit: term ? 20 : 100 }),
    retry: false,
    staleTime: 60_000,
  })
  // Names seen in any search, so a picked tenant keeps its name after the search changes.
  const labels = useRef(new Map<string, string>())
  for (const scope of scopes.data ?? []) labels.current.set(scope.scope_id, `${scope.tenant_name}（${scope.display_id}）`)
  const options = useMemo(() => {
    const items = (scopes.data ?? []).map((scope) => ({ value: scope.scope_id, label: labels.current.get(scope.scope_id)! }))
    for (const id of [...value, term]) {
      if (id && (value.includes(id) || canonicalScopeUUIDPattern.test(id)) && !items.some((item) => item.value === id)) {
        items.push({ value: id, label: labels.current.get(id) ?? id })
      }
    }
    return items
  }, [scopes.data, term, value])
  return <Select mode="multiple" size="small" style={{ width: '100%' }} aria-label={ariaLabel} disabled={disabled}
    showSearch filterOption={false} onSearch={setSearch} onBlur={() => setSearch('')} loading={scopes.isFetching}
    placeholder={t('systemRules.showToPlaceholder')} value={value} options={options}
    notFoundContent={scopes.isError ? t('systemRules.showToListFailed') : t('systemRules.showToEmpty')}
    onChange={(next: string[]) => { setSearch(''); onChange(next) }} />
}

/**
 * Read-only view of the system rules delivered by the license center.
 * Tenants can only switch a rule on or off; platform admins set whether (and
 * to whom) it is shown. Withdrawn rules stay listed, frozen, and cannot be
 * newly enabled.
 */
export default function SystemRuleCatalogTable({ accessToken, kind, cacheKey, isAdmin, canManage }: {
  accessToken: string
  kind: SystemRuleKind
  cacheKey: string
  isAdmin: boolean
  canManage: boolean
}) {
  const { t, i18n } = useTranslation('securityPolicies')
  const tokenRef = useRef(accessToken)
  tokenRef.current = accessToken
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const query = useSystemRules(accessToken, kind, cacheKey)
  const [searchParams, setSearchParams] = useSearchParams()
  const open = searchParams.get(catalogParam) === 'open'
  const setOpen = (next: boolean) => {
    const params = new URLSearchParams(searchParams)
    if (next) params.set(catalogParam, 'open')
    else params.delete(catalogParam)
    setSearchParams(params, { replace: true })
  }
  const bodyID = useId()
  const [filter, setFilter] = useState('')
  const [page, setPage] = useState(1)
  const references = useQuery({
    queryKey: ['security-system-rules', cacheKey, 'references'],
    enabled: kind === 'cc_rule_group',
    retry: false,
    queryFn: async () => [...await securitySystemRulesApi.list(tokenRef.current, 'cc_matcher'), ...await securitySystemRulesApi.list(tokenRef.current, 'cc_filter')],
  })
  // A system rule delivery (CRS text, default-on rule packs, trusted crawler
  // dataset: trigger rule_catalog) is being republished; shown on the WAF and
  // CC rule pages, polled while it lasts.
  const republication = useQuery({
    queryKey: ['security-system-rules', cacheKey, 'republication'],
    enabled: kind === 'waf_rule_set' || kind === 'cc_rule_group',
    retry: false,
    queryFn: () => securitySystemRulesApi.republication(tokenRef.current),
    refetchInterval: (current) => current.state.data?.pending ? 10_000 : false,
  })
  const names = new Map((references.data ?? []).map((rule) => [rule.system_key, rule.name]))
  const bodies = new Map((references.data ?? []).map((rule) => [rule.system_key, rule.body as ExplainBody]))
  const explain = (rule: SystemRule) => explainRule(rule.system_key, rule.body as ExplainBody, (key) => bodies.get(key), rule.description)
  const plain = (rule: SystemRule) => i18n.language.startsWith('zh') ? explain(rule) : systemRuleSummary(rule, t as never)
  const onError = (error: unknown) => feedback.error(error instanceof ApiError
    ? t(`systemRules.errors.${error.code}`, { defaultValue: t('systemRules.failed') }) : t('systemRules.failed'))
  const onSaved = () => {
    messageApi.success(t('systemRules.saved'))
    void queryClient.invalidateQueries({ queryKey: ['security-system-rules'] })
  }
  const toggle = useMutation({
    mutationFn: ({ rule, enabled }: { rule: SystemRule; enabled: boolean }) => securitySystemRulesApi.setEnabled(tokenRef.current, rule.system_key, enabled),
    onSuccess: onSaved, onError,
  })
  const visibility = useMutation({
    mutationFn: ({ rule, visible, showTo }: { rule: SystemRule; visible: boolean; showTo: string[] }) =>
      securitySystemRulesApi.setVisibility(tokenRef.current, rule.system_key, visible, showTo),
    onSuccess: onSaved, onError,
  })
  const status = (rule: SystemRule) => rule.status === 'active'
    ? <Tag color="success">{t('systemRules.values.active')}</Tag>
    : <Tooltip title={t('systemRules.values.withdrawnHint')}><Tag color="default">{t('systemRules.values.withdrawn')}</Tag></Tooltip>
  const columns: TableColumnsType<SystemRule> = [
    { title: t('systemRules.columns.id'), dataIndex: 'legacy_id', width: 80, render: (value: string, rule) => value || rule.system_key },
    { title: t('systemRules.columns.name'), dataIndex: 'name', width: 200, render: (value: string, rule) => <span className="system-rule-name" title={rule.description || undefined}>
      <strong>{value}</strong><small>{t('systemRules.values.systemRule')} · {t('systemRules.sortLabel', { sort: rule.sort })}</small></span> },
    { title: t('systemRules.columns.type'), key: 'type', width: 80, render: () => <Tag>{t('systemRules.values.system')}</Tag> },
    // One plain-language line (full text on hover and in the expanded row); the
    // technical summary is no longer repeated in the same cell.
    { title: t('systemRules.columns.effect'), key: 'effect', ellipsis: { showTitle: false }, render: (_value, rule) => {
      const text = plain(rule)
      return <span className="system-rule-effect" title={text}>{text}</span>
    } },
    { title: t('systemRules.columns.status'), key: 'status', width: 100, render: (_value, rule) => status(rule) },
    ...(isAdmin ? [
      { title: t('systemRules.columns.visible'), key: 'visible', width: 120, render: (_value: unknown, rule: SystemRule) => <Switch size="small"
        aria-label={`${t('systemRules.columns.visible')} ${rule.name}`} checked={rule.visibility?.visible ?? true} disabled={!canManage}
        loading={visibility.isPending && visibility.variables?.rule.system_key === rule.system_key}
        onChange={(visible) => visibility.mutate({ rule, visible, showTo: rule.visibility?.show_to_scope_ids ?? [] })} /> },
      { title: t('systemRules.columns.showTo'), key: 'show_to', width: 260, render: (_value: unknown, rule: SystemRule) => <ShowToSelect
        accessToken={accessToken} cacheKey={cacheKey} ariaLabel={`${t('systemRules.columns.showTo')} ${rule.name}`} disabled={!canManage}
        value={rule.visibility?.show_to_scope_ids ?? []}
        onChange={(showTo) => visibility.mutate({ rule, visible: rule.visibility?.visible ?? true, showTo })} /> },
    ] : [
      { title: t('systemRules.columns.enabled'), key: 'enabled', width: 90, render: (_value: unknown, rule: SystemRule) => <Switch size="small"
        aria-label={`${t('systemRules.columns.enabled')} ${rule.name}`} checked={rule.enabled}
        disabled={!canManage || (!rule.selectable && !rule.enabled)}
        loading={toggle.isPending && toggle.variables?.rule.system_key === rule.system_key}
        onChange={(enabled) => toggle.mutate({ rule, enabled })} /> },
    ]),
  ]
  const entryColumns: TableColumnsType<SystemRuleGroupEntry & { index: number }> = [
    { title: t('systemRules.columns.matcher'), dataIndex: 'matcher_key', render: (key: string) => names.get(key) ?? key },
    { title: t('systemRules.columns.filter1'), dataIndex: 'filter1_key', render: (key: string) => names.get(key) ?? key },
    { title: t('systemRules.columns.filter2'), dataIndex: 'filter2_key', render: (key: string) => key ? names.get(key) ?? key : '—' },
    { title: t('systemRules.columns.action'), dataIndex: 'action', render: (value: string) => t(`systemRules.values.${value}`) },
    { title: t('systemRules.columns.mode'), dataIndex: 'mode', render: (value: string) => t(`systemRules.values.${value}`) },
  ]
  const rows = [...(query.data ?? [])].sort((left, right) => left.sort - right.sort || left.system_key.localeCompare(right.system_key))
  const needle = filter.trim().toLowerCase()
  const shown = needle ? rows.filter((rule) => [rule.name, rule.legacy_id, rule.system_key].some((value) => value?.toLowerCase().includes(needle))) : rows
  const empty = !query.isLoading && rows.length === 0
  const notice = t(kind === 'waf_rule_set' ? 'systemRules.wafSignatureNotice' : 'systemRules.enforcementPending')
  const detail = (rule: SystemRule) => {
    const summary = systemRuleSummary(rule, t as never)
    const entries = rule.body.cc_rule_group?.entries ?? []
    return <div className="system-rule-detail">
      <p className="system-rule-detail-text">{plain(rule)}</p>
      {summary && summary !== plain(rule) ? <p className="system-rule-detail-summary">{summary}</p> : null}
      {entries.length ? <Table size="small" pagination={false} rowKey="index" columns={entryColumns}
        dataSource={entries.map((entry, index) => ({ ...entry, index }))} /> : null}
    </div>
  }
  return (
    <section className="system-rule-catalog" aria-label={t('systemRules.title')}>
      {messageContext}
      <Alert type="info" showIcon className="system-rule-catalog-notice"
        message={<>
          {empty ? t('systemRules.empty')
            : `${t('systemRules.count', { count: rows.length })} · ${t(isAdmin ? 'systemRules.adminNotice' : 'systemRules.notice')}`}
          {/* Only while a republication is actually running; gone once it finishes (10-25). */}
          {republication.data?.pending ? <Tooltip title={t('crsRepublish:republishingDetail')} trigger={['hover', 'focus']}>
            <Tag color="processing" role="status" tabIndex={0} className="system-rule-republishing">
              {t('crsRepublish:republishing', { count: republication.data.pending_scopes })}</Tag>
          </Tooltip> : null}
        </>}
        description={open || empty ? notice : undefined}
        action={rows.length ? <Button size="small" type="link" aria-expanded={open} aria-controls={bodyID} onClick={() => setOpen(!open)}>
          {t(open ? 'systemRules.collapse' : 'systemRules.expand')}</Button> : undefined} />
      {open && rows.length ? <div id={bodyID} className="system-rule-catalog-body">
        <Input type="search" size="small" allowClear className="system-rule-catalog-search" aria-label={t('systemRules.searchLabel')}
          placeholder={t('systemRules.searchPlaceholder')} value={filter} onChange={(event) => { setFilter(event.target.value); setPage(1) }} />
        <Table<SystemRule> rowKey="system_key" size="small" loading={query.isLoading} columns={columns} dataSource={shown}
          pagination={{ current: page, pageSize, size: 'small', hideOnSinglePage: true, showSizeChanger: false, onChange: setPage }}
          locale={{ emptyText: t(needle ? 'systemRules.noMatch' : 'systemRules.empty') }} scroll={{ x: 900 }}
          rowClassName={(rule) => rule.status === 'withdrawn' ? 'system-rule-withdrawn' : ''}
          expandable={{ expandedRowRender: detail }} />
      </div> : null}
    </section>
  )
}

/**
 * Catalog block shown above a tenant's own rules. Tenants do not see an
 * empty block, platform admins do (so a never-synced installation is visible
 * as such). A failed read is not an empty catalog (SEC-ACCOUNT-03): the block
 * stays with the reason and an in-place retry, for both roles.
 */
export function SystemRuleCatalogSection({ accessToken, kind, cacheKey, isAdmin, canManage }: {
  accessToken: string
  kind: SystemRuleKind
  cacheKey: string
  isAdmin: boolean
  canManage: boolean
}) {
  const { t } = useTranslation('securityPolicies')
  const query = useSystemRules(accessToken, kind, cacheKey)
  if (query.isError) {
    return (
      <section className="system-rule-catalog" aria-label={t('systemRules.title')}>
        <Alert type="error" showIcon role="alert" className="system-rule-catalog-notice" message={t('systemRules.loadFailed')}
          description={localizedUnknownApiError(query.error, t('errors.request_failed'))}
          action={<Button size="small" loading={query.isFetching} onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
      </section>
    )
  }
  if (!isAdmin && (query.data ?? []).length === 0) return null
  return <SystemRuleCatalogTable accessToken={accessToken} kind={kind} cacheKey={cacheKey} isAdmin={isAdmin} canManage={canManage} />
}
