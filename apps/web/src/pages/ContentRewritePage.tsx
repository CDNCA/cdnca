import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App as AntApp, Button, Input, InputNumber, Popconfirm, Select, Space, Switch, type TableColumnsType } from 'antd'
import { ArrowDown, ArrowUp, Pencil, Plus, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { DataTable, PageHeader, PageSection, StatusTag } from '@cdnca/ui'

import { ApiError } from '../api/auth'
import {
  contentRewriteApi, newRuleID, REWRITE_DEFAULT_MAX_BYTES, REWRITE_MAX_MAX_BYTES, REWRITE_MAX_RULES, REWRITE_MAX_TEST_BODY,
  REWRITE_MIN_MAX_BYTES, rewriteContentTypes, type RewriteRule, type RewriteSettings, type RewriteTestResult,
} from '../api/contentRewrite'
import { sitesApi } from '../api/sites'
import { useSessionStore } from '../auth/session'
import '../i18n/contentRewrite'
import { RuleDrawer, type FieldProblem } from './content-rewrite/RuleDrawer'
import './ContentRewritePage.css'

// 内容改写: one
// site's rules, saved as a whole with If-Match, and the tester that runs the
// node's algorithm on the control plane.

const MiB = 1 << 20

function emptyRule(rules: RewriteRule[]): RewriteRule {
  return { id: newRuleID(rules), name: '', enabled: true, kind: 'link', paths: [], content_types: ['text/html'],
    from_hosts: [], to_host: '', scheme: 'keep', include_site_domains: true, hosts: [] }
}

// only the fields of the rule's kind go to the server
function clean(rule: RewriteRule): RewriteRule {
  const common = { id: rule.id, name: rule.name.trim(), enabled: rule.enabled, kind: rule.kind, paths: rule.paths, content_types: rule.content_types }
  if (rule.kind === 'link') return { ...common, from_hosts: rule.from_hosts ?? [], to_host: (rule.to_host ?? '').trim(), scheme: rule.scheme ?? 'keep' }
  if (rule.kind === 'replace') return { ...common, find: rule.find ?? '', replace: rule.replace ?? '', regex: rule.regex ?? false, ignore_case: rule.ignore_case ?? false }
  return { ...common, include_site_domains: rule.include_site_domains ?? true, hosts: rule.hosts ?? [] }
}

export default function ContentRewritePage() {
  const { t } = useTranslation('contentRewrite')
  const { message } = AntApp.useApp()
  const queryClient = useQueryClient()
  const accessToken = useSessionStore((state) => state.accessToken)
  const canWrite = useSessionStore((state) => state.principal?.permissions.includes('sites.manage') ?? false)
  const [siteSearch, setSiteSearch] = useState('')
  const [siteID, setSiteID] = useState<string>()
  const [editing, setEditing] = useState<{ rule: RewriteRule; index: number }>()
  const [problem, setProblem] = useState<FieldProblem>()
  const [testPath, setTestPath] = useState('/')
  const [testType, setTestType] = useState<string>('text/html')
  const [testBody, setTestBody] = useState('')
  const [testResult, setTestResult] = useState<RewriteTestResult>()
  const sites = useQuery({
    queryKey: ['content-rewrite-sites', siteSearch],
    queryFn: async () => (await sitesApi.list(accessToken!, { page: 1, limit: 100, ...(siteSearch ? { domain: siteSearch } : {}) })).items,
    enabled: Boolean(accessToken),
    staleTime: 30_000,
  })
  const stateKey = ['content-rewrite', siteID]
  const state = useQuery({
    queryKey: stateKey,
    queryFn: ({ signal }) => contentRewriteApi.get(accessToken!, siteID!, signal),
    enabled: Boolean(accessToken && siteID),
    retry: false,
  })
  useEffect(() => { setTestResult(undefined); setEditing(undefined) }, [siteID])
  const settings: RewriteSettings = state.data?.settings ?? { max_bytes: REWRITE_DEFAULT_MAX_BYTES, rules: [] }
  const save = useMutation({
    mutationFn: (next: RewriteSettings) => contentRewriteApi.replace(accessToken!, siteID!, state.data!.version,
      { max_bytes: next.max_bytes, rules: next.rules.map(clean) }),
    onSuccess: (data) => {
      queryClient.setQueryData(stateKey, data)
      setEditing(undefined)
      setProblem(undefined)
      void message.success(t('saved'))
    },
    onError: (error) => {
      if (error instanceof ApiError && error.code === 'version_conflict') {
        void message.warning(t('conflict'))
        void state.refetch()
        setEditing(undefined)
        return
      }
      if (error instanceof ApiError && error.field) {
        setProblem({ field: error.field, reason: error.reason ?? error.message })
        if (editing) return
      }
      void message.error(t('saveFailed'))
    },
  })
  const test = useMutation({
    mutationFn: () => contentRewriteApi.test(accessToken!, siteID!, {
      settings: { max_bytes: settings.max_bytes, rules: settings.rules.map(clean) }, path: testPath, content_type: testType, body: testBody,
    }),
    onSuccess: setTestResult,
  })
  const write = (rules: RewriteRule[], maxBytes = settings.max_bytes) => save.mutate({ max_bytes: maxBytes, rules })
  const move = (index: number, by: number) => {
    const rules = [...settings.rules]
    const [rule] = rules.splice(index, 1)
    rules.splice(index + by, 0, rule!)
    write(rules)
  }
  const nameOf = (rule: RewriteRule) => rule.name || t('unnamed')
  const summary = (rule: RewriteRule) => rule.kind === 'link' ? `${(rule.from_hosts ?? []).join(', ')} → ${rule.to_host ?? ''}`
    : rule.kind === 'replace' ? `${rule.regex ? '/' : '"'}${rule.find ?? ''}${rule.regex ? '/' : '"'} → "${rule.replace ?? ''}"`
      : [rule.include_site_domains ? state.data?.domains.join(', ') : '', ...(rule.hosts ?? [])].filter(Boolean).join(', ')
  const columns: TableColumnsType<RewriteRule> = [
    { title: t('columns.enabled'), key: 'enabled', width: 72, render: (_, rule, index) => <Switch size="small" checked={rule.enabled}
      disabled={!canWrite || save.isPending} aria-label={t('toggle', { name: nameOf(rule) })}
      onChange={(enabled) => write(settings.rules.map((item, at) => at === index ? { ...item, enabled } : item))} /> },
    { title: t('columns.name'), key: 'name', render: (_, rule) => <span>{nameOf(rule)}{rule.enabled ? null
      : <span className="cr-off">{t('disabled')}</span>}</span> },
    { title: t('columns.kind'), key: 'kind', width: 120, render: (_, rule) => <StatusTag status="processing">{t(`kind.${rule.kind}`)}</StatusTag> },
    { title: t('columns.scope'), key: 'scope', render: (_, rule) => `${rule.paths.length ? rule.paths.join(', ') : t('allPaths')} · ${
      rule.content_types.map((value) => t(`types.${value}`)).join(', ')}` },
    { title: t('columns.summary'), key: 'summary', render: (_, rule) => { const text = summary(rule); return <span className="cr-mono cr-ellipsis" title={text}>{text}</span> } },
    { title: t('columns.actions'), key: 'actions', width: 168, render: (_, rule, index) => <Space size={2}>
      <Button type="text" size="small" icon={<Pencil size={14} aria-hidden="true" />} aria-label={`${t('edit')} ${nameOf(rule)}`}
        disabled={!canWrite} onClick={() => { setProblem(undefined); setEditing({ rule, index }) }} />
      <Button type="text" size="small" icon={<ArrowUp size={14} aria-hidden="true" />} aria-label={t('moveUp', { name: nameOf(rule) })}
        disabled={!canWrite || index === 0 || save.isPending} onClick={() => move(index, -1)} />
      <Button type="text" size="small" icon={<ArrowDown size={14} aria-hidden="true" />} aria-label={t('moveDown', { name: nameOf(rule) })}
        disabled={!canWrite || index === settings.rules.length - 1 || save.isPending} onClick={() => move(index, 1)} />
      <Popconfirm title={t('removeConfirm', { name: nameOf(rule) })} onConfirm={() => write(settings.rules.filter((_, at) => at !== index))}>
        <Button type="text" size="small" danger icon={<Trash2 size={14} aria-hidden="true" />} aria-label={`${t('remove')} ${nameOf(rule)}`}
          disabled={!canWrite || save.isPending} />
      </Popconfirm>
    </Space> },
  ]
  return (
    <PageSection className="content-rewrite" aria-labelledby="content-rewrite-title">
      <PageHeader title={<span id="content-rewrite-title">{t('title')}</span>} description={t('description')}
        extra={<Select showSearch allowClear aria-label={t('site')} placeholder={t('sitePlaceholder')} style={{ width: 260 }}
          filterOption={false} onSearch={setSiteSearch} value={siteID} onChange={setSiteID} loading={sites.isFetching}
          options={(sites.data ?? []).map((site) => ({ value: site.id, label: site.domain }))} />} />
      {!siteID ? <Alert type="info" showIcon message={t('pickSite')} /> : null}
      {state.isError ? <Alert type="error" showIcon message={t('failed')} /> : null}
      {state.data ? <>
        <PageSection title={t('rules', { count: settings.rules.length })} extra={<Space wrap>
          <label className="cr-inline" htmlFor="cr-max-bytes">{t('maxBytes')}</label>
          <InputNumber id="cr-max-bytes" min={REWRITE_MIN_MAX_BYTES / MiB} max={REWRITE_MAX_MAX_BYTES / MiB} step={0.5}
            value={settings.max_bytes / MiB} addonAfter={t('mib')} disabled={!canWrite} aria-describedby="cr-max-bytes-hint"
            onBlur={(event) => {
              const value = Math.round(Number(event.target.value) * MiB)
              if (value >= REWRITE_MIN_MAX_BYTES && value <= REWRITE_MAX_MAX_BYTES && value !== settings.max_bytes) write(settings.rules, value)
            }} />
          <span id="cr-max-bytes-hint" className="cr-hint">{t('maxBytesHint')}</span>
          <Button type="primary" icon={<Plus size={14} aria-hidden="true" />} disabled={!canWrite || settings.rules.length >= REWRITE_MAX_RULES}
            onClick={() => { setProblem(undefined); setEditing({ rule: emptyRule(settings.rules), index: -1 }) }}>{t('add')}</Button>
        </Space>}>
          <DataTable rowKey="id" columns={columns} dataSource={settings.rules} pagination={false} locale={{ emptyText: t('empty') }} />
        </PageSection>
        <PageSection title={t('tester')}>
          <p className="cr-hint">{t('testerHint')}</p>
          <Space wrap className="cr-tester-bar">
            <label htmlFor="cr-test-path">{t('path')}</label>
            <Input id="cr-test-path" className="cr-mono" style={{ width: 220 }} value={testPath} onChange={(event) => setTestPath(event.target.value)} />
            <label htmlFor="cr-test-type">{t('contentType')}</label>
            <Select id="cr-test-type" style={{ width: 220 }} value={testType} onChange={setTestType}
              options={rewriteContentTypes.map((value) => ({ value, label: value }))} />
            <Button type="primary" loading={test.isPending} disabled={!testBody || !testPath.startsWith('/')}
              onClick={() => test.mutate()}>{t('run')}</Button>
          </Space>
          <div className="cr-tester">
            <div>
              <label className="cr-label" htmlFor="cr-test-input">{t('input')}</label>
              <Input.TextArea id="cr-test-input" className="cr-mono" rows={14} value={testBody} maxLength={REWRITE_MAX_TEST_BODY}
                placeholder={t('inputPlaceholder')} onChange={(event) => setTestBody(event.target.value)} />
            </div>
            <div>
              <span className="cr-label" id="cr-test-output-label">{t('output')}</span>
              <pre className="cr-mono cr-output" aria-labelledby="cr-test-output-label" tabIndex={0}>{testResult?.body ?? ''}</pre>
            </div>
          </div>
          <div aria-live="polite" className="cr-result">
            {test.isError ? <Alert type="error" showIcon message={t('testFailed')} /> : null}
            {testResult ? testResult.matched_rules.length === 0 ? t('noMatch')
              : <>{t('result', { rules: testResult.matched_rules.length, replacements: testResult.replacements })}
                {testResult.truncated ? <> · {t('truncated')}</> : null}</> : null}
          </div>
        </PageSection>
      </> : null}
      {editing ? <RuleDrawer open rule={editing.rule} isNew={editing.index < 0} saving={save.isPending}
        problem={problem} onCancel={() => { setEditing(undefined); setProblem(undefined) }}
        onSave={(rule) => write(editing.index < 0 ? [...settings.rules, rule]
          : settings.rules.map((item, at) => at === editing.index ? rule : item))} /> : null}
    </PageSection>
  )
}
