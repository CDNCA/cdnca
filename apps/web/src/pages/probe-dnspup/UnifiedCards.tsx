import { useDeferredValue, useEffect, useId, useMemo, useRef, useState, type CSSProperties } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Form, Input, InputNumber, Popconfirm, Radio, Select, Skeleton, Space, Switch, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { newIdempotencyKey } from '../../api/market'
import {
  nodeProbeTypes, probeCarriers, probeDNSPupUnifiedApi, probeWindows, type NodeProbeType, type ProbeDiagnosis,
  type ProbeMatrixCell, type ProbeOverrideInput, type ProbePurposeInput, type ProbePurposeStatus, type ProbeSelection,
  type ProbeWindow, type ProbeDNSPupStatus,
} from '../../api/probeDNSPup'
import { nodesApi } from '../../api/nodes'
import { nodeSchedulingApi } from '../../api/nodeScheduling'
import { useSessionStore } from '../../auth/session'
import { MetricTrendChart } from '../../components/MetricTrendChart'
import TenantScopeSelect from '../../components/TenantScopeSelect'
import '../../i18n/probeDNSPup'
import { FeedbackWhen, PageSection, useFeedback, Table } from '@cdnca/ui'
import { SelectionFields, selectionOf, type SelectionValues } from './SelectionFields'
import { MTRResult } from './MTRResult'
import { useProbeReason as useReason } from './probeErrors'
import { inactiveReason } from './NodeProbeCard'

// Per purpose quota and frequency: one dnspup quota for availability,
// scheduling, plugins and reports, slowed by priority when short.
// 拨测未在使用（未授权/未启用/已暂停/未配置 Key）时，
// 用途行的额度状态写原因而不是「正常」，账户额度一行只在接入生效后显示（未读到账户时不说不限额）。
export function PurposesCard({ token, connection }: { token: string; connection: ProbeDNSPupStatus }) {
  const { t, i18n } = useTranslation('probeDNSPup')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const reason = useReason()
  const client = useQueryClient()
  const query = useQuery({ queryKey: ['probe-dnspup-purposes'], queryFn: () => probeDNSPupUnifiedApi.purposes(token), enabled: Boolean(token) })
  const [draft, setDraft] = useState<Record<string, ProbePurposeInput>>({})
  useEffect(() => {
    if (query.data) setDraft(Object.fromEntries(query.data.purposes.map((item) => [item.purpose, { purpose: item.purpose,
      enabled: item.enabled, monthly_cap: item.monthly_cap, interval_seconds: item.interval_seconds,
      ...(item.probe_type ? { probe_type: item.probe_type } : {}) }])))
  }, [query.data])
  const save = useMutation({
    mutationFn: () => probeDNSPupUnifiedApi.savePurposes(token, Object.values(draft), newIdempotencyKey('probe-dnspup-purposes')),
    onSuccess: (data) => { client.setQueryData(['probe-dnspup-purposes'], data); void message.success(t('unified.purposes.saved')) },
    onError: (error) => void feedback.error(reason(error)),
  })
  const number = (value: number) => new Intl.NumberFormat(i18n.resolvedLanguage ?? i18n.language).format(value)
  const set = (purpose: string, change: Partial<ProbePurposeInput>) =>
    setDraft((current) => ({ ...current, [purpose]: { ...current[purpose], ...change } }))
  if (query.error) return <PageSection title={t('unified.purposes.title')}><FeedbackWhen title={reason(query.error)} /></PageSection>
  const data = query.data
  const inactive = connection.active ? null : inactiveReason(connection)
  const state = (item: ProbePurposeStatus) => {
    if (inactive) return <Tag>{t(`node.inactiveReasons.${inactive}`)}</Tag>
    if (item.gate.stopped) return <Tag color="red">{t('unified.purposes.gate.stopped')} · {t(`unified.purposes.reasons.${item.gate.reason ?? 'disabled'}`)}</Tag>
    if (item.gate.factor > 1) return <Tag color="orange">{t('unified.purposes.gate.slowed', { factor: item.gate.factor })}</Tag>
    return <Tag color="green">{t('unified.purposes.gate.normal')}</Tag>
  }
  return <PageSection title={t('unified.purposes.title')}>
    {query.isLoading ? <Skeleton active /> : <div className="probe-dnspup-section-body">
      <Typography.Paragraph type="secondary" className="probe-dnspup-section-intro">{t('unified.purposes.intro')}</Typography.Paragraph>
      {data && !inactive ? <Typography.Text strong>{data.monthly_limit > 0
        ? t('unified.purposes.account', { used: number(data.monthly_used), limit: number(data.monthly_limit), projected: number(data.projected_monthly) })
        : t('unified.purposes.accountUnlimited', { projected: number(data.projected_monthly) })}</Typography.Text> : null}
      {/* 表头按词不折行，表格局部横滚，用途列固定在左侧保留行归属 */}
      <Table<ProbePurposeStatus> className="probe-dnspup-purposes" rowKey="purpose" size="small" pagination={false} dataSource={(data?.purposes ?? []).filter((item) => item.purpose !== 'edge_health')}
        scroll={{ x: 'max-content' }}
        columns={[
          { title: t('unified.purposes.columns.purpose'), fixed: 'left', render: (_, item) => t(`unified.purposes.names.${item.purpose}`) },
          { title: t('unified.purposes.columns.class'), render: (_, item) => t(`unified.purposes.classes.${item.class}`) },
          { title: t('unified.purposes.columns.enabled'), render: (_, item) => <Switch size="small"
            aria-label={`${t(`unified.purposes.names.${item.purpose}`)} ${t('unified.purposes.columns.enabled')}`}
            checked={draft[item.purpose]?.enabled ?? item.enabled} disabled={item.class === 1}
            title={item.class === 1 ? t('unified.purposes.availabilityLocked') : undefined}
            onChange={(enabled) => set(item.purpose, { enabled })} /> },
          { title: t('unified.purposes.columns.cap'), render: (_, item) => <InputNumber min={0} max={1_000_000_000} precision={0}
            aria-label={`${t(`unified.purposes.names.${item.purpose}`)} ${t('unified.purposes.columns.cap')}`}
            value={draft[item.purpose]?.monthly_cap ?? item.monthly_cap} onChange={(value) => set(item.purpose, { monthly_cap: value ?? 0 })} /> },
          { title: t('unified.purposes.columns.interval'), render: (_, item) => <InputNumber min={0} max={86400} precision={0}
            aria-label={`${t(`unified.purposes.names.${item.purpose}`)} ${t('unified.purposes.columns.interval')}`}
            value={draft[item.purpose]?.interval_seconds ?? item.interval_seconds}
            onChange={(value) => set(item.purpose, { interval_seconds: value ?? 0 })} /> },
          // The probe type applies to aggregated edge candidates only (edge_health, hidden here): no column.
          { title: t('unified.purposes.columns.used'), render: (_, item) => number(item.used_this_month) },
          { title: t('unified.purposes.columns.projected'), render: (_, item) => number(item.gate.projected_monthly) },
          { title: t('unified.purposes.columns.state'), render: (_, item) => state(item) },
        ]} />
      <div><Button type="primary" loading={save.isPending} disabled={!data} onClick={() => save.mutate()}>{t('unified.purposes.save')}</Button></div>
    </div>}
  </PageSection>
}

function percent(value: number) {
  return `${Math.round(value * 1000) / 10}%`
}

// Area × carrier matrix with the history curve, and on-demand mtr.
export function MatrixCard({ token, initialNode }: { token: string; initialNode?: string }) {
  const { t, i18n } = useTranslation('probeDNSPup')
  const feedback = useFeedback()
  const reason = useReason()
  // cdncaCE: no aggregated edge, so its purpose row and the edge matrix subject are not shown (the row is still
  // saved as read, so the server keeps its settings).
  const [subject, setSubject] = useState<'node' | 'edge'>('node')
  const [id, setID] = useState(initialNode ?? '')
  const [window, setWindow] = useState<ProbeWindow>('24h')
  const [shown, setShown] = useState<{ subject: 'node' | 'edge'; id: string; window: ProbeWindow } | null>(
    initialNode ? { subject: 'node', id: initialNode, window: '24h' } : null)
  const edges = useQuery({ queryKey: ['probe-dnspup-edge-subjects'], queryFn: () => probeDNSPupUnifiedApi.edgeSubjects(token),
    enabled: Boolean(token) && subject === 'edge' })
  const matrix = useQuery({ queryKey: ['probe-dnspup-matrix', shown], enabled: Boolean(token && shown),
    queryFn: () => probeDNSPupUnifiedApi.matrix(token, shown!.subject, shown!.id, shown!.window) })
  const areas = useMemo(() => [...new Set((matrix.data?.cells ?? []).map((cell) => cell.area))].sort(), [matrix.data])
  const carriers = probeCarriers.filter((carrier) => matrix.data?.cells.some((cell) => cell.carrier === carrier))
  const cellOf = (area: string, carrier: string) => matrix.data?.cells.find((cell) => cell.area === area && cell.carrier === carrier)
  // The submitted diagnosis is in the URL (?diagnosis=<id>): a reload or another layout reads it back with GET, which
  // never starts or meters a new mtr; only a pending one is polled.
  const [params, setParams] = useSearchParams()
  const diagnosisID = params.get('diagnosis') ?? ''
  const [started, setStarted] = useState<ProbeDiagnosis | null>(null)
  const [target, setTarget] = useState('')
  const [points, setPoints] = useState('')
  const start = useMutation({
    mutationFn: () => probeDNSPupUnifiedApi.diagnose(token, { target: target.trim(),
      node_id: subject === 'node' && shown?.id ? shown.id : undefined,
      checkpoints: points.split(/[,，\s]+/).filter(Boolean).slice(0, 2) }, newIdempotencyKey('probe-dnspup-diagnose')),
    onSuccess: (created) => {
      setStarted(created)
      setParams((current) => { const next = new URLSearchParams(current); next.set('diagnosis', created.id); return next }, { replace: true })
    },
    onError: (error) => void feedback.error(reason(error)),
  })
  const read = useQuery({ queryKey: ['probe-dnspup-diagnosis', diagnosisID], enabled: Boolean(token && diagnosisID),
    queryFn: () => probeDNSPupUnifiedApi.diagnosis(token, diagnosisID),
    refetchInterval: (query) => query.state.data?.status === 'pending' ? 3000 : false })
  const diagnosis = read.data ?? (started?.id === diagnosisID ? started : null)
  const failure = (code?: string) => code && i18n.exists(`probeDNSPup:errors.${code}`) ? t(`errors.${code}`) : code ?? ''
  const cellText = (cell?: ProbeMatrixCell) => cell ? <Space size={4} wrap>
    <Tag color={cell.availability >= 0.95 ? 'green' : cell.availability >= 0.5 ? 'orange' : 'red'}>
      {t('unified.matrix.cell', { availability: percent(cell.availability), latency: cell.avg_latency_ms })}</Tag>
    {cell.top_failure ? <Typography.Text type="danger">{t(`unified.failures.${cell.top_failure}`)}</Typography.Text> : null}
  </Space> : '—'
  return <PageSection title={t('unified.matrix.title')}>
    <div className="probe-dnspup-section-body">
      <Typography.Paragraph type="secondary" className="probe-dnspup-section-intro">{t('unified.matrix.intro')}</Typography.Paragraph>
      <Space wrap className="probe-dnspup-controls">
        {/* 换对象类型时清空不再适用的选择与结果。 */}
        <Select value={subject} onChange={(next: 'node' | 'edge') => { setSubject(next); setID(''); setShown(null) }} aria-label={t('unified.matrix.subject')} style={{ minWidth: 'min(160px, 100cqi)' }}
          options={(['node'] as const).map((value) => ({ value, label: t(`unified.matrix.subjects.${value}`) }))} />
        {subject === 'node'
          // 节点按名称或编号搜索选择（同「添加覆盖」），值仍是节点 UUID。
          ? <NodePicker token={token} value={id || undefined} onChange={setID} ariaLabel={t('unified.matrix.nodeID')} style={{ minWidth: 'min(280px, 100cqi)' }} />
          : <Select value={id || undefined} onChange={setID} aria-label={t('unified.matrix.edgeHost')} style={{ minWidth: 'min(280px, 100cqi)' }}
            placeholder={t('unified.matrix.edgeHost')} loading={edges.isFetching} options={(edges.data?.items ?? []).map((value) => ({ value, label: value }))}
            notFoundContent={edges.isError ? t('unified.overrides.listFailed') : t('unified.matrix.edgeEmpty')} />}
        <Select value={window} onChange={setWindow} aria-label={t('unified.matrix.window')}
          options={probeWindows.map((value) => ({ value, label: t(`unified.matrix.windows.${value}`) }))} />
        <Button type="primary" disabled={!id.trim()} onClick={() => setShown({ subject, id: id.trim(), window })}>{t('unified.matrix.load')}</Button>
      </Space>
      {matrix.error ? <FeedbackWhen title={reason(matrix.error)} /> : null}
      {matrix.data && matrix.data.cells.length === 0 ? <Alert type="info" showIcon message={t('unified.matrix.empty')} /> : null}
      {matrix.data && matrix.data.cells.length > 0 ? <>
        <Table rowKey="area" size="small" pagination={false} scroll={{ x: true }} dataSource={areas.map((area) => ({ area }))}
          columns={[{ title: t('unified.matrix.area'), dataIndex: 'area', render: (area: string) => area || t('unified.matrix.unknownArea') },
            ...carriers.map((carrier) => ({ title: t(`unified.carriers.${carrier}`), key: carrier,
              render: (_: unknown, row: { area: string }) => cellText(cellOf(row.area, carrier)) }))]} />
        <Typography.Text strong className="probe-dnspup-subtitle">{t('unified.matrix.history')}</Typography.Text>
        <MetricTrendChart status="success" points={matrix.data.series.map((point) => ({
          label: new Date(point.at).toLocaleString(), value: Math.round(point.availability * 1000) / 10 }))} />
      </> : null}
      <Space wrap className="probe-dnspup-controls">
        <Typography.Text strong className="probe-dnspup-subtitle">{t('unified.matrix.diagnose')}</Typography.Text>
        <Input value={target} onChange={(event) => setTarget(event.target.value)} aria-label={t('unified.matrix.diagnoseTarget')}
          placeholder={t('unified.matrix.diagnoseTarget')} style={{ width: 'min(240px, 100cqi)' }} />
        <Input value={points} onChange={(event) => setPoints(event.target.value)} aria-label={t('unified.matrix.diagnosePoints')}
          placeholder={t('unified.matrix.diagnosePoints')} style={{ width: 'min(300px, 100cqi)' }} />
        <Button loading={start.isPending} disabled={!target.trim() || !points.trim()} onClick={() => start.mutate()}>
          {t('unified.matrix.diagnoseStart')}</Button>
      </Space>
      {read.error && !diagnosis ? <Alert showIcon type="error" message={reason(read.error)} /> : null}
      {diagnosis ? <Alert showIcon type={diagnosis.status === 'failed' ? 'error' : diagnosis.status === 'completed' ? 'success' : 'info'}
        message={diagnosis.status === 'pending' ? t('unified.matrix.diagnoseRunning') : diagnosis.status === 'completed'
          ? t('unified.matrix.diagnoseDone') : t('unified.matrix.diagnoseFailed', { code: failure(diagnosis.error_code) })} /> : null}
      {diagnosis?.status === 'completed' ? <MTRResult traces={diagnosis.traces} /> : null}
    </div>
  </PageSection>
}

interface OverrideForm extends SelectionValues {
  kind: 'node' | 'line_group'
  node_id?: string
  // Line group overrides: the platform's own groups, or a tenant's.
  group_scope?: 'platform' | 'tenant'
  tenant_scope_id?: string
  line_group_id?: string
  probe_type?: NodeProbeType | 'inherit'
}

interface SubjectOption { value: string; label: string; tenantScopeID?: string }

// Searchable node picker: the inventory search matches name, IP, display ID and UUID.
function NodePicker({ token, value, onChange, ariaLabel, style }: {
  token: string; value?: string; onChange?: (value: string) => void; ariaLabel?: string; style?: CSSProperties
}) {
  const { t } = useTranslation('probeDNSPup')
  const [search, setSearch] = useState('')
  const [picked, setPicked] = useState<SubjectOption>()
  const term = useDeferredValue(search.trim())
  const query = useQuery({
    queryKey: ['probe-dnspup-override-nodes', term],
    queryFn: () => nodesApi.list(token, { limit: 50, ...(term ? { search: term } : {}) }),
    enabled: Boolean(token), retry: false, staleTime: 60_000,
  })
  const options = (query.data?.items ?? []).map((node): SubjectOption => ({ value: node.id, label: `${node.name} (ID ${node.display_id})` }))
  if (picked && picked.value === value && !options.some((option) => option.value === picked.value)) options.unshift(picked)
  return <Select aria-label={ariaLabel ?? t('unified.overrides.node')} showSearch filterOption={false} onSearch={setSearch} style={style}
    placeholder={t('unified.overrides.nodePlaceholder')} loading={query.isFetching} options={options} value={value}
    notFoundContent={query.isError ? t('unified.overrides.listFailed') : t('unified.overrides.noMatch')}
    onChange={(next: string) => { setPicked(options.find((option) => option.value === next)); onChange?.(next) }} />
}

// Line groups of one scope: the platform's (the session scope) or a picked tenant's (the list carries each group's
// tenant scope).
function useLineGroupOptions(token: string, scopeID: string, enabled: boolean) {
  return useQuery({
    queryKey: ['probe-dnspup-override-line-groups', scopeID],
    queryFn: async () => (await nodeSchedulingApi.list(token, { kind: 'platform', targetScopeId: scopeID })).items
      .map((group): SubjectOption => ({ value: group.id, label: `${group.name} (ID ${group.display_id})`, tenantScopeID: group.tenant_scope_id })),
    enabled: enabled && Boolean(token && scopeID), retry: false, staleTime: 60_000,
  })
}

// Per node / line group overrides of the probe type and the selection.
export function OverridesCard({ token }: { token: string }) {
  const { t } = useTranslation('probeDNSPup')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const reason = useReason()
  const client = useQueryClient()
  const [form] = Form.useForm<OverrideForm>()
  const [adding, setAdding] = useState(false)
  // 触发按钮带展开状态并指向表单；展开后焦点给第一个字段，取消收起并回到触发按钮。
  const formID = useId()
  const toggleRef = useRef<HTMLButtonElement>(null)
  const firstOpen = useRef(false)
  useEffect(() => {
    if (!adding || !firstOpen.current) return
    firstOpen.current = false
    form.getFieldInstance('kind')?.focus?.()
  }, [adding, form])
  const toggle = (open: boolean) => {
    firstOpen.current = open
    setAdding(open)
    if (!open) { form.resetFields(); toggleRef.current?.focus() }
  }
  const kind = Form.useWatch('kind', form)
  const groupScope = Form.useWatch('group_scope', form) ?? 'platform'
  const tenantScopeID = Form.useWatch('tenant_scope_id', form) ?? ''
  const principal = useSessionStore((state) => state.principal)
  const platformScopeID = principal?.scope_id ?? ''
  const canListTenants = Boolean(principal?.permissions.some((p) => p === 'identity.users.manage' || p === 'platform.admin'))
  const groupScopeID = groupScope === 'tenant' ? tenantScopeID : platformScopeID
  const lineGroups = useLineGroupOptions(token, groupScopeID, adding && kind === 'line_group')
  const query = useQuery({ queryKey: ['probe-dnspup-overrides'], queryFn: () => probeDNSPupUnifiedApi.overrides(token), enabled: Boolean(token) })
  const refresh = () => client.invalidateQueries({ queryKey: ['probe-dnspup-overrides'] })
  const save = useMutation({
    mutationFn: async () => {
      const values = await form.validateFields()
      const group = lineGroups.data?.find((option) => option.value === values.line_group_id)
      const input: ProbeOverrideInput = values.kind === 'node' ? { node_id: values.node_id }
        : { tenant_scope_id: group?.tenantScopeID, line_group_id: values.line_group_id }
      if (values.probe_type && values.probe_type !== 'inherit') input.probe_type = values.probe_type
      const selection: ProbeSelection | null = selectionOf(values)
      if (selection) input.selection = selection
      return probeDNSPupUnifiedApi.saveOverride(token, input, newIdempotencyKey('probe-dnspup-override'))
    },
    onSuccess: () => { void refresh(); setAdding(false); form.resetFields(); void message.success(t('unified.overrides.saved')) },
    onError: (error) => void feedback.error(reason(error)),
  })
  const remove = useMutation({
    mutationFn: (id: string) => probeDNSPupUnifiedApi.deleteOverride(token, id, newIdempotencyKey('probe-dnspup-override-delete')),
    onSuccess: () => { void refresh(); void message.success(t('unified.overrides.removed')) },
    onError: (error) => void feedback.error(reason(error)),
  })
  if (query.error) return <PageSection title={t('unified.overrides.title')}><FeedbackWhen title={reason(query.error)} /></PageSection>
  return <PageSection title={t('unified.overrides.title')}
    extra={<Button ref={toggleRef} aria-expanded={adding} aria-controls={adding ? formID : undefined} onClick={() => toggle(!adding)}>
      {t(adding ? 'unified.overrides.collapse' : 'unified.overrides.add')}</Button>}>
    {query.isLoading ? <Skeleton active /> : <div className="probe-dnspup-section-body">
      <Typography.Paragraph type="secondary" className="probe-dnspup-section-intro">{t('unified.overrides.intro')}</Typography.Paragraph>
      <Table rowKey="id" size="small" pagination={false} dataSource={query.data?.items ?? []}
        locale={{ emptyText: t('unified.overrides.empty') }} scroll={{ x: true }}
        columns={[
          { title: t('unified.overrides.subject'), render: (_, item) => <Space size={4}>
            <Tag>{t(`unified.overrides.kinds.${item.subject_kind}`)}</Tag>{item.subject_name || t('unified.overrides.unnamed')}
            {item.subject_kind === 'line_group' && item.tenant_scope_id !== platformScopeID ? <Tag>{t('unified.overrides.tenantTag')}</Tag> : null}
            {/* Display ID when the subject still exists; the UUID stays one copy away. */}
            <Typography.Text type="secondary" copyable={{ text: item.node_id ?? item.line_group_id }}>
              {item.subject_display_id != null ? `ID ${item.subject_display_id}` : item.node_id ?? item.line_group_id}</Typography.Text></Space> },
          { title: t('unified.node.probeType'), render: (_, item) => item.probe_type ? t(`unified.node.probeTypes.${item.probe_type}`) : t('unified.overrides.inherit') },
          { title: t('unified.selection.title'), render: (_, item) => item.selection
            ? [...(item.selection.areas ?? []).map((value) => t(`unified.areas.${value}`)),
              ...(item.selection.carriers ?? []).map((value) => t(`unified.carriers.${value}`))].join(' / ') || `× ${item.selection.points_per_group}`
            : t('unified.overrides.inherit') },
          { title: '', render: (_, item) => <Popconfirm title={t('unified.overrides.remove')} onConfirm={() => remove.mutate(item.id)}>
            <Button size="small" danger>{t('unified.overrides.remove')}</Button></Popconfirm> },
        ]} />
      {adding ? <Form id={formID} form={form} layout="vertical" requiredMark={false} className="probe-dnspup-override-form"
        initialValues={{ kind: 'node', group_scope: 'platform', probe_type: 'inherit', selection_enabled: false, points_per_group: 3 }}>
        <div className="density-form-grid probe-dnspup-form-grid">
        <Form.Item name="kind" label={t('unified.overrides.subject')}>
          <Select aria-label={t('unified.overrides.subject')} options={(['node', 'line_group'] as const).map((value) => ({ value, label: t(`unified.overrides.kinds.${value}`) }))} />
        </Form.Item>
        {kind === 'line_group' ? <>
          <Form.Item name="group_scope" label={t('unified.overrides.groupScope')}>
            <Radio.Group onChange={() => form.setFieldsValue({ tenant_scope_id: undefined, line_group_id: undefined })}
              options={[{ value: 'platform', label: t('unified.overrides.groupScopes.platform') },
                { value: 'tenant', label: t('unified.overrides.groupScopes.tenant') }]} />
          </Form.Item>
          {groupScope === 'tenant'
            ? <Form.Item name="tenant_scope_id" label={t('unified.overrides.tenant')} rules={[{ required: true, message: t('unified.overrides.required') }]}>
              <TenantScopeSelect accessToken={token} ownerKey={platformScopeID} canList={canListTenants} queryKeyPrefix="probe-dnspup-override-tenants"
                ariaLabel={t('unified.overrides.tenant')} placeholder={t('unified.overrides.tenantPlaceholder')} emptyText={t('unified.overrides.noMatch')}
                value={tenantScopeID}
                onChange={(scopeID) => form.setFieldsValue({ tenant_scope_id: scopeID || undefined, line_group_id: undefined })} />
            </Form.Item> : null}
          <Form.Item name="line_group_id" label={t('unified.overrides.lineGroup')} rules={[{ required: true, message: t('unified.overrides.required') }]}>
            <Select aria-label={t('unified.overrides.lineGroup')} showSearch optionFilterProp="label"
              placeholder={t('unified.overrides.lineGroupPlaceholder')} loading={lineGroups.isFetching} options={lineGroups.data ?? []}
              notFoundContent={lineGroups.isError ? t('unified.overrides.listFailed') : t('unified.overrides.noMatch')} />
          </Form.Item></>
          : <Form.Item name="node_id" label={t('unified.overrides.node')} rules={[{ required: true, message: t('unified.overrides.required') }]}>
            <NodePicker token={token} />
          </Form.Item>}
        <Form.Item name="probe_type" label={t('unified.node.probeType')}>
          <Select aria-label={t('unified.node.probeType')} options={[{ value: 'inherit', label: t('unified.overrides.inherit') },
            ...nodeProbeTypes.map((value) => ({ value, label: t(`unified.node.probeTypes.${value}`) }))]} />
        </Form.Item>
        <SelectionFields form={form} />
        </div>
        <Space>
          <Button type="primary" loading={save.isPending} onClick={() => save.mutate()}>{t('unified.overrides.save')}</Button>
          <Button disabled={save.isPending} onClick={() => toggle(false)}>{t('unified.overrides.cancel')}</Button>
        </Space>
      </Form> : null}
    </div>}
  </PageSection>
}
