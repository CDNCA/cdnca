import { Collapse, Descriptions, Tag, Typography } from 'antd'
import { Table } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import '../../i18n/probeDNSPup'

// One checkpoint's mtr as dnspup answers it (traces[] of GET /v1/admin/probe-dnspup/diagnoses/{id}; fields as the
// 1132 live answer: real-dns-and-mtr-evidence-20261123.json). "--" is dnspup's "no value".
export interface MTRHop {
  hop?: number
  ip?: string
  ptr?: string
  serverPtr?: string
  agentPtr?: string
  averageMs?: number
  loss?: string
  sent?: number
  status?: string
}

export interface MTRTrace {
  nodeId?: string
  node?: string
  isp?: string
  city?: string
  region?: string
  available?: boolean
  trace?: { target?: string; targetIp?: string; complete?: boolean; hops?: MTRHop[] }
}

const record = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)
const text = (value: unknown) => typeof value === 'string' && value !== '' && value !== '--' ? value : undefined
const count = (value: unknown) => typeof value === 'number' && Number.isFinite(value) ? value : undefined

function hopOf(value: unknown): MTRHop | null {
  if (!record(value)) return null
  return { hop: count(value.hop), ip: text(value.ip), ptr: text(value.ptr), serverPtr: text(value.serverPtr),
    agentPtr: text(value.agentPtr), averageMs: count(value.averageMs), loss: text(value.loss), sent: count(value.sent),
    status: text(value.status) }
}

/** The checkpoints of a diagnosis' traces; anything not shaped like a trace is left out (it stays in the raw JSON). */
function tracesOf(traces: unknown): MTRTrace[] {
  if (!Array.isArray(traces)) return []
  return traces.filter(record).map((item) => {
    const trace = record(item.trace) ? item.trace : {}
    return { nodeId: text(item.nodeId), node: text(item.node), isp: text(item.isp), city: text(item.city), region: text(item.region),
      available: typeof item.available === 'boolean' ? item.available : undefined,
      trace: { target: text(trace.target), targetIp: text(trace.targetIp),
        complete: typeof trace.complete === 'boolean' ? trace.complete : undefined,
        hops: Array.isArray(trace.hops) ? trace.hops.map(hopOf).filter((hop): hop is MTRHop => hop !== null) : [] } }
  })
}

function TraceTable({ trace, index }: { trace: MTRTrace; index: number }) {
  const { t } = useTranslation('probeDNSPup')
  const hops = trace.trace?.hops ?? []
  const noResponse = trace.available === false || hops.length === 0
  const state = noResponse ? <Tag>{t('unified.mtr.noResponse')}</Tag>
    : trace.trace?.complete === false ? <Tag color="orange">{t('unified.mtr.partial')}</Tag>
      : <Tag color="green">{t('unified.mtr.complete')}</Tag>
  const place = [trace.node, trace.isp].filter(Boolean).join(' · ')
  const target = trace.trace?.targetIp && trace.trace.targetIp !== trace.trace.target
    ? `${trace.trace.target ?? ''} (${trace.trace.targetIp})` : trace.trace?.target ?? trace.trace?.targetIp ?? '—'
  return <div className="probe-dnspup-mtr-trace" data-testid={`mtr-trace-${index}`}>
    <Descriptions size="small" bordered column={{ xs: 1, md: 3 }}>
      <Descriptions.Item label={t('unified.mtr.checkpoint')}>
        <span>{place || trace.nodeId || '—'}</span>
        {place && trace.nodeId ? <Typography.Text type="secondary"> {trace.nodeId}</Typography.Text> : null}
      </Descriptions.Item>
      <Descriptions.Item label={t('unified.mtr.target')}>{target}</Descriptions.Item>
      <Descriptions.Item label={t('unified.mtr.state')}>{state}</Descriptions.Item>
    </Descriptions>
    {noResponse ? null : <Table<MTRHop> size="small" pagination={false} scroll={{ x: true }} dataSource={hops}
      rowKey={(hop) => `${hop.hop ?? ''}-${hop.ip ?? ''}`}
      columns={[
        { title: t('unified.mtr.hop'), dataIndex: 'hop', width: 64 },
        { title: t('unified.mtr.host'), render: (_, hop) => {
          const name = hop.serverPtr ?? hop.ptr ?? hop.agentPtr
          return <span className="probe-dnspup-mtr-host">{hop.ip ?? '*'}
            {name && name !== hop.ip ? <Typography.Text type="secondary">{name}</Typography.Text> : null}</span>
        } },
        { title: t('unified.mtr.average'), dataIndex: 'averageMs', align: 'right',
          render: (value: number | undefined, hop) => value === undefined || !hop.ip ? '—' : value },
        { title: t('unified.mtr.loss'), dataIndex: 'loss', align: 'right',
          render: (value: string | undefined) => value ?? '—' },
        { title: t('unified.mtr.sent'), dataIndex: 'sent', align: 'right', render: (value: number | undefined) => value ?? '—' },
      ]} />}
  </div>
}

// A finished mtr: one hop table per checkpoint, the raw answer folded away.
export function MTRResult({ traces }: { traces: unknown }) {
  const { t } = useTranslation('probeDNSPup')
  const items = tracesOf(traces)
  return <div className="probe-dnspup-mtr">
    {items.length === 0 ? <Typography.Text type="secondary">{t('unified.mtr.empty')}</Typography.Text>
      : items.map((trace, index) => <TraceTable key={`${trace.nodeId ?? ''}-${index}`} trace={trace} index={index} />)}
    {traces === undefined || traces === null ? null : <Collapse size="small" items={[{ key: 'raw', label: t('unified.mtr.raw'),
      children: <pre className="probe-dnspup-mtr-raw">{JSON.stringify(traces, null, 2)}</pre> }]} />}
  </div>
}
