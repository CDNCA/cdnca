import { Table, Tag, type TableColumnsType } from 'antd'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'

import type { CacheItemState, CacheOperation } from '../api/cacheOperations'
import '../i18n/cacheOperations'
import { formatNumber } from '../i18n/formatters'
import { cacheFailureText } from './cacheFailureText'
import './CacheOperationOutcome.css'

// CACHE-ADD-06 (P2-10): the outcome part of a cache task's detail, shared by
// the purge page and the operation history so both answer the same way which
// URL ended how on which node, why, and what to do next.

type ItemState = CacheItemState | 'unconfirmed'

interface OutcomeRow {
  key: string
  url: string
  nodeID: string
  nodeDisplayID: string
  state: ItemState
  errorCode?: string
}

const itemColor: Partial<Record<ItemState, string>> = {
  succeeded: 'success', failed: 'error', running: 'processing', cancelled: 'default', unconfirmed: 'warning',
}

function outcomeRows(operation: CacheOperation): OutcomeRow[] {
  const urls = new Map(operation.targets.map((target) => [target.ordinal, target.display_url]))
  const rows: OutcomeRow[] = []
  for (const node of operation.nodes) {
    const reported = new Map(node.targets.map((target) => [target.target_ordinal, target]))
    for (const target of operation.targets) {
      const item = reported.get(target.ordinal)
      rows.push({
        key: `${node.node_id}-${target.ordinal}`,
        url: target.display_url,
        nodeID: node.node_id,
        nodeDisplayID: node.node_display_id,
        // An item the node has not reported yet (or an older node that
        // reports only its summary) is not confirmed, not "queued".
        state: item ? item.state : 'unconfirmed',
        errorCode: item?.error_code,
      })
    }
    for (const item of node.targets) {
      if (urls.has(item.target_ordinal)) continue
      rows.push({
        key: `${node.node_id}-${item.target_ordinal}`, url: `#${item.target_ordinal}`, nodeID: node.node_id,
        nodeDisplayID: node.node_display_id, state: item.state, errorCode: item.error_code,
      })
    }
  }
  // Failures first: the user opens the detail to find them.
  const order: Record<ItemState, number> = { failed: 0, unconfirmed: 1, running: 2, queued: 3, cancelled: 4, succeeded: 5 }
  return rows.sort((a, b) => order[a.state] - order[b.state])
}

function nextStep(row: OutcomeRow, operation: CacheOperation, t: TFunction<'cacheOperations'>): string {
  if (row.state === 'failed') {
    return operation.state === 'failed' || operation.state === 'partial_failed' ? t('outcome.next.retryFailed') : t('outcome.next.wait')
  }
  if (row.state === 'cancelled') return t('outcome.next.resubmit')
  if (row.state === 'succeeded') return t('values.placeholder')
  return t('outcome.next.wait')
}

export default function CacheOperationOutcome({ operation }: { operation: CacheOperation }) {
  const { t, i18n } = useTranslation('cacheOperations')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const { progress } = operation
  const total = Math.max(progress.total, 0)
  const share = (value: number) => total === 0 ? 0 : value / total * 100
  const rows = outcomeRows(operation)

  const columns: TableColumnsType<OutcomeRow> = [
    { title: t('history.table.target'), dataIndex: 'url', width: 360, render: (value: string) => <code>{value}</code> },
    {
      title: t('detail.node'), dataIndex: 'nodeDisplayID', width: 90,
      render: (value: string, row) => <span title={row.nodeID}>{value}</span>,
    },
    {
      title: t('history.table.state'), dataIndex: 'state', width: 100,
      render: (value: ItemState) => <Tag color={itemColor[value]}>{t(`outcome.states.${value}`)}</Tag>,
    },
    {
      title: t('detail.failure'), dataIndex: 'errorCode', width: 240,
      render: (value: string | undefined, row) => row.state === 'succeeded' ? t('values.placeholder') : cacheFailureText(value, t),
    },
    { title: t('outcome.nextStep'), key: 'next', width: 180, render: (_value, row) => nextStep(row, operation, t) },
  ]

  return (
    <div className="cache-operation-outcome">
      {/* One bar for every state: green succeeded, red failed, grey cancelled; the rest is still open. */}
      <div className="cache-operation-outcome-head">
        <strong>{t('outcome.finished', { done: formatNumber(progress.completed, locale), total: formatNumber(total, locale) })}</strong>
        <div className="cache-operation-outcome-facts" aria-label={t('outcome.factsLabel')}>
          {(['succeeded', 'failed', 'cancelled'] as const).map((key) => (
            <span key={key} className={`is-${key}`}>{t('progress.fact', { label: t(`progress.${key}`), value: formatNumber(progress[key], locale) })}</span>
          ))}
        </div>
      </div>
      <div
        className="cache-operation-outcome-bar"
        role="progressbar"
        aria-label={t('outcome.finished', { done: progress.completed, total })}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={progress.completed}
      >
        {(['succeeded', 'failed', 'cancelled'] as const).map((key) => (
          <span key={key} className={`is-${key}`} style={{ width: `${share(progress[key])}%` }} />
        ))}
      </div>
      {operation.target_type === 'whole_site' && operation.targets.length === 0 ? (
        <p className="cache-operation-outcome-empty">{t('outcome.wholeSite')}</p>
      ) : (
        <section aria-label={t('outcome.title')}>
          <h3>{t('outcome.title')}</h3>
          <Table<OutcomeRow>
            rowKey="key"
            size="small"
            columns={columns}
            dataSource={rows}
            pagination={rows.length > 50 ? { pageSize: 50, showSizeChanger: false } : false}
            locale={{ emptyText: t('values.noNodes') }}
            scroll={{ x: 970 }}
          />
        </section>
      )}
    </div>
  )
}
