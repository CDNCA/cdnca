import { screen, within } from '@testing-library/react'

import type { CacheOperation } from '../api/cacheOperations'
import CacheOperationOutcome from '../components/CacheOperationOutcome'
import { renderWithProviders } from '../test/render'

const nodeA = '44444444-4444-4444-8444-444444444444'
const nodeB = '45555555-5555-4555-8555-555555555555'

const base: CacheOperation = {
  id: '55555555-5555-4555-8555-555555555555',
  display_id: '12',
  site_id: '33333333-3333-4333-8333-333333333333',
  site_display_id: '3',
  action: 'purge',
  target_type: 'exact_url',
  state: 'partial_failed',
  max_attempts: 4,
  auto_nodes: false,
  progress: { total: 3, completed: 3, succeeded: 1, failed: 1, cancelled: 1 },
  targets: [
    { ordinal: 1, display_url: 'https://www.example.com/a.js?v=1', canonical_path: '/a.js?v=1', target_sha256: 'a'.repeat(64), query_redacted: false },
    { ordinal: 2, display_url: 'https://www.example.com/a.js?v=2', canonical_path: '/a.js?v=2', target_sha256: 'b'.repeat(64), query_redacted: false },
    { ordinal: 3, display_url: 'https://www.example.com/b.js?token=redacted', canonical_path: '/b.js?token=redacted', target_sha256: 'c'.repeat(64), query_redacted: true },
  ],
  nodes: [{
    node_id: nodeA, node_display_id: '7', state: 'partial_failed', attempt: 1,
    progress: { total: 3, completed: 3, succeeded: 1, failed: 1, cancelled: 1 },
    targets: [
      { target_ordinal: 1, state: 'succeeded', attempt: 1, sequence: 1 },
      { target_ordinal: 2, state: 'failed', attempt: 1, sequence: 2, error_code: 'cache_delete_failed' },
      { target_ordinal: 3, state: 'cancelled', attempt: 1, sequence: 3, error_code: 'cancelled' },
    ],
    updated_at: '2026-07-28T08:00:00Z',
  }],
  created_at: '2026-07-28T07:59:00Z',
  updated_at: '2026-07-28T08:00:00Z',
}

// P2-10 CACHE-ADD-06：详情直接回答哪条 URL、哪个节点、什么原因、下一步。
describe('CacheOperationOutcome', () => {
  it('names the failed URL, node, reason and next step instead of an ordinal', () => {
    renderWithProviders(<CacheOperationOutcome operation={base} />)

    const results = screen.getByRole('region', { name: '逐项结果' })
    const failed = within(results).getByText('https://www.example.com/a.js?v=2').closest('tr')!
    expect(within(failed).getByText('7')).toHaveAttribute('title', nodeA)
    expect(within(failed).getByText('失败')).toBeInTheDocument()
    expect(within(failed).getByText('节点删除缓存条目失败')).toBeInTheDocument()
    expect(within(failed).getByText('重新提交失败项')).toBeInTheDocument()
    // Same path, other query: its own row and outcome.
    const succeeded = within(results).getByText('https://www.example.com/a.js?v=1').closest('tr')!
    expect(within(succeeded).getByText('成功')).toBeInTheDocument()
    const cancelled = within(results).getByText('https://www.example.com/b.js?token=redacted').closest('tr')!
    expect(within(cancelled).getByText('已取消')).toBeInTheDocument()
    expect(screen.queryByText('token=abc')).toBeNull()
  })

  it('reports finished N/M with success, failure and cancel counts in one color rule', () => {
    const { container } = renderWithProviders(<CacheOperationOutcome operation={base} />)

    expect(screen.getByText('已结束 3/3')).toBeInTheDocument()
    expect(screen.getByLabelText('任务结果统计')).toHaveTextContent('成功：1失败：1取消：1')
        expect(container.querySelector('.cache-operation-outcome-bar')).not.toBeNull()
  })

  it('shows not-yet-confirmed items of an old node and an all-cancelled task', () => {
    renderWithProviders(<CacheOperationOutcome operation={{
      ...base,
      state: 'cancelled',
      progress: { total: 3, completed: 1, succeeded: 0, failed: 0, cancelled: 1 },
      nodes: [{ ...base.nodes[0]!, state: 'cancelled', targets: [{ target_ordinal: 3, state: 'cancelled', attempt: 1, sequence: 1, error_code: 'cancelled' }] },
        { ...base.nodes[0]!, node_id: nodeB, node_display_id: '8', state: 'queued', targets: [] }],
    }} />)

    expect(screen.getByText('已结束 1/3')).toBeInTheDocument()
    const results = screen.getByRole('region', { name: '逐项结果' })
    expect(within(results).getAllByText('未确认').length).toBeGreaterThan(0)
  })

  it('states a whole-site task has no per-URL items', () => {
    renderWithProviders(<CacheOperationOutcome operation={{
      ...base, target_type: 'whole_site', targets: [], state: 'succeeded',
      progress: { total: 1, completed: 1, succeeded: 1, failed: 0, cancelled: 0 },
      nodes: [{ ...base.nodes[0]!, state: 'succeeded', targets: [] }],
    }} />)
    expect(screen.getByText('已结束 1/1')).toBeInTheDocument()
    expect(screen.getByText('整站刷新按节点汇总，没有逐条 URL')).toBeInTheDocument()
  })
})
