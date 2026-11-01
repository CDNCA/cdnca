import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { changeLocale } from '../i18n'
import { stream } from '../tests/streamFixture'
import StreamPublicationModal from './StreamPublicationModal'

const failed = (failure_code: string | null) => ({ ...stream, publish_intent: { ...stream.publish_intent, state: 'failed' as const, failure_code } })

// A3-04：发布详情给出失败原因（已知码中英文说明，未知码原样显示）。
describe('StreamPublicationModal failure reason', () => {
  it.each([
    ['zh-CN', 'node_artifacts_syncing', /节点尚未加载 IP 库/],
    ['zh-CN', 'node_capability_unavailable', /节点能力不足/],
    ['zh-CN', 'no_target_nodes', /没有可用节点/],
    ['en-US', 'node_artifacts_syncing', /Nodes have not loaded the IP library/],
    ['en-US', 'node_scope_conflict', /occupied by another user/],
  ])('%s maps %s', async (language, code, text) => {
    await changeLocale(language as 'zh-CN' | 'en-US')
    render(<StreamPublicationModal item={failed(code)} onClose={() => {}} />)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(text)).toBeInTheDocument()
    expect(within(dialog).getByText(code)).toBeInTheDocument()
  })

  it('shows an unknown code as is', async () => {
    await changeLocale('zh-CN')
    render(<StreamPublicationModal item={failed('future_reason_x')} onClose={() => {}} />)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('失败原因')).toBeInTheDocument()
    expect(within(dialog).getAllByText('future_reason_x').length).toBeGreaterThan(0)
  })

  it('says when a failed publication recorded no reason, in English too', async () => {
    await changeLocale('en-US')
    render(<StreamPublicationModal item={failed(null)} onClose={() => {}} />)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Failure reason')).toBeInTheDocument()
    expect(within(dialog).getByText(/No failure reason was recorded/)).toBeInTheDocument()
    await changeLocale('zh-CN')
  })

  it('has no failure row unless the publication failed', async () => {
    await changeLocale('zh-CN')
    render(<StreamPublicationModal item={stream} onClose={() => {}} />)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByText('失败原因')).toBeNull()
  })
})
