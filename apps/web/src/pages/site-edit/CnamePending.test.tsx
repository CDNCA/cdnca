import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import { renderWithProviders } from '../../test/render'
import CnamePending from './CnamePending'

function TaskProbe() { return <div>任务中心 {useLocation().search}</div> }

describe('CnamePending', () => {
  it('a pending CNAME without a stall code stays a plain 生成中 tag', () => {
    renderWithProviders(<CnamePending code={null} admin onRegenerate={vi.fn()} />)
    expect(screen.getByTestId('site-cname-pending')).toHaveTextContent('生成中')
    expect(screen.queryByTestId('site-cname-stalled')).not.toBeInTheDocument()
  })

  it('a stalled CNAME shows why and offers 重新生成 CNAME and the task center', async () => {
    const onRegenerate = vi.fn()
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<Routes>
      <Route path="/site/list" element={<CnamePending code="cname_stalled" taskID="task-1" admin onRegenerate={onRegenerate} />} />
      <Route path="/sys/task" element={<TaskProbe />} />
    </Routes>, ['/site/list'])

    await user.click(screen.getByTestId('site-cname-stalled'))
    const dialog = await screen.findByRole('dialog', { name: '生成中（已停滞）' })
    expect(within(dialog).getByTestId('cname-pending-reason')).toHaveTextContent('超过 15 分钟仍未完成')
    await user.click(within(dialog).getByRole('button', { name: '重新生成 CNAME' }))
    expect(onRegenerate).toHaveBeenCalledTimes(1)

    await user.click(screen.getByTestId('site-cname-stalled'))
    await user.click(within(await screen.findByRole('dialog', { name: '生成中（已停滞）' })).getByRole('button', { name: '去任务中心' }))
    expect(await screen.findByText('任务中心 ?task_id=task-1')).toBeInTheDocument()
  })

  it('without regenerate permission the dialog only explains the stall', async () => {
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<CnamePending code="cname_worker_idle" admin={false} />)
    await user.click(screen.getByTestId('site-cname-stalled'))
    const dialog = await screen.findByRole('dialog', { name: '生成中（已停滞）' })
    expect(within(dialog).getByTestId('cname-pending-reason')).toHaveTextContent('排队超过 5 分钟')
    expect(within(dialog).queryByRole('button', { name: '重新生成 CNAME' })).not.toBeInTheDocument()
  })
})
