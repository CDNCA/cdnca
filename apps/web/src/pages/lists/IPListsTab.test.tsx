import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import * as api from '../../api/securityIPLists'
import { renderWithProviders } from '../../test/render'
import { IPListsTab } from './IPListsTab'

const list: api.SecurityIPList = {
  id: '0199e2a4-7c1d-7a3b-8f00-0000000000a1', name: 'office', description: '', entries: ['192.0.2.1'],
  revision: 1, platform: false, updated_at: '2026-11-23T22:00:00Z', reference_count: 0,
}

describe('IPListsTab', () => {
  // 行操作列固定在右侧，窄屏横滑时编辑/删除仍在可视区。
  it('pins the row actions to the right edge', async () => {
    vi.spyOn(api, 'listSecurityIPLists').mockResolvedValue([list])
    renderWithProviders(<IPListsTab audience="tenant" accessToken="t" canManage />)
    const edit = await screen.findByRole('button', { name: /编辑/ })
    expect(edit.closest('td')).toHaveClass('ant-table-cell-fix-right')
  })

  // 保存回执只确认名单与版本，不从保存推断网站已重新发布。
  it('confirms a save with the list and revision only', async () => {
    vi.spyOn(api, 'listSecurityIPLists').mockResolvedValue([list])
    vi.spyOn(api, 'updateSecurityIPList').mockResolvedValue({ ...list, revision: 2 })
    const user = userEvent.setup()
    renderWithProviders(<IPListsTab audience="tenant" accessToken="t" canManage />)
    await user.click(await screen.findByRole('button', { name: /编辑/ }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(api.updateSecurityIPList).toHaveBeenCalled())
    expect(await screen.findByText('已保存名单“office”（版本 2）。')).toBeInTheDocument()
    expect(screen.queryByText(/重新发布/)).not.toBeInTheDocument()
  })
})
