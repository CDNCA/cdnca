import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, vi } from 'vitest'

import { notificationHistoryApi } from '../api/notificationHistory'
import SystemSentLogPanel from '../pages/SystemSentLogPanel'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

vi.mock('../api/notificationHistory', async () => {
  const actual = await vi.importActual<typeof import('../api/notificationHistory')>('../api/notificationHistory')
  return {
    ...actual,
    notificationHistoryApi: {
      ...actual.notificationHistoryApi,
      list: vi.fn().mockResolvedValue({
        schema: 'cdnca.notification-delivery-history/v1', items: [], total_count: 0,
      }),
    },
  }
})

beforeEach(() => {
  vi.clearAllMocks()
  useSessionStore.getState().setSession(authResponse(principal({
    scope_kind: 'platform', tenant_id: null, permissions: ['system_configuration.read'],
  })), principal({
    scope_kind: 'platform', tenant_id: null, permissions: ['system_configuration.read'],
  }))
})

it('exposes the observed competitor notification types and submits the selected legacy value', async () => {
  renderWithProviders(<SystemSentLogPanel />)
  await screen.findByText('暂无数据')

  fireEvent.mouseDown(screen.getByRole('combobox', { name: '所有类型' }))
  for (const label of ['套餐即将到期', '套餐已到期', '流量即将用尽', '流量已用尽', 'CC规则组自动切换', '套餐带宽超限', '套餐连接数超限', '证书已过期', '证书即将过期', '二次实名']) {
    expect(await screen.findByText(label)).toBeInTheDocument()
  }
  expect(screen.queryByText('公告已发布')).not.toBeInTheDocument()

  fireEvent.click(screen.getByText('套餐即将到期'))
  await waitFor(() => expect(vi.mocked(notificationHistoryApi.list)).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({
    eventType: 'package-expiring',
  }), expect.anything()))
})
