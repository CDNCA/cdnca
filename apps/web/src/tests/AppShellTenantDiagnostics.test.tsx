import { screen } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'

import * as session from '../auth/session'
import { AppShell } from '../components/AppShell'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 租户的四层访问日志在「统计分析 › 诊断」下；深链进入要展开两层祖先并高亮该项。
describe('tenant diagnostics deep link', () => {
  it('opens 统计分析 and 诊断 and highlights 四层访问日志', async () => {
    const actor = principal({ scope_kind: 'tenant', roles: ['tenant_owner'], permissions: ['sites.read', 'streams.read'] })
    session.useSessionStore.getState().setSession(authResponse(actor), actor)
    const { container } = renderWithProviders(
      <Routes>
        <Route element={<AppShell />}>
          <Route path="*" element={<section aria-label="diagnostics-probe" />} />
        </Route>
      </Routes>,
      ['/monitor/stream/access-log'],
    )
    const entry = await screen.findByRole('menuitem', { name: '四层访问日志' })
    expect(entry.closest('li')).toHaveClass('ant-menu-item-selected')
    expect(screen.getByRole('menuitem', { name: '统计分析' })).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('menuitem', { name: '诊断' })).toHaveAttribute('aria-expanded', 'true')
    expect(container.querySelector('.shell-breadcrumb-a11y')).toHaveTextContent('首页/统计分析/诊断/四层访问日志')
  })
})
