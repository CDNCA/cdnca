import { fireEvent, screen } from '@testing-library/react'
import { Route, Routes, useLocation } from 'react-router-dom'

import * as session from '../auth/session'
import { AppShell } from '../components/AppShell'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

function LocationProbe() {
  return <output data-testid="shell-location">{useLocation().pathname}</output>
}

function renderTenant(permissions: string[]) {
  const actor = principal({ scope_kind: 'tenant', roles: ['tenant_owner'], permissions })
  session.useSessionStore.getState().setSession(authResponse(actor), actor)
  return renderWithProviders(
    <Routes>
      <Route element={<AppShell />}>
        <Route path="*" element={<LocationProbe />} />
      </Route>
    </Routes>,
    ['/account/user'],
  )
}

// ui-fix1: the balance and message pages had routes but no menu entry.
// tp-b1: the balance page is named 账户充值 like the competitor's; the balance
// ledger entry is gone (merged into 消费记录).
describe('account center sidebar entries', () => {
  it.each([
    ['消息查询', '/account/message'],
  ])('opens %s from the account center', async (label, path) => {
    renderTenant(['billing.account.read', 'announcements.read'])
    const entry = await screen.findByRole('menuitem', { name: label })
    fireEvent.click(entry)
    expect(screen.getByTestId('shell-location')).toHaveTextContent(path)
  })

  // 社区版：账户中心没有账户充值。
  it('has no balance entry even with billing.account.read', async () => {
    renderTenant(['billing.account.read', 'announcements.read'])
    expect(await screen.findByRole('menuitem', { name: '消息查询' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: '账户充值' })).not.toBeInTheDocument()
  })

  it('hides the entries without the pages\' permissions', async () => {
    // fp-role ID-06：个人资料也跟随页面权限 identity.self.read。
    renderTenant(['identity.self.read'])
    expect(await screen.findByRole('menuitem', { name: '个人资料' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: '账户充值' })).not.toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: '消息查询' })).not.toBeInTheDocument()
  })
})
