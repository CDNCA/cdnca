import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import { renderWithProviders } from '../../test/render'
import CnameFailureActions from './CnameFailureActions'

function TicketProbe() { return <div>工单页 {useLocation().search}</div> }

const reason = '尚未配置 DNS 服务商（节点管理 → DNS配置）'

describe('CnameFailureActions (ui-feedback-modal)', () => {
  it('shows a 生成失败 mark in place; the dialog holds the reason, 去 DNS 配置, 重新生成 and 知道了', async () => {
    const onRegenerate = vi.fn()
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<Routes>
      <Route path="/site/list" element={<CnameFailureActions code="dns_provider_not_configured" reason={reason} admin onRegenerate={onRegenerate} />} />
      <Route path="/node/dns" element={<div>DNS 配置页</div>} />
    </Routes>, ['/site/list'])

    // Only the mark in the cell; the reason sentence and code wait in the dialog.
    expect(screen.queryByText('原因码：未配置DNS服务商')).not.toBeInTheDocument()
    // 53 补充：名称只说失败对象，原因作为说明，不拼标点。
    const mark = screen.getByRole('button', { name: 'CNAME 生成失败' })
    expect(mark).toHaveAccessibleDescription(reason)
    expect(mark.getAttribute('aria-label')).not.toMatch(/[。，]{2}|。，|，。/)
    await user.click(mark)
    const dialog = await screen.findByRole('dialog', { name: 'CNAME 生成失败' })
    expect(within(dialog).getByTestId('cname-failure-text')).toHaveTextContent(reason)
    expect(within(dialog).getByTestId('cname-failure-code')).toHaveTextContent('原因码：未配置DNS服务商')
    expect(within(dialog).getByRole('button', { name: '知道了' })).toBeInTheDocument()

    await user.click(within(dialog).getByRole('button', { name: '重新生成' }))
    expect(onRegenerate).toHaveBeenCalledOnce()
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: /生成失败/ }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '去 DNS 配置' }))
    expect(await screen.findByText('DNS 配置页')).toBeInTheDocument()
  })

  it('closes with 知道了 and with Esc', async () => {
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<CnameFailureActions code="node_targets_unavailable" reason="线路组没有可解析的节点 IP" admin />)
    await user.click(screen.getByRole('button', { name: /生成失败/ }))
    // rc-dialog reads keyCode, which user-event does not set; a real browser does (see the after screenshots).
    fireEvent.keyDown(await screen.findByRole('dialog'), { key: 'Escape', code: 'Escape', keyCode: 27 })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: /生成失败/ }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '知道了' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('FLOW001: sends an administrator to line groups and a tenant to a ticket when no line is available', async () => {
    const user = userEvent.setup({ delay: null })
    const routes = (admin: boolean) => <Routes>
      <Route path="/site/list" element={<CnameFailureActions code="cname_no_default_line_group" reason="x" admin={admin} siteID="11111111-1111-4111-8111-111111111111" />} />
      <Route path="/node/line-group" element={<div>线路组页</div>} />
      <Route path="/account/tickets" element={<TicketProbe />} />
    </Routes>
    const { unmount } = renderWithProviders(routes(true), ['/site/list'])
    await user.click(screen.getByRole('button', { name: /生成失败/ }))
    let dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByRole('button', { name: '联系管理员（提交工单）' })).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '去线路组' }))
    expect(await screen.findByText('线路组页')).toBeInTheDocument()
    unmount()
    renderWithProviders(routes(false), ['/site/list'])
    await user.click(screen.getByRole('button', { name: /生成失败/ }))
    dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByRole('button', { name: '去线路组' })).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '联系管理员（提交工单）' }))
    expect(await screen.findByText('工单页 ?new=1&site_id=11111111-1111-4111-8111-111111111111')).toBeInTheDocument()
  })

  // 两种原因各给对应入口；普通用户只有工单，没有 /node/dns 与“重新生成”。
  it('package without a CNAME domain vs missing DNS provider: entry by role, no regenerate for a tenant', async () => {
    const user = userEvent.setup({ delay: null })
    const siteID = '11111111-1111-4111-8111-111111111111'
    const routes = (code: string, admin: boolean, onRegenerate = vi.fn()) => <Routes>
      <Route path="/site/list" element={<CnameFailureActions code={code} reason="r" admin={admin} siteID={siteID} onRegenerate={onRegenerate} />} />
      <Route path="/node/dns" element={<div>DNS 配置页</div>} />
      <Route path="/account/tickets" element={<TicketProbe />} />
    </Routes>
    const open = async () => {
      await user.click(screen.getByRole('button', { name: /生成失败/ }))
      return screen.findByRole('dialog')
    }

    let view = renderWithProviders(routes('cname_package_domain_missing', true), ['/site/list'])
    let dialog = await open()
    expect(within(dialog).getByTestId('cname-failure-code')).toHaveTextContent('原因码：套餐未绑定CNAME域名')
    expect(within(dialog).queryByRole('button', { name: '去 DNS 配置' })).not.toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '重新生成' })).toBeInTheDocument()
    // 社区版没有套餐管理页：只给原因与“重新生成”，不给跳转。
    expect(within(dialog).queryByRole('button', { name: '去套餐管理' })).not.toBeInTheDocument()
    view.unmount()

    view = renderWithProviders(routes('dns_provider_not_configured', true), ['/site/list'])
    dialog = await open()
    expect(within(dialog).queryByRole('button', { name: '去套餐管理' })).not.toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '重新生成' })).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '去 DNS 配置' })).toBeInTheDocument()
    view.unmount()

    for (const code of ['cname_package_domain_missing', 'dns_provider_not_configured']) {
      const onRegenerate = vi.fn()
      view = renderWithProviders(routes(code, false, onRegenerate), ['/site/list'])
      dialog = await open()
      expect(within(dialog).queryByRole('button', { name: '去 DNS 配置' })).not.toBeInTheDocument()
      expect(within(dialog).queryByRole('button', { name: '去套餐管理' })).not.toBeInTheDocument()
      expect(within(dialog).queryByRole('button', { name: '重新生成' })).not.toBeInTheDocument()
      expect(dialog.querySelector('a[href="/node/dns"]')).toBeNull()
      await user.click(within(dialog).getByRole('button', { name: '联系管理员（提交工单）' }))
      expect(await screen.findByText(`工单页 ?new=1&site_id=${siteID}`)).toBeInTheDocument()
      expect(onRegenerate).not.toHaveBeenCalled()
      view.unmount()
    }
  })

  it('hides 去 DNS 配置 for tenants and non-configuration failures, and 重新生成 without the right', async () => {
    const user = userEvent.setup({ delay: null })
    const { unmount } = renderWithProviders(<CnameFailureActions code="cname_zone_not_configured" reason={reason} admin={false} />)
    await user.click(screen.getByRole('button', { name: /生成失败/ }))
    let dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByRole('button', { name: '去 DNS 配置' })).not.toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: '重新生成' })).not.toBeInTheDocument()
    unmount()
    renderWithProviders(<CnameFailureActions code="node_targets_unavailable" reason={reason} admin onRegenerate={vi.fn()} regenerateDisabled />)
    await user.click(screen.getByRole('button', { name: /生成失败/ }))
    dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByRole('button', { name: '去 DNS 配置' })).not.toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: '重新生成' })).not.toBeInTheDocument()
  })
})
