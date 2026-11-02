import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { SiteAccessReadiness as Readiness } from '../../api/sites'
import i18n from '../../i18n'
import { renderWithProviders } from '../../test/render'
import { SiteAccessReadinessCard, SiteAccessStatus } from './SiteAccessReadiness'

const at = '2026-10-27T12:00:00Z'
function readiness(state: Readiness['state'], failing: Partial<Record<string, string>> = {}): Readiness {
  const codes = ['package', 'line_group', 'cname_generated', 'dns_resolved', 'https_cert', 'published'] as const
  return { state, checks: codes.map((code) => ({ code, ok: !(code in failing), detail: failing[code] ?? '', checked_at: at })) }
}

function Probe() { return <div data-testid="probe">{useLocation().pathname}{useLocation().search}</div> }

afterEach(() => { vi.restoreAllMocks(); void i18n.changeLanguage('zh-CN') })

describe('SiteAccessStatus (list column)', () => {
  it('shows ready only when the server says ready', () => {
    renderWithProviders(<SiteAccessStatus readiness={readiness('ready')} />)
    expect(screen.getByTestId('site-access-status')).toHaveTextContent('接入已就绪')
  })

  it('names the first failing check and keeps the reason in the tooltip label', () => {
    renderWithProviders(<SiteAccessStatus readiness={readiness('pending', { dns_resolved: 'dns_points_elsewhere' })} />)
    const status = screen.getByTestId('site-access-status')
    expect(status).toHaveTextContent('接入未就绪：域名未解析到 CNAME')
    expect(status).toHaveAttribute('aria-label', expect.stringContaining('域名解析指向了其他地址'))
  })

  it('blocked is marked as needing action, pending as waiting', () => {
    const { unmount } = renderWithProviders(<SiteAccessStatus readiness={readiness('blocked', { line_group: 'no_online_nodes', dns_resolved: 'not_checked' })} />)
    expect(screen.getByTestId('site-access-status')).toHaveTextContent('接入受阻：线路无在线节点')
    expect(screen.getByTestId('site-access-status')).toHaveClass('is-blocked')
    unmount()
    renderWithProviders(<SiteAccessStatus readiness={readiness('pending', { published: 'publishing' })} />)
    expect(screen.getByTestId('site-access-status')).toHaveClass('is-pending')
    expect(screen.getByTestId('site-access-status')).toHaveTextContent('接入未就绪：发布中')
  })

  it('English', async () => {
    await i18n.changeLanguage('en-US')
    renderWithProviders(<SiteAccessStatus readiness={readiness('pending', { dns_resolved: 'not_checked' })} />)
    expect(screen.getByTestId('site-access-status')).toHaveTextContent('Access not ready: DNS not pointed at the CNAME')
  })
})

describe('package and publication checks', () => {
  it('no valid package blocks access and names the reason first', () => {
    renderWithProviders(<SiteAccessStatus readiness={readiness('blocked', { package: 'package_disabled', dns_resolved: 'not_checked' })} />)
    expect(screen.getByTestId('site-access-status')).toHaveTextContent('接入受阻：套餐已停用')
    expect(screen.getByTestId('site-access-status')).toHaveAttribute('aria-label', expect.stringContaining('不会下发到节点'))
  })

  it('a latest publication without the site reads as not live', () => {
    renderWithProviders(<SiteAccessStatus readiness={readiness('pending', { published: 'site_not_in_publication' })} />)
    expect(screen.getByTestId('site-access-status')).toHaveTextContent('接入未就绪：未发布到节点')
    expect(screen.getByTestId('site-access-status')).toHaveAttribute('aria-label', expect.stringContaining('最近一次发布不包含本网站'))
  })
})

describe('SiteAccessReadinessCard (detail card)', () => {
  const routes = (card: React.ReactElement) => (
    <Routes>
      <Route path="/site/edit/:id" element={card} />
      <Route path="*" element={<Probe />} />
    </Routes>
  )

  it('lists all six checks with pass/fail and reasons', () => {
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin={false} cname="a1.cdn.example.net"
      readiness={readiness('blocked', { https_cert: 'certificate_expired', dns_resolved: 'dns_not_found' })} onCheckNow={vi.fn()} />)
    const card = screen.getByRole('region', { name: '接入状态' })
    // 六项检测压成标题行内的一行标签，未通过项的原因与建议另起一行列出
    const [summary, details] = within(card).getAllByRole('list')
    const items = within(summary).getAllByRole('listitem')
    expect(items).toHaveLength(6)
    expect(within(items[0]).getByText('套餐有效')).toBeInTheDocument()
    expect(within(items[1]).getByText('线路可用')).toBeInTheDocument()
    expect(within(items[1]).getByText('通过')).toBeInTheDocument()
    expect(within(items[3]).getByText('未通过')).toBeInTheDocument()
    expect(summary.closest('header')).not.toBeNull()
    const failed = within(details).getAllByRole('listitem')
    expect(failed).toHaveLength(2)
    expect(within(failed[0]).getByText(/没有查到域名的解析记录/)).toBeInTheDocument()
    expect(within(failed[0]).getByText(/a1\.cdn\.example\.net/)).toBeInTheDocument()
    expect(within(failed[1]).getByText(/证书已过期/)).toBeInTheDocument()
  })

  it('tenant: a platform-side gap offers the ticket, never 节点管理', async () => {
    const user = userEvent.setup({ delay: null })
    renderWithProviders(routes(<SiteAccessReadinessCard siteID="s1" admin={false} cname=""
      readiness={readiness('blocked', { line_group: 'no_online_nodes' })} onCheckNow={vi.fn()} />), ['/site/edit/s1'])
    const card = screen.getByRole('region', { name: '接入状态' })
    expect(within(card).queryByText(/节点管理/)).not.toBeInTheDocument()
    expect(within(card).getByText(/请联系管理员/)).toBeInTheDocument()
    await user.click(within(card).getByRole('button', { name: '联系管理员（提交工单）' }))
    expect(screen.getByTestId('probe')).toHaveTextContent('/account/tickets?new=1&site_id=s1')
  })

  it('admin: no online node points at the node list, no line group at line groups', async () => {
    const user = userEvent.setup({ delay: null })
    const { unmount } = renderWithProviders(routes(<SiteAccessReadinessCard siteID="s1" admin cname=""
      readiness={readiness('blocked', { line_group: 'no_online_nodes' })} onCheckNow={vi.fn()} />), ['/site/edit/s1'])
    expect(screen.getByText(/线路组里没有在线可调度的节点/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '去节点列表' }))
    expect(screen.getByTestId('probe')).toHaveTextContent('/node/list')
    unmount()
    renderWithProviders(routes(<SiteAccessReadinessCard siteID="s1" admin cname=""
      readiness={readiness('blocked', { line_group: 'no_line_group' })} onCheckNow={vi.fn()} />), ['/site/edit/s1'])
    await user.click(screen.getByRole('button', { name: '去线路组' }))
    expect(screen.getByTestId('probe')).toHaveTextContent('/node/line-group')
  })

  it('certificate gap opens the HTTPS tab for both roles', async () => {
    const user = userEvent.setup({ delay: null })
    function Search() { return <div data-testid="search">{useLocation().search}</div> }
    renderWithProviders(<Routes>
      <Route path="/site/edit/:id" element={<><SiteAccessReadinessCard siteID="s1" admin={false} cname="a1.cdn.example.net"
        readiness={readiness('blocked', { https_cert: 'certificate_missing' })} onCheckNow={vi.fn()} /><Search /></>} />
    </Routes>, ['/site/edit/s1'])
    await user.click(screen.getByRole('button', { name: '去 HTTPS 设置' }))
    await waitFor(() => expect(screen.getByTestId('search')).toHaveTextContent('tab=https'))
  })

  it('立即检查 calls the server and shows the throttle wait', async () => {
    const user = userEvent.setup({ delay: null })
    const onCheckNow = vi.fn().mockResolvedValueOnce(undefined).mockRejectedValueOnce(Object.assign(new Error('throttled'),
      { status: 429, code: 'access_check_throttled', retryAfter: 40 }))
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin={false} cname="a1.cdn.example.net"
      readiness={readiness('pending', { dns_resolved: 'not_checked' })} onCheckNow={onCheckNow} />)
    const button = screen.getByRole('button', { name: /立即检查/ })
    await user.click(button)
    expect(onCheckNow).toHaveBeenCalledOnce()
    await waitFor(() => expect(button).not.toHaveClass('ant-btn-loading'))
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    await user.click(button)
    expect(await screen.findByRole('status')).toHaveTextContent('刚检查过，请 40 秒后再试')
  })

  // 发布失败写出失败节点名与原因，旁边给“重新发布”；节点明细只有平台管理员拿得到。
  it('publish failed names the failed nodes for the platform admin and offers 重新发布', async () => {
    const user = userEvent.setup({ delay: null })
    const failed = readiness('blocked', { published: 'publish_failed' })
    failed.checks[5] = { ...failed.checks[5], failed_nodes: [
      { node_id: 'n1', node_name: 'hk-1', state: 'failed', error_code: 'ERROR_CODE_PRECHECK_FAILED' },
      { node_id: 'n2', node_name: 'hk-2', state: 'reverted', error_code: null },
    ] }
    const onRepublish = vi.fn().mockResolvedValueOnce(undefined).mockRejectedValueOnce(Object.assign(new Error('busy'),
      { status: 409, code: 'publish_in_flight' }))
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin cname="" readiness={failed} onRepublish={onRepublish} />)
    const card = screen.getByRole('region', { name: '接入状态' })
    expect(within(card).getByText('以下节点发布失败：hk-1（ERROR_CODE_PRECHECK_FAILED）、hk-2（已回退到旧配置）。')).toBeInTheDocument()
    expect(within(card).queryByText(/最近一次发布没有/)).not.toBeInTheDocument()
    const button = within(card).getByRole('button', { name: /重新发布/ })
    await user.click(button)
    expect(onRepublish).toHaveBeenCalledOnce()
    expect(await within(card).findByRole('status')).toHaveTextContent('已重新发布，等待节点回执。')
    await user.click(button)
    expect(await within(card).findByText('正在发布中，请等这次发布完成后再试。')).toBeInTheDocument()
  })

  // 平台节点名不给用户看。租户响应没有 failed_nodes，只有失败节点数与归一化原因。
  it('publish failed for a tenant: node count and reasons, no node names, contact the administrator', () => {
    const failed = readiness('blocked', { published: 'publish_failed' })
    failed.checks[5] = { ...failed.checks[5], failed_node_count: 2, failed_node_reasons: ['precheck_failed', 'some_new_code'] }
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin={false} cname="" readiness={failed} onRepublish={vi.fn()} />)
    const card = screen.getByRole('region', { name: '接入状态' })
    expect(within(card).getByText('2 个节点发布失败：预检未通过、原因 some_new_code。如持续失败请联系管理员。')).toBeInTheDocument()
    expect(within(card).queryByText(/以下节点发布失败/)).not.toBeInTheDocument()
    expect(within(card).getByRole('button', { name: /重新发布/ })).toBeInTheDocument()
  })

  it('publish failed for a tenant in English', async () => {
    const failed = readiness('blocked', { published: 'publish_failed' })
    failed.checks[5] = { ...failed.checks[5], failed_node_count: 1, failed_node_reasons: ['reverted'] }
    await i18n.changeLanguage('en-US')
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin={false} cname="" readiness={failed} onRepublish={vi.fn()} />)
    expect(screen.getByText('Publishing failed on 1 of the nodes serving this site: reverted to the previous settings. ' +
      'If it keeps failing, contact the administrator.')).toBeInTheDocument()
  })

  it('publish failed before any node: the request reason, no node list', () => {
    const failed = readiness('blocked', { published: 'publish_failed' })
    failed.checks[5] = { ...failed.checks[5], failure_code: 'no_target_nodes' }
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin cname="" readiness={failed} onRepublish={vi.fn()} />)
    expect(screen.getByText('自动发布没有下发到节点：线路组里没有可用节点。')).toBeInTheDocument()
  })

  it('重新发布 is hidden without a handler, while publishing and when published', () => {
    const { unmount } = renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin cname=""
      readiness={readiness('blocked', { published: 'publish_failed' })} />)
    expect(screen.queryByRole('button', { name: /重新发布/ })).not.toBeInTheDocument()
    unmount()
    const second = renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin cname=""
      readiness={readiness('pending', { published: 'publishing' })} onRepublish={vi.fn()} />)
    expect(screen.queryByRole('button', { name: /重新发布/ })).not.toBeInTheDocument()
    second.unmount()
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin cname="" readiness={readiness('ready')} onRepublish={vi.fn()} />)
    expect(screen.queryByRole('button', { name: /重新发布/ })).not.toBeInTheDocument()
  })

  it('立即检查 is hidden without a check handler', () => {
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin cname="" readiness={readiness('ready')} />)
    expect(screen.queryByRole('button', { name: /立即检查/ })).not.toBeInTheDocument()
  })
})
