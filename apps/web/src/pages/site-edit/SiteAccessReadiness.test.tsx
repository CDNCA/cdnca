import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { SiteAccessReadiness as Readiness } from '../../api/sites'
import i18n from '../../i18n'
import { renderWithProviders } from '../../test/render'
import { SiteAccessReadinessCard, SiteAccessStatus } from './SiteAccessReadiness'
import SiteCreatedProgress from './SiteCreatedProgress'
import '../../i18n/siteCreate'

const at = '2026-10-27T12:00:00Z'
function readiness(state: Readiness['state'], failing: Partial<Record<string, string>> = {}): Readiness {
  const codes = ['package', 'line_group', 'cname_generated', 'dns_resolved', 'https_cert', 'published'] as const
  return { state, checks: codes.map((code) => ({ code, ok: !(code in failing), detail: failing[code] ?? '', checked_at: at })) }
}

function Probe() { return <div data-testid="probe">{useLocation().pathname}{useLocation().search}</div> }

// 与网站列表相同的结构：可点的状态按钮引用 SiteAccessStatus 里的原因节点作为说明。
function renderListStatus(value: Readiness) {
  renderWithProviders(<button type="button" aria-describedby="reason-s1"><SiteAccessStatus readiness={value} reasonID="reason-s1" /></button>)
  return screen.getByRole('button')
}

afterEach(() => { vi.restoreAllMocks(); void i18n.changeLanguage('zh-CN') })

describe('SiteAccessStatus (list column)', () => {
  it('shows ready only when the server says ready', () => {
    renderWithProviders(<SiteAccessStatus readiness={readiness('ready')} />)
    expect(screen.getByTestId('site-access-status')).toHaveTextContent('接入已就绪')
  })

  it('names the first failing check and keeps the reason in the tooltip label', () => {
    renderWithProviders(<SiteAccessStatus readiness={readiness('pending', { dns_resolved: 'dns_points_elsewhere' })} />)
    expect(screen.getByTestId('site-access-status')).toHaveTextContent('接入未就绪：域名未解析到 CNAME')
    // 53 补充：名称只是状态，原因作为说明。
    expect(screen.getByTestId('site-access-status')).not.toHaveAttribute('aria-label')
  })

  it('the list button reads the status as its name and the reason as its description', () => {
    const button = renderListStatus(readiness('pending', { dns_resolved: 'dns_points_elsewhere' }))
    expect(button).toHaveAccessibleName('接入未就绪：域名未解析到 CNAME')
    expect(button).toHaveAccessibleDescription(expect.stringContaining('域名解析指向了其他地址'))
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
    const button = renderListStatus(readiness('blocked', { package: 'package_disabled', dns_resolved: 'not_checked' }))
    expect(screen.getByTestId('site-access-status')).toHaveTextContent('接入受阻：套餐已停用')
    expect(button).toHaveAccessibleDescription(expect.stringContaining('不会下发到节点'))
  })

  it('a latest publication without the site reads as not live', () => {
    const button = renderListStatus(readiness('pending', { published: 'site_not_in_publication' }))
    expect(screen.getByTestId('site-access-status')).toHaveTextContent('接入未就绪：未发布到节点')
    expect(button).toHaveAccessibleDescription(expect.stringContaining('最近一次发布不包含本网站'))
  })
})

describe('SiteAccessReadinessCard (detail card)', () => {
  const routes = (card: React.ReactElement) => (
    <Routes>
      <Route path="/site/edit/:id" element={card} />
      <Route path="*" element={<Probe />} />
    </Routes>
  )

  // 卡里先列未通过项（原因与动作），已通过项收进默认收起的一行。
  it('lists the failing checks with reasons first and folds the passed ones away', () => {
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin={false} cname="a1.cdn.example.net"
      readiness={readiness('blocked', { https_cert: 'certificate_expired', dns_resolved: 'dns_not_found' })} onCheckNow={vi.fn()} />)
    const card = screen.getByRole('region', { name: '接入状态' })
    // 整体状态只在页头：卡头没有「接入受阻」，也不再逐项列「通过/未通过」标签
    expect(card.querySelector('.site-access-card-head')).not.toHaveTextContent(/接入受阻|通过/)
    const [details, passedList] = within(card).getAllByRole('list')
    const passed = card.querySelector('details.site-access-passed') as HTMLDetailsElement
    expect(passed.open).toBe(false)
    expect(passed.querySelector('summary')).toHaveTextContent('已通过 4 项')
    expect(passed).toContainElement(passedList)
    expect(within(passedList).getAllByRole('listitem').map((item) => item.querySelector('.site-access-check-title')?.textContent))
      .toEqual(['套餐', '线路', 'CNAME', '节点发布'])
    const failed = within(details).getAllByRole('listitem')
    expect(failed).toHaveLength(2)
    expect(failed.map((item) => item.querySelector('strong')?.textContent)).toEqual(['域名解析：失败', 'HTTPS 证书：失败'])
    expect(card).not.toHaveTextContent('未通过')
    expect(within(failed[0]).getByText(/没有查到域名的解析记录/)).toBeInTheDocument()
    expect(within(failed[0]).getByText(/a1\.cdn\.example\.net/)).toBeInTheDocument()
    expect(within(failed[1]).getByText(/证书已过期/)).toBeInTheDocument()
  })

  // 标题是中性字段名加实际状态，图标不进 AX；不再把未通过项读成完成语句。
  it.each([
    [{ cname_generated: 'cname_pending', dns_resolved: 'waiting_cname' }, ['CNAME：等待中', '域名解析：等待中']],
    [{ cname_generated: 'cname_failed', dns_resolved: 'waiting_cname' }, ['CNAME：失败', '域名解析：等待中']],
    [{ dns_resolved: 'dns_points_elsewhere' }, ['域名解析：失败']],
    [{ published: 'publishing' }, ['节点发布：等待中']],
  ] as const)('names each failing check by field and actual state (%o)', (details, titles) => {
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin={false} cname="a1.cdn.example.net"
      readiness={readiness('pending', details)} onCheckNow={vi.fn()} />)
    const card = screen.getByRole('region', { name: '接入状态' })
    const failed = within(card.querySelector('.site-access-check-details') as HTMLElement).getAllByRole('listitem')
    expect(failed.map((item) => item.querySelector('strong')?.textContent)).toEqual(titles)
    expect(card).not.toHaveTextContent(/CNAME 已生成|已解析到/)
    for (const item of failed) expect(item.querySelector('svg')).toHaveAttribute('aria-hidden', 'true')
  })

  it('tenant: a platform-side gap offers the ticket, never 节点管理', async () => {
    const user = userEvent.setup({ delay: null })
    renderWithProviders(routes(<SiteAccessReadinessCard siteID="s1" admin={false} cname=""
      readiness={readiness('blocked', { line_group: 'no_online_nodes' })} onCheckNow={vi.fn()} />), ['/site/edit/s1'])
    const card = screen.getByRole('region', { name: '接入状态' })
    expect(within(card).queryByText(/节点管理/)).not.toBeInTheDocument()
    // 53 补充：原因 + 工单入口，不再附“需要平台处理”“网站配置已保存”。
    expect(card).not.toHaveTextContent(/需要平台处理|网站配置已保存/)
    const ticket = within(card).getByRole('button', { name: '联系管理员（提交工单）' })
    expect(ticket).toHaveAccessibleDescription('线路组里没有在线可调度的节点。')
    await user.click(ticket)
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
    // antd Button 在 loading 期间忽略点击；先等第一次的 loading 结束，第二次点击才不会在高负载下被吞掉。
    await waitFor(() => expect(button).not.toHaveClass('ant-btn-loading'))
    await user.click(button)
    expect(onRepublish).toHaveBeenCalledTimes(2)
    expect(await within(card).findByText('正在发布中，请等这次发布完成后再试。')).toBeInTheDocument()
  })

  // 平台节点名不给用户看。租户响应没有 failed_nodes，只有失败节点数与归一化原因。
  it('publish failed for a tenant: node count and reasons, no node names, contact the administrator', () => {
    const failed = readiness('blocked', { published: 'publish_failed' })
    failed.checks[5] = { ...failed.checks[5], failed_node_count: 2, failed_node_reasons: ['precheck_failed', 'some_new_code'] }
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin={false} cname="" readiness={failed} onRepublish={vi.fn()} />)
    const card = screen.getByRole('region', { name: '接入状态' })
    expect(within(card).getByText('2 个节点发布失败：预检未通过、节点部署失败。如持续失败请联系管理员。')).toBeInTheDocument()
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

// 解析指向别处时写明域名、当前值与应改成的 CNAME，并可一键复制。
describe('dns_points_elsewhere with the observed answer', () => {
  function mismatched(observed: string[]): Readiness {
    const base = readiness('pending', { dns_resolved: 'dns_points_elsewhere' })
    return { ...base, checks: base.checks.map((check) => check.code === 'dns_resolved'
      ? { ...check, dns_mismatch: { domain: 'tenant.example.com', observed, expected_cname: 'a1b2c3d4.cdn.example.net' } } : check) }
  }

  it('names the domain, its current target and the CNAME to set, with a copy button', async () => {
    // user-event 的 setup 会装自己的剪贴板替身，之后再监听。
    const user = userEvent.setup({ delay: null })
    const writeText = vi.spyOn(navigator.clipboard, 'writeText')
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin={false} cname="a1b2c3d4.cdn.example.net"
      readiness={mismatched(['z9y8x7w6.other-cdn.example.net'])} onCheckNow={vi.fn()} />)
    const [details] = within(screen.getByRole('region', { name: '接入状态' })).getAllByRole('list')
    const item = within(details).getByRole('listitem')
    expect(within(item).getByText('tenant.example.com 当前指向 z9y8x7w6.other-cdn.example.net，请在域名 DNS 处改为 a1b2c3d4.cdn.example.net')).toBeInTheDocument()
    await user.click(within(item).getByRole('button', { name: /复制 CNAME/ }))
    expect(writeText).toHaveBeenCalledWith('a1b2c3d4.cdn.example.net')
    expect(await within(item).findByRole('button', { name: /已复制/ })).toBeInTheDocument()
  })

  it('lists A records and keeps the list tooltip in English too', async () => {
    await i18n.changeLanguage('en-US')
    expect(renderListStatus(mismatched(['198.51.100.7', '198.51.100.8']))).toHaveAccessibleDescription(
      expect.stringContaining('tenant.example.com currently points to 198.51.100.7, 198.51.100.8. At your DNS provider, change it to a1b2c3d4.cdn.example.net'))
  })

  it('falls back to the generic reason without an observed answer', () => {
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin={false} cname="a1b2c3d4.cdn.example.net"
      readiness={readiness('pending', { dns_resolved: 'dns_points_elsewhere' })} />)
    expect(screen.getByText('域名解析指向了其他地址，没有指向本站的 CNAME。')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /复制 CNAME/ })).not.toBeInTheDocument()
  })
})

// 53 补充（租户新建站点）：失败项只说一次原因 + 一个按角色的操作；
// 创建横幅按保存/节点发布/DNS 接入分开说，不断言公网不可访问。
describe('四态', () => {
  const routes = (card: React.ReactElement) => (
    <Routes>
      <Route path="/site/edit/:id" element={card} />
      <Route path="*" element={<Probe />} />
    </Routes>
  )
  const withPublished = (base: Readiness, ok: boolean, detail = ''): Readiness => ({
    ...base, checks: base.checks.map((check) => check.code === 'published' ? { ...check, ok, detail } : check),
  })
  const noDns = () => readiness('blocked', { cname_generated: 'dns_provider_not_configured', dns_resolved: 'waiting_cname' })
  const stacked = /。，|，。|，，|。。/
  const progress = (value: Readiness | null) => {
    const view = renderWithProviders(<SiteCreatedProgress readiness={value} />)
    const list = screen.getByRole('list', { name: '创建进度' })
    return { view, list, item: (name: string) => screen.getByTestId(`site-created-${name}`) }
  }

  it('DNS 未配置不能自动接入：租户只有工单入口、无重试、原因只说一次', async () => {
    const user = userEvent.setup({ delay: null })
    renderWithProviders(routes(<SiteAccessReadinessCard siteID="s1" admin={false} cname="" cnameFailureCode="dns_provider_not_configured"
      readiness={noDns()} onCheckNow={vi.fn()} />), ['/site/edit/s1'])
    const card = screen.getByRole('region', { name: '接入状态' })
    // 卡头不再重复页头的状态；“CNAME 未生成”的原因只在逐项列表里出现一次。
    expect(card.querySelector('.site-access-card-head .site-access-status')).toBeNull()
    expect(card).not.toHaveTextContent(/CNAME 未生成/)
    const row = card.querySelector<HTMLElement>('#site-access-check-cname_generated')!
    const reason = '平台 DNS 服务商未配置，管理员处理后会自动重新生成。'
    expect(within(row).getByText(reason)).toBeInTheDocument()
    expect(row).not.toHaveTextContent(/需要平台处理|网站配置已保存|请联系管理员/)
    expect(card).not.toHaveTextContent(/需要平台处理|网站配置已保存|节点管理|DNS配置/)
    const buttons = within(row).getAllByRole('button')
    expect(buttons).toHaveLength(1)
    expect(buttons[0]).toHaveAccessibleName('联系管理员（提交工单）')
    expect(buttons[0]).toHaveAccessibleDescription(reason)
    expect(within(card).queryByRole('button', { name: /重新生成|查看 CNAME|去 DNS 配置/ })).not.toBeInTheDocument()
    for (const button of within(card).getAllByRole('button')) expect(button.getAttribute('aria-label') ?? button.textContent).not.toMatch(stacked)
    await user.click(buttons[0])
    expect(screen.getByTestId('probe')).toHaveTextContent('/account/tickets?new=1&site_id=s1')
  })

  it('列表状态徽标的名称不含原因与标点堆叠', () => {
    const button = renderListStatus(noDns())
    expect(button).toHaveAccessibleName('接入受阻：CNAME 未生成')
    expect(button).toHaveAccessibleDescription('CNAME 生成失败，原因见基本设置里的 CNAME。')
    expect(screen.getByTestId('site-access-status').getAttribute('aria-label')).toBeNull()
  })

  it('有 A 记录已发布：发布项已发布，DNS 项为「检查 DNS 接入」，不说公网不可访问', () => {
    const { list, item } = progress(withPublished(noDns(), true))
    expect(item('saved')).toHaveTextContent('保存：已保存')
    expect(item('publish')).toHaveTextContent('节点发布：已发布')
    expect(item('dns')).toHaveTextContent('DNS 接入：检查 DNS 接入')
    expect(item('dns')).not.toHaveClass('is-failed')
    expect(list).not.toHaveTextContent(/公网|不能访问|不可访问|发布完成前/)
  })

  it('未发布：发布项为发布中/未完成', () => {
    const first = progress(withPublished(readiness('pending', { published: 'publishing' }), false, 'publishing'))
    expect(first.item('publish')).toHaveTextContent('节点发布：发布中')
    expect(first.item('publish')).toHaveClass('is-pending')
    first.view.unmount()
    const second = progress(withPublished(readiness('pending', { published: 'not_published' }), false, 'not_published'))
    expect(second.item('publish')).toHaveTextContent('节点发布：未完成')
    second.view.unmount()
    const third = progress(null)
    expect(third.item('publish')).toHaveTextContent('节点发布：待确认')
    expect(third.item('dns')).toHaveTextContent('DNS 接入：待确认')
  })

  it('已发布且 CNAME 核验通过：全部通过，无失败文案', () => {
    const { list, item } = progress(readiness('ready'))
    expect(item('saved')).toHaveTextContent('保存：已保存')
    expect(item('publish')).toHaveTextContent('节点发布：已发布')
    expect(item('dns')).toHaveTextContent('DNS 接入：已接入')
    for (const li of within(list).getAllByRole('listitem')) expect(li).toHaveClass('is-ok')
    expect(list).not.toHaveTextContent(/失败|检查 DNS|未完成|公网/)
  })

  it('已就绪的接入卡没有未通过项与失败文案', () => {
    renderWithProviders(<SiteAccessReadinessCard siteID="s1" admin={false} cname="a1.cdn.example.net" readiness={readiness('ready')} />)
    const card = screen.getByRole('region', { name: '接入状态' })
    // 「接入已就绪」在页头；卡里只有收起的六项通过
    expect(card).toHaveTextContent('已通过 6 项')
    expect(card.querySelector('.site-access-check-details')).toBeNull()
    expect(card).not.toHaveTextContent(/未通过|失败|联系管理员/)
  })
})
