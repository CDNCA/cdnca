import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { securityPoliciesApi, type SiteQuickBlockState } from '../api/securityPolicies'
import { SiteQuickBlockOverrideCard } from '../pages/site-edit/SiteQuickBlockOverrideCard'
import { renderWithProviders } from '../test/render'

const siteID = '55555555-5555-4555-8555-555555555555'
const libraryBlock = { block_idc_cn: true, block_idc_global: false, carriers: ['carrier:cn-mobile' as const],
  allowed_crawlers: [{ networks: ['66.249.64.0/19'], user_agent_prefixes: ['Googlebot'] }] }
const inherited: SiteQuickBlockState = {
  site_id: siteID, version: 9,
  override: { block_idc_cn: null, block_idc_global: null, carriers: null, allowed_crawlers: null },
  library: { policy_id: '88888888-8888-4888-8888-888888888888', version: 4, active_version: 4, supported: true, quick_block: libraryBlock },
  effective: libraryBlock, updated_at: null,
}

function renderCard(state: SiteQuickBlockState = inherited, ready = true, canManage = true) {
  vi.spyOn(securityPoliciesApi, 'getSiteQuickBlock').mockResolvedValue(state)
  vi.spyOn(securityPoliciesApi, 'ipIntelStatus').mockResolvedValue({ ready, revision: ready ? 7 : 0 })
  renderWithProviders(<SiteQuickBlockOverrideCard siteId={siteID} accessToken="token" canManage={canManage} onOpenLibraries={vi.fn()} />)
}

// The server keeps the override it was sent (each change is a save against the returned version).
const echo = () => {
  let current: SiteQuickBlockState | null = null
  vi.mocked(securityPoliciesApi.getSiteQuickBlock).mockImplementation(async () => current ?? inherited)
  return vi.spyOn(securityPoliciesApi, 'setSiteQuickBlock').mockImplementation(async (_token, _site, version, override) => {
    current = { ...inherited, version: version + 1, override }
    return current
  })
}

const group = (name: string) => screen.getByRole('radiogroup', { name })
const option = (groupName: string, label: RegExp | string) =>
  [...group(groupName).querySelectorAll('label')].find((item) => (typeof label === 'string' ? item.textContent === label : label.test(item.textContent ?? '')))!

describe('本站快速屏蔽', () => {
  afterEach(() => vi.restoreAllMocks())

  it('shows every item following the library with the library value', async () => {
    renderCard()
    expect(await screen.findByRole('heading', { name: /本站快速屏蔽/ })).toBeInTheDocument()
    expect(option('屏蔽国内 IDC', /跟随规则库（已开启）/).querySelector('input')).toBeChecked()
    expect(option('屏蔽境外 IDC', /跟随规则库（未开启）/).querySelector('input')).toBeChecked()
    expect(option('屏蔽运营商', /跟随规则库（1 项）/).querySelector('input')).toBeChecked()
    expect(option('放行搜索引擎蜘蛛', /跟随规则库（1 项）/).querySelector('input')).toBeChecked()
    // Inheriting needs no list.
    expect(screen.queryByRole('combobox', { name: '本站屏蔽的运营商' })).not.toBeInTheDocument()
  })

  it('saves per-item inherit / on / off; an on list starts from the library and replaces it, off is an empty list', async () => {
    renderCard()
    const save = echo()
    const actor = userEvent.setup()
    await screen.findByRole('heading', { name: /本站快速屏蔽/ })
    expect(screen.queryByRole('button', { name: '保存' })).toBeNull()
    await actor.click(option('屏蔽国内 IDC', '关闭'))
    await actor.click(option('屏蔽境外 IDC', '开启'))
    await actor.click(option('屏蔽运营商', '开启'))
    // Prefilled with the library's carriers.
    expect(screen.getByRole('combobox', { name: '本站屏蔽的运营商' })).toBeInTheDocument()
    expect(screen.getByText('中国移动')).toBeInTheDocument()
    await actor.click(option('放行搜索引擎蜘蛛', '开启'))
    const crawlers = screen.getByRole('textbox', { name: '本站放行的蜘蛛网段' })
    expect(crawlers).toHaveValue('66.249.64.0/19,Googlebot')
    await actor.clear(crawlers)
    await actor.type(crawlers, '40.77.167.0/24,bingbot')
    fireEvent.blur(crawlers)
    await waitFor(() => expect(save.mock.calls.at(-1)![3]).toEqual({
      block_idc_cn: false, block_idc_global: true, carriers: ['carrier:cn-mobile'],
      allowed_crawlers: [{ networks: ['40.77.167.0/24'], user_agent_prefixes: ['bingbot'] }],
    }))
    // each save is against the version the previous one returned
    expect(save.mock.calls.map((call) => call[2])).toEqual(save.mock.calls.map((_, index) => 9 + index))
    expect(save.mock.calls[0]![4]).toMatch(/^site-quick-block-override-[0-9a-f-]+-9-[0-9a-f-]+$/)
    expect((await screen.findAllByText('操作成功'))[0]).toBeInTheDocument()
  })

  it('shows a stored override and turns crawlers off as an empty list; everything back to inherit sends nulls', async () => {
    renderCard({ ...inherited, override: { block_idc_cn: false, block_idc_global: null, carriers: [],
      allowed_crawlers: [{ networks: ['40.77.167.0/24'], user_agent_prefixes: ['bingbot'] }] } })
    const save = echo()
    const actor = userEvent.setup()
    await screen.findByRole('heading', { name: /本站快速屏蔽/ })
    expect(option('屏蔽国内 IDC', '关闭').querySelector('input')).toBeChecked()
    expect(option('屏蔽运营商', '关闭').querySelector('input')).toBeChecked()
    expect(screen.getByRole('textbox', { name: '本站放行的蜘蛛网段' })).toHaveValue('40.77.167.0/24,bingbot')
    await actor.click(option('放行搜索引擎蜘蛛', '关闭'))
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1))
    expect(save.mock.calls[0]![3]).toEqual({ block_idc_cn: false, block_idc_global: null, carriers: [], allowed_crawlers: [] })
    await actor.click(option('屏蔽国内 IDC', /跟随规则库/))
    await actor.click(option('屏蔽运营商', /跟随规则库/))
    await actor.click(option('放行搜索引擎蜘蛛', /跟随规则库/))
    await waitFor(() => expect(save.mock.calls.at(-1)![3]).toEqual({ block_idc_cn: null, block_idc_global: null, carriers: null, allowed_crawlers: null }))
  })

  it('cannot turn a block on without the IP intelligence library, but can turn off and allow crawlers', async () => {
    renderCard(inherited, false)
    const actor = userEvent.setup()
    expect(await screen.findByText(/主控还没有同步到 IP 情报库/)).toBeInTheDocument()
    expect(option('屏蔽境外 IDC', '开启').querySelector('input')).toBeDisabled()
    expect(option('屏蔽运营商', '开启').querySelector('input')).toBeDisabled()
    expect(option('放行搜索引擎蜘蛛', '开启').querySelector('input')).toBeEnabled()
    const save = echo()
    await actor.click(option('屏蔽国内 IDC', '关闭'))
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1))
  })

  it('requires a list when an item is on, and maps refusals', async () => {
    renderCard()
    // the first change (开启 with the library's list) is saved; the later one is refused
    const save = echo()
    save.mockImplementationOnce(async (_token, _site, version, override) => ({ ...inherited, version: version + 1, override }))
      .mockRejectedValue(new ApiError('x', 409, 'site_locked'))
    const actor = userEvent.setup()
    await screen.findByRole('heading', { name: /本站快速屏蔽/ })
    await actor.click(option('放行搜索引擎蜘蛛', '开启'))
    const crawlers = screen.getByRole('textbox', { name: '本站放行的蜘蛛网段' })
    await actor.clear(crawlers)
    expect(screen.getByText('开启时至少填写一行；不想放行请选“关闭”。')).toBeInTheDocument()
    await actor.type(crawlers, '66.249.64.0/19')
    expect(screen.getByText('第 1 行格式应为“网段,User-Agent 前缀”')).toBeInTheDocument()
    await actor.click(option('放行搜索引擎蜘蛛', '关闭'))
    expect(await screen.findByText('站点已被平台管理员锁定，暂时不能修改。')).toBeInTheDocument()
  })

  it('explains a site without a WAF library', async () => {
    renderCard({ ...inherited, library: null, effective: null })
    expect(await screen.findByText(/站点还没有应用 WAF 规则库/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '保存' })).not.toBeInTheDocument()
  })

  it('a library that cannot block only offers off / inherit', async () => {
    renderCard({ ...inherited, library: { ...inherited.library!, supported: false } })
    expect(await screen.findByText(/本站只能选择关闭或跟随规则库/)).toBeInTheDocument()
    expect(option('屏蔽国内 IDC', '开启').querySelector('input')).toBeDisabled()
  })

  it('is read only without manage permission', async () => {
    renderCard(inherited, true, false)
    await screen.findByRole('heading', { name: /本站快速屏蔽/ })
    expect(option('屏蔽国内 IDC', '关闭').querySelector('input')).toBeDisabled()
    expect(screen.queryByRole('button', { name: '保存' })).toBeNull()
  })
})
