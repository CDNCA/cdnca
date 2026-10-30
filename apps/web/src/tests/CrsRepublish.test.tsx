import { fireEvent, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'

import { ApiError, responseApiError } from '../api/auth'
import { securitySystemRulesApi } from '../api/securitySystemRules'
import { challengePolicyRefusalText } from '../i18n/crsRepublish'
import i18n from '../i18n'
import { SystemRuleCatalogSection } from '../pages/security/SystemRuleCatalogTable'
import { renderWithProviders } from '../test/render'

const node = '01990000-0000-7000-8000-0000000000a1'
const other = '01990000-0000-7000-8000-0000000000a2'
const site = '01990000-0000-7000-8000-0000000000b1'

function refusal(challenge: unknown, code = 'challenge_policy_unavailable') {
  return new Response(JSON.stringify({ error: { code, message: 'raw-server-detail', request_id: 'req-1', challenge } }),
    { status: 422, headers: { 'Content-Type': 'application/json' } })
}

describe('JS challenge policy refusal', () => {
  it('names the node and the site the server refused', async () => {
    await i18n.changeLanguage('zh-CN')
    const error = await responseApiError(refusal({ node_id: node, site_id: site, domain: 'www.example.com',
      policy_version: 7, other_node_ids: [other] }))
    expect(error.challenge).toEqual({ node_id: node, site_id: site, domain: 'www.example.com', policy_version: 7, other_node_ids: [other] })
    const text = challengePolicyRefusalText(error)!
    expect(text).toContain(node)
    expect(text).toContain('www.example.com')
    expect(text).toContain('v7')
    expect(text).toContain(`同样缺少策略的节点：${other}`)
    expect(text).not.toContain('raw-server-detail')
  })

  it.each([
    [{ node_id: 'raw-secret', site_id: site, domain: 'www.example.com', policy_version: 7, other_node_ids: [] }, 'challenge_policy_unavailable'],
    [{ node_id: node, site_id: site, domain: '<b>x</b>', policy_version: 7, other_node_ids: [] }, 'challenge_policy_unavailable'],
    [{ node_id: node, site_id: site, domain: 'www.example.com', policy_version: 0, other_node_ids: [] }, 'challenge_policy_unavailable'],
    [{ node_id: node, site_id: site, domain: 'www.example.com', policy_version: 7, other_node_ids: ['raw-secret'] }, 'challenge_policy_unavailable'],
    [{ node_id: node, site_id: site, domain: 'www.example.com', policy_version: 7, other_node_ids: [] }, 'publication_not_ready'],
  ])('keeps no details it cannot verify: %j', async (challenge, code) => {
    const error = await responseApiError(refusal(challenge, code))
    expect(error).not.toHaveProperty('challenge')
    expect(challengePolicyRefusalText(error)).toBeUndefined()
    expect(JSON.stringify(error)).not.toContain('raw-secret')
  })

  it('is localized in English', async () => {
    await i18n.changeLanguage('en-US')
    const error = new ApiError('x', 422, 'challenge_policy_unavailable')
    error.challenge = { node_id: node, site_id: site, domain: 'a.example', policy_version: 2, other_node_ids: [] }
    expect(challengePolicyRefusalText(error)).toContain(`Node ${node} has not installed the JS challenge policy of site a.example`)
    await i18n.changeLanguage('zh-CN')
  })
})

describe('CRS rule library republication status', () => {
  afterEach(() => vi.restoreAllMocks())

  // 10-25 用户：不要常驻大横幅；只在确有进行中的重新发布时在标题旁显示小标签，悬停看说明。
  it('shows a small status tag beside the catalog title while scopes are pending, with the detail on hover', async () => {
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([])
    const republication = vi.spyOn(securitySystemRulesApi, 'republication').mockResolvedValue({ pending: true, pending_scopes: 3 })
    renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="waf_rule_set" cacheKey="crs:1" isAdmin canManage />)
    const tag = await screen.findByRole('status')
    expect(tag).toHaveTextContent('正在更新规则（3）')
    expect(tag.closest('.system-rule-catalog-notice')).not.toBeNull()
    expect(document.querySelector('.ant-alert-warning')).toBeNull()
    expect(screen.queryByText(/授权中心下发的系统规则/)).not.toBeInTheDocument()
    fireEvent.mouseEnter(tag)
    expect(await screen.findByText(/授权中心下发的系统规则/)).toBeInTheDocument()
    expect(republication).toHaveBeenCalledWith('t')
  })

  // 10-25：CC 规则页同样只在进行中时显示标签（两页共用 SystemRuleCatalogTable）。
  it('shows the same tag on the CC rule group catalog, and it goes away once the republication finishes', async () => {
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([])
    const republication = vi.spyOn(securitySystemRulesApi, 'republication')
      .mockResolvedValueOnce({ pending: true, pending_scopes: 1 })
      .mockResolvedValue({ pending: false, pending_scopes: 0 })
    renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="cc_rule_group" cacheKey="crs:4" isAdmin canManage />)
    expect(await screen.findByRole('status')).toHaveTextContent('正在更新规则（1）')
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument(), { timeout: 15_000 })
    expect(republication).toHaveBeenCalledTimes(2)
  }, 20_000)

  it('shows nothing when no republication is pending, and never asks for CC matchers', async () => {
    vi.spyOn(securitySystemRulesApi, 'list').mockResolvedValue([])
    const republication = vi.spyOn(securitySystemRulesApi, 'republication').mockResolvedValue({ pending: false, pending_scopes: 0 })
    const view = renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="waf_rule_set" cacheKey="crs:2" isAdmin canManage />)
    await waitFor(() => expect(republication).toHaveBeenCalled())
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    expect(screen.queryByText(/正在更新规则/)).not.toBeInTheDocument()
    view.unmount()
    republication.mockClear()
    renderWithProviders(<SystemRuleCatalogSection accessToken="t" kind="cc_matcher" cacheKey="crs:3" isAdmin canManage />)
    await waitFor(() => expect(securitySystemRulesApi.list).toHaveBeenCalledWith('t', 'cc_matcher'))
    expect(republication).not.toHaveBeenCalled()
  })
})
