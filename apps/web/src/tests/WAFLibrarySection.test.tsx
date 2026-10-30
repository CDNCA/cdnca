import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { securityPoliciesApi, type SecurityPolicy } from '../api/securityPolicies'
import { wafRuleSubscriptionsApi, type WAFRuleLibrary } from '../api/wafRuleSubscriptions'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import SecurityPoliciesPage from '../pages/SecurityPoliciesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const library = (id: string, name: string, subscription: WAFRuleLibrary['subscription']): WAFRuleLibrary => ({
  id, name, description: `${name} 说明`, origin: 'system', scope: 'global', owner: '平台授权中心', enabled: true, subscription,
  protected: true, revision: 3, updated_at: '2026-10-21T00:00:00Z',
})
const fresh = library('11111111-1111-4111-8111-111111111111', '已知漏洞防护', 'not_subscribed')
const stale = library('22222222-2222-4222-8222-222222222222', '爬虫防护', 'update_available')
const current = library('33333333-3333-4333-8333-333333333333', '注入防护', 'subscribed')
const custom: WAFRuleLibrary = { ...library('44444444-4444-4444-8444-444444444444', '我的规则库', 'not_applicable'), origin: 'custom', scope: 'user' }

const policy = (id: string, name: string, libraryID?: string): SecurityPolicy => ({
  id, scope_id: '22222222-2222-4222-8222-222222222222', kind: 'waf', name, description: '', enabled: true,
  default_action: 'allow', version: 1, created_at: '2026-10-21T00:00:00Z', updated_at: '2026-10-21T00:00:00Z',
  rules: [], protected: Boolean(libraryID), ...(libraryID ? { library_id: libraryID } : {}),
})
// The caller's policy list: two subscribed copies (protected, library_id names the library) and one own library.
// The 爬虫防护 copy is renamed locally: pairing goes by ID, not name.
const policies = [
  policy('55555555-5555-4555-8555-555555555555', '爬虫防护', stale.id),
  policy('66666666-6666-4666-8666-666666666666', '注入防护', current.id),
  policy('77777777-7777-4777-8777-777777777777', '我的规则库'),
]

function authenticate(permissions = ['security_policies.read', 'security_policies.manage']) {
  const user = principal({ permissions })
  useSessionStore.getState().setSession(authResponse(user), user)
}

function stub() {
  vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: policies, total: policies.length, page: 1, limit: 10 })
  vi.spyOn(wafRuleSubscriptionsApi, 'libraries').mockResolvedValue([fresh, stale, current, custom])
  // SEC-ACCOUNT-03 reports a failed pending-publication read, so stub it as "nothing pending".
  vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications').mockResolvedValue([])
  return {
    subscribe: vi.spyOn(wafRuleSubscriptionsApi, 'subscribeLibrary').mockResolvedValue(undefined),
    unsubscribe: vi.spyOn(wafRuleSubscriptionsApi, 'unsubscribeLibrary').mockResolvedValue(undefined),
    refresh: vi.spyOn(wafRuleSubscriptionsApi, 'refreshLibraries').mockResolvedValue(undefined),
  }
}

const row = async (name: string) => (await screen.findByText(name, { selector: '.waf-rule-name-text' })).closest('tr') as HTMLElement

describe('平台 WAF 规则库 in the rule library table (tp-b4)', () => {
  it('shows platform libraries as table rows with a real 订阅 column, no separate card', async () => {
    await changeLocale('zh-CN')
    authenticate()
    stub()
    renderWithProviders(<SecurityPoliciesPage kind="waf" referenceLayout />, ['/site/waf-rule'])

    expect(within(await row('已知漏洞防护')).getByText('未订阅')).toBeInTheDocument()
    expect(within(await row('已知漏洞防护')).getByText('平台')).toBeInTheDocument()
    expect(within(await row('爬虫防护')).getByText('可更新')).toBeInTheDocument()
    expect(within(await row('注入防护')).getByText('已订阅')).toBeInTheDocument()
    // The caller's own library is listed once (from the policy list) and has no subscription.
    expect(screen.getAllByText('我的规则库', { selector: '.waf-rule-name-text' })).toHaveLength(1)
    expect(within(await row('我的规则库')).getByRole('button', { name: '编辑' })).toBeInTheDocument()
    expect(screen.queryByText('平台 WAF 规则库')).not.toBeInTheDocument()
    expect(document.querySelector('.waf-library-section')).toBeNull()
    expect(screen.getByText('4 个')).toBeInTheDocument()
    for (const name of ['新增规则库', '批量操作', '刷新']) expect(screen.getByRole('button', { name: new RegExp(name) })).toBeInTheDocument()
  })

  // SEC-ACCOUNT-03: a failed catalog read is reported with a retry instead of silently dropping platform rows.
  it('SEC-ACCOUNT-03: reports a failed platform library read and restores the rows on retry', async () => {
    await changeLocale('zh-CN')
    authenticate()
    stub()
    const libraries = vi.spyOn(wafRuleSubscriptionsApi, 'libraries')
      .mockRejectedValueOnce(new ApiError('boom', 500, 'internal_error'))
      .mockResolvedValue([fresh, stale, current, custom])
    renderWithProviders(<SecurityPoliciesPage kind="waf" referenceLayout />, ['/site/waf-rule'])

    expect(await screen.findByText('平台规则库读取失败，订阅状态未知，列表中暂不显示平台规则库')).toBeInTheDocument()
    expect(screen.queryByText('已知漏洞防护', { selector: '.waf-rule-name-text' })).not.toBeInTheDocument()
    // fix-feedbackui: the retry is in the failure dialog's bottom row.
    const failure = document.querySelector<HTMLElement>('.cdnca-feedback-error')!
    fireEvent.click(within(failure).getByRole('button', { name: '重试' }))
    expect(await row('已知漏洞防护')).toBeInTheDocument()
    expect(libraries).toHaveBeenCalledTimes(2)
  })

  it('subscribes, updates, unsubscribes and refreshes from the rows and 批量操作', async () => {
    await changeLocale('zh-CN')
    authenticate()
    const calls = stub()
    renderWithProviders(<SecurityPoliciesPage kind="waf" referenceLayout />, ['/site/waf-rule'])

    fireEvent.click(within(await row('已知漏洞防护')).getByRole('button', { name: '订阅 已知漏洞防护' }))
    await waitFor(() => expect(calls.subscribe).toHaveBeenCalledWith(expect.any(String), fresh.id))
    fireEvent.click(within(await row('爬虫防护')).getByRole('button', { name: '更新 爬虫防护' }))
    await waitFor(() => expect(calls.subscribe).toHaveBeenLastCalledWith(expect.any(String), stale.id))
    fireEvent.click(within(await row('注入防护')).getByRole('button', { name: '取消订阅 注入防护' }))
    const confirm = (await screen.findByText(/取消订阅后删除你的这份规则库副本/)).closest('.ant-popover') as HTMLElement
    fireEvent.click(within(confirm).getByRole('button', { name: '取消订阅' }))
    await waitFor(() => expect(calls.unsubscribe).toHaveBeenCalledWith(expect.any(String), current.id))

    fireEvent.click(screen.getByRole('button', { name: /批量操作/ }))
    fireEvent.click(await screen.findByRole('menuitem', { name: '刷新订阅' }))
    await waitFor(() => expect(calls.refresh).toHaveBeenCalledTimes(1))
  })

  it('batch-deletes only the caller\'s own selected libraries', async () => {
    await changeLocale('zh-CN')
    authenticate()
    stub()
    // SEC-ACCOUNT-04: deletion goes through the batch API with each row's version.
    const batch = vi.spyOn(securityPoliciesApi, 'batch').mockResolvedValue({ items: [{ id: policies[2]!.id, status: 'ok' }] })
    renderWithProviders(<SecurityPoliciesPage kind="waf" referenceLayout />, ['/site/waf-rule'])

    expect(within(await row('注入防护')).getByRole('checkbox')).toBeDisabled()
    expect(within(await row('已知漏洞防护')).getByRole('checkbox')).toBeDisabled()
    fireEvent.click(within(await row('我的规则库')).getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /批量操作/ }))
    fireEvent.click(await screen.findByRole('menuitem', { name: '删除选中（1）' }))
    const dialog = await screen.findByRole('dialog', { name: '删除选中的 1 个规则库？' })
    fireEvent.click(within(dialog).getByRole('button', { name: /^删\s*除$/ }))
    await waitFor(() => expect(batch).toHaveBeenCalledTimes(1))
    expect(batch.mock.calls[0]?.[1]).toBe('delete')
    expect(batch.mock.calls[0]?.[2]).toEqual([{ id: policies[2]!.id, version: policies[2]!.version }])
  })

  it('hides every subscription action without security_policies.manage', async () => {
    await changeLocale('zh-CN')
    authenticate(['security_policies.read'])
    stub()
    renderWithProviders(<SecurityPoliciesPage kind="waf" referenceLayout />, ['/site/waf-rule'])
    expect(await row('已知漏洞防护')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^订阅/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^取消订阅/ })).not.toBeInTheDocument()
  })
})
