import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { subscriptionURLProblem, wafRuleSubscriptionsApi, type WAFRuleSubscription, type WAFSubscriptionPack } from '../api/wafRuleSubscriptions'
import WAFRuleSubscriptionsPanel from '../pages/security/WAFRuleSubscriptionsPanel'
import { renderWithProviders } from '../test/render'

const item: WAFRuleSubscription = {
  id: '11111111-1111-4111-8111-111111111111', name: '已知漏洞防护', description: 'N-day', source_url: 'https://rules.example.com/nday.json',
  interval_minutes: 360, enabled: true, revision: 3, feed_version: '20261017', feed_generated_at: '', rule_count: 42,
  last_attempt_at: '2026-10-17T01:00:00Z', last_success_at: '2026-10-17T00:00:00Z',
  last_error: 'rule "cve-1": action_config status=302: the node blocks with 403 only', next_fetch_at: '2026-10-17T06:00:00Z',
  subscribers: 2, pending_sites: 1, updated_at: '2026-10-17T00:00:00Z',
}

describe('WAF rule library subscriptions (NF37)', () => {
  afterEach(() => vi.restoreAllMocks())

  it('checks subscription URLs like the server', () => {
    expect(subscriptionURLProblem('https://rules.example.com/a.json')).toBeNull()
    expect(subscriptionURLProblem('https://fdomain.example/a.json')).toBeNull()
    expect(subscriptionURLProblem('http://rules.example.com/a.json')).toBe('scheme')
    expect(subscriptionURLProblem('https://u:p@rules.example.com/a.json')).toBe('credentials')
    for (const url of ['https://127.0.0.1/a', 'https://10.0.0.8/a', 'https://169.254.169.254/latest', 'https://[::1]/a', 'https://localhost/a']) {
      expect(subscriptionURLProblem(url)).toBe('internal')
    }
  })

  it('lists last good snapshot, error and next fetch; updates now and keeps the error visible', async () => {
    vi.spyOn(wafRuleSubscriptionsApi, 'list').mockResolvedValue([item])
    const sync = vi.spyOn(wafRuleSubscriptionsApi, 'sync').mockResolvedValue(item)
    renderWithProviders(<WAFRuleSubscriptionsPanel accessToken="token" open onClose={() => undefined} />)
    const row = (await screen.findByText('已知漏洞防护')).closest('tr')!
    expect(within(row).getByText('20261017')).toBeInTheDocument()
    expect(within(row).getByText('第 3 版')).toBeInTheDocument()
    expect(within(row).getByText('42')).toBeInTheDocument()
    expect(within(row).getByText('失败')).toBeInTheDocument()
    expect(within(row).getByText(item.last_error)).toBeInTheDocument()
    await userEvent.setup().click(within(row).getByRole('button', { name: /立即更新/ }))
    await waitFor(() => expect(sync).toHaveBeenCalledWith('token', item.id))
    expect(await screen.findByText(/已保留上次成功的版本/)).toBeInTheDocument()
  })

  it('shows each subscriber rule pack and the sites waiting to publish its new version (PA-25)', async () => {
    vi.spyOn(wafRuleSubscriptionsApi, 'list').mockResolvedValue([item])
    const pack: WAFSubscriptionPack = {
      subscription_id: item.id, tenant_scope_id: '22222222-2222-4222-8222-222222222222', tenant_name: '客户甲',
      pack_id: 'user/22222222-2222-4222-8222-222222222222/waf-sub-11111111111141118111111111111111',
      current_version: '3.0.0', latest_version: '3.0.0', update_policy: 'auto', subscribed_at: '2026-10-17T00:00:00Z',
      pending_sites: [{ site_id: '55555555-5555-4555-8555-555555555555', domain: 'a.example.com', published_version: '2.0.0' }],
    }
    const packs = vi.spyOn(wafRuleSubscriptionsApi, 'packs').mockResolvedValue([pack])
    const actor = userEvent.setup()
    renderWithProviders(<WAFRuleSubscriptionsPanel accessToken="token" open onClose={() => undefined} />)
    const row = (await screen.findByText('已知漏洞防护')).closest('tr')!
    expect(within(row).getByText('规则包 3.x')).toBeInTheDocument()
    expect(screen.getByText(/1 个网站挂载的订阅规则包有新版本、待发布/)).toBeInTheDocument()
    await actor.click(within(row).getByRole('button', { name: /展开行|Expand row/ }))
    await waitFor(() => expect(packs).toHaveBeenCalledWith('token', item.id))
    expect(await screen.findByText('客户甲')).toBeInTheDocument()
    expect(screen.getByText(pack.pack_id)).toBeInTheDocument()
    expect(screen.getByText('3.0.0 / 3.0.0')).toBeInTheDocument()
    expect(screen.getByText(/a\.example\.com（已发布 2\.0\.0）/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /去发布/ })).toHaveAttribute('href', '/site/rule-packs?site_id=55555555-5555-4555-8555-555555555555')
  })

  it('creates a subscription with the default interval and refuses internal URLs before sending', async () => {
    vi.spyOn(wafRuleSubscriptionsApi, 'list').mockResolvedValue([])
    const create = vi.spyOn(wafRuleSubscriptionsApi, 'create').mockResolvedValue({ ...item, last_error: '', revision: 0 })
    const actor = userEvent.setup()
    renderWithProviders(<WAFRuleSubscriptionsPanel accessToken="token" open onClose={() => undefined} />)
    await actor.click(await screen.findByRole('button', { name: /新增订阅/ }))
    // The drawer and the modal are both dialogs; the editor is the one titled 新增订阅.
    const dialog = await waitFor(() => {
      const found = screen.getAllByRole('dialog').find((node) => node.textContent?.startsWith('新增订阅'))
      expect(found).toBeTruthy()
      return found!
    })
    await actor.type(within(dialog).getByLabelText('名称'), '已知漏洞防护')
    await actor.type(within(dialog).getByLabelText('订阅地址'), 'https://192.168.1.2/a.json')
    await actor.click(within(dialog).getByRole('button', { name: /OK|确\s*定/ }))
    expect(await within(dialog).findByText('不能使用本机或内网地址')).toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()
    await actor.clear(within(dialog).getByLabelText('订阅地址'))
    await actor.type(within(dialog).getByLabelText('订阅地址'), 'https://rules.example.com/nday.json')
    await actor.click(within(dialog).getByRole('button', { name: /OK|确\s*定/ }))
    await waitFor(() => expect(create).toHaveBeenCalledWith('token', {
      name: '已知漏洞防护', description: '', source_url: 'https://rules.example.com/nday.json', interval_minutes: 360, enabled: true,
    }))
  })

  it('localizes a refused save instead of showing the dropped server text', async () => {
    vi.spyOn(wafRuleSubscriptionsApi, 'list').mockResolvedValue([])
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ error: {
      code: 'validation_error', message: 'invalid WAF rule subscription input: raw-server-detail', request_id: 'req-waf-1',
    } }), { status: 400, headers: { 'Content-Type': 'application/json' } }))
    const actor = userEvent.setup()
    renderWithProviders(<WAFRuleSubscriptionsPanel accessToken="token" open onClose={() => undefined} />)
    await actor.click(await screen.findByRole('button', { name: /新增订阅/ }))
    const dialog = await waitFor(() => {
      const found = screen.getAllByRole('dialog').find((node) => node.textContent?.startsWith('新增订阅'))
      expect(found).toBeTruthy()
      return found!
    })
    await actor.type(within(dialog).getByLabelText('名称'), '已知漏洞防护')
    await actor.type(within(dialog).getByLabelText('订阅地址'), 'https://rules.example.com/nday.json')
    await actor.click(within(dialog).getByRole('button', { name: /OK|确\s*定/ }))
    expect(await screen.findByText(/订阅设置未通过服务端校验/)).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('API request failed')
    expect(document.body.textContent).not.toContain('raw-server-detail')
  })
})
