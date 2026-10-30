import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'

import { ApiError, type Principal } from '../api/auth'
import {
  originAuthRulesApi,
  type OriginAuthRule,
} from '../api/originAuthRules'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import OriginAuthRulesPage from './OriginAuthRulesPage'

const scopeID = '22222222-2222-4222-8222-222222222222'
const ruleID = '33333333-3333-4333-8333-333333333333'
const siteID = '44444444-4444-4444-8444-444444444444'
const credentialID = '55555555-5555-4555-8555-555555555555'
const rule: OriginAuthRule = {
  id: ruleID,
  tenant_scope_id: scopeID,
  site_id: siteID,
  source_position: 1,
  provider: 's3',
  algorithm: 'aws4-hmac-sha256',
  endpoint: 'https://objects.example.com',
  bucket: 'media',
  path_prefix: '/',
  region: 'us-east-1',
  service: 's3',
  signature_ttl_seconds: 900,
  current_credential: { credential_id: credentialID, revision: 2 },
  enabled: true,
  deleted: false,
  revision: 7,
  created_at: '2026-08-07T01:00:00Z',
  updated_at: '2026-08-07T02:00:00Z',
}

function actor(overrides: Partial<Principal> = {}) {
  return principal({ permissions: ['origin_auth.read', 'origin_auth.manage'], ...overrides })
}

function authenticate(current = actor(), token = 'origin-token', update?: 'new' | 'refresh') {
  useSessionStore.getState().setSession({ ...authResponse(current), access_token: token }, current, update)
  return useSessionStore.getState().sessionEpoch
}

function renderPage(queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, gcTime: Infinity } },
})) {
  return {
    queryClient,
    ...render(
      <ConfigProvider button={{ autoInsertSpace: false }}>
        <AntApp>
          <QueryClientProvider client={queryClient}>
            <OriginAuthRulesPage />
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>,
    ),
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

async function chooseOption(user: ReturnType<typeof userEvent.setup>, name: string, option: string) {
  await user.click(screen.getByRole('combobox', { name }))
  const matches = await screen.findAllByText(option)
  await user.click(matches.find((node) => node.closest('.ant-select-item-option'))!)
}

describe('OriginAuthRulesPage', () => {
  beforeEach(async () => {
    resetSessionStore()
    await i18n.changeLanguage('zh-CN')
  })

  it.each([
    ['missing read', actor({ permissions: ['origin_auth.manage'] })],
    ['platform principal', actor({ scope_kind: 'platform', tenant_id: null })],
    ['missing user', actor({ user_id: '' })],
  ])('renders local forbidden with zero requests for %s', async (_name, current) => {
    authenticate(current)
    const listSpy = vi.spyOn(originAuthRulesApi, 'list')
    renderPage()

    expect(await screen.findByText('无权查看源站鉴权规则')).toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
  })

  it('renders natural loading, empty, localized error/retry, and server forbidden states', async () => {
    authenticate()
    const pending = deferred<{ items: OriginAuthRule[] }>()
    vi.spyOn(originAuthRulesApi, 'list')
      .mockReturnValueOnce(pending.promise)
      .mockRejectedValueOnce(new ApiError('raw service topology', 503, 'origin_auth_unavailable'))
      .mockResolvedValueOnce({ items: [rule] })
      .mockRejectedValueOnce(new ApiError('raw policy detail', 403, 'origin_auth_permission_denied'))
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByLabelText('正在加载源站鉴权规则')).toBeInTheDocument()
    await act(async () => pending.resolve({ items: [] }))
    expect(await screen.findByText('暂无源站鉴权规则')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('源站鉴权服务暂不可用，请稍后重试')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw service topology')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText(rule.endpoint)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('无权查看源站鉴权规则')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw policy detail')
  })

  it('keeps token-free owner/filter/cursor state across refresh and clears stale owner data on a new session', async () => {
    const current = actor()
    const epoch = authenticate(current, 'old-origin-token')
    const second = {
      ...rule,
      id: '66666666-6666-4666-8666-666666666666',
      provider: 'oss' as const,
      endpoint: 'https://oss.example.com',
    }
    const late = deferred<{ items: OriginAuthRule[] }>()
    const listSpy = vi.spyOn(originAuthRulesApi, 'list')
      .mockImplementationOnce(async () => ({ items: [rule], next_cursor: 'next-page' }))
      .mockImplementationOnce(async () => ({ items: [rule], next_cursor: 'next-page' }))
      .mockImplementationOnce(async () => ({ items: [second] }))
      .mockImplementationOnce(async () => late.promise)
      .mockResolvedValue({ items: [second] })
    const user = userEvent.setup()
    const { queryClient } = renderPage()

    expect(await screen.findByText(rule.endpoint)).toBeInTheDocument()
    await user.type(screen.getByRole('textbox', { name: '站点 ID' }), siteID)
    await chooseOption(user, '存储提供商', 'S3')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith('old-origin-token', scopeID, {
      siteID, enabled: undefined, limit: 20, cursor: undefined,
    }))
    await user.click(screen.getByRole('button', { name: '下一页' }))
    expect(await screen.findByText('第 2 页')).toBeInTheDocument()

    const callsBeforeRefresh = listSpy.mock.calls.length
    await act(async () => {
      authenticate(current, 'new-origin-token', 'refresh')
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(listSpy).toHaveBeenCalledTimes(callsBeforeRefresh)
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    for (const query of queryClient.getQueryCache().getAll()) {
      expect(JSON.stringify(query.queryKey)).not.toMatch(/old-origin-token|new-origin-token/)
    }

    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(listSpy).toHaveBeenCalledTimes(callsBeforeRefresh + 1))
    const nextActor = actor({ user_id: '77777777-7777-4777-8777-777777777777' })
    await act(async () => {
      authenticate(nextActor, 'next-session-token')
      await Promise.resolve()
    })
    expect(await screen.findByText(second.endpoint)).toBeInTheDocument()
    await act(async () => late.resolve({ items: [{ ...rule, endpoint: 'https://late-private.example' }] }))
    expect(screen.queryByText('https://late-private.example')).not.toBeInTheDocument()
    const keys = queryClient.getQueryCache().getAll().map((query) => JSON.stringify(query.queryKey))
    expect(keys.some((key) => key.includes(current.user_id))).toBe(false)
    expect(keys.some((key) => key.includes(nextActor.user_id))).toBe(true)
  })

  it('keeps read-only users functional while hiding mutation controls', async () => {
    authenticate(actor({ permissions: ['origin_auth.read'] }))
    vi.spyOn(originAuthRulesApi, 'list').mockResolvedValue({ items: [rule] })
    renderPage()

    expect(await screen.findByText(rule.endpoint)).toBeInTheDocument()
    expect(screen.getByText('只读模式')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新建规则' })).not.toBeInTheDocument()
    const row = screen.getByText(rule.endpoint).closest('tr')!
    expect(within(row).queryByRole('button', { name: '编辑' })).not.toBeInTheDocument()
    expect(within(row).queryByRole('button', { name: '删除' })).not.toBeInTheDocument()
  })

  it('creates a rule without secret fields and confirms destructive actions', async () => {
    authenticate()
    vi.spyOn(originAuthRulesApi, 'list').mockResolvedValue({ items: [rule] })
    const createSpy = vi.spyOn(originAuthRulesApi, 'create').mockResolvedValue(rule)
    const removeSpy = vi.spyOn(originAuthRulesApi, 'remove').mockResolvedValue({ ...rule, deleted: true, revision: 8 })
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByText(rule.endpoint)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '新建规则' }))
    await user.type(screen.getByRole('textbox', { name: '新建站点 ID' }), siteID)
    await user.type(screen.getByRole('textbox', { name: '端点' }), 'https://objects.example.com')
    await user.type(screen.getByRole('textbox', { name: '存储桶' }), 'media')
    await user.type(screen.getByRole('textbox', { name: '区域' }), 'us-east-1')
    await user.type(screen.getByRole('textbox', { name: '凭据 ID' }), credentialID)
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(createSpy).toHaveBeenCalledOnce())
    const body = createSpy.mock.calls[0]?.[2]
    expect(JSON.stringify(body)).not.toMatch(/secret|session_token/i)
    expect(createSpy.mock.calls[0]?.[3]).toMatch(/^origin-auth-/)

    const row = screen.getByText(rule.endpoint).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '删除' }))
    await user.click(await screen.findByRole('button', { name: '确认删除' }))
    await waitFor(() => expect(removeSpy).toHaveBeenCalledWith(
      'origin-token', scopeID, ruleID, 7, expect.stringMatching(/^origin-auth-/),
    ))
  })

  it('retries an unknown write with the exact same operation and key, or abandons it', async () => {
    authenticate()
    vi.spyOn(originAuthRulesApi, 'list').mockResolvedValue({ items: [rule] })
    const enableSpy = vi.spyOn(originAuthRulesApi, 'setEnabled')
      .mockRejectedValueOnce(new ApiError('raw uncertain result', 503, 'origin_auth_result_unknown'))
      .mockResolvedValueOnce({ ...rule, enabled: false, revision: 8 })
      .mockRejectedValueOnce(new ApiError('raw uncertain result', 0, 'network_error'))
    const user = userEvent.setup()
    renderPage()
    const row = (await screen.findByText(rule.endpoint)).closest('tr')!

    await user.click(within(row).getByRole('button', { name: '停用' }))
    expect(await screen.findByText('写入结果未知')).toBeInTheDocument()
    const firstKey = enableSpy.mock.calls[0]?.[5]
    await user.click(screen.getByRole('button', { name: '按原操作重试' }))
    await waitFor(() => expect(enableSpy).toHaveBeenCalledTimes(2))
    expect(enableSpy.mock.calls[1]?.slice(0, 5)).toEqual(enableSpy.mock.calls[0]?.slice(0, 5))
    expect(enableSpy.mock.calls[1]?.[5]).toBe(firstKey)

    await user.click(within(row).getByRole('button', { name: '停用' }))
    expect(await screen.findByText('写入结果未知')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '放弃重试' }))
    await waitFor(() => expect(screen.queryByText('写入结果未知')).not.toBeInTheDocument())
  })
})
