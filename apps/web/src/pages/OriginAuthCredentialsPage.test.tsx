import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  originAuthCredentialsApi,
  type OriginAuthCredential,
} from '../api/originAuthCredentials'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import OriginAuthCredentialsPage from './OriginAuthCredentialsPage'

const scopeID = '22222222-2222-4222-8222-222222222222'
const credential: OriginAuthCredential = {
  id: '33333333-3333-4333-8333-333333333333',
  tenant_scope_id: scopeID,
  provider: 's3',
  name: 'primary-origin',
  status: 'pending',
  revision: 2,
  revision_ref: '44444444-4444-4444-8444-444444444444',
  not_before: '2026-08-07T08:00:00Z',
  expires_at: '2026-09-07T08:00:00Z',
  created_at: '2026-08-07T08:00:00Z',
  updated_at: '2026-08-07T08:05:00Z',
}

function tenantActor(overrides: Partial<Principal> = {}) {
  return principal({
    scope_id: scopeID,
    tenant_id: scopeID,
    permissions: ['origin_auth.read', 'origin_auth.manage'],
    ...overrides,
  })
}

function authenticate(actor = tenantActor(), token = 'origin-auth-token', update: 'new' | 'refresh' = 'new') {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
  return useSessionStore.getState().sessionEpoch
}

function renderPage(queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, gcTime: Infinity } },
})) {
  return {
    queryClient,
    ...render(
      <ConfigProvider button={{ autoInsertSpace: false }}>
        <AntApp><QueryClientProvider client={queryClient}>
          <MemoryRouter><OriginAuthCredentialsPage /></MemoryRouter>
        </QueryClientProvider></AntApp>
      </ConfigProvider>,
    ),
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

async function chooseOption(user: ReturnType<typeof userEvent.setup>, label: string, option: string) {
  await user.click(screen.getByRole('combobox', { name: label }))
  const matches = await screen.findAllByText(option)
  const target = matches.find((element) => element.closest('.ant-select-item-option'))
  if (!target) throw new Error(`option not found: ${option}`)
  await user.click(target)
}

async function submitCreate(user: ReturnType<typeof userEvent.setup>, secret = 'request-only-secret') {
  await user.click(screen.getByRole('button', { name: '新增凭据' }))
  await chooseOption(user, '服务商', 'S3 / S3 兼容')
  await user.type(screen.getByRole('textbox', { name: '凭据名称' }), 'new-origin')
  await user.type(screen.getByRole('textbox', { name: 'Access Key ID' }), 'AKIA-NEW')
  await user.type(screen.getByLabelText('Secret Access Key'), secret)
  await user.type(screen.getByLabelText('Session Token（可选）'), 'request-only-session')
  await user.type(screen.getByRole('textbox', { name: '生效时间' }), '2026-08-07T08:00:00Z')
  await user.type(screen.getByRole('textbox', { name: '到期时间' }), '2026-09-07T08:00:00Z')
  await user.click(screen.getByRole('button', { name: '提交' }))
}

describe('OriginAuthCredentialsPage', () => {
  beforeEach(async () => { await i18n.changeLanguage('zh-CN') })

  it.each([
    ['missing read permission', tenantActor({ permissions: ['origin_auth.manage'] })],
    ['platform identity', tenantActor({ scope_kind: 'platform', tenant_id: null })],
    ['missing user', tenantActor({ user_id: '' })],
  ])('renders local forbidden with zero requests for %s', async (_name, actor) => {
    authenticate(actor)
    const listSpy = vi.spyOn(originAuthCredentialsApi, 'list')
    renderPage()
    expect(await screen.findByText('无权查看源站鉴权凭据')).toBeInTheDocument()
    expect(listSpy).not.toHaveBeenCalled()
  })

  it('renders loading, empty, localized error/retry, and server forbidden states', async () => {
    authenticate()
    const pending = deferred<{ items: OriginAuthCredential[] }>()
    vi.spyOn(originAuthCredentialsApi, 'list')
      .mockReturnValueOnce(pending.promise)
      .mockRejectedValueOnce(new ApiError('raw private backend', 503, 'origin_auth_unavailable'))
      .mockResolvedValueOnce({ items: [credential] })
      .mockRejectedValueOnce(new ApiError('raw IAM detail', 403, 'origin_auth_permission_denied'))
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByLabelText('正在加载源站鉴权凭据')).toBeInTheDocument()
    await act(async () => pending.resolve({ items: [] }))
    expect(await screen.findByText('暂无源站鉴权凭据')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('源站鉴权服务暂不可用，请稍后重试')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw private backend')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText(credential.name)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('无权查看源站鉴权凭据')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw IAM detail')
  })

  it('uses tenant-bound token-free identity, filters/cursor, preserves refresh, and isolates a new session', async () => {
    const actorA = tenantActor({ user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' })
    const actorB = tenantActor({ user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' })
    const epoch = authenticate(actorA, 'old-token')
    const late = deferred<{ items: OriginAuthCredential[] }>()
    const listSpy = vi.spyOn(originAuthCredentialsApi, 'list')
      .mockImplementation(async (token, _scope, params) => {
        if (token === 'session-b-token') return { items: [{ ...credential, name: 'session-b' }] }
        if (params?.cursor) return late.promise
        return { items: [credential], next_cursor: 'next-page' }
      })
    const user = userEvent.setup()
    const { queryClient } = renderPage()

    expect(await screen.findByText(credential.name)).toBeInTheDocument()
    await chooseOption(user, '服务商筛选', 'S3 / S3 兼容')
    await chooseOption(user, '状态', '待验证')
    await user.click(screen.getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(listSpy).toHaveBeenLastCalledWith('old-token', scopeID, {
      provider: 's3', status: 'pending', limit: 20, cursor: 'next-page',
    }, expect.any(AbortSignal)))

    await act(async () => {
      authenticate(actorA, 'new-token', 'refresh')
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(screen.getByText('第 2 页')).toBeInTheDocument()
    const keys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(keys).not.toMatch(/old-token|new-token/)

    await act(async () => {
      authenticate(actorB, 'session-b-token')
      await Promise.resolve()
    })
    expect(await screen.findByText('session-b')).toBeInTheDocument()
    await act(async () => late.resolve({ items: [{ ...credential, name: 'late-owner-secret' }] }))
    expect(screen.queryByText('late-owner-secret')).not.toBeInTheDocument()
    const finalKeys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(finalKeys).not.toContain(actorA.user_id)
    expect(finalKeys).toContain(actorB.user_id)
  })

  it('keeps manage actions local and retries a 408 with frozen input and metadata but the current token', async () => {
    const actor = tenantActor()
    const epoch = authenticate(actor)
    vi.spyOn(originAuthCredentialsApi, 'list').mockResolvedValue({ items: [credential] })
    const createSpy = vi.spyOn(originAuthCredentialsApi, 'create')
      .mockRejectedValueOnce(new ApiError('private timeout', 408, 'request_timeout'))
      .mockResolvedValueOnce(credential)
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByText(credential.name)).toBeInTheDocument()

    await submitCreate(user)
    expect(await screen.findByText('写入结果未知', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('request-only-secret')
    expect(document.body.textContent).not.toContain('request-only-session')
    await act(async () => {
      authenticate(actor, 'refreshed-origin-auth-token', 'refresh')
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    await user.click(screen.getByRole('button', { name: '精确重试' }))
    await waitFor(() => expect(createSpy).toHaveBeenCalledTimes(2))
    expect(createSpy.mock.calls[0]![0]).toBe('origin-auth-token')
    expect(createSpy.mock.calls[1]![0]).toBe('refreshed-origin-auth-token')
    expect(createSpy.mock.calls[1]!.slice(1)).toEqual(createSpy.mock.calls[0]!.slice(1))
    expect(document.body.textContent).not.toContain('request-only-secret')
  })

  it('treats 429 as a localized terminal rate limit without retaining an exact retry', async () => {
    authenticate()
    vi.spyOn(originAuthCredentialsApi, 'list').mockResolvedValue({ items: [credential] })
    const createSpy = vi.spyOn(originAuthCredentialsApi, 'create')
      .mockRejectedValue(new ApiError('raw private rate limit', 429, 'rate_limited'))
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByText(credential.name)).toBeInTheDocument()

    await submitCreate(user, 'rate-limited-secret')
    expect(await screen.findByText('操作过于频繁，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '精确重试' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增凭据' })).toBeEnabled()
    expect(document.body.textContent).not.toContain('raw private rate limit')
    expect(createSpy.mock.calls[0]![2].secret.secret_access_key).toBe('')
  })

  it('abandons an unknown write by clearing secrets and refetching the list and selected detail', async () => {
    authenticate()
    const listSpy = vi.spyOn(originAuthCredentialsApi, 'list').mockResolvedValue({ items: [credential] })
    const detailSpy = vi.spyOn(originAuthCredentialsApi, 'get').mockResolvedValue(credential)
    const createSpy = vi.spyOn(originAuthCredentialsApi, 'create')
      .mockRejectedValue(new ApiError('raw invalid response', 502, 'origin_auth_invalid_response'))
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByText(credential.name)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '查看详情' }))
    expect(await screen.findByText(credential.revision_ref)).toBeInTheDocument()

    await submitCreate(user, 'abandoned-secret')
    expect(await screen.findByText('写入结果未知', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '放弃并刷新' }))
    await waitFor(() => {
      expect(listSpy).toHaveBeenCalledTimes(2)
      expect(detailSpy).toHaveBeenCalledTimes(2)
    })
    expect(screen.queryByRole('button', { name: '精确重试' })).not.toBeInTheDocument()
    expect(createSpy.mock.calls[0]![2].secret.secret_access_key).toBe('')
    expect(createSpy.mock.calls[0]![2].secret.session_token).toBeUndefined()
  })

  it('clears an old unknown attempt on a new session and ignores a late write result', async () => {
    const actorA = tenantActor({ user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' })
    const actorB = tenantActor({ user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' })
    authenticate(actorA, 'session-a-token')
    vi.spyOn(originAuthCredentialsApi, 'list').mockImplementation(async (token) => ({
      items: [{ ...credential, name: token === 'session-b-token' ? 'session-b' : 'session-a' }],
    }))
    const late = deferred<OriginAuthCredential>()
    const createSpy = vi.spyOn(originAuthCredentialsApi, 'create').mockReturnValue(late.promise)
    const user = userEvent.setup()
    const { queryClient } = renderPage()
    expect(await screen.findByText('session-a')).toBeInTheDocument()

    await submitCreate(user, 'late-owner-secret')
    await waitFor(() => expect(createSpy).toHaveBeenCalledOnce())
    await act(async () => {
      authenticate(actorB, 'session-b-token')
      await Promise.resolve()
    })
    expect(await screen.findByText('session-b')).toBeInTheDocument()
    expect(createSpy.mock.calls[0]![2].secret.secret_access_key).toBe('')
    await act(async () => late.resolve({ ...credential, name: 'late-write-secret' }))
    expect(screen.queryByText('late-write-secret')).not.toBeInTheDocument()
    expect(JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))).not.toContain(actorA.user_id)
    expect(screen.queryByRole('button', { name: '精确重试' })).not.toBeInTheDocument()
  })

  it('hides mutations without manage permission and performs revision-bound lifecycle actions', async () => {
    authenticate(tenantActor({ permissions: ['origin_auth.read'] }))
    vi.spyOn(originAuthCredentialsApi, 'list').mockResolvedValue({ items: [credential] })
    renderPage()
    expect(await screen.findByText(credential.name)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增凭据' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '验证' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '停用' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '删除' })).not.toBeInTheDocument()
  })
})
