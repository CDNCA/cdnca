import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, vi } from 'vitest'

import { ApiError, type Principal } from '../api/auth'
import {
  originAuthPublicationsApi,
  type OriginAuthEdgePublication,
  type OriginAuthPublication,
} from '../api/originAuthPublications'
import { resetSessionStore, useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import OriginAuthPublicationsPage from './OriginAuthPublicationsPage'

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const scopeID = '22222222-2222-4222-8222-222222222222'
const ruleID = '33333333-3333-4333-8333-333333333333'
const nodeA = '99999999-9999-4999-8999-999999999999'
const nodeB = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'

const publication: OriginAuthPublication = {
  id: '11111111-1111-4111-8111-111111111111',
  tenant_scope_id: scopeID,
  revision: 1,
  snapshot_hash: 'a'.repeat(64),
  snapshot: {
    schema_version: 'cdnca.control.originauth-publication/v1',
    tenant_scope_id: scopeID,
    publication_revision: 1,
    rules: [{
      rule_id: ruleID,
      site_id: '44444444-4444-4444-8444-444444444444',
      source_position: 1,
      provider: 's3',
      algorithm: 'aws4-hmac-sha256',
      endpoint: 'https://objects.example.test',
      bucket: 'tenant-assets',
      path_prefix: '/public',
      region: 'us-east-1',
      service: 's3',
      signature_ttl_seconds: 900,
      current_credential_revision_ref: '55555555-5555-4555-8555-555555555555',
      activate_current_at_unix: 1_786_060_800,
    }],
  },
  created_at: '2026-08-07T08:00:00Z',
}

const changedPublication: OriginAuthPublication = {
  ...publication,
  id: '66666666-6666-4666-8666-666666666666',
  revision: 2,
  snapshot_hash: 'b'.repeat(64),
  previous_hash: publication.snapshot_hash,
  snapshot: {
    ...publication.snapshot,
    publication_revision: 2,
    rules: [
      { ...publication.snapshot.rules[0]!, endpoint: 'https://objects-v2.example.test' },
      {
        ...publication.snapshot.rules[0]!,
        rule_id: '77777777-7777-4777-8777-777777777777',
        site_id: '88888888-8888-4888-8888-888888888888',
        source_position: 2,
      },
    ],
  },
  created_at: '2026-08-07T09:00:00Z',
}

const edgePublication: OriginAuthEdgePublication = {
  tenant_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  tenant_scope_id: scopeID,
  publication_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  source_publication_id: publication.id,
  source_revision: publication.revision,
  config_version_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  rollout_id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
  config_snapshot_sha256: 'b'.repeat(64),
  artifact_manifest_sha256: 'c'.repeat(64),
  recipient_binding_sha256: 'd'.repeat(64),
  node_count: 2,
  created_at: '2026-08-08T10:00:00Z',
}

const retryBinding = {
  method: 'POST',
  path: `/v1/tenant-scopes/${scopeID}/origin-auth/edge-publications`,
  if_match: '"1"',
  idempotency_key: 'edge-retry-1',
  body_sha256: 'e'.repeat(64),
  request_id: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
  correlation_id: '12121212-1212-4121-8121-121212121212',
  traceparent: `00-${'a'.repeat(32)}-${'b'.repeat(16)}-01`,
  task_id: 'origin-edge-task-1',
}

function tenant(overrides: Partial<Principal> = {}) {
  return principal({
    scope_id: scopeID,
    tenant_id: scopeID,
    permissions: ['origin_auth.read', 'origin_auth.manage'],
    ...overrides,
  })
}

function platform(permissions = [
  'origin_auth.read', 'origin_auth.manage', 'edge_publications.read', 'edge_publications.manage',
]) {
  return principal({
    scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions,
  })
}

function authenticate(actor = tenant(), token = 'origin-auth-token', update?: 'new' | 'refresh') {
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
  return useSessionStore.getState().sessionEpoch
}

function renderPage(queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false, gcTime: Infinity },
    mutations: { retry: false, gcTime: Infinity },
  },
}), initialEntry = '/site/origin-auth/publications') {
  const rendered = render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={[initialEntry]}>
            <OriginAuthPublicationsPage />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
  return { ...rendered, queryClient }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

async function submitEdgePublication(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: '发布到节点' }))
  const dialog = await screen.findByRole('dialog', { name: '发布源站鉴权到节点' })
  await user.type(within(dialog).getByLabelText('目标节点 UUID'), `${nodeA}\n${nodeB}`)
  const activation = within(dialog).getByLabelText('激活超时（毫秒）')
  const observation = within(dialog).getByLabelText('观察窗口（毫秒）')
  const successes = within(dialog).getByLabelText('连续成功次数')
  await user.clear(activation)
  await user.type(activation, '30000')
  await user.clear(observation)
  await user.type(observation, '10000')
  await user.clear(successes)
  await user.type(successes, '3')
  fireEvent.change(within(dialog).getByLabelText('截止时间（UTC）'), { target: { value: '2026-08-08T12:00' } })
  await user.click(within(dialog).getByRole('button', { name: '确认发布到节点' }))
}

afterEach(() => vi.restoreAllMocks())

describe('OriginAuthPublicationsPage', () => {
  beforeEach(async () => {
    resetSessionStore()
    await i18n.changeLanguage('zh-CN')
  })

  it.each([
    ['missing read permission', tenant({ permissions: ['origin_auth.manage'] })],
    ['missing scope identity', tenant({ scope_id: '' })],
    ['missing user identity', tenant({ user_id: '' })],
    ['whitespace-only scope and tenant identity', tenant({ scope_id: ' \t ', tenant_id: ' \t ' })],
    ['whitespace-only user identity', tenant({ user_id: ' \t ' })],
    ['padded scope and tenant identity', tenant({ scope_id: ` ${scopeID} `, tenant_id: ` ${scopeID} ` })],
    ['padded user identity', tenant({ user_id: ` ${principal().user_id} ` })],
  ])('fails locally with zero requests for %s', async (_name, actor) => {
    authenticate(actor)
    const getSpy = vi.spyOn(originAuthPublicationsApi, 'getLatest')

    renderPage()

    expect(await screen.findByText('无权查看回源鉴权发布')).toBeInTheDocument()
    expect(getSpy).not.toHaveBeenCalled()
  })

  it('renders loading, no-publication, localized error/retry, and a secret-free snapshot', async () => {
    authenticate()
    const pending = deferred<OriginAuthPublication>()
    vi.spyOn(originAuthPublicationsApi, 'getLatest')
      .mockReturnValueOnce(pending.promise)
      .mockRejectedValueOnce(new ApiError('raw private database message', 503, 'service_unavailable'))
      .mockResolvedValueOnce(publication)
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByLabelText('正在加载回源鉴权发布')).toBeInTheDocument()

    await act(async () => pending.reject(new ApiError('absent', 404, 'not_found')))
    expect(await screen.findByText('尚未创建回源鉴权发布')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新' }))
    expect(await screen.findByText('回源鉴权服务暂不可用，请稍后重试。')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw private database message')

    await user.click(screen.getByRole('button', { name: '重试' }))
    const row = (await screen.findByText('objects.example.test')).closest('tr')!
    expect(within(row).getByText('S3')).toBeInTheDocument()
    expect(within(row).getByText('tenant-assets')).toBeInTheDocument()
    expect(screen.getByText('版本 1')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/secret|access key|session token/i)
  })

  it('keeps token-free owner cache on refresh, clears it on new session, and ignores a late response', async () => {
    const actorA = tenant({ user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' })
    const actorB = tenant({ user_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' })
    const epoch = authenticate(actorA, 'old-origin-token')
    const pendingA = deferred<OriginAuthPublication>()
    const getSpy = vi.spyOn(originAuthPublicationsApi, 'getLatest')
      .mockReturnValueOnce(pendingA.promise)
      .mockResolvedValueOnce(changedPublication)
    const { queryClient } = renderPage()

    expect(await screen.findByLabelText('正在加载回源鉴权发布')).toBeInTheDocument()
    await act(async () => {
      authenticate(actorA, 'new-origin-token', 'refresh')
      await Promise.resolve()
    })
    expect(useSessionStore.getState().sessionEpoch).toBe(epoch)
    expect(getSpy).toHaveBeenCalledTimes(1)
    for (const query of queryClient.getQueryCache().getAll()) {
      expect(JSON.stringify(query.queryKey)).not.toMatch(/old-origin-token|new-origin-token/)
    }

    await act(async () => {
      authenticate(actorB, 'session-b-token')
      await Promise.resolve()
    })
    expect(await screen.findByText('版本 2')).toBeInTheDocument()
    expect(getSpy).toHaveBeenLastCalledWith('session-b-token', scopeID, expect.any(AbortSignal))
    await act(async () => pendingA.resolve(publication))
    expect(screen.queryByText('版本 1')).not.toBeInTheDocument()
    const keys = queryClient.getQueryCache().getAll().map((query) => JSON.stringify(query.queryKey))
    expect(keys.some((key) => key.includes(actorA.user_id))).toBe(false)
    expect(keys.some((key) => key.includes(actorB.user_id))).toBe(true)
  })

  it('allows read-only access without manage permission and maps server 403 locally', async () => {
    authenticate(tenant({ permissions: ['origin_auth.read'] }))
    vi.spyOn(originAuthPublicationsApi, 'getLatest').mockResolvedValue(publication)
    const { unmount } = renderPage()
    expect(await screen.findByText('版本 1')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '创建新发布' })).not.toBeInTheDocument()
    unmount()

    authenticate()
    vi.spyOn(originAuthPublicationsApi, 'getLatest')
      .mockRejectedValue(new ApiError('raw authorization detail', 403, 'permission_denied'))
    renderPage()
    expect(await screen.findByText('无权查看回源鉴权发布')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw authorization detail')
  })

  it('makes a server publish 403 terminal for the current owner without retrying stale writes', async () => {
    authenticate()
    const getSpy = vi.spyOn(originAuthPublicationsApi, 'getLatest').mockResolvedValue(publication)
    const createSpy = vi.spyOn(originAuthPublicationsApi, 'create').mockRejectedValue(
      new ApiError('raw manage authorization detail', 403, 'permission_denied'),
    )
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByText('版本 1')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '创建新发布' }))
    await user.click(await screen.findByRole('button', { name: '确认发布' }))

    expect(await screen.findByText('当前身份缺少回源鉴权权限。')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw manage authorization detail')
    expect(screen.queryByRole('button', { name: '创建新发布' })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(getSpy).toHaveBeenCalledTimes(2))
    await act(async () => {
      authenticate(tenant(), 'refreshed-origin-auth-token', 'refresh')
      await Promise.resolve()
    })
    expect(screen.queryByRole('button', { name: '创建新发布' })).not.toBeInTheDocument()
    expect(createSpy).toHaveBeenCalledOnce()
  })

  it('confirms first publication with zero CAS and compares immutable returned snapshots', async () => {
    authenticate()
    vi.spyOn(originAuthPublicationsApi, 'getLatest')
      .mockRejectedValue(new ApiError('absent', 404, 'not_found'))
    const createSpy = vi.spyOn(originAuthPublicationsApi, 'create').mockResolvedValue(changedPublication)
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByText('尚未创建回源鉴权发布')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '创建新发布' }))
    await user.click(await screen.findByRole('button', { name: '确认发布' }))

    expect(await screen.findByText('版本 2')).toBeInTheDocument()
    expect(screen.getByText('新增 2 / 删除 0 / 变更 0 / 未变 0')).toBeInTheDocument()
    expect(createSpy).toHaveBeenCalledWith(
      'origin-auth-token', scopeID, 0,
      expect.objectContaining({
        idempotencyKey: expect.any(String),
        requestID: expect.any(String),
        traceID: expect.any(String),
      }),
    )
  })

  it('retries an unknown publish with the exact frozen attempt or abandons and refreshes', async () => {
    authenticate()
    const getSpy = vi.spyOn(originAuthPublicationsApi, 'getLatest').mockResolvedValue(publication)
    const createSpy = vi.spyOn(originAuthPublicationsApi, 'create')
      .mockRejectedValueOnce(new ApiError('network', 0, 'network_error'))
      .mockRejectedValueOnce(new ApiError('timeout', 503, 'request_canceled'))
      .mockResolvedValueOnce(changedPublication)
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByText('版本 1')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '创建新发布' }))
    await user.click(await screen.findByRole('button', { name: '确认发布' }))
    expect(await screen.findByText('发布结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '放弃并刷新' }))
    await waitFor(() => expect(getSpy).toHaveBeenCalledTimes(2))

    await user.click(screen.getByRole('button', { name: '创建新发布' }))
    await user.click(await screen.findByRole('button', { name: '确认发布' }))
    expect(await screen.findByText('发布结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    const frozenAttempt = createSpy.mock.calls[1]
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('版本 2')).toBeInTheDocument()
    expect(createSpy.mock.calls[2]).toEqual(frozenAttempt)
  })

  it.each([
    [new ApiError('raw conflict', 409, 'idempotency_conflict'), '幂等请求与原请求不一致，请刷新确认。'],
    [new ApiError('raw stale', 412, 'revision_conflict'), '发布版本已变化，请刷新后重试。'],
    [new ApiError('raw invalid', 422, 'validation_error'), '当前规则无法生成有效发布，请检查后重试。'],
  ])('treats terminal publication errors as localized and not retryable', async (error, expected) => {
    authenticate()
    vi.spyOn(originAuthPublicationsApi, 'getLatest').mockResolvedValue(publication)
    vi.spyOn(originAuthPublicationsApi, 'create').mockRejectedValue(error)
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByText('版本 1')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '创建新发布' }))
    await user.click(await screen.findByRole('button', { name: '确认发布' }))

    expect(await screen.findByText(expected)).toBeInTheDocument()
    expect(document.body.textContent).not.toContain(error.message)
    expect(screen.queryByText('发布结果待确认')).not.toBeInTheDocument()
  })

  it('requires a canonical explicit tenant target for platform access and keeps both publication commands separate', async () => {
    authenticate(platform(), 'platform-origin-token')
    const getSpy = vi.spyOn(originAuthPublicationsApi, 'getLatest').mockResolvedValue(publication)
    vi.spyOn(originAuthPublicationsApi, 'publishToNodes')
    const user = userEvent.setup()

    renderPage()
    expect(await screen.findByText('请先选择要查看的租户作用域。')).toBeInTheDocument()
    expect(getSpy).not.toHaveBeenCalled()
    await user.type(screen.getByLabelText('目标租户作用域'), 'not-a-uuid')
    await user.click(screen.getByRole('button', { name: '应用目标' }))
    expect(await screen.findByText('请输入有效的小写租户作用域 UUID。')).toBeInTheDocument()
    expect(getSpy).not.toHaveBeenCalled()

    await user.clear(screen.getByLabelText('目标租户作用域'))
    await user.type(screen.getByLabelText('目标租户作用域'), scopeID)
    await user.click(screen.getByRole('button', { name: '应用目标' }))
    expect(await screen.findByText('版本 1')).toBeInTheDocument()
    expect(getSpy).toHaveBeenCalledWith('platform-origin-token', scopeID, expect.any(AbortSignal))
    expect(screen.getByRole('button', { name: '创建新发布' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '发布到节点' })).toBeInTheDocument()
  })

  it('publishes explicit node targets and reads back immutable rollout and artifact identities', async () => {
    authenticate(platform(), 'platform-origin-token')
    vi.spyOn(originAuthPublicationsApi, 'getLatest').mockResolvedValue(publication)
    const publishSpy = vi.spyOn(originAuthPublicationsApi, 'publishToNodes').mockResolvedValue(edgePublication)
    const readback = deferred<OriginAuthEdgePublication>()
    const readSpy = vi.spyOn(originAuthPublicationsApi, 'getEdgePublication').mockReturnValue(readback.promise)
    const user = userEvent.setup()

    renderPage(undefined, `/site/origin-auth/publications?target_scope_id=${scopeID}`)
    expect(await screen.findByText('版本 1')).toBeInTheDocument()
    expect(screen.getByText('尚未执行节点发布')).toBeInTheDocument()

    await submitEdgePublication(user)
    expect(await screen.findByText('正在加载节点发布结果')).toBeInTheDocument()
    expect(publishSpy).toHaveBeenCalledWith(
      'platform-origin-token', scopeID, publication.revision,
      {
        node_ids: [nodeA, nodeB],
        health_check: {
          activation_timeout_ms: 30_000,
          observation_window_ms: 10_000,
          required_consecutive_successes: 3,
        },
        deadline: '2026-08-08T12:00:00Z',
      },
      expect.objectContaining({
        idempotencyKey: expect.any(String), requestID: expect.any(String), correlationID: expect.any(String),
        traceparent: expect.stringMatching(/^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/),
        taskID: expect.any(String),
      }),
    )
    expect(readSpy).toHaveBeenCalledWith(
      'platform-origin-token', scopeID, edgePublication.publication_id, expect.any(String), expect.any(AbortSignal),
    )

    await act(async () => readback.resolve(edgePublication))
    expect(await screen.findByText('节点发布结果')).toBeInTheDocument()
    expect(screen.getByText(edgePublication.publication_id)).toBeInTheDocument()
    expect(screen.getByText(edgePublication.rollout_id)).toBeInTheDocument()
    expect(screen.getByText(edgePublication.config_version_id)).toBeInTheDocument()
    expect(screen.getByText(edgePublication.config_snapshot_sha256)).toBeInTheDocument()
    expect(screen.getByText(edgePublication.artifact_manifest_sha256)).toBeInTheDocument()
    expect(screen.getByText(edgePublication.recipient_binding_sha256)).toBeInTheDocument()
    expect(screen.getByText('2 个节点')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/private|secret|ciphertext|recipient key|wrapped key/i)
  })

  it('retries an unknown node publication with the exact frozen attempt or abandons it and refreshes', async () => {
    authenticate(platform(), 'platform-origin-token')
    const getSpy = vi.spyOn(originAuthPublicationsApi, 'getLatest').mockResolvedValue(publication)
    const unknown = () => Object.assign(
      new ApiError('raw encrypted artifact transaction detail', 503, 'origin_auth_edge_publication_outcome_unknown'),
      { retry: Object.freeze({ ...retryBinding }) },
    )
    const publishSpy = vi.spyOn(originAuthPublicationsApi, 'publishToNodes')
      .mockRejectedValueOnce(unknown())
      .mockRejectedValueOnce(unknown())
      .mockResolvedValueOnce({ ...edgePublication, replayed: true })
    vi.spyOn(originAuthPublicationsApi, 'getEdgePublication').mockResolvedValue({ ...edgePublication, replayed: true })
    const user = userEvent.setup()

    renderPage(undefined, `/site/origin-auth/publications?target_scope_id=${scopeID}`)
    expect(await screen.findByText('版本 1')).toBeInTheDocument()
    await submitEdgePublication(user)
    expect(await screen.findByText('节点发布结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw encrypted artifact')
    await user.click(screen.getByRole('button', { name: '放弃节点发布并刷新' }))
    await waitFor(() => expect(getSpy).toHaveBeenCalledTimes(2))
    expect(publishSpy).toHaveBeenCalledTimes(1)

    await submitEdgePublication(user)
    expect(await screen.findByText('节点发布结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    const frozenAttempt = publishSpy.mock.calls[1]
    await user.click(screen.getByRole('button', { name: '使用同一节点发布请求重试' }))
    expect(await screen.findByText('节点发布结果')).toBeInTheDocument()
    expect(publishSpy.mock.calls[2]).toEqual(frozenAttempt)
  })

  it('localizes node publication read errors and enforces edge read permission without raw details', async () => {
    authenticate(platform(), 'platform-origin-token')
    vi.spyOn(originAuthPublicationsApi, 'getLatest').mockResolvedValue(publication)
    vi.spyOn(originAuthPublicationsApi, 'publishToNodes').mockResolvedValue(edgePublication)
    const readSpy = vi.spyOn(originAuthPublicationsApi, 'getEdgePublication')
      .mockRejectedValueOnce(new ApiError(
        'raw rollout storage and recipient detail', 503, 'origin_auth_edge_publication_unavailable',
      ))
      .mockResolvedValueOnce(edgePublication)
    const user = userEvent.setup()

    const { unmount } = renderPage(undefined, `/site/origin-auth/publications?target_scope_id=${scopeID}`)
    expect(await screen.findByText('版本 1')).toBeInTheDocument()
    await submitEdgePublication(user)
    expect(await screen.findByText('节点发布服务暂不可用，请稍后重试。')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw rollout storage')
    await user.click(screen.getByRole('button', { name: '重试读取节点发布结果' }))
    expect(await screen.findByText('节点发布结果')).toBeInTheDocument()
    expect(readSpy).toHaveBeenCalledTimes(2)
    unmount()

    resetSessionStore()
    authenticate(platform(['origin_auth.read', 'origin_auth.manage', 'edge_publications.manage']), 'no-edge-read-token')
    vi.mocked(originAuthPublicationsApi.getLatest).mockResolvedValue(publication)
    renderPage(undefined, `/site/origin-auth/publications?target_scope_id=${scopeID}`)
    expect(await screen.findByText('无权查看节点发布结果')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '发布到节点' })).not.toBeInTheDocument()
  })

  it.each([
    ['en-US', 'Publish to nodes', 'No node publication has been run'],
    ['qps-ploc', '［发~布~到~节~点~］', '［尚~未~执~行~节~点~发~布~］'],
  ] as const)('renders complete %s node publication controls', async (locale, publishLabel, emptyLabel) => {
    await i18n.changeLanguage(locale)
    authenticate(platform())
    vi.spyOn(originAuthPublicationsApi, 'getLatest').mockResolvedValue(publication)
    renderPage(undefined, `/site/origin-auth/publications?target_scope_id=${scopeID}`)

    expect(await screen.findByRole('button', { name: publishLabel })).toBeInTheDocument()
    expect(screen.getByText(emptyLabel)).toBeInTheDocument()
  })
})
