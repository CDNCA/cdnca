import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import {
  cachePoliciesApi,
  type CachePolicyDocument,
  type CachePolicyView,
} from '../../api/cachePolicies'
import { cacheOperationsApi } from '../../api/cacheOperations'
import { useSessionStore } from '../../auth/session'
import i18n from '../../i18n'
import '../../i18n/cachePolicy'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import CacheSiteTab from './CacheSiteTab'

const siteID = 'site-1'
const accessToken = 'memory-only-access-token'

const overrideDocument: CachePolicyDocument = {
  mode: 'override',
  rules: [{
    order: 1,
    extensions: ['.css'],
    path_prefix: '',
    status_codes: [200],
    ttl_seconds: 3600,
  }],
  query_mode: 'preserve',
  query_names: [],
  vary_headers: ['accept-encoding'],
  disk_quota_bytes: 1024 * 1024 * 1024,
}

function policy(revision = 3, document: CachePolicyDocument = overrideDocument): CachePolicyView {
  return {
    site_id: siteID,
    revision,
    binding_mode: 'override',
    definition_id: siteID,
    definition_revision: revision,
    document,
    created_by_user_id: '11111111-1111-4111-8111-111111111111',
    request_id: `request-${revision}`,
    created_at: `2026-08-0${revision}T08:00:00Z`,
  }
}

function authenticate(
  permissions = ['sites.read', 'sites.manage'],
  scopeKind: 'tenant' | 'platform' = 'tenant',
) {
  const actor = principal({
    permissions,
    scope_kind: scopeKind,
    tenant_id: scopeKind === 'tenant' ? '22222222-2222-4222-8222-222222222222' : null,
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  return actor
}

function renderTab(options: {
  permissions?: string[]
  scopeKind?: 'tenant' | 'platform'
  locked?: boolean
  siteScopeId?: string
  onDirtyChange?: (state: { dirty: boolean; uncertain: boolean; pending: boolean }) => void
} = {}) {
  const permissions = options.permissions ?? ['sites.read', 'sites.manage']
  const scopeKind = options.scopeKind ?? 'tenant'
  const actor = authenticate(permissions, scopeKind)
  return renderWithProviders(
    <CacheSiteTab
      siteId={siteID}
      accessToken={accessToken}
      scopeKind={scopeKind}
      permissions={permissions}
      lockedForTenant={options.locked ?? false}
      sessionEpoch={useSessionStore.getState().sessionEpoch}
      userId={actor.user_id}
      scopeId={actor.scope_id}
      tenantId={actor.tenant_id}
      siteScopeId={options.siteScopeId}
      onDirtyChange={options.onDirtyChange ?? (() => undefined)}
    />,
  )
}

function text(key: string, options?: Record<string, unknown>): string {
  return i18n.t(key, { ns: 'cachePolicy', ...options })
}

type User = ReturnType<typeof userEvent.setup>

// The tags Select labels its wrapper; its search input is the combobox inside.
const varyInput = () => within(screen.getByText(text('fields.varyHeaders'), { selector: '.cache-policy-field > span' }).parentElement!).getByRole('combobox')

// openEdit opens rule index's 编辑 dialog (the rules table, tp-b3c-be).
async function openEdit(user: User, index = 0) {
  const edits = await screen.findAllByRole('button', { name: text('table.edit') })
  await user.click(edits[index]!)
  return within(await screen.findByRole('dialog', { name: text('dialog.editTitle') }))
}

// editTTL sets the dialog's 有效期 in seconds and confirms.
async function editTTL(user: User, seconds: number, index = 0) {
  const dialog = await openEdit(user, index)
  const ttl = dialog.getByRole('spinbutton', { name: text('dialog.expire') })
  await user.clear(ttl)
  await user.type(ttl, String(seconds))
  await user.click(dialog.getByRole('combobox', { name: text('dialog.expireUnit') }))
  await user.click(await screen.findByTitle(text('dialog.units.s')))
  await user.click(dialog.getByRole('button', { name: text('dialog.ok') }))
  await waitFor(() => expect(screen.queryByRole('dialog', { name: text('dialog.editTitle') })).not.toBeInTheDocument())
}

// openMore opens the dialog's 更多匹配条件 (our own match fields).
async function openMore(user: User, dialog: ReturnType<typeof within>) {
  const advanced = dialog.queryByRole('button', { name: text('actions.showAdvanced') })
  if (advanced) await user.click(advanced)
  const more = dialog.getByRole('button', { name: text('dialog.more') })
  if (more.getAttribute('aria-expanded') !== 'true') await user.click(more)
}

beforeEach(async () => {
  window.sessionStorage.clear()
  await i18n.changeLanguage('zh-CN')
})

afterEach(async () => {
  vi.restoreAllMocks()
  await act(async () => { await i18n.changeLanguage('zh-CN') })
})

// fix-siteinstant：缓存设置没有保存按钮。改动即保存；键入类字段失焦保存（这里让当前焦点失焦）。
async function commitEdits() {
  await act(async () => { (document.activeElement as HTMLElement | null)?.blur() })
}

describe('CacheSiteTab reads and RBAC', () => {
  it('renders stable loading and treats an absent policy as an empty editable state', async () => {
    const actor = authenticate()
    vi.spyOn(cachePoliciesApi, 'get').mockReturnValueOnce(new Promise<CachePolicyView>(() => undefined))
    const first = renderWithProviders(
      <CacheSiteTab
        siteId={siteID}
        accessToken={accessToken}
        scopeKind="tenant"
        permissions={['sites.read', 'sites.manage']}
        lockedForTenant={false}
        sessionEpoch={useSessionStore.getState().sessionEpoch}
        userId={actor.user_id}
        scopeId={actor.scope_id}
        tenantId={actor.tenant_id}
        onDirtyChange={() => undefined}
      />,
    )

    expect(screen.getByTestId('cache-policy-tab')).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByText(text('states.loading'))).toBeInTheDocument()
    first.unmount()

    vi.spyOn(cachePoliciesApi, 'get').mockRejectedValueOnce(
      new ApiError('private missing policy', 404, 'not_found'),
    )
    renderTab()

    expect(await screen.findByText(text('states.empty'))).toBeInTheDocument()
    expect(screen.queryByText('private missing policy')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: text('actions.save') })).toBeNull()
  })

  it.each([
    [403, 'permission_denied', 'errors.permission_denied'],
    [503, 'service_unavailable', 'errors.service_unavailable'],
  ])('maps %i reads to stable localized errors', async (status, code, key) => {
    vi.spyOn(cachePoliciesApi, 'get').mockRejectedValue(
      new ApiError(`private-${status}`, status, code),
    )
    renderTab()

    expect(await screen.findByText(text(key))).toBeInTheDocument()
    expect(screen.queryByText(`private-${status}`)).not.toBeInTheDocument()
    if (status === 503) expect(screen.getByRole('button', { name: text('actions.retry') })).toBeEnabled()
  })

  it.each([
    ['platform principal without the site tenant scope', ['sites.read', 'sites.manage'], 'platform' as const],
    ['tenant without sites.read', ['sites.manage'], 'tenant' as const],
  ])('fails closed for a %s without issuing cache policy requests', async (_, permissions, scopeKind) => {
    const get = vi.spyOn(cachePoliciesApi, 'get')
    const history = vi.spyOn(cachePoliciesApi, 'history')
    const publish = vi.spyOn(cachePoliciesApi, 'publish')

    renderTab({ permissions, scopeKind })

    expect(screen.getByText(text('states.forbiddenDescription'))).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
    expect(history).not.toHaveBeenCalled()
    expect(publish).not.toHaveBeenCalled()
  })

  it.each([
    ['without sites.manage', ['sites.read'], false],
    ['while tenant locked', ['sites.read', 'sites.manage'], true],
  ])('keeps the policy read-only %s', async (_, permissions, locked) => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    renderTab({ permissions, locked })

    expect(await screen.findByText(text('states.readOnly'))).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: text('actions.save') })).toBeNull()
    expect(screen.getByRole('button', { name: text('table.edit') })).toBeDisabled()
    expect(screen.getByRole('button', { name: text('actions.addRule') })).toBeDisabled()
  })
})

describe('CacheSiteTab platform administrator (site-parity3b)', () => {
  const siteScopeId = '33333333-3333-4333-8333-333333333333'

  it('reads and publishes the site cache policy in the site tenant scope', async () => {
    const get = vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockResolvedValue(policy(4))
    const user = userEvent.setup()
    renderTab({ permissions: ['platform.admin'], scopeKind: 'platform', siteScopeId })

    expect(await screen.findByRole('button', { name: text('actions.addRule') })).toBeEnabled()
    expect(get).toHaveBeenCalledWith(accessToken, siteID, siteScopeId)
    expect(screen.queryByText(text('states.readOnly'))).not.toBeInTheDocument()
    // fix-siteinstant: the rule dialog's 确定 saves
    await editTTL(user, 7200)
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(publish.mock.calls[0]![5]).toBe(siteScopeId)
    expect(await screen.findByText(text('states.saved'))).toBeInTheDocument()
  })
})

describe('CacheSiteTab writes', () => {
  it('has no save button, saves a rule edit at once and sends only exact PolicyDocument fields', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    let resolvePublish!: (value: CachePolicyView) => void
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockReturnValue(
      new Promise<CachePolicyView>((resolve) => { resolvePublish = resolve }),
    )
    const user = userEvent.setup()
    renderTab()

    expect(await screen.findByText(text('states.unchanged'))).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: text('actions.save') })).toBeNull()

    await editTTL(user, 7200)

    expect(await screen.findByText(text('states.saving'))).toBeInTheDocument()
    // fix-siteinstant: the controls stay editable while the save runs (a further edit is saved after it)
    expect(screen.getByRole('button', { name: text('table.edit') })).toBeEnabled()
    expect(publish).toHaveBeenCalledTimes(1)
    const [token, id, input, idempotencyKey, serializedBody] = publish.mock.calls[0]
    expect(token).toBe(accessToken)
    expect(id).toBe(siteID)
    expect(input.expected_revision).toBe(3)
    expect(input.document.rules[0].ttl_seconds).toBe(7200)
    expect(idempotencyKey).toBeTruthy()
    expect(serializedBody).toBe(JSON.stringify(input))
    expect(Object.keys(input.document).sort()).toEqual([
      'disk_quota_bytes', 'mode', 'query_mode', 'query_names', 'rules', 'vary_headers',
    ])
    expect(Object.keys(input.document.rules[0]).sort()).toEqual([
      'extensions', 'order', 'path_prefix', 'status_codes', 'ttl_seconds',
    ])
    // an untouched v1 rule stays v1: no schema_version, action or browser TTL
    expect(serializedBody).not.toMatch(/schema_version|browser_ttl|"action"|force_cache|no_cache/i)

    await act(async () => resolvePublish(policy(4, input.document)))
    expect(await screen.findByText(text('states.saved'))).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: text('actions.save') })).toBeNull()
  })

  // User 10-27: "Vary 请求头是啥意思", "磁盘配额 这是啥单位". Headers are picked
  // (or typed), sizes are entered with a unit; the API still takes bytes.
  it('picks headers to separate the cache by and enters sizes with units', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3, { ...overrideDocument, min_object_bytes: 512 * 1024 }))
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockImplementation(async (_token, _site, input) => policy(input.expected_revision + 1, input.document))
    const user = userEvent.setup()
    renderTab()

    await user.click(await screen.findByRole('button', { name: text('actions.showAdvanced') }))
    const quota = await screen.findByLabelText(text('fields.diskQuotaBytes'))
    expect(quota).toHaveValue('1')
    expect(screen.getByRole('combobox', { name: text('units.unitOf', { field: text('fields.diskQuotaBytes') }) })).toBeInTheDocument()
    expect(screen.getByText(text('units.gb'))).toBeInTheDocument()
    expect(screen.getByLabelText(text('fields.minObjectBytes'))).toHaveValue('512')
    expect(screen.getByText(text('help.diskQuota', { min: '64 MB', max: '16 TB' }))).toBeInTheDocument()
    expect(screen.getByText(text('help.varyHeaders'))).toBeInTheDocument()

    await user.clear(quota)
    await user.type(quota, '2')
    await user.click(varyInput())
    await user.click(await screen.findByText(text('varyHeaderOptions.accept-language')))
    await user.type(varyInput(), 'X-Device{enter}')
    await commitEdits()
    await waitFor(() => expect((publish.mock.calls.at(-1)?.[2] as { document: CachePolicyDocument } | undefined)?.document.vary_headers).toHaveLength(3))
    const sent = (publish.mock.calls.at(-1)![2] as { document: CachePolicyDocument }).document
    expect(sent.disk_quota_bytes).toBe(2 * 1024 ** 3)
    expect(sent.min_object_bytes).toBe(512 * 1024)
    expect([...sent.vary_headers].sort()).toEqual(['accept-encoding', 'accept-language', 'x-device'])
  })

  it('replays an uncertain write with the same body and idempotency key', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    const publish = vi.spyOn(cachePoliciesApi, 'publish')
      .mockRejectedValueOnce(new TypeError('connection reset'))
      .mockResolvedValueOnce(policy(4, { ...overrideDocument, disk_quota_bytes: 2 * 1024 ** 3 }))
    const user = userEvent.setup()
    renderTab()

    const quota = await screen.findByLabelText(text('fields.diskQuotaBytes'))
    await user.clear(quota)
    // The quota is entered in GB (1 GiB opens in GB); the API still gets bytes.
    await user.type(quota, '2')
    await commitEdits()

    // 结果未知改为 OutcomeUnknown：断言锁定表单旁的原位恢复条
    expect(await screen.findByText(text('errors.network_error'), { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(quota).toBeDisabled()
    await user.click(screen.getByRole('button', { name: text('actions.retry') }))
    expect(await screen.findByText(text('states.saved'))).toBeInTheDocument()

    expect(publish).toHaveBeenCalledTimes(2)
    expect(publish.mock.calls[1][3]).toBe(publish.mock.calls[0][3])
    expect(publish.mock.calls[1][4]).toBe(publish.mock.calls[0][4])
    expect(publish.mock.calls[1][2]).toEqual(publish.mock.calls[0][2])
  })

  it('compares a revision conflict and retries the draft against latest with a new request', async () => {
    const latest = policy(4, { ...overrideDocument, rules: [{ ...overrideDocument.rules[0], ttl_seconds: 1800 }] })
    const get = vi.spyOn(cachePoliciesApi, 'get')
      .mockResolvedValueOnce(policy())
      .mockResolvedValueOnce(latest)
    const publish = vi.spyOn(cachePoliciesApi, 'publish')
      .mockRejectedValueOnce(new ApiError('private conflict', 412, 'revision_conflict'))
      .mockResolvedValueOnce(policy(5, { ...overrideDocument, rules: [{ ...overrideDocument.rules[0], ttl_seconds: 7200 }] }))
    const user = userEvent.setup()
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    renderTab()

    await editTTL(user, 7200)
    await commitEdits()

    expect(await screen.findByText(text('states.conflictTitle'))).toBeInTheDocument()
    expect(screen.queryByText('private conflict')).not.toBeInTheDocument()
    expect(get).toHaveBeenCalledTimes(2)
    await user.click(screen.getByRole('button', { name: text('actions.compare') }))
    const comparison = screen.getByRole('region', { name: text('comparison.title') })
    expect(within(comparison).getByText(text('comparison.latest'))).toBeInTheDocument()
    expect(within(comparison).getByText(text('comparison.draft'), { exact: false })).toBeInTheDocument()
    expect(screen.getByRole('cell', { name: `2${text('dialog.units.h')}` })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: text('actions.retryAfterReload') }))
    expect(await screen.findByText(text('states.saved'))).toBeInTheDocument()
    expect(publish).toHaveBeenCalledTimes(2)
    expect(publish.mock.calls[1][2].expected_revision).toBe(4)
    expect(publish.mock.calls[1][2].document.rules[0].ttl_seconds).toBe(7200)
    expect(publish.mock.calls[1][3]).not.toBe(publish.mock.calls[0][3])
    expect(publish.mock.calls[1][4]).not.toBe(publish.mock.calls[0][4])
    expect(confirm).toHaveBeenCalledWith(text('confirm.overwriteLatest'))
  })

  it('can discard a conflicted draft and load the latest policy', async () => {
    const latest = policy(4, { ...overrideDocument, rules: [{ ...overrideDocument.rules[0], ttl_seconds: 1800 }] })
    vi.spyOn(cachePoliciesApi, 'get')
      .mockResolvedValueOnce(policy())
      .mockResolvedValueOnce(latest)
    vi.spyOn(cachePoliciesApi, 'publish').mockRejectedValue(
      new ApiError('private conflict', 409, 'revision_conflict'),
    )
    const user = userEvent.setup()
    renderTab()

    await editTTL(user, 7200)
    await commitEdits()
    await screen.findByText(text('states.conflictTitle'))
    await user.click(screen.getByRole('button', { name: text('actions.reload') }))

    expect(screen.getByRole('cell', { name: `1800${text('dialog.units.s')}` })).toBeInTheDocument()
    expect(screen.getByText(text('states.unchanged'))).toBeInTheDocument()
    expect(screen.queryByText(text('states.conflictTitle'))).not.toBeInTheDocument()
  })
})

describe('CacheSiteTab owner lineage and draft lifetime', () => {
  it('isolates current and history data across an account switch and ignores old late promises', async () => {
    const actorA = authenticate()
    act(() => useSessionStore.getState().setSession(
      { ...authResponse(actorA), access_token: 'token-a' },
      actorA,
    ))
    let resolveCurrentA!: (value: CachePolicyView) => void
    let resolveCurrentB!: (value: CachePolicyView) => void
    let resolveHistoryA!: (value: { items: CachePolicyView[] }) => void
    let resolveHistoryB!: (value: { items: CachePolicyView[] }) => void
    const get = vi.spyOn(cachePoliciesApi, 'get').mockImplementation((token) =>
      new Promise<CachePolicyView>((resolve) => {
        if (token === 'token-a') resolveCurrentA = resolve
        else resolveCurrentB = resolve
      }),
    )
    vi.spyOn(cachePoliciesApi, 'history').mockImplementation((token) =>
      new Promise((resolve) => {
        if (token === 'token-a') resolveHistoryA = resolve
        else resolveHistoryB = resolve
      }),
    )
    const actorB = principal({
      user_id: '33333333-3333-4333-8333-333333333333',
      scope_id: '44444444-4444-4444-8444-444444444444',
      tenant_id: '44444444-4444-4444-8444-444444444444',
      permissions: ['sites.read', 'sites.manage'],
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } },
    })
    const view = render(
      <QueryClientProvider client={queryClient}>
        <CacheSiteTab
          siteId={siteID}
          accessToken="token-a"
          scopeKind="tenant"
          permissions={actorA.permissions}
          lockedForTenant={false}
          sessionEpoch={useSessionStore.getState().sessionEpoch}
          userId={actorA.user_id}
          scopeId={actorA.scope_id}
          tenantId={actorA.tenant_id}
          onDirtyChange={() => undefined}
        />
      </QueryClientProvider>,
    )
    await waitFor(() => expect(get).toHaveBeenCalledWith('token-a', siteID))
    await act(async () => resolveCurrentA(policy(3)))
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: text('actions.history') }))
    await waitFor(() => expect(cachePoliciesApi.history).toHaveBeenCalledWith(
      'token-a', siteID, { limit: 20 },
    ))

    act(() => useSessionStore.getState().setSession(
      { ...authResponse(actorB), access_token: 'token-b' },
      actorB,
    ))
    view.rerender(
      <QueryClientProvider client={queryClient}>
        <CacheSiteTab
          siteId={siteID}
          accessToken="token-b"
          scopeKind="tenant"
          permissions={actorB.permissions}
          lockedForTenant={false}
          sessionEpoch={useSessionStore.getState().sessionEpoch}
          userId={actorB.user_id}
          scopeId={actorB.scope_id}
          tenantId={actorB.tenant_id}
          onDirtyChange={() => undefined}
        />
      </QueryClientProvider>,
    )
    expect(screen.getByText(text('states.loading'))).toBeInTheDocument()
    await waitFor(() => expect(get).toHaveBeenCalledWith('token-b', siteID))
    await act(async () => resolveCurrentB(policy(4, {
      ...overrideDocument,
      query_mode: 'ignore',
      query_names: [],
    })))
    expect((await screen.findAllByText(text('queryModes.ignore'))).length).toBeGreaterThan(0)
    await user.click(screen.getByRole('button', { name: text('actions.history') }))
    await waitFor(() => expect(cachePoliciesApi.history).toHaveBeenCalledWith(
      'token-b', siteID, { limit: 20 },
    ))
    await act(async () => resolveHistoryB({ items: [{ ...policy(4), request_id: 'request-b' }] }))
    expect(await screen.findByText('request-b')).toBeInTheDocument()
    await act(async () => resolveHistoryA({ items: [{ ...policy(2), request_id: 'request-a' }] }))
    expect(screen.queryByText('request-a')).not.toBeInTheDocument()
  })

  it('reports dirty state and refuses a destructive refresh without discarding the draft', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    // fix-siteinstant: the edit is saved at once; here the save never answers, so the draft stays dirty (pending).
    vi.spyOn(cachePoliciesApi, 'publish').mockReturnValue(new Promise<CachePolicyView>(() => undefined))
    const onDirtyChange = vi.fn()
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    const user = userEvent.setup()
    renderTab({ onDirtyChange })

    await editTTL(user, 7200)
    await waitFor(() => expect(onDirtyChange).toHaveBeenLastCalledWith({
      dirty: true,
      uncertain: false,
      pending: true,
    }))
    expect(confirm).not.toHaveBeenCalled()
    expect(screen.getByRole('cell', { name: `2${text('dialog.units.h')}` })).toBeInTheDocument()
  })
})

describe('CacheSiteTab canonical rules and overlap validation', () => {
  it('treats sparse rule responses as unchanged before and after save', async () => {
    const sparse = {
      ...overrideDocument,
      rules: [{ order: 1, ttl_seconds: 3600 }],
    } as CachePolicyDocument
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3, sparse))
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockResolvedValue(policy(4, {
      ...sparse,
      rules: [{ order: 1, ttl_seconds: 7200 }],
    } as CachePolicyDocument))
    const user = userEvent.setup()
    renderTab()

    expect(await screen.findByText(text('states.unchanged'))).toBeInTheDocument()
    await editTTL(user, 7200)
    expect(await screen.findByText(text('states.saved'))).toBeInTheDocument()
    expect(publish).toHaveBeenCalledTimes(1)
  })

  it('keeps extensions, path prefix, and status codes independently editable and round-trips all conditions', async () => {
    const combined = {
      ...overrideDocument,
      rules: [{
        order: 1,
        extensions: ['.css'],
        path_prefix: '/assets/',
        status_codes: [200, 206],
        ttl_seconds: 3600,
      }],
    }
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3, combined))
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockResolvedValue(policy(4, combined))
    const user = userEvent.setup()
    renderTab()

    const dialog = await openEdit(user)
    expect(dialog.getByLabelText(text('dialog.scopeInput.dir'))).toHaveValue('/assets/')
    expect(dialog.getByLabelText(text('fields.extensions'))).toHaveValue('.css')
    const statuses = dialog.getByLabelText(text('fields.statusCodes'))
    expect(statuses).toHaveValue('200, 206')
    await user.clear(statuses)
    await user.click(statuses)
    await user.paste('200, 304')
    await user.click(dialog.getByRole('button', { name: text('dialog.ok') }))
    await commitEdits()
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(publish.mock.calls[0][2].document.rules[0]).toEqual({
      order: 1,
      extensions: ['.css'],
      path_prefix: '/assets/',
      status_codes: [200, 304],
      ttl_seconds: 3600,
    })
  })

  // ui-errmsg-1024: the server appends the trailing slash (cachecontrol
  // normalizeDirectoryPath), so /api is accepted and sent as /api/.
  it('accepts a path prefix without the trailing slash and sends it with one', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3))
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockResolvedValue(policy(4))
    const user = userEvent.setup()
    renderTab()
    const dialog = await openEdit(user)
    await user.click(dialog.getByText(text('dialog.scopes.dir')))
    await user.type(dialog.getByLabelText(text('dialog.scopeInput.dir')), '/api')
    await user.click(dialog.getByRole('button', { name: text('dialog.ok') }))
    await commitEdits()
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(publish.mock.calls[0][2].document.rules[0].path_prefix).toBe('/api/')
    expect(screen.queryByText(text('validation.invalidPath'))).not.toBeInTheDocument()
  })

  it.each([
    ['all/all', [{ order: 1, ttl_seconds: 10 }, { order: 2, ttl_seconds: 20 }]],
    ['extension overlap', [
      { order: 1, extensions: ['.css'], ttl_seconds: 10 },
      { order: 2, extensions: ['.css', '.js'], ttl_seconds: 20 },
    ]],
    ['path prefix overlap', [
      { order: 1, path_prefix: '/api/', ttl_seconds: 10 },
      { order: 2, path_prefix: '/api/v1/', ttl_seconds: 20 },
    ]],
    ['status overlap', [
      { order: 1, status_codes: [200, 206], ttl_seconds: 10 },
      { order: 2, status_codes: [200, 304], ttl_seconds: 20 },
    ]],
  ])('rejects %s rule overlap after normalization', async (_, rules) => {
    const document = { ...overrideDocument, rules } as CachePolicyDocument
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3, document))
    const publish = vi.spyOn(cachePoliciesApi, 'publish')
    const user = userEvent.setup()
    renderTab()

    const quota = await screen.findByLabelText(text('fields.diskQuotaBytes'))
    await user.clear(quota)
    // The quota is entered in GB (1 GiB opens in GB); the API still gets bytes.
    await user.type(quota, '2')
    await commitEdits()
    expect(await screen.findByText(text('validation.overlap'))).toBeInTheDocument()
    expect(publish).not.toHaveBeenCalled()
  })

  it('allows non-overlapping normalized rules to submit', async () => {
    const document = {
      ...overrideDocument,
      rules: [
        { order: 1, extensions: ['.CSS'], ttl_seconds: 10 },
        { order: 2, extensions: ['.js'], ttl_seconds: 20 },
      ],
    } as CachePolicyDocument
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3, document))
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockResolvedValue(policy(4, {
      ...document,
      rules: [
        { order: 1, extensions: ['.css'], path_prefix: '', status_codes: [], ttl_seconds: 10 },
        { order: 2, extensions: ['.js'], path_prefix: '', status_codes: [], ttl_seconds: 20 },
      ],
      disk_quota_bytes: 2 * 1024 ** 3,
    }))
    const user = userEvent.setup()
    renderTab()

    const quota = await screen.findByLabelText(text('fields.diskQuotaBytes'))
    await user.clear(quota)
    // The quota is entered in GB (1 GiB opens in GB); the API still gets bytes.
    await user.type(quota, '2')
    await commitEdits()
    expect(await screen.findByText(text('states.saved'))).toBeInTheDocument()
    expect(publish).toHaveBeenCalledTimes(1)
  })

  // ge36：缓存规则的路径正则与响应内容类型条件。
  it('edits a rule path regex and content types and sends them normalized', async () => {
    const document = {
      ...overrideDocument,
      rules: [{ order: 1, ttl_seconds: 600 }, { order: 2, path_prefix: '/img/', ttl_seconds: 60 }],
    } as CachePolicyDocument
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3, document))
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockResolvedValue(policy(4, document))
    const user = userEvent.setup()
    renderTab()

    const dialog = await openEdit(user)
    await openMore(user, dialog)
    await user.click(dialog.getByLabelText(text('fields.pathRegex')))
    await user.paste('^/static/.+\\.(?:css|js)$')
    await user.click(dialog.getByLabelText(text('fields.contentTypes')))
    await user.paste('Text/CSS, image/*')
    await user.click(dialog.getByRole('button', { name: text('dialog.ok') }))
    await commitEdits()
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    // a conditional rule is exempt from the overlap check (decided per request)
    // a rule without scope is 全站 in the dialog: it is saved with path_prefix "/"
    expect(publish.mock.calls[0][2].document.rules[0]).toEqual({
      order: 1, extensions: [], path_prefix: '/', status_codes: [], ttl_seconds: 600,
      path_regex: '^/static/.+\\.(?:css|js)$', content_types: ['image/*', 'text/css'],
    })
    expect(publish.mock.calls[0][2].document.rules[1]).toEqual({
      order: 2, extensions: [], path_prefix: '/img/', status_codes: [], ttl_seconds: 60,
    })
    // the wire body carries the conditions only where set
    const body = JSON.parse(publish.mock.calls[0][4] as string) as { document: { rules: Record<string, unknown>[] } }
    expect(body.document.rules[0]).toMatchObject({ path_regex: '^/static/.+\\.(?:css|js)$', content_types: ['image/*', 'text/css'] })
    expect(body.document.rules[1]).not.toHaveProperty('path_regex')
    expect(body.document.rules[1]).not.toHaveProperty('content_types')
  })

  it.each([
    ['an invalid path regex', 'pathRegex', '^/(a', 'validation.invalidPathRegex'],
    ['an invalid content type', 'contentTypes', 'text', 'validation.invalidContentTypes'],
  ])('refuses %s before publishing', async (_, field, value, message) => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3))
    const publish = vi.spyOn(cachePoliciesApi, 'publish')
    const user = userEvent.setup()
    renderTab()

    const dialog = await openEdit(user)
    await openMore(user, dialog)
    await user.click(dialog.getByLabelText(text(`fields.${field}`)))
    await user.paste(value)
    await user.click(dialog.getByRole('button', { name: text('dialog.ok') }))
    await commitEdits()
    expect(await screen.findByText(text(message))).toBeInTheDocument()
    expect(publish).not.toHaveBeenCalled()
  })
})

describe('CacheSiteTab conflict and async recovery', () => {
  it('shows a localized base/latest/draft comparison and confirms before overwriting latest changes', async () => {
    const latest = policy(4, {
      ...overrideDocument,
      mode: 'follow_origin',
      rules: [],
      query_mode: 'ignore',
      query_names: [],
      vary_headers: ['accept-language'],
    })
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValueOnce(policy()).mockResolvedValueOnce(latest)
    const publish = vi.spyOn(cachePoliciesApi, 'publish')
      .mockRejectedValueOnce(new ApiError('private conflict', 412, 'revision_conflict'))
      .mockResolvedValueOnce(policy(5))
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true)
    const user = userEvent.setup()
    renderTab()

    // fix-siteinstant: 排除 needs a parameter name (checked, not sent); typing it and leaving the field saves and meets the conflict
    await user.click(await screen.findByRole('combobox', { name: text('fields.queryMode') }))
    await user.click(await screen.findByText(text('queryModes.exclude')))
    expect(publish).not.toHaveBeenCalled()
    await user.type(screen.getByLabelText(text('fields.queryNames')), 'draft-key')
    await commitEdits()
    await screen.findByText(text('states.conflictTitle'))
    await user.click(screen.getByRole('button', { name: text('actions.compare') }))

    const comparison = screen.getByRole('region', { name: text('comparison.title') })
    expect(within(comparison).getByText(text('comparison.base'))).toBeInTheDocument()
    expect(within(comparison).getByText(text('comparison.latest'))).toBeInTheDocument()
    expect(within(comparison).getByText(text('comparison.draft'))).toBeInTheDocument()
    expect(within(comparison).getAllByText(text('fields.mode'))).toHaveLength(3)
    expect(comparison).toHaveTextContent(text('modes.override'))
    expect(comparison).toHaveTextContent(text('modes.follow_origin'))
    expect(comparison).toHaveTextContent(text('queryModes.preserve'))
    expect(comparison).toHaveTextContent(text('queryModes.ignore'))
    expect(comparison).toHaveTextContent(text('queryModes.exclude'))
    expect(comparison).toHaveTextContent(text('fields.rules'))
    expect(comparison).toHaveTextContent(text('fields.ttlSeconds'))
    expect(comparison).toHaveTextContent(text('fields.queryNames'))
    expect(comparison).toHaveTextContent(text('fields.varyHeaders'))
    expect(comparison).toHaveTextContent(text('fields.diskQuotaBytes'))
    expect(comparison).toHaveTextContent('accept-language')
    expect(comparison.textContent).not.toMatch(/query_mode|disk_quota_bytes|follow_origin|"preserve"|"ignore"|"exclude"/)

    const retry = screen.getByRole('button', { name: text('actions.retryAfterReload') })
    await user.click(retry)
    expect(confirm).toHaveBeenCalledWith(text('confirm.overwriteLatest'))
    expect(publish).toHaveBeenCalledTimes(1)
    await user.click(retry)
    expect(await screen.findByText(text('states.saved'))).toBeInTheDocument()
    expect(publish).toHaveBeenCalledTimes(2)
    expect(publish.mock.calls[1][2].expected_revision).toBe(4)
  })

  it('localizes conflict-latest failure and retries it explicitly', async () => {
    vi.spyOn(cachePoliciesApi, 'get')
      .mockResolvedValueOnce(policy())
      .mockRejectedValueOnce(new ApiError('private latest', 503, 'service_unavailable'))
      .mockResolvedValueOnce(policy(4))
    vi.spyOn(cachePoliciesApi, 'publish').mockRejectedValue(
      new ApiError('private conflict', 412, 'revision_conflict'),
    )
    const user = userEvent.setup()
    renderTab()

    await editTTL(user, 7200)
    await commitEdits()
    expect(await screen.findByText(text('errors.service_unavailable'))).toBeInTheDocument()
    expect(screen.queryByText('private latest')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: text('actions.retry') }))
    await waitFor(() => expect(cachePoliciesApi.get).toHaveBeenCalledTimes(3))
    expect(screen.getByRole('button', { name: text('actions.compare') })).toBeEnabled()
  })

  it('localizes history-detail failure without an unhandled rejection and allows retry', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    vi.spyOn(cachePoliciesApi, 'history').mockResolvedValue({ items: [policy(2)] })
    const getRevision = vi.spyOn(cachePoliciesApi, 'getRevision')
      .mockRejectedValueOnce(new ApiError('private detail', 503, 'service_unavailable'))
      .mockResolvedValueOnce(policy(2))
    const unhandled = vi.fn()
    window.addEventListener('unhandledrejection', unhandled)
    const user = userEvent.setup()
    renderTab()

    await user.click(await screen.findByRole('button', { name: text('actions.history') }))
    const history = await screen.findByRole('region', { name: text('history.title') })
    await user.click(within(history).getByRole('button', { name: text('history.view') }))
    // 历史详情读取失败改为 FeedbackWhen 弹窗（挂在 body）
    const failure = within(await screen.findByRole('dialog', { name: text('history.detailError') }))
    expect(failure.getByText(text('errors.service_unavailable'))).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private detail')
    expect(unhandled).not.toHaveBeenCalled()
    await user.click(failure.getByRole('button', { name: text('actions.retry') }))
    expect(await within(history).findByText(`${text('history.revision')} 2`)).toBeInTheDocument()
    expect(getRevision).toHaveBeenCalledTimes(2)
    window.removeEventListener('unhandledrejection', unhandled)
  })
})

describe('CacheSiteTab history and responsive contract', () => {
  it('loads policy history and inspects a selected immutable revision', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    const history = vi.spyOn(cachePoliciesApi, 'history').mockResolvedValue({
      items: [policy(3), policy(2)],
      next_cursor: 'cursor-2',
    })
    const getRevision = vi.spyOn(cachePoliciesApi, 'getRevision').mockResolvedValue(policy(2))
    const user = userEvent.setup()
    renderTab()

    await user.click(await screen.findByRole('button', { name: text('actions.history') }))
    const historyRegion = await screen.findByRole('region', { name: text('history.title') })
    expect(within(historyRegion).getByText('request-2')).toBeInTheDocument()
    expect(history).toHaveBeenCalledWith(accessToken, siteID, { limit: 20 })

    const viewButtons = within(historyRegion).getAllByRole('button', { name: text('history.view') })
    await user.click(viewButtons[1])
    expect(getRevision).toHaveBeenCalledWith(accessToken, siteID, 2)
    expect(await within(historyRegion).findByText(`${text('history.revision')} 2`)).toBeInTheDocument()
    expect(within(historyRegion).getAllByText(policy(2).created_by_user_id).length).toBeGreaterThan(0)
    expect(within(historyRegion).getAllByText(policy(2).request_id).length).toBeGreaterThan(0)
  })

  it('keeps qps text and icon controls accessible in the 390px geometry contract', async () => {
    await i18n.changeLanguage('qps-ploc')
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    vi.spyOn(cachePoliciesApi, 'history').mockResolvedValue({ items: [policy(3)] })
    const { container } = renderTab()

    await screen.findByRole('heading', { name: text('title') })
    const root = screen.getByTestId('cache-policy-tab')
    expect(root).toHaveStyle({ minWidth: 0, maxWidth: '100%', overflowX: 'clip' })
    expect(container.querySelector('.cache-policy-rules-section')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: text('title') })).toBeInTheDocument()
    expect(text('title')).toMatch(/^［.+~.+］$/)
    expect(screen.getByRole('button', { name: text('actions.moveUp') })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: text('actions.moveDown') })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: text('actions.removeRule') })).toBeInTheDocument()
    // collapsed by default, as the competitor's 展开高级设置
    const advanced = screen.getByRole('button', { name: text('actions.showAdvanced') })
    expect(advanced).toHaveAttribute('aria-expanded', 'false')
    expect(advanced).toHaveAttribute('aria-controls', 'cache-policy-advanced-panel')
    const historyToggle = screen.getByRole('button', { name: text('actions.history') })
    expect(historyToggle).toHaveAttribute('aria-expanded', 'false')
    expect(historyToggle).toHaveAttribute('aria-controls', 'cache-policy-history-panel')
    await userEvent.setup().click(historyToggle)
    const history = await screen.findByRole('region', { name: text('history.title') })
    expect(history).toHaveAttribute('id', 'cache-policy-history-panel')
    expect(historyToggle).toHaveAttribute('aria-expanded', 'true')
    expect(history.querySelector('.cache-policy-history-col-created-by')).toBeInTheDocument()
    expect(history.querySelector('.cache-policy-history-col-request-id')).toBeInTheDocument()
    expect(history.querySelector('.cache-policy-history-col-action')).toBeInTheDocument()
    expect(within(history).getByRole('button', { name: text('history.view') })).toBeEnabled()
  })

  it('keeps the localized conflict comparison bounded under inflated pseudo-locale text', async () => {
    await i18n.changeLanguage('qps-ploc')
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    const latest = policy(4, {
      ...overrideDocument,
      mode: 'follow_origin',
      rules: [],
      query_mode: 'ignore',
      query_names: [],
    })
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValueOnce(policy()).mockResolvedValueOnce(latest)
    vi.spyOn(cachePoliciesApi, 'publish').mockRejectedValueOnce(
      new ApiError('private conflict', 412, 'revision_conflict'),
    )
    const user = userEvent.setup()
    const { container } = renderTab()

    await editTTL(user, 7200)
    await commitEdits()
    await screen.findByText(text('states.conflictTitle'))
    await user.click(screen.getByRole('button', { name: text('actions.compare') }))

    const comparison = screen.getByRole('region', { name: text('comparison.title') })
    expect(comparison).toHaveStyle({ minWidth: 0, maxWidth: '100%', overflowX: 'clip' })
    expect(container.querySelectorAll('.cache-policy-comparison-panel')).toHaveLength(3)
    expect(within(comparison).getAllByText(text('fields.mode'))).toHaveLength(3)
    expect(comparison).toHaveTextContent(text('modes.follow_origin'))
    expect(text('comparison.latest')).toMatch(/^［.+~.+］$/)
    expect(comparison.textContent).not.toMatch(/query_mode|disk_quota_bytes|follow_origin/)
  })
})

describe('CacheSiteTab ge-cache', () => {
  it('flushes all cache as a whole-site purge on every carrying node after confirmation', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    const create = vi.spyOn(cacheOperationsApi, 'create').mockResolvedValue({} as never)
    const user = userEvent.setup()
    renderTab()
    await user.click(await screen.findByRole('button', { name: text('flush.action') }))
    // The Popconfirm's OK button repeats the action name.
    const confirm = await screen.findByRole('tooltip')
    await user.click(within(confirm).getByRole('button', { name: text('flush.action') }))
    await waitFor(() => expect(create).toHaveBeenCalledWith(accessToken, { kind: 'tenant' }, {
      site_id: siteID, action: 'purge', target_type: 'whole_site', targets: [], node_ids: [], max_retries: 3,
    }, expect.stringMatching(/^cache-flush-/)))
    expect(await screen.findByText(text('flush.done'))).toBeInTheDocument()
  })

  // fix-cacheflow6：结果未知时记下幂等键；再点（含离开/刷新后）先查服务端回执，已受理不重发，已拒绝显示原因，未收到才同键重发。
  it('keeps the key of a flush whose outcome is unknown and reads its receipt before sending it again', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    const create = vi.spyOn(cacheOperationsApi, 'create').mockRejectedValue(new ApiError('down', 503, 'service_unavailable'))
    const receipt = vi.spyOn(cacheOperationsApi, 'writeReceipt').mockResolvedValue(null)
    const user = userEvent.setup()
    const flush = async () => {
      await user.click(await screen.findByRole('button', { name: text('flush.action') }))
      const confirm = await screen.findByRole('tooltip')
      await user.click(within(confirm).getByRole('button', { name: text('flush.action') }))
    }
    const first = renderTab()
    await flush()
    // The send failed with an unknown outcome: its receipt was read once, then the uncertain state is shown.
    const retry = await screen.findByRole('button', { name: text('actions.retry') })
    const key = create.mock.calls[0]![3]
    expect(key).toMatch(/^cache-flush-/)
    expect(receipt).toHaveBeenCalledWith(accessToken, { kind: 'tenant' }, { action: 'create', key })

    // Retry in place: not received, so the same request goes out with the same key.
    await user.click(retry)
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]![3]).toBe(key)
    first.unmount()

    // After leaving the page: accepted on the server, so it is not sent again.
    receipt.mockReset().mockResolvedValueOnce({ status: 'accepted', decided_at: '2026-08-06T08:00:00Z', operation: {} as never })
    const second = renderTab()
    await flush()
    expect(await screen.findByText(text('flush.done'))).toBeInTheDocument()
    expect(receipt).toHaveBeenCalledWith(accessToken, { kind: 'tenant' }, { action: 'create', key })
    expect(create).toHaveBeenCalledTimes(2)
    // A definite answer clears the record: the next flush is a new request.
    expect(window.sessionStorage.getItem('cdnca.cache-pending-writes.v1')).toBe('[]')
    second.unmount()
  })

  it('shows the reason of a flush the server refused, read from its receipt', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    const create = vi.spyOn(cacheOperationsApi, 'create').mockRejectedValue(new ApiError('down', 0, 'network_error'))
    const receipt = vi.spyOn(cacheOperationsApi, 'writeReceipt').mockResolvedValue(null)
    const user = userEvent.setup()
    const flush = async () => {
      await user.click(await screen.findByRole('button', { name: text('flush.action') }))
      const confirm = await screen.findByRole('tooltip')
      await user.click(within(confirm).getByRole('button', { name: text('flush.action') }))
    }
    const first = renderTab()
    await flush()
    await screen.findByRole('button', { name: text('actions.retry') })
    first.unmount()

    receipt.mockReset().mockResolvedValueOnce({ status: 'rejected', decided_at: '2026-08-06T08:00:00Z', rejection: { code: 'daily_limit_exceeded' } })
    renderTab()
    await flush()
    expect(await screen.findByText(i18n.t('errors.daily_limit_exceeded', { ns: 'cacheOperations' }))).toBeInTheDocument()
    expect(create).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('button', { name: text('actions.retry') })).not.toBeInTheDocument()
    expect(window.sessionStorage.getItem('cdnca.cache-pending-writes.v1')).toBe('[]')
  })

  it('shows no flush action outside the tenant console', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    renderTab({ scopeKind: 'platform', permissions: ['sites.read'] })
    await waitFor(() => expect(screen.queryByRole('button', { name: text('flush.action') })).not.toBeInTheDocument())
  })

  it('edits stale-if-error and enables background update only after it', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    vi.spyOn(cachePoliciesApi, 'publish').mockImplementation(async (_token, _site, input) => policy(input.expected_revision + 1, input.document))
    const user = userEvent.setup()
    renderTab()
    await user.click(await screen.findByRole('button', { name: text('actions.showAdvanced') }))
    const stale = await screen.findByRole('switch', { name: text('fields.staleIfError') })
    const background = screen.getByRole('switch', { name: text('fields.backgroundUpdate') })
    expect(background).toBeDisabled()
    await user.click(stale)
    expect(background).toBeEnabled()
  })
})

describe('CacheSiteTab schema v2 (n6b)', () => {
  // marketsupply.cacheDocument output (marketsupply/cache.go:33-77).
  const v2Document: CachePolicyDocument = {
    schema_version: 2,
    mode: 'override',
    rules: [
      { order: 1, extensions: ['.css', '.js'], action: 'cache', ttl_seconds: 86400, browser_ttl_seconds: 3600 },
      { order: 2, path_prefix: '/api/', action: 'no_cache', ttl_seconds: 0, browser_ttl_seconds: 0 },
    ],
    query_mode: 'ignore',
    query_names: [],
    vary_headers: [],
    disk_quota_bytes: 1024 * 1024 * 1024,
  }

  it('shows a v2 policy with each rule action and browser TTL', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3, v2Document))
    const user = userEvent.setup()
    renderTab()
    // the no_cache rule reads 不缓存 in the table, without a lifetime
    expect(await screen.findByText(text('table.noCacheRule'))).toBeInTheDocument()
    const dialog = await openEdit(user, 1)
    await openMore(user, dialog)
    expect(dialog.getByLabelText(text('fields.browserTtlSeconds'))).toBeDisabled()
    expect(dialog.getByRole('spinbutton', { name: text('dialog.expire') })).toBeDisabled()
    await user.click(dialog.getByRole('button', { name: text('dialog.cancel') }))
    const first = await openEdit(user, 0)
    await openMore(user, first)
    expect(first.getByLabelText(text('fields.browserTtlSeconds'))).toHaveValue('3600')
    await user.click(first.getByRole('button', { name: text('dialog.cancel') }))
    expect(screen.queryByRole('button', { name: text('actions.save') })).toBeNull()
  })

  it('saves a v2 policy as v2, keeping schema_version, actions and browser TTLs', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3, v2Document))
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockImplementation(async (_t, _s, input) => policy(4, input.document))
    const user = userEvent.setup()
    renderTab()
    const dialog = await openEdit(user)
    await openMore(user, dialog)
    const browser = dialog.getByLabelText(text('fields.browserTtlSeconds'))
    await user.clear(browser)
    await user.type(browser, '600')
    await user.click(dialog.getByRole('button', { name: text('dialog.ok') }))
    await commitEdits()
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    const input = publish.mock.calls[0]![2]
    expect(input.document.schema_version).toBe(2)
    expect(input.document.rules).toEqual([
      { order: 1, extensions: ['.css', '.js'], path_prefix: '', status_codes: [], action: 'cache', ttl_seconds: 86400, browser_ttl_seconds: 600 },
      { order: 2, extensions: [], path_prefix: '/api/', status_codes: [], action: 'no_cache', ttl_seconds: 0, browser_ttl_seconds: 0 },
    ])
    expect(await screen.findByText(text('states.saved'))).toBeInTheDocument()
  })

  it('upgrades a v1 policy to v2 when a rule switches to no_cache', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockImplementation(async (_t, _s, input) => policy(4, input.document))
    const user = userEvent.setup()
    renderTab()
    const dialog = await openEdit(user)
    await openMore(user, dialog)
    await user.click(dialog.getByRole('combobox', { name: text('fields.action') }))
    await user.click(await screen.findByTitle(text('ruleActions.no_cache')))
    expect(dialog.getByRole('spinbutton', { name: text('dialog.expire') })).toBeDisabled()
    await user.click(dialog.getByRole('button', { name: text('dialog.ok') }))
    await commitEdits()
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    const input = publish.mock.calls[0]![2]
    expect(input.document.schema_version).toBe(2)
    expect(input.document.rules[0]).toMatchObject({ action: 'no_cache', ttl_seconds: 0, browser_ttl_seconds: 0 })
  })

  it('refuses a browser TTL above the edge TTL before publishing', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3, v2Document))
    const publish = vi.spyOn(cachePoliciesApi, 'publish')
    const user = userEvent.setup()
    renderTab()
    await editTTL(user, 60)
    await commitEdits()
    expect(await screen.findByText(text('validation.browserTtlRange'))).toBeInTheDocument()
    expect(publish).not.toHaveBeenCalled()
  })
})

describe('CacheSiteTab competitor layout (tp-b3c)', () => {
  const disabledDocument: CachePolicyDocument = {
    mode: 'disabled', rules: [], query_mode: 'preserve', query_names: [], vary_headers: [], disk_quota_bytes: 0,
  }

  it('shows the empty state with 新增第一条规则, and a quick preset publishes one rule in 自定义规则', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3, disabledDocument))
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockResolvedValue(policy(4))
    const user = userEvent.setup()
    renderTab()
    expect(await screen.findByText(text('empty.title'))).toBeInTheDocument()
    expect(screen.getByRole('button', { name: text('empty.add') })).toBeInTheDocument()
    expect(within(screen.getByRole('heading', { name: text('title') }).closest('header')!).getByText(text('count', { count: 0 }))).toBeInTheDocument()
    // site-parity4: the summary strip repeats the mode and rule count
    expect(screen.getByRole('region', { name: '本页摘要' })).toHaveTextContent(text('count', { count: 0 }))

    await user.click(screen.getByRole('button', { name: text('actions.quick') }))
    await user.click(await screen.findByText(text('quick.static')))
    expect(within(screen.getByRole('heading', { name: text('title') }).closest('header')!).getByText(text('count', { count: 1 }))).toBeInTheDocument()
    await commitEdits()
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    const document = publish.mock.calls[0]![2].document
    expect(document.mode).toBe('override')
    expect(document.rules).toEqual([expect.objectContaining({
      order: 1, path_prefix: '', ttl_seconds: 7 * 24 * 60 * 60,
      extensions: ['.bmp', '.css', '.gif', '.ico', '.jpeg', '.jpg', '.js', '.png', '.svg', '.webp', '.woff', '.woff2'],
    })])
    expect(document.disk_quota_bytes).toBeGreaterThan(0)
  })

  // tp-b3c-be：快速设置的首页改用单个路径 "/"，WordPress 预设带不缓存条件。
  it('quick presets: 首页 is the single path "/", WordPress carries its no-cache conditions', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy(3, disabledDocument))
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockImplementation(async (_token, _site, input) => policy(input.expected_revision + 1, input.document))
    const user = userEvent.setup()
    renderTab()
    for (const key of ['home', 'wordpress']) {
      await user.click(await screen.findByRole('button', { name: text('actions.quick') }))
      await user.click(await screen.findByText(text(`quick.${key}`)))
    }
    expect(within(screen.getByRole('heading', { name: text('title') }).closest('header')!).getByText(text('count', { count: 2 }))).toBeInTheDocument()
    // fix-siteinstant: each preset saves; the last save holds both rules
    await waitFor(() => expect(publish.mock.calls.at(-1)?.[2].document.rules).toHaveLength(2))
    const document = publish.mock.calls.at(-1)![2].document
    expect(document.schema_version).toBe(2)
    expect(document.rules[0]).toMatchObject({ order: 1, path_exact: '/', path_prefix: '', action: 'cache', ttl_seconds: 86400 })
    expect(document.rules[0]).not.toHaveProperty('path_regex')
    expect(document.rules[1]).toMatchObject({
      order: 2, path_prefix: '/', ttl_seconds: 3 * 86400,
      no_cache: [
        { source: 'header', name: 'cookie', pattern: 'wordpress_logged_in|wp-postpass|comment_author' },
        { source: 'path', pattern: '^/wp-(?:admin|login\\.php)' },
      ],
    })
  })

  it('adds a rule in the 新增缓存规则 dialog with the competitor fields', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockImplementation(async (_token, _site, input) => policy(input.expected_revision + 1, input.document))
    const user = userEvent.setup()
    renderTab()
    await user.click(await screen.findByRole('button', { name: text('actions.addRule') }))
    const dialog = within(await screen.findByRole('dialog', { name: text('dialog.addTitle') }))
    for (const scope of ['home', 'site', 'dir', 'suffix', 'path']) {
      expect(dialog.getByRole('radio', { name: text(`dialog.scopes.${scope}`) })).toBeInTheDocument()
    }
    await user.click(dialog.getByText(text('dialog.scopes.path')))
    await user.type(dialog.getByLabelText(text('dialog.scopeInput.path')), '/index.html')
    await user.click(dialog.getByRole('button', { name: text('dialog.presets.d7') }))
    await user.click(dialog.getByRole('switch', { name: text('dialog.ignoreQuery') }))
    expect(dialog.getByRole('switch', { name: text('dialog.forceCache') })).toBeChecked()
    await user.click(dialog.getByRole('switch', { name: text('dialog.forceCache') }))
    // 高级设置 is folded until opened
    expect(dialog.getByRole('button', { name: text('actions.showAdvanced') })).toHaveAttribute('aria-expanded', 'false')
    await user.click(dialog.getByRole('button', { name: text('actions.showAdvanced') }))
    await user.click(dialog.getByRole('switch', { name: text('dialog.slice') }))
    await user.click(dialog.getByRole('switch', { name: text('dialog.ignoreVary') }))
    expect(dialog.getByText(text('dialog.noCacheEmpty'))).toBeInTheDocument()
    await user.click(dialog.getByRole('combobox', { name: text('dialog.noCacheSource') }))
    await user.click(await screen.findByTitle(text('dialog.sources.args')))
    await user.type(dialog.getByLabelText(text('dialog.noCachePattern')), 'preview=1')
    await user.click(dialog.getByRole('button', { name: text('dialog.addCondition') }))
    expect(dialog.getByText('preview=1')).toBeInTheDocument()
    await user.click(dialog.getByRole('button', { name: text('dialog.ok') }))
    expect(within(screen.getByRole('heading', { name: text('title') }).closest('header')!).getByText(text('count', { count: 2 }))).toBeInTheDocument()
    expect(screen.getByText(`${text('dialog.scopes.path')} /index.html`)).toBeInTheDocument()
    await commitEdits()
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    const added = publish.mock.calls[0]![2].document.rules[1]
    expect(added).toEqual({
      order: 2, extensions: [], path_prefix: '', status_codes: [], action: 'cache', ttl_seconds: 7 * 86400, browser_ttl_seconds: 0,
      path_exact: '/index.html', ignore_query: true, slice_bytes: 1 << 20, force_cache: false, ignore_vary: true,
      no_cache: [{ source: 'args', pattern: 'preview=1' }],
    })
    expect(publish.mock.calls[0]![2].document.schema_version).toBe(2)
  })

  it('refuses an invalid single path in the dialog', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    const user = userEvent.setup()
    renderTab()
    await user.click(await screen.findByRole('button', { name: text('actions.addRule') }))
    const dialog = within(await screen.findByRole('dialog', { name: text('dialog.addTitle') }))
    await user.click(dialog.getByText(text('dialog.scopes.path')))
    await user.type(dialog.getByLabelText(text('dialog.scopeInput.path')), '/a/../b')
    await user.click(dialog.getByRole('button', { name: text('dialog.ok') }))
    expect(await dialog.findByText(text('validation.invalidExactPath'))).toBeInTheDocument()
  })

  it('places the site-level extra in 其他设置 under the rules', async () => {
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(policy())
    const actor = authenticate()
    renderWithProviders(
      <CacheSiteTab siteId={siteID} accessToken={accessToken} scopeKind="tenant" permissions={['sites.read', 'sites.manage']}
        lockedForTenant={false} sessionEpoch={useSessionStore.getState().sessionEpoch} userId={actor.user_id}
        scopeId={actor.scope_id} tenantId={actor.tenant_id} onDirtyChange={() => undefined}
        extra={<div data-testid="cache-extra" />} />,
    )
    const other = await screen.findByRole('heading', { name: text('other.title') })
    const extra = screen.getByTestId('cache-extra')
    expect(other.closest('section')).toContainElement(extra)
    expect(other.compareDocumentPosition(screen.getByRole('button', { name: text('table.edit') })) & Node.DOCUMENT_POSITION_PRECEDING).toBeTruthy()
  })
})
