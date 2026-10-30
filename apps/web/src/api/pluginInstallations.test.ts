import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from './auth'
import {
  newPluginInstallationIdempotencyKey,
  platformPluginInstallationsApi,
  pluginInstallationsApi,
  type PluginInstallation,
} from './pluginInstallations'

const scopeID = '018cc251-f400-7def-8000-000000000020'
const authorizationID = '018cc251-f400-7def-8000-000000000021'
const installationID = '018cc251-f400-7def-8000-000000000022'
const verificationID = '018cc251-f400-7def-8000-000000000023'

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function installation(overrides: Partial<PluginInstallation> = {}): PluginInstallation {
  return {
    schema: 'cdnca.control.plugin-installation/v1',
    tenant_scope_id: scopeID,
    authorization_id: authorizationID,
    installation_id: installationID,
    verification_id: verificationID,
    plugin_id: 'acme.cache',
    version: '1.2.3',
    resource_scope: 'tenant',
    entrypoint_type: 'external_https',
    manifest_sha256: 'a'.repeat(64),
    configuration_schema_sha256: 'b'.repeat(64),
    manifest_scopes: ['cache.purge', 'sites.read'],
    approved_scopes: ['cache.purge', 'sites.read'],
    sensitive_scopes: ['cache.purge'],
    new_scopes: [],
    status: 'enabled',
    revision: 4,
    identity_generation: 2,
    lkg_verification_id: verificationID,
    lkg_version: '1.2.3',
    stable_reason_code: null,
    updated_at: '2026-08-08T08:00:00Z',
    ...overrides,
  }
}

describe('pluginInstallationsApi', () => {
  beforeEach(() => vi.restoreAllMocks())

  // 报告 A：平台主题由主控平台管理员在 /v1/platform 确认；两条通道各自只接受自己作用域的数据。
  it('keeps platform and tenant resource scopes on their own routes', async () => {
    const platformScope = '018cc251-f400-7def-8000-000000000030'
    const theme = installation({ tenant_scope_id: platformScope, resource_scope: 'platform', entrypoint_type: 'theme', plugin_id: 'acme.audit-theme',
      status: 'pending_confirmation' })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ items: [theme] }))
    const page = await platformPluginInstallationsApi.list('token', '')
    expect(page.items[0]?.resource_scope).toBe('platform')
    expect(String(fetchSpy.mock.calls[0]?.[0])).toBe('/v1/platform/plugin-installations')

    fetchSpy.mockResolvedValueOnce(response({ installation: { ...theme, status: 'enabled' } }))
    await platformPluginInstallationsApi.confirm('token', '', authorizationID, 1, {
      verification_id: verificationID, approved_scopes: ['cache.purge', 'sites.read'],
      sensitive_permissions_confirmed: true, new_permissions_confirmed: true,
    }, 'platform-confirm-key')
    expect(String(fetchSpy.mock.calls[1]?.[0])).toBe(`/v1/platform/plugin-installations/${authorizationID}/confirm`)
    expect(new Headers(fetchSpy.mock.calls[1]?.[1]?.headers).get('If-Match')).toBe('"1"')

    // A tenant list never accepts a platform row, and the platform list never a tenant row.
    fetchSpy.mockResolvedValueOnce(response({ items: [{ ...theme, tenant_scope_id: scopeID }] }))
    await expect(pluginInstallationsApi.list('token', scopeID)).rejects.toMatchObject({ code: 'invalid_response' })
    fetchSpy.mockResolvedValueOnce(response({ items: [installation()] }))
    await expect(platformPluginInstallationsApi.list('token', '')).rejects.toMatchObject({ code: 'invalid_response' })
    fetchSpy.mockResolvedValueOnce(response({ items: [{ ...installation(), resource_scope: undefined }] }))
    await expect(pluginInstallationsApi.list('token', scopeID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  // fix-plugconfirm3：插件类型来自授权端签名，缺失、未知或与作用域不符的行一律拒收。
  it('requires a signed plugin type that agrees with the resource scope', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    for (const entrypoint of [undefined, 'wasm', 'theme', 'rule_pack']) {
      fetchSpy.mockResolvedValueOnce(response({ items: [{ ...installation(), entrypoint_type: entrypoint }] }))
      await expect(pluginInstallationsApi.list('token', scopeID)).rejects.toMatchObject({ code: 'invalid_response' })
    }
    fetchSpy.mockResolvedValueOnce(response({ items: [installation({ entrypoint_type: 'ui_page' })] }))
    expect((await pluginInstallationsApi.list('token', scopeID)).items[0]?.entrypoint_type).toBe('ui_page')
  })

  it('uses the tenant-scoped list contract and rejects cross-tenant or extra response fields', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({
      items: [installation()], next_cursor: 'next-page',
    }))
    const page = await pluginInstallationsApi.list('token', scopeID, {
      limit: 20, cursor: 'cursor-1', status: 'enabled', plugin_id: 'acme.cache',
    })
    expect(page.items[0]?.authorization_id).toBe(authorizationID)
    expect(String(fetchSpy.mock.calls[0]?.[0])).toBe(
      `/v1/tenant-scopes/${scopeID}/plugin-installations?limit=20&cursor=cursor-1&status=enabled&plugin_id=acme.cache`,
    )
    expect(fetchSpy.mock.calls[0]?.[1]).toMatchObject({ credentials: 'include' })
    const listHeaders = new Headers(fetchSpy.mock.calls[0]?.[1]?.headers)
    expect(listHeaders.get('Authorization')).toBe('Bearer token')
    expect(listHeaders.get('X-Request-ID')).toMatch(/^plugin-installation-list-[A-Za-z0-9]+$/)

    fetchSpy.mockResolvedValueOnce(response({ items: [installation({ tenant_scope_id: installationID })] }))
    await expect(pluginInstallationsApi.list('token', scopeID)).rejects.toMatchObject({ code: 'invalid_response', status: 502 })
    fetchSpy.mockResolvedValueOnce(response({ items: [{ ...installation(), proof: 'secret' }] }))
    await expect(pluginInstallationsApi.list('token', scopeID)).rejects.toMatchObject({ code: 'invalid_response', status: 502 })
    // A purchased market plugin waiting for this controller's administrator (license migration 076).
    fetchSpy.mockResolvedValueOnce(response({ items: [{ ...installation(), authorization_status: 'pending_confirmation' }] }))
    expect((await pluginInstallationsApi.list('token', scopeID)).items[0]?.authorization_status).toBe('pending_confirmation')
    fetchSpy.mockResolvedValueOnce(response({ items: [{ ...installation(), authorization_status: 'purchased' }] }))
    await expect(pluginInstallationsApi.list('token', scopeID)).rejects.toMatchObject({ code: 'invalid_response', status: 502 })
  })

  it('sends exact confirmation and protective lifecycle requests with CAS and idempotency', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => response({ installation: installation() }))
    await pluginInstallationsApi.confirm('token', scopeID, authorizationID, 3, {
      verification_id: verificationID,
      approved_scopes: ['cache.purge', 'sites.read'],
      sensitive_permissions_confirmed: true,
      new_permissions_confirmed: false,
    }, 'plugin-install-confirm-1')
    const confirm = fetchSpy.mock.calls[0]!
    expect(String(confirm[0])).toBe(`/v1/tenant-scopes/${scopeID}/plugin-installations/${authorizationID}/confirm`)
    expect(confirm[1]?.method).toBe('POST')
    expect(confirm[1]?.body).toBe(JSON.stringify({
      verification_id: verificationID,
      approved_scopes: ['cache.purge', 'sites.read'],
      sensitive_permissions_confirmed: true,
      new_permissions_confirmed: false,
    }))
    expect(confirm[1]?.headers).toMatchObject({ 'Idempotency-Key': 'plugin-install-confirm-1', 'If-Match': '"3"' })
    expect(new Headers(confirm[1]?.headers).get('X-Request-ID')).toBe('plugin-install-confirm-1')

    await pluginInstallationsApi.disable('token', scopeID, authorizationID, 4, { reason: '不再使用' }, 'plugin-install-disable-1')
    expect(fetchSpy.mock.calls[1]?.[1]?.body).toBe('{"reason":"不再使用"}')
    expect(new Headers(fetchSpy.mock.calls[1]?.[1]?.headers).get('X-Request-ID')).toBe('plugin-install-disable-1')
  })

  // 报告 B：恢复使用是独立动作，体为 {}，带 If-Match 与幂等键；暂停归属只认三种取值。
  it('sends an exact resume request and parses who paused the plugin', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => response({ installation: installation() }))
    await pluginInstallationsApi.resume('token', scopeID, authorizationID, 5, 'plugin-install-resume-1')
    const resume = fetchSpy.mock.calls[0]!
    expect(String(resume[0])).toBe(`/v1/tenant-scopes/${scopeID}/plugin-installations/${authorizationID}/resume`)
    expect(resume[1]?.method).toBe('POST')
    expect(resume[1]?.body).toBe('{}')
    expect(resume[1]?.headers).toMatchObject({ 'Idempotency-Key': 'plugin-install-resume-1', 'If-Match': '"5"' })

    fetchSpy.mockResolvedValueOnce(response({ items: [{ ...installation(), status: 'disabled', authorization_status: 'disabled',
      paused_by: 'operator', paused_reason: '合规复核' }] }))
    const paused = (await pluginInstallationsApi.list('token', scopeID)).items[0]
    expect(paused?.paused_by).toBe('operator')
    expect(paused?.paused_reason).toBe('合规复核')
    fetchSpy.mockResolvedValueOnce(response({ items: [{ ...installation(), paused_by: 'tenant' }] }))
    await expect(pluginInstallationsApi.list('token', scopeID)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('sends exact upgrade and uninstall requests with stable CAS and idempotency headers', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => response({ installation: installation() }))
    const approval = {
      verification_id: verificationID,
      approved_scopes: ['cache.purge', 'sites.read'],
      sensitive_permissions_confirmed: true,
      new_permissions_confirmed: true,
    }

    await pluginInstallationsApi.upgrade(
      'token', scopeID, authorizationID, 7, approval, 'plugin-installation-upgrade-1',
    )
    expect(String(fetchSpy.mock.calls[0]?.[0])).toBe(
      `/v1/tenant-scopes/${scopeID}/plugin-installations/${authorizationID}/upgrade`,
    )
    expect(fetchSpy.mock.calls[0]?.[1]).toMatchObject({
      method: 'POST', body: JSON.stringify(approval),
      headers: { 'If-Match': '"7"', 'Idempotency-Key': 'plugin-installation-upgrade-1' },
    })

    await pluginInstallationsApi.uninstall(
      'token', scopeID, authorizationID, 8, { reason: 'retire plugin' }, 'plugin-installation-uninstall-1',
    )
    expect(String(fetchSpy.mock.calls[1]?.[0])).toBe(
      `/v1/tenant-scopes/${scopeID}/plugin-installations/${authorizationID}/uninstall`,
    )
    expect(fetchSpy.mock.calls[1]?.[1]).toMatchObject({
      method: 'POST', body: '{"reason":"retire plugin"}',
      headers: { 'If-Match': '"8"', 'Idempotency-Key': 'plugin-installation-uninstall-1' },
    })
  })

  it('rejects malformed identities, revisions, keys, scope sets and reasons before fetch', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(pluginInstallationsApi.get('token', 'NOT-A-UUID', authorizationID)).rejects.toMatchObject({ code: 'invalid_request' })
    await expect(pluginInstallationsApi.confirm('token', scopeID, authorizationID, 0, {
      verification_id: verificationID,
      approved_scopes: ['sites.read', 'cache.purge'],
      sensitive_permissions_confirmed: true,
      new_permissions_confirmed: true,
    }, 'bad key')).rejects.toMatchObject({ code: 'invalid_request' })
    await expect(pluginInstallationsApi.uninstall('token', scopeID, authorizationID, 1, { reason: ' ' }, 'plugin-uninstall-1'))
      .rejects.toMatchObject({ code: 'invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('retains stable server error codes without exposing raw messages', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({
      error: { code: 'plugin_installation_scope_approval_required', message: 'database detail', request_id: 'req-1' },
    }, 422))
    const error = await pluginInstallationsApi.get('token', scopeID, authorizationID).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ code: 'plugin_installation_scope_approval_required', status: 422, requestId: 'req-1' })
    expect((error as Error).message).not.toContain('database detail')
  })

  it('creates bounded non-secret idempotency keys', () => {
    const key = newPluginInstallationIdempotencyKey('upgrade')
    expect(key).toMatch(/^plugin-installation-upgrade-[A-Za-z0-9]+$/)
    expect(key.length).toBeLessThanOrEqual(128)
  })
})
