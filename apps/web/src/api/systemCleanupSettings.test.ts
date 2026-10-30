import { systemCleanupSettingsApi, type PlatformSystemCleanupDocument } from './systemCleanupSettings'

const document: PlatformSystemCleanupDocument = {
  schema: 'cdnca.platform-system-cleanup-settings/v1', revision: 2,
  value: {
    cleanup_cache_days: 30, audit_retention_days: { admin: 365, user: 180, auth: 90, site: 180, security: 180, rule: 180, finance: 1095, package: 365, plugin: 180, node: 90, dns: 180, cert: 180, system: 365, other: 180 }, access_logs_days: 7,
    node_metrics_days: 7, bandwidth_history_days: 90, blacklist_history_days: 7, node_traffic_history_days: 45,
  },
}

describe('systemCleanupSettingsApi', () => {
  it('reads a strict cleanup document', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(document), { status: 200 }))
    await expect(systemCleanupSettingsApi.get('token')).resolves.toEqual(document)
    expect(fetchSpy).toHaveBeenCalledWith(expect.stringContaining('/v1/admin/system-cleanup-settings'), expect.objectContaining({ credentials: 'include' }))
  })

  it('writes CAS and idempotency headers', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...document, revision: 3 }), { status: 200 }))
    await systemCleanupSettingsApi.put('token', 2, document.value)
    const [, init] = fetchSpy.mock.calls[0]
    const headers = new Headers(init?.headers)
    expect(init?.method).toBe('PUT')
    expect(headers.get('If-Match')).toBe('"2"')
    expect(headers.get('Idempotency-Key')).toMatch(/^system-cleanup-settings-/)
    expect(JSON.parse(String(init?.body))).toEqual({ value: document.value })
  })

  it('rejects extra response fields and values outside the API contract', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ ...document, extra: true }), { status: 200 }))
    await expect(systemCleanupSettingsApi.get('token')).rejects.toMatchObject({ code: 'invalid_response' })
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ ...document, value: { ...document.value, audit_retention_days: { ...document.value.audit_retention_days, auth: -1 } } }), { status: 200 }))
    await expect(systemCleanupSettingsApi.get('token')).rejects.toMatchObject({ code: 'invalid_response' })
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ ...document, value: { ...document.value, audit_retention_days: { ...document.value.audit_retention_days, bogus: 1 } } }), { status: 200 }))
    await expect(systemCleanupSettingsApi.get('token')).rejects.toMatchObject({ code: 'invalid_response' })
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ ...document, value: { ...document.value, login_records_days: 30 } }), { status: 200 }))
    await expect(systemCleanupSettingsApi.get('token')).rejects.toMatchObject({ code: 'invalid_response' })
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ ...document, value: { ...document.value, backup_directory: '/data/backup/cdn/' } }), { status: 200 }))
    await expect(systemCleanupSettingsApi.get('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
