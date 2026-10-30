import { systemSettingsApi, validGlobalJSReportHosts, type PlatformSystemSettingsDocument } from './systemSettings'

const document: PlatformSystemSettingsDocument = {
  schema: 'cdnca.platform-system-settings/v1', revision: 2,
  value: {
    system_name: 'CDNCA', user_title: '用户', admin_title: '管理员', footer_links: '', footer_text: '', global_js: '', bound_domains: '',
    favicon: 'asset://favicon-v1', logo: 'asset://logo-v1', login_ad: 'asset://login-ad-v1',
    expiry_close: false, traffic_close: false, allow_upgrade: true, allow_downgrade: false, maintenance: false,
    maintenance_message: '维护中', auto_upgrade_node: false, certificate: 'vault://certificates/platform', private_key: 'kms-envelope://keys/platform',
  },
}

describe('systemSettingsApi', () => {
  it('accepts global JS report hosts only as plain unique hostnames (at most 20)', async () => {
    expect(validGlobalJSReportHosts(['hm.baidu.com', 'stats.example.com'])).toBe(true)
    for (const host of ['https://hm.baidu.com', 'hm.baidu.com:443', '*.baidu.com', '192.0.2.1', 'localhost', 'HM.baidu.com', 'a.com/x']) {
      expect(validGlobalJSReportHosts([host])).toBe(false)
    }
    expect(validGlobalJSReportHosts(['a.example.com', 'a.example.com'])).toBe(false)
    expect(validGlobalJSReportHosts(Array.from({ length: 21 }, (_, index) => `h${index}.example.com`))).toBe(false)
    const withHosts = { ...document, value: { ...document.value, global_js_report_hosts: ['hm.baidu.com'] } }
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify(withHosts), { status: 200 }))
    await expect(systemSettingsApi.get('token')).resolves.toEqual(withHosts)
    const bad = { ...document, value: { ...document.value, global_js_report_hosts: ["a.com; script-src 'unsafe-inline'"] } }
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify(bad), { status: 200 }))
    await expect(systemSettingsApi.get('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('reads a strict document with the platform route', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(document), { status: 200 }))
    await expect(systemSettingsApi.get('token')).resolves.toEqual(document)
    expect(fetchSpy).toHaveBeenCalledWith(expect.stringContaining('/v1/admin/system-settings'), expect.objectContaining({ credentials: 'include' }))
  })

  it('writes CAS and idempotency headers', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...document, revision: 3 }), { status: 200 }))
    await systemSettingsApi.put('token', 2, document.value)
    const [, init] = fetchSpy.mock.calls[0]
    const headers = new Headers(init?.headers)
    expect(init?.method).toBe('PUT')
    expect(headers.get('If-Match')).toBe('"2"')
    expect(headers.get('Idempotency-Key')).toMatch(/^system-settings-/)
    expect(JSON.parse(String(init?.body))).toEqual({ value: document.value })
  })

  it('rejects extra response fields', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ...document, extra: true }), { status: 200 }))
    await expect(systemSettingsApi.get('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts the signed-in public subset with the branding fields', async () => {
    const body = { system_name: '云盾', user_title: '用户', admin_title: '管理', purchase_notice: '<p>x</p>', global_js: '' }
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify(body), { status: 200 }))
    await expect(systemSettingsApi.public('token')).resolves.toEqual(body)
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ ...body, bound_domains: 'a' }), { status: 200 }))
    await expect(systemSettingsApi.public('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
