import { systemOtherSettingsApi } from './systemOtherSettings'

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

describe('systemOtherSettingsApi', () => {
  it('backfills newly added fields from a legacy successful response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      schema: 'cdnca.platform-system-other-settings/v1',
      revision: 0,
      value: {
        source_ip_header: 'X-Real-IP',
        dns_protection: true,
        sync_batch: 1000,
        resource_rank: 100,
        http_proxy: '',
        tcp_factor: 1.1,
      },
    }))
    await expect(systemOtherSettingsApi.get('token')).resolves.toMatchObject({
      value: { api_key_enabled: true, record_repair_mode: 'repair', sync_scope: 'line_group', disable_failed_sync_nodes: false, l4_drain_max_seconds: 86400, domain_ownership_policy: 'wildcard_only' },
    })
  })

  it('converts the legacy boolean DNS protection field to the observed hostname input', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      schema: 'cdnca.platform-system-other-settings/v1',
      revision: 0,
      value: { source_ip_header: 'X-Real-IP', api_key_enabled: false, dns_protection: true, record_repair_mode: 'repair', sync_batch: 1000, sync_scope: 'line_group', disable_failed_sync_nodes: false, resource_rank: 100, http_proxy: '', tcp_factor: 1.1 },
    }))
    await expect(systemOtherSettingsApi.get('token')).resolves.toMatchObject({ value: { api_key_enabled: false, dns_protection: '' } })
  })

  it('accepts the L4 drain limit and rejects one beyond seven days', async () => {
    const value = { source_ip_header: 'X-Real-IP', api_key_enabled: true, dns_protection: '', record_repair_mode: 'repair', sync_batch: 1000, sync_scope: 'line_group', disable_failed_sync_nodes: false, resource_rank: 100, http_proxy: '', tcp_factor: 1.1 }
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ schema: 'cdnca.platform-system-other-settings/v1', revision: 1, value: { ...value, l4_drain_max_seconds: 0 } }))
    await expect(systemOtherSettingsApi.get('token')).resolves.toMatchObject({ value: { l4_drain_max_seconds: 0 } })
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ schema: 'cdnca.platform-system-other-settings/v1', revision: 1, value: { ...value, l4_drain_max_seconds: 604801 } }))
    await expect(systemOtherSettingsApi.get('token')).rejects.toMatchObject({ code: 'system_other_settings_invalid_response' })
  })

  // ui-leftover3 #1：后端 DefaultSettings 自 ri-08 起恒带 rule_intel_contribution，
  // 旧前端的 exact() 只认 13 个键，整页显示「其它配置暂时不可用」。
  it('accepts the current control-api document that carries rule_intel_contribution', async () => {
    const current = { source_ip_header: 'X-Real-IP', api_key_enabled: true, dns_protection: '', record_repair_mode: 'repair', sync_batch: 1000, sync_scope: 'line_group', disable_failed_sync_nodes: false, resource_rank: 100, http_proxy: '', tcp_factor: 1.1, l4_drain_max_seconds: 86400, domain_ownership_policy: 'wildcard_only', certificate_expiry_notice_days: [30, 14, 7, 3, 1], rule_intel_contribution: false }
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ schema: 'cdnca.platform-system-other-settings/v1', revision: 0, value: current }))
    await expect(systemOtherSettingsApi.get('token')).resolves.toMatchObject({ value: { rule_intel_contribution: false } })
    const legacy: Partial<typeof current> = { ...current }
    delete legacy.rule_intel_contribution
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ schema: 'cdnca.platform-system-other-settings/v1', revision: 0, value: legacy }))
    await expect(systemOtherSettingsApi.get('token')).resolves.toMatchObject({ value: { rule_intel_contribution: true } })
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ schema: 'cdnca.platform-system-other-settings/v1', revision: 0, value: { ...current, rule_intel_contribution: 'yes' } }))
    await expect(systemOtherSettingsApi.get('token')).rejects.toMatchObject({ code: 'system_other_settings_invalid_response' })
  })

  it('accepts the three domain ownership policies and rejects others', async () => {
    const value = { source_ip_header: 'X-Real-IP', api_key_enabled: true, dns_protection: '', record_repair_mode: 'repair', sync_batch: 1000, sync_scope: 'line_group', disable_failed_sync_nodes: false, resource_rank: 100, http_proxy: '', tcp_factor: 1.1, l4_drain_max_seconds: 86400 }
    for (const policy of ['off', 'wildcard_only', 'all']) {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ schema: 'cdnca.platform-system-other-settings/v1', revision: 1, value: { ...value, domain_ownership_policy: policy } }))
      await expect(systemOtherSettingsApi.get('token')).resolves.toMatchObject({ value: { domain_ownership_policy: policy } })
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ schema: 'cdnca.platform-system-other-settings/v1', revision: 1, value: { ...value, domain_ownership_policy: 'strict' } }))
    await expect(systemOtherSettingsApi.get('token')).rejects.toMatchObject({ code: 'system_other_settings_invalid_response' })
  })
})
