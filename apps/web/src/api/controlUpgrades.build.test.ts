import { afterEach, describe, expect, it, vi } from 'vitest'

import { controlUpgradesApi } from './controlUpgrades'

function status(build: unknown) {
  return {
    data: {
      schema: 'cdnca.maintenance-upgrade-status/v1', observed_at: '2026-10-08T01:00:00Z',
      control: {
        component: 'control-api', current_version: '2026.10.8', configured_version_matches: false, build,
        authorization: { state: 'unavailable', reason: 'entitlement_unavailable' },
        candidate: { state: 'unavailable', reason: 'entitlement_unavailable', version: null, expires_at: null },
        runtime: { ready: false, reason: 'control_upgrade_plan_writer_unconfigured' },
      },
      nodes: [],
    },
  }
}

const build = {
  source_commit: 'a'.repeat(40), source_tree: 'b'.repeat(40),
  built_at: '2026-10-08T01:02:03Z', binary_sha256: 'c'.repeat(64),
}

afterEach(() => vi.restoreAllMocks())

describe('maintenance build provenance', () => {
  it('accepts full authoritative metadata without using configured version', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(status(build)), { status: 200 }))
    const result = await controlUpgradesApi.maintenanceStatus('token')
    expect(result.control.current_version).toBe('2026.10.8')
    expect(result.control.build).toEqual(build)
  })

  it('preserves unavailable provenance as null', async () => {
    const missing = { source_commit: null, source_tree: null, built_at: null, binary_sha256: null }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(status(missing)), { status: 200 }))
    expect((await controlUpgradesApi.maintenanceStatus('token')).control.build).toEqual(missing)
  })

  it.each([
    { ...build, source_commit: 'main' }, { ...build, source_tree: 'B'.repeat(40) },
    { ...build, built_at: 'yesterday' }, { ...build, binary_sha256: 'sha256:1234' },
    { ...build, token: 'must-not-reach-browser' },
  ])('rejects malformed or extra build fields', async (invalid) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(status(invalid)), { status: 200 }))
    await expect(controlUpgradesApi.maintenanceStatus('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
