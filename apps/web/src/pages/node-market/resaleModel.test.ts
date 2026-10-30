import { describe, expect, it } from 'vitest'

import type { MarketFrozenTerms } from '../../api/market'
import { defaultValues } from './listingModel'
import { defaultRows } from './limitsModel'
import {
  ccOptions, comboOfferOf, comboPlugins, comboTotals, maxIn, overUpstream, pluginLabel, resaleOfferOf, rowsFromUpstream, valuesFromUpstream,
} from './resaleModel'

// C16: a resale starts at the upstream's frozen terms and may only tighten them.
const up: MarketFrozenTerms = {
  name: 'Up', billing_model: 'daily_bundle', allocation: { http_ports: 4, stream_ports: 1, websocket: true, http3: false },
  limits: [{ metric: 'domains', cap: 10, action: 'reject_new' }, { metric: 'bandwidth_peak_bps', cap: 2e9, action: 'pause', sustain_buckets: 2 },
    { metric: 'monthly_traffic_bytes', cap: 1536 * 1024 ** 3, action: 'throttle', throttle_bps: 5e6 }],
  tags: { cc_protection: 'basic', ddos_protection_gbps: 20, complaint_resistant: false, tenancy: 'shared', mobile_reachable: true,
    region_block: false, line_class: 'BGP', plugins: ['module.autodefense'] },
  compliance: { require_icp: true }, prepaid_exhausted_action: 'stop',
}

describe('resale model', () => {
  it('starts the rows at the upstream caps in a unit that keeps the cap exact', () => {
    const rows = rowsFromUpstream(up)
    const get = (m: string) => rows.find((r) => r.metric === m)!
    expect(get('domains')).toMatchObject({ enabled: true, value: 10, unit: 'count', action: 'reject_new' })
    expect(get('bandwidth_peak_bps')).toMatchObject({ enabled: true, value: 2, unit: 'Gbps', action: 'pause' })
    // 1.5 TB is not a whole TB: GB keeps it exact.
    expect(get('monthly_traffic_bytes')).toMatchObject({ value: 1536, unit: 'GB', action: 'throttle', throttleMbps: 5 })
    expect(get('qps').enabled).toBe(false)
    expect(maxIn(get('bandwidth_peak_bps'), up, null)).toBe(2)
    expect(maxIn({ ...get('bandwidth_peak_bps'), unit: 'Mbps' }, up, null)).toBe(2000)
    expect(maxIn(get('qps'), up, null)).toBeUndefined()
    expect(maxIn(get('node_cpu_percent'), up, { cpu_percent: 80, memory_percent: 70 })).toBe(80)
  })

  it('flags caps above the upstream before submit', () => {
    const rows = rowsFromUpstream(up).map((r) => (r.metric === 'domains' ? { ...r, value: 11 } : r.metric === 'qps' ? { ...r, enabled: true, value: 1e6 } : r))
    expect(overUpstream(rows, up)).toEqual(['domains'])
  })

  it('offers only CC levels up to the upstream', () => {
    expect(ccOptions(up)).toEqual(['none', 'basic'])
  })

  it('bounds every term by the upstream even when the form holds looser values', () => {
    const v = { ...defaultValues, ...valuesFromUpstream(up), name: ' R ', price: 7 }
    const body = resaleOfferOf({ ...v, httpPorts: 9, streamPorts: 3, http3: true, cc: 'advanced', ddos: 99, complaint: true, tenancy: 'dedicated',
      regionBlock: true, lineClass: 'CN2', icp: false, plugins: ['module.autodefense', 'pack.crs'] }, rowsFromUpstream(up), null, 'sub-1', up)
    expect(body.allocation).toEqual({ http_ports: 4, stream_ports: 1, websocket: true, http3: false })
    expect(body.tags).toEqual({ cc_protection: 'none', ddos_protection_gbps: 20, complaint_resistant: false, tenancy: 'shared',
      mobile_reachable: true, region_block: false, plugins: ['module.autodefense'] })
    expect(body.compliance).toEqual({ require_icp: true })
    expect(body.prepaid_exhausted_action).toBe('stop')
    expect(body.components).toEqual([{ kind: 'upstream', subscription_id: 'sub-1' }])
    expect(body.limits.map((l) => [l.metric, l.cap])).toEqual([['domains', 10], ['bandwidth_peak_bps', 2e9], ['monthly_traffic_bytes', 1536 * 1024 ** 3]])
    expect(body.name).toBe('R')
  })
})

// u4g: combined offers and plugin names.
describe('combo model', () => {
  const other: MarketFrozenTerms = { ...up, allocation: { http_ports: 2, stream_ports: 0 }, limits: [{ metric: 'domains', cap: 5, action: 'reject_new' }],
    tags: { ...up.tags, plugins: ['module.autodefense', 'ja4'] } }

  it('sums ports and caps capped on every component; my nodes make the sum unlimited', () => {
    const t = comboTotals([up, other], false)
    expect(t.httpPorts).toBe(6)
    expect(t.streamPorts).toBe(1)
    expect(t.limits).toEqual({ domains: 15 })
    expect(comboTotals([up, other], true).limits).toEqual({ domains: null })
    expect(comboTotals([], false).limits).toEqual({})
  })

  it('keeps only plugins every component has', () => {
    expect(comboPlugins([up, other], null)).toEqual(['module.autodefense'])
    expect(comboPlugins([other], ['ja4', 'pack.crs'])).toEqual(['ja4'])
    expect(comboPlugins([], null)).toEqual([])
  })

  it('builds own_pool plus sorted upstream components and drops plugins not allowed', () => {
    const body = comboOfferOf({ ...defaultValues, name: ' c ', price: 10, httpPorts: 3, streamPorts: 0, websocket: true, http3: false,
      plugins: ['ja4', 'pack.crs'] }, defaultRows(), null, 'pool-1', ['b', 'a'], ['ja4'])
    expect(body.name).toBe('c')
    expect(body.components).toEqual([{ kind: 'own_pool', node_pool_ref: 'pool-1' }, { kind: 'upstream', subscription_id: 'a' },
      { kind: 'upstream', subscription_id: 'b' }])
    expect(body.allocation).toEqual({ http_ports: 3, stream_ports: 0, websocket: true, http3: false })
    expect(body.tags.plugins).toEqual(['ja4'])
    expect(comboOfferOf({ ...defaultValues, name: 'x', price: 1, httpPorts: 0, streamPorts: 0, websocket: false, http3: false },
      defaultRows(), null, null, ['a', 'b'], []).components.map((c) => c.kind)).toEqual(['upstream', 'upstream'])
  })

  it('names a plugin from the catalogue or falls back to the code', () => {
    const names = new Map([['ja4', { name_zh: 'JA4 指纹', name_en: 'JA4 fingerprints' }]])
    expect(pluginLabel('ja4', names, false)).toBe('JA4 指纹')
    expect(pluginLabel('ja4', names, true)).toBe('JA4 fingerprints')
    expect(pluginLabel('rule_pack:system/x', names, false)).toBe('rule_pack:system/x')
  })
})
