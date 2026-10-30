import { vi } from 'vitest'
import { ApiError } from '../api/auth'
import i18n from '../i18n'
import {
  errorMessage, guardRuleFromRow, guardRuleProblem, guardRuleRow, normalizeServerNames, parseListenPorts, portRangeProblem, regionCIDRsInput, streamFields,
  streamFormFields, type GuardRuleRow, type StreamFormValues,
} from '../pages/streamForm'
import { withQuickBan } from '../pages/L4SessionPanels'
import { stream } from './streamFixture'

function values(overrides: Partial<StreamFormValues>): StreamFormValues {
  return {
    ...streamFields(stream),
    upstream_mode: 'address',
    geo_trusted_proxy_cidrs: '',
    geo_blocked_regions: '',
    geo_region_cidrs: regionCIDRsInput([]),
    ...overrides,
  }
}

describe('stream form TLS passthrough mapping', () => {
  it('copies passthrough facts from a stream without sharing the server name array', () => {
    const item = { ...stream, tls_passthrough: true, server_names: ['app.example.com', '*.example.com'] }
    const fields = streamFields(item)
    expect(fields).toMatchObject({ tls_passthrough: true, server_names: ['app.example.com', '*.example.com'] })
    expect(fields.server_names).not.toBe(item.server_names)
  })

  it('trims and lower-cases server names without silently removing duplicates', () => {
    expect(normalizeServerNames([' App.Example.COM ', '', '*.Example.com', 'app.example.com'])).toEqual(['app.example.com', '*.example.com', 'app.example.com'])
    expect(normalizeServerNames(undefined)).toEqual([])
  })

  it('sends normalized names when passthrough is on and clears them when it is off', () => {
    expect(streamFormFields(values({ tls_passthrough: true, server_names: [' A.Example.com', '*.example.com'] })))
      .toMatchObject({ protocol: 'tcp', tls_passthrough: true, server_names: ['a.example.com', '*.example.com'] })
    expect(streamFormFields(values({ tls_passthrough: false, server_names: ['a.example.com'] })))
      .toMatchObject({ tls_passthrough: false, server_names: [] })
    expect(streamFormFields(values({ tls_passthrough: undefined as unknown as boolean, server_names: undefined as unknown as string[] })))
      .toMatchObject({ tls_passthrough: false, server_names: [] })
  })
})

// fp-role L4-004：写了结束端口就是范围，0 / 00000 / 逆序 / 65536 都是字段错误，不能退成单端口。
describe('stream listen port text parsing', () => {
  it.each([
    ['20000-0', { problem: 'listenPortEndRange' }],
    ['20000-00000', { problem: 'listenPortEndRange' }],
    ['20000-19999', { problem: 'listenPortEndRange' }],
    ['20000-20000', { problem: 'listenPortEndRange' }],
    ['20000-65536', { problem: 'listenPortEndRange' }],
    ['20000-20001', { entries: [{ protocol: 'tcp', port: 20000, port_end: 20001 }] }],
    ['20000', { entries: [{ protocol: 'tcp', port: 20000 }] }],
    ['20000-20010/udp 88', { entries: [{ protocol: 'udp', port: 20000, port_end: 20010 }, { protocol: 'tcp', port: 88 }] }],
  ] as const)('parses %s', (text, expected) => {
    expect(parseListenPorts(text)).toEqual(expected)
  })
})

describe('stream write error messages', () => {
  it.each([
    ['zh-CN', '这个端口有多个使用方（转发或网站），不能开启 PROXY 协议（入站或出站）'],
    ['en-US', 'PROXY protocol (inbound or outbound) cannot be used on a port shared with other streams or websites'],
  ])('maps the shared-port PROXY conflict in %s without leaking the server message', (locale, expected) => {
    const t = i18n.getFixedT(locale, 'streams')
    expect(errorMessage(new ApiError('raw backend text', 409, 'stream_shared_port_proxy_protocol'), t)).toBe(expected)
    expect(errorMessage(new ApiError('raw backend text', 409, 'something_else'), t)).toBe(t('errors.operationFailed'))
  })
})

describe('stream form combination field errors (L4-006)', () => {
  it.each(['zh-CN', 'en-US'])('maps details.field + reason to a specific message in %s', async (locale) => {
    const t = i18n.getFixedT(locale, 'streams')
    const { streamsApi } = await import('../api/streams')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ error: {
      code: 'validation_error', message: 'raw', request_id: 'r',
      details: { field: 'proxy_protocol_inbound', reason: 'trusted_proxy_required' },
    } }), { status: 400 }))
    const error = await streamsApi.create('token', streamFields(stream), 'key').catch((caught: unknown) => caught) as ApiError
    expect(error.field).toBe('proxy_protocol_inbound')
    expect(error.fieldReason).toBe('trusted_proxy_required')
    const message = errorMessage(error, t)
    expect(message).toBe(t('errors.fieldReason.proxy_protocol_inbound__trusted_proxy_required'))
    expect(message).not.toBe(t('errors.operationFailed'))
    expect(message).not.toContain('raw')
    vi.restoreAllMocks()
  })

  it('falls back to the field message for an unknown reason', () => {
    const t = i18n.getFixedT('zh-CN', 'streams')
    const error = new ApiError('raw', 400, 'validation_error')
    error.field = 'balance_way'
    error.fieldReason = 'something_new'
    expect(errorMessage(error, t)).toBe(t('errors.field.balance_way'))
  })
})

describe('stream form new connection rate mapping', () => {
  it('copies the rate from a stream and sends it back unchanged', () => {
    const item = { ...stream, max_new_connections_per_client_per_second: 20, new_connection_burst: 5, new_connection_ban_seconds: 60 }
    expect(streamFields(item)).toMatchObject({ max_new_connections_per_client_per_second: 20, new_connection_burst: 5, new_connection_ban_seconds: 60 })
    expect(streamFormFields(values(streamFields(item))))
      .toMatchObject({ max_new_connections_per_client_per_second: 20, new_connection_burst: 5, new_connection_ban_seconds: 60 })
  })

  it('clears burst and ban when the rate is unlimited or left empty', () => {
    expect(streamFormFields(values({ max_new_connections_per_client_per_second: 0, new_connection_burst: 5, new_connection_ban_seconds: 60 })))
      .toMatchObject({ max_new_connections_per_client_per_second: 0, new_connection_burst: 0, new_connection_ban_seconds: 0 })
    expect(streamFormFields(values({
      max_new_connections_per_client_per_second: undefined as unknown as number,
      new_connection_burst: undefined as unknown as number, new_connection_ban_seconds: undefined as unknown as number,
    }))).toMatchObject({ max_new_connections_per_client_per_second: 0, new_connection_burst: 0, new_connection_ban_seconds: 0 })
    expect(streamFormFields(values({ max_new_connections_per_client_per_second: 10, new_connection_burst: undefined as unknown as number })))
      .toMatchObject({ max_new_connections_per_client_per_second: 10, new_connection_burst: 0, new_connection_ban_seconds: 0 })
  })
})

describe('stream form client address mapping', () => {
  it('copies TOA from a stream and sends it back without PROXY', () => {
    const item = { ...stream, proxy_protocol_v1: false, toa: true }
    expect(streamFields(item)).toMatchObject({ toa: true, proxy_protocol_v1: false })
    expect(streamFormFields(values(streamFields(item)))).toMatchObject({ toa: true, proxy_protocol_v1: false })
  })

  it('never sends TOA with PROXY or on UDP', () => {
    expect(streamFormFields(values({ toa: true, proxy_protocol_v1: true }))).toMatchObject({ toa: true, proxy_protocol_v1: false })
    expect(streamFormFields(values({ toa: true, protocol: 'udp' }))).toMatchObject({ toa: false, proxy_protocol_v1: false })
    expect(streamFormFields(values({ toa: true, proxy_protocol_inbound: true,
      geo_policy: { ...stream.geo_policy, enabled: true } }))).toMatchObject({ toa: false })
  })
})

// 端口范围 / 跟随端口回源：未用时请求体不变；跟随端口时回源端口取监听端口。
describe('stream form port range mapping', () => {
  it('omits the range fields when unused and sends them when set', () => {
    const plain = streamFormFields(values({}))
    expect(plain).not.toHaveProperty('listen_port_end')
    expect(plain).not.toHaveProperty('upstream_follow_port')
    expect(streamFormFields(values({ listen_port: 20000, listen_port_end: 20999, upstream_follow_port: true, upstream_port: 9000 })))
      .toMatchObject({ listen_port: 20000, listen_port_end: 20999, upstream_follow_port: true, upstream_port: 20000 })
    expect(streamFields({ ...stream, listen_port_end: 18199, upstream_follow_port: true }))
      .toMatchObject({ listen_port_end: 18199, upstream_follow_port: true })
    expect(streamFields({ ...stream, listen_port_end: 0, upstream_follow_port: false })).not.toHaveProperty('listen_port_end')
  })

  it.each([
    [20000, undefined, false, null], [20000, 20999, false, null], [20000, 21000, false, 'listenPortEndTooMany'],
    [20000, 20000, false, 'listenPortEndRange'], [400, 500, false, 'listenPortEndProtected'],
    [18000, 18100, false, 'listenPortEndProtected'], [20000, 20010, true, 'listenPortEndTLSPassthrough'],
  ])('checks range %s-%s (passthrough %s) as %s', (port, end, passthrough, problem) => {
    expect(portRangeProblem(port, end, passthrough)).toBe(problem)
  })
})

describe('stream port conflict messages', () => {
  it.each([
    ['zh-CN', { protocol: 'tcp', port: 20000, port_end: 20010, with: 'stream', name: 'game' }, 'TCP 端口 20000-20010 已被其他转发规则「game」占用'],
    ['zh-CN', { protocol: 'tcp', port: 25080, with: 'site', name: 'a.example.com' }, 'TCP 端口 25080 已被网站「a.example.com」使用'],
    ['zh-CN', { protocol: 'udp', port: 443, with: 'reserved' }, 'UDP 端口 443 是节点自用端口，不能用于转发'],
    ['en-US', { protocol: 'tcp', port: 20000, port_end: 20010, with: 'stream' }, 'TCP ports 20000-20010 are taken by another forwarding rule'],
  ] as const)('names where the %s conflict is', async (locale, details, expected) => {
    const { streamsApi } = await import('../api/streams')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ error: { code: 'stream_port_conflict', message: 'raw', request_id: 'r', details } }), { status: 409 }))
    const error = await streamsApi.create('token', streamFields(stream), 'key').catch((caught: unknown) => caught) as ApiError
    expect(errorMessage(error, i18n.getFixedT(locale, 'streams'))).toBe(expected)
  })
})

describe('stream form guard rules', () => {
  const id = '99999999-9999-4999-8999-999999999991'
  const rule = {
    id, action: 'ban' as const, ban_seconds: 600, threshold: 5, window_seconds: 60,
    first_packet: { match: 'prefix_hex' as const, value: '16030100' },
    client_ip: { cidrs: ['203.0.113.0/24', '2001:db8::/32'], negate: true },
    geo: [{ field: 'tag' as const, values: ['idc:global'] }, { field: 'country' as const, negate: true, values: ['CN'] },
      { field: 'asn' as const, values: ['13335'] }],
  }

  it('round-trips a rule through the editable row, keeping geo conditions the form does not show', () => {
    const row = guardRuleRow(rule)
    expect(row).toMatchObject({ client_cidrs: '203.0.113.0/24\n2001:db8::/32', client_negate: true, tags: ['idc:global'],
      countries: 'CN', countries_negate: true, geo_other: [{ field: 'asn', values: ['13335'] }] })
    expect(guardRuleFromRow(row, false)).toEqual(rule)
  })

  it('normalizes row input and drops ban fields of other actions', () => {
    const row: GuardRuleRow = { id, action: 'drop', first_packet_match: 'prefix_hex', first_packet_value: ' 16 03 01 FF ',
      countries: 'us, sg', ban_seconds: 600, threshold: 1, server_names: ['A.example.com'] }
    expect(guardRuleFromRow(row, true)).toEqual({ id, action: 'drop', first_packet: { match: 'prefix_hex', value: '160301ff' },
      server_names: ['a.example.com'], geo: [{ field: 'country', values: ['US', 'SG'] }] })
    expect(guardRuleFromRow({ id, action: 'ban', client_cidrs: '192.0.2.0/24', ban_seconds: 60, threshold: 1, window_seconds: 30 }, false))
      .toEqual({ id, action: 'ban', client_ip: { cidrs: ['192.0.2.0/24'] }, ban_seconds: 60, threshold: 1 })
  })

  it.each([
    [{ id, action: 'drop' }, 'noCondition'],
    [{ id, action: 'drop', server_names: ['a.example.com'] }, 'sniNeedsPassthrough'],
    [{ id, action: 'drop', first_packet_match: 'prefix_hex', first_packet_value: 'abc' }, 'hexInvalid'],
    [{ id, action: 'drop', first_packet_match: 'contains', first_packet_value: 'x'.repeat(257) }, 'patternTooLong'],
    [{ id, action: 'drop', client_cidrs: '192.0.2.0' }, 'cidrInvalid'],
    [{ id, action: 'drop', countries: 'USA' }, 'countryInvalid'],
    [{ id, action: 'ban', client_cidrs: '192.0.2.0/24', threshold: 1 }, 'banSecondsRange'],
    [{ id, action: 'ban', client_cidrs: '192.0.2.0/24', ban_seconds: 60, threshold: 3 }, 'windowRange'],
    [{ id, action: 'ban', client_cidrs: '192.0.2.0/24', ban_seconds: 60, threshold: 3, window_seconds: 60 }, null],
  ] as Array<[GuardRuleRow, string | null]>)('validates rows: %o', (row, problem) => {
    expect(guardRuleProblem(row, false)).toBe(problem)
  })

  it('sends rules from the rows, keeps the stream\'s rules when the rows are not mounted, omits none', () => {
    expect(streamFormFields(values({ guard_rule_rows: [guardRuleRow(rule)] })).guard_rules).toEqual([rule])
    expect(streamFormFields(values({ guard_rules: [rule] })).guard_rules).toEqual([rule])
    expect('guard_rules' in streamFormFields(values({ guard_rule_rows: [] }))).toBe(false)
    expect('guard_rules' in streamFields(stream)).toBe(false)
  })

  it('collects quick bans in one rule placed first, refusing repeats', () => {
    const allow = { id, action: 'allow' as const, client_ip: { cidrs: ['0.0.0.0/0'] } }
    const first = withQuickBan([allow], '203.0.113.9', 3600)!
    expect(first).toHaveLength(2)
    expect(first[0]).toMatchObject({ action: 'ban', ban_seconds: 3600, threshold: 1, client_ip: { cidrs: ['203.0.113.9/32'] } })
    expect(first[1]).toBe(allow)
    const second = withQuickBan(first, '2001:DB8::9', 3600)!
    expect(second).toHaveLength(2)
    expect(second[0].client_ip!.cidrs).toEqual(['203.0.113.9/32', '2001:db8::9/128'])
    expect(withQuickBan(second, '203.0.113.9', 3600)).toBeNull()
    expect(withQuickBan(second, '203.0.113.9', 60)).toHaveLength(3)
    expect(withQuickBan(Array.from({ length: 64 }, () => allow), '203.0.113.9', 60)).toBeNull()
  })
})
