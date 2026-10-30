import { fireEvent, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { Stream, StreamListResponse } from '../api/streams'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { enUS, pseudoCN, zhCN } from '../i18n/resources'
import StreamListPage from '../pages/StreamListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const stream: Stream = {
  id: '11111111-1111-4111-8111-111111111111',
  display_id: '1',
  scope_id: '22222222-2222-4222-8222-222222222222',
  eligibility_state: 'eligible',
  origins: [{ address: '192.0.2.10', weight: 1, down: false }],
  listen_ipv6: false,
  acl: { default_action: 'allow', rules: [] },
  admin_status: 'normal',
  line: { region_id: null, region_name: '', node_group_id: null, node_group_name: '', backup_node_group_id: null, backup_node_group_name: '' },
  overrides: { cname_domain: null, cname_mode: null, region_id: null, node_group_id: null, backup_node_group_id: null },
  sync_state: 'done',
  package_subscription_id: '55555555-5555-4555-8555-555555555555',
  owner: { id: '44444444-4444-4444-8444-444444444444', display_name: 'jason' },
  name: 'TCP gateway',
  remark: '',
  protocol: 'tcp',
  listen_address: '*',
  listen_port: 18100,
  upstream_address: '192.0.2.10',
  upstream_host: '',
  upstream_port: 9000,
  dns_policy: {
    positive_min_ttl_seconds: 0,
    positive_max_ttl_seconds: 0,
    negative_ttl_seconds: 0,
    stale_if_error_seconds: 0,
    allow_private_addresses: false,
  },
  geo_policy: {
    enabled: false,
    unknown_region_action: 'allow',
    trusted_proxy_cidrs: [],
    blocked_regions: [],
    region_cidrs: [],
  },
  connect_timeout_ms: 3000,
  response_timeout_ms: 30000,
  max_connections_per_client: 100,
  proxy_protocol_inbound: false,
  proxy_protocol_v1: true,
  balance_way: 'rr',
  groups: [],
  enabled: true,
  tls_passthrough: false,
  server_names: [],
  max_new_connections_per_client_per_second: 0,
  new_connection_burst: 0,
  new_connection_ban_seconds: 0,
  toa: false,
  session_log_enabled: false,
  revision: 1,
  publish_intent: {
    id: '33333333-3333-4333-8333-333333333333',
    version: 1,
    operation: 'create',
    desired_state: 'enabled',
    resource_revision: 1,
    configuration_source_revision: 41,
    runtime_spec: {
      schema_version: 'cdnca.edge.l4/v2',
      tenant_id: '22222222-2222-4222-8222-222222222222',
      stream_id: '11111111-1111-4111-8111-111111111111',
      revision: 1,
      listener: { protocol: 'tcp', address: '*', port: 18100 },
      endpoint: { address: '192.0.2.10', port: 9000 },
      dns: { positive_min_ttl_seconds: 0, positive_max_ttl_seconds: 0, negative_ttl_seconds: 0, stale_if_error_seconds: 0, allow_private_addresses: false },
      geo: {
        enabled: false, tenant_id: '22222222-2222-4222-8222-222222222222', stream_id: '11111111-1111-4111-8111-111111111111', revision: 1,
        unknown_region_action: 'allow', trusted_proxy_cidrs: [], blocked_regions: [], region_cidrs: [],
      },
      connect_timeout_ms: 3000,
      response_timeout_ms: 30000,
      max_connections_per_client: 100,
      drain_timeout_ms: 30000,
      proxy_protocol_inbound: false,
      proxy_protocol_outbound: true,
    },
    state: 'unknown',
    automatic_request_id: null,
    publication_id: null,
    rollout_id: null,
    created_at: '2026-07-22T08:00:00Z',
  },
  created_at: '2026-07-22T08:00:00Z',
  updated_at: '2026-07-22T08:00:00Z',
}

function listResponse(): Response {
  const body: StreamListResponse = { items: [stream], total: 1, page: 1, limit: 10 }
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

function authenticate() {
  const user = principal({ permissions: ['streams.read', 'streams.manage'] })
  useSessionStore.getState().setSession(authResponse(user), user)
}

// fix-advfilter2：高级筛选展开状态记在 localStorage，各用例从收起开始。
beforeEach(() => { localStorage.removeItem('cdnca.advancedFilters.stream-list') })

describe('StreamListPage internationalization', () => {
  const pseudoStreams = (pseudoCN as unknown as typeof zhCN).streams
  const validationKeys = [
    'targetScopeRequired',
    'targetScopeInvalid',
    'ownerRequired',
    'ownerInvalid',
    'nameRequired',
    'nameTooLong',
    'remarkTooLong',
    'packageSubscriptionRequired',
    'packageSubscriptionInvalid',
    'protocolRequired',
    'listenAddressRequired',
    'listenPortRequired',
    'listenPortRange',
    'upstreamRequired',
    'invalidUpstream',
    'upstreamHostRequired',
    'invalidUpstreamHost',
    'upstreamPortRequired',
    'upstreamPortRange',
    'connectTimeoutRequired',
    'connectTimeoutRange',
    'responseTimeoutRequired',
    'responseTimeoutRange',
    'maxConnectionsRequired',
    'maxConnectionsRange',
    'dnsPositiveMinRequired',
    'dnsPositiveMinRange',
    'dnsPositiveMaxRequired',
    'dnsPositiveMaxRange',
    'dnsNegativeRequired',
    'dnsNegativeRange',
    'dnsStaleRequired',
    'dnsStaleRange',
    'geoUnknownRequired',
    'geoTrustedProxyContract',
    'geoRegionCIDRsInvalid',
    'geoBlockedRegionMissing',
  ] as const

  it('localizes the publication command for an authorized platform principal', async () => {
    await changeLocale('en-US')
    const admin = principal({
      scope_kind: 'platform',
      tenant_id: null,
      roles: ['platform_admin'],
      permissions: ['edge_publications.manage'],
    })
    useSessionStore.getState().setSession(authResponse(admin), admin)
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup()

    renderWithProviders(<StreamListPage />, ['/stream/list'])

    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: 'Forwarding action menu' }))
    const link = await screen.findByRole('link', { name: 'Publish configuration' })
    expect(link).toHaveAttribute(
      'href',
      '/site/publications?target_scope_id=22222222-2222-4222-8222-222222222222&stream_id=11111111-1111-4111-8111-111111111111&stream_revision=1',
    )
    expect(screen.getByText('v1 delivery status unknown')).toBeInTheDocument()
    expect(screen.queryByText(/active on edge|activated/iu)).not.toBeInTheDocument()
  })

  it('renders filters, table state, and the create form in English', async () => {
    await changeLocale('en-US')
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup()

    renderWithProviders(<StreamListPage />, ['/stream/list'])

    await screen.findByText('TCP gateway')
    expect(screen.getByRole('columnheader', { name: 'Listen port' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Origin' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Group' })).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: 'Line' })).not.toBeInTheDocument() // tenant: no line column (competitor)
    expect(screen.getByLabelText('Search forwarding rules')).toHaveAttribute('placeholder', 'Enter a listen port')
    await user.click(screen.getByRole('button', { name: /^(Advanced filters|高级筛选)/ }))
    expect(screen.getByRole('combobox', { name: 'Filter by protocol' })).toBeInTheDocument()
    expect(screen.getByText('v1 delivery status unknown')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Add forwarding rule' }))
    const dialog = await screen.findByRole('dialog', { name: 'Add forwarding rule' })
    expect(within(dialog).getByLabelText('Listen ports')).toHaveAttribute('placeholder', '88, 99/udp or 88/tcp; separate ports with spaces')
    expect(within(dialog).getByLabelText('Origin address:port')).toHaveAttribute('placeholder', '1.1.1.1:99 or www.abc.com:99')
    await user.click(within(dialog).getByRole('button', { name: 'Show more' }))
    await user.click(within(dialog).getByText('Basic settings'))
    expect(within(dialog).getByLabelText('Rule name')).toHaveAttribute('placeholder', 'For example: game ingress')
    expect(within(dialog).queryByLabelText('Package subscription ID')).not.toBeInTheDocument()
    expect(within(dialog).queryByLabelText('Site ID')).not.toBeInTheDocument()
    expect(within(dialog).getByRole('switch', { name: 'Enable forwarding' })).toBeChecked()
    expect(within(dialog).getByRole('button', { name: 'OK' })).toBeInTheDocument()
  })

  it('provides complete namespaced validation copy with an expanded pseudo locale', () => {
    for (const key of validationKeys) {
      const chinese = zhCN.streams.form[key]
      const english = enUS.streams.form[key]
      const pseudo = pseudoStreams.form[key]
      expect(chinese).toBeTruthy()
      expect(english).toBeTruthy()
      expect(pseudo).toBeTruthy()
      expect(pseudo).not.toBe(chinese)
      expect(pseudo.length).toBeGreaterThan(chinese.length)
    }
  })

  it.each([
    ['zh-CN', zhCN.streams],
    ['en-US', enUS.streams],
    ['qps-ploc', pseudoStreams],
  ] as const)('renders invalid name, address, port, timeout, and UUID rules from the %s namespace', async (locale, copy) => {
    await changeLocale(locale)
    const admin = principal({
      scope_kind: 'platform',
      tenant_id: null,
      roles: ['platform_admin'],
      // 没有用户列表权限时回退为手填租户/归属用户 UUID。
      permissions: ['streams.read', 'streams.manage'],
    })
    useSessionStore.getState().setSession(authResponse(admin), admin)
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup()

    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')
    await user.click(screen.getByRole('button', { name: copy.actions.add }))
    const dialog = await screen.findByRole('dialog', { name: copy.form.addTitle })
    await user.type(screen.getByLabelText(copy.form.targetScopeId), 'invalid-tenant')
    await user.type(screen.getByLabelText(copy.form.ownerId), 'invalid-owner')
    fireEvent.change(screen.getByLabelText(copy.form.origin), { target: { value: '[::::]:99' } })
    await user.click(within(dialog).getByRole('button', { name: copy.form.expandMore }))
    await user.click(within(dialog).getByText(copy.form.groupBasic))
    await user.click(within(dialog).getByText(copy.form.groupConnection))
    await user.type(screen.getByLabelText(copy.form.name), 'x'.repeat(129))
    await user.clear(screen.getByLabelText(copy.form.connectTimeout))
    await user.clear(screen.getByLabelText(copy.form.responseTimeout))
    await user.click(screen.getByRole('button', { name: copy.form.confirm }))

    for (const message of [
      copy.form.targetScopeInvalid,
      copy.form.ownerInvalid,
      copy.form.nameTooLong,
      copy.form.listenPortRequired,
      copy.form.invalidUpstream,
      copy.form.connectTimeoutRequired,
      copy.form.responseTimeoutRequired,
    ]) {
      expect(await screen.findByText(message)).toBeInTheDocument()
    }
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })

  it('keeps public delivery copy truthful in both locales', () => {
    const strings = (value: unknown): string[] => {
      if (typeof value === 'string') return [value]
      if (!value || typeof value !== 'object') return []
      return Object.values(value).flatMap(strings)
    }
    expect(zhCN.streams.values.publishUnknown).toBe('v{{version}} 下发状态待确认')
    expect(enUS.streams.values.publishUnknown).toBe('v{{version}} delivery status unknown')
    expect(zhCN.streams.values.publishSucceeded).toBe('v{{version}} 已生效')
    expect(enUS.streams.values.publishSucceeded).toBe('v{{version}} active')
    expect(zhCN.streams.confirm.stateDescription).not.toContain('待下发')
    expect(enUS.streams.confirm.stateDescription).not.toMatch(/pending delivery/i)
    for (const notice of strings(zhCN.streams.notices)) expect(notice).not.toContain('待下发')
    for (const notice of strings(enUS.streams.notices)) expect(notice).not.toMatch(/pending delivery/i)
  })

  it('localizes a stable write error and hides the server message', async () => {
    await changeLocale('en-US')
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      if (init?.method === 'PATCH') {
        return Promise.resolve(new Response(JSON.stringify({
          error: { code: 'version_conflict', message: 'internal stream revision detail' },
        }), { status: 409, headers: { 'Content-Type': 'application/json' } }))
      }
      return Promise.resolve(listResponse())
    })
    const user = userEvent.setup()

    renderWithProviders(<StreamListPage />, ['/stream/list'])
    await screen.findByText('TCP gateway')

    await user.click(screen.getByRole('button', { name: 'Forwarding action menu' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Disable' }))
    const confirmation = await screen.findByRole('dialog', { name: 'Disable forwarding' })
    await user.click(within(confirmation).getByRole('button', { name: 'Confirm' }))

    expect(await screen.findByText('Another operation modified this rule. Refresh and try again.')).toBeInTheDocument()
    expect(screen.queryByText('internal stream revision detail')).not.toBeInTheDocument()
  })
})
