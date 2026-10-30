import { act, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { SiteDetail, SiteListItem, SiteListResponse } from '../api/sites'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import SiteListPage from '../pages/SiteListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const site: SiteListItem = {
  id: 'site-1',
  display_id: '27',
  version: 7,
  owner: { id: 'tenant-1', display_id: '2', display_name: 'jason' },
  domain: 'www.example.com',
  listen_ports: ['80', '443'],
  origins: ['192.0.2.10:80'],
  cname: 'edge.example.net',
  https_enabled: true,
  package: { id: 'package-1', name: 'Base package' },
  group_name: 'Default group',
  region: { name: 'Mainland China', node_group_name: 'Primary line' },
  status: 'active',
  listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
  lock: { locked: false, reason: null, locked_at: null, operator: null },
  created_at: '2026-07-22T08:00:00Z',
}

function listResponse(items: SiteListItem[] = [site]): Response {
  const body: SiteListResponse = { items, total: items.length, page: 1, limit: 10 }
  return jsonResponse(body)
}

function detailResponse(): SiteDetail {
  return {
    id: site.id,
    version: site.version,
    owner: site.owner,
    created_at: site.created_at,
    updated_at: site.created_at,
    lock: site.lock,
    listener_state: site.listener_state,
    origin_pool: {
      origins: [{ host: '192.0.2.10', port: 80, weight: 1, enabled: true }],
      balance_method: 'round_robin',
      failover_tries: 1,
      connect_timeout_ms: 3000,
      read_timeout_ms: 30000,
    },
    basic: {
      package_id: site.package?.id ?? null,
      package_name: site.package?.name ?? null,
      group_id: null,
      group_name: site.group_name,
      domains: [site.domain],
      http_enabled: true,
      http_listen_ports: ['80'],
      https_listen_ports: ['443'],
      ipv6_enabled: false,
      tls_protocols: ['TLSv1.2', 'TLSv1.3'],
      origins: site.origins,
      cname: site.cname,
      https_enabled: true,
      enabled: true,
      status: 'active',
      sync_status: 'synced',
      is_default: false,
    },
  }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function authenticate(
  role: 'admin' | 'user' = 'admin',
  permissions: string[] = ['sites.read', 'sites.manage'],
) {
  const user = principal(role === 'admin' ? {
    scope_kind: 'platform',
    tenant_id: null,
    username: 'admin',
    display_name: 'admin',
    roles: ['platform_admin'],
    permissions,
  } : {
    permissions,
  })
  useSessionStore.getState().setSession(authResponse(user), user)
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

describe('SiteListPage internationalization', () => {
  it('renders the administrator list and advanced filters in English', async () => {
    await changeLocale('en-US')
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup()

    renderWithProviders(<SiteListPage />, ['/site/list'])

    await screen.findByText(site.domain)
    expect(screen.getByRole('navigation', { name: 'Site management sections' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Domain' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Origin / listen' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Group' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Region' })).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: 'User' })).not.toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add site' })).toBeInTheDocument()
    expect(screen.getByLabelText('Quick search value')).toHaveAttribute('placeholder', 'Enter a domain for fuzzy search')

    // fix-advfilter2：高级条件进共享 AdvancedFilters；其按钮文案随 antd ConfigProvider 语言（测试渲染未包 ConfigProvider，取默认中文），
    // 这里只核对页面自己的英文字段。
    const toggle = screen.getByRole('button', { name: /^(Advanced filters|高级筛选)/ })
    await user.click(toggle)
    const advanced = document.getElementById(toggle.getAttribute('aria-controls')!)!
    expect(within(advanced).getByText('Multiple domains')).toBeInTheDocument()
    expect(within(advanced).getByRole('combobox', { name: 'Site status' })).toBeInTheDocument()
  })

  it('localizes a stable lock error and hides the server message', async () => {
    await changeLocale('en-US')
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(listResponse())
      if (url === `/v1/sites/${site.id}` && !init?.method) return Promise.resolve(jsonResponse(detailResponse()))
      if (url.endsWith('/lock') && init?.method === 'POST') {
        return Promise.resolve(jsonResponse({
          error: { code: 'version_conflict', message: 'internal site revision detail' },
        }, 409))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup()

    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('button', { name: 'More' }))
    await user.click(await screen.findByText('Lock site (keeps serving, owner cannot edit)'))
    const dialog = await screen.findByRole('dialog', { name: 'Lock site' })
    await user.type(within(dialog).getByLabelText('Lock reason'), 'ownership review')
    await user.click(within(dialog).getByRole('button', { name: 'Confirm lock' }))

    expect(await within(dialog).findByText('The site version has changed')).toBeInTheDocument()
    expect(within(dialog).queryByText('internal site revision detail')).not.toBeInTheDocument()
  })

  it('localizes stable batch item error codes', async () => {
    await changeLocale('en-US')
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = String(input)
      if (url.startsWith('/v1/sites?')) return Promise.resolve(listResponse())
      if (url === '/v1/sites/batch-action' && init?.method === 'POST') {
        return Promise.resolve(jsonResponse({
          items: [{ id: site.id, status: 'failed', error: { code: 'version_conflict' } }],
        }))
      }
      return Promise.reject(new Error(`unexpected request ${url}`))
    })
    const user = userEvent.setup()

    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)

    await user.click(screen.getByRole('checkbox', { name: site.domain }))
    await user.click(screen.getByRole('button', { name: /More actions/ }))
    await user.click(await screen.findByText('Enable'))
    const dialog = await screen.findByRole('dialog', { name: 'Batch enable' })
    await user.click(within(dialog).getByRole('button', { name: 'Confirm enable' }))

    const result = await screen.findByRole('dialog', { name: 'Batch operation results' })
    expect(within(result).getByText('The site version has changed')).toBeInTheDocument()
    expect(within(result).queryByText('version_conflict')).not.toBeInTheDocument()
  })

  it.each([
    ['en-US', 'Add site', 'Site domain', 'Origin address', 'Create site'],
    ['qps-ploc', '［添~加~网~站~］', '［网~站~域~名~］', '［源~站~地~址~］', '［创~建~网~站~］'],
  ] as const)('renders the tenant create form without missing keys in %s', async (
    locale,
    title,
    domainLabel,
    originLabel,
    submitLabel,
  ) => {
    await changeLocale(locale)
    authenticate('user')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse())
    const user = userEvent.setup()

    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText(site.domain)
    await user.click(screen.getByRole('button', { name: title }))
    const dialog = screen.getByRole('dialog', { name: title })

    expect(within(dialog).getByRole('textbox', { name: domainLabel })).toBeInTheDocument()
    expect(within(dialog).getByRole('textbox', { name: originLabel })).toBeInTheDocument()
    const advancedLabel = i18n.getFixedT(locale, 'siteCreate')('advanced.expand')
    const collapseLabel = i18n.getFixedT(locale, 'siteCreate')('advanced.collapse')
    expect(within(dialog).getByRole('button', { name: advancedLabel })).toHaveAttribute('aria-expanded', 'false')
    await user.click(within(dialog).getByRole('button', { name: advancedLabel }))
    expect(within(dialog).getByRole('button', { name: collapseLabel })).toHaveAttribute('aria-expanded', 'true')
    // 社区版：建站不选套餐。
    expect(within(dialog).queryByRole('combobox', { name: i18n.t('siteCreate:packageSelect.label') })).not.toBeInTheDocument()
    expect(within(dialog).queryByRole('textbox', { name: i18n.t('siteCreate:packageSubscription.label') })).not.toBeInTheDocument()
    expect(within(dialog).getByRole('combobox', { name: i18n.t('siteCreate:groupSelect.label') })).toBeInTheDocument()
    expect(within(dialog).getByRole('combobox', { name: i18n.t('siteCreate:balance.label') })).toBeInTheDocument()
    expect(within(dialog).getByRole('textbox', { name: i18n.t('siteCreate:httpPorts.label') })).toBeInTheDocument()
    expect(within(dialog).getByRole('switch', { name: i18n.t('siteCreate:httpsEnabled.label') })).toBeInTheDocument()
    expect(within(dialog).getByText(i18n.t('siteCreate:tls.safeOnly'))).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: submitLabel })).toBeInTheDocument()
  })

  it('keeps qps-ploc loading, empty, error recovery, and local/API permission states localized', async () => {
    await changeLocale('qps-ploc')
    const t = i18n.getFixedT('qps-ploc', 'sites')
    authenticate('user')
    const pending = deferred<Response>()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockImplementationOnce(() => pending.promise)
      .mockResolvedValueOnce(listResponse([]))
    const user = userEvent.setup()
    const recoveryView = renderWithProviders(<SiteListPage />, ['/site/list'])

    expect(screen.getByTestId('site-table-scroll')).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByRole('table')).toBeInTheDocument()
    await act(async () => pending.resolve(jsonResponse({
      error: { code: 'unavailable', message: 'private qps site shard detail' },
    }, 503)))
    expect(await screen.findByText(t('errors.listFailed'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.operationFailed'))).toBeInTheDocument()
    expect(screen.queryByText('private qps site shard detail')).not.toBeInTheDocument()
    expect(screen.queryByText(t('values.empty'))).not.toBeInTheDocument()
    // Site list reads only: the tenant's automatic publication notice reads
    // /v1/site-publications once the list loaded (O2).
    const listReads = () => fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/sites?')).length
    const readsBeforeRetry = listReads()
    await user.click(screen.getByRole('button', { name: t('actions.retry') }))
    expect(await screen.findByText(t('values.empty'))).toBeInTheDocument()
    expect(listReads()).toBe(readsBeforeRetry + 1)
    recoveryView.unmount()

    vi.restoreAllMocks()
    authenticate('user', [])
    const localFetch = vi.spyOn(globalThis, 'fetch')
    const localView = renderWithProviders(<SiteListPage />, ['/site/list'])
    expect(await screen.findByText(t('errors.forbiddenTitle'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.forbiddenDescription'))).toBeInTheDocument()
    expect(localFetch).not.toHaveBeenCalled()
    localView.unmount()

    vi.restoreAllMocks()
    authenticate('user')
    const apiFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({
      error: { code: 'forbidden', message: 'private qps authorization row' },
    }, 403))
    renderWithProviders(<SiteListPage />, ['/site/list'])
    expect(await screen.findByText(t('errors.forbiddenTitle'))).toBeInTheDocument()
    expect(screen.getByText(t('errors.forbiddenDescription'))).toBeInTheDocument()
    expect(screen.queryByText('private qps authorization row')).not.toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledOnce()
  })

  it.each(['en-US', 'qps-ploc'] as const)(
    'renders the permission-gated CNAME regeneration action in %s',
    async (locale) => {
      await changeLocale(locale)
      authenticate('user', ['sites.read', 'sites.manage', 'dns.manage'])
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(listResponse([
        { ...site, cname_state: 'failed', cname_task_id: null },
      ]))
      const user = userEvent.setup()
      renderWithProviders(<SiteListPage />, ['/site/list'])
      await screen.findByText(site.domain)

      await user.click(screen.getByRole('checkbox', { name: site.domain }))
      await user.click(screen.getByRole('button', { name: i18n.t('sites:actions.moreActions') }))

      expect(await screen.findByText(i18n.t('siteCnameRegeneration:action'))).toBeInTheDocument()
    },
  )
})
