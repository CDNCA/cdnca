import { fireEvent, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'

import type { SiteDetail } from '../api/sites'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import '../i18n/httpPolicies'
import '../i18n/sitePolicy'
import SiteEditPage from '../pages/SiteEditPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const detail: SiteDetail = {
  id: 'site-1',
  version: 1,
  owner: { id: 'tenant-1', display_name: 'jason' },
  created_at: '2026-07-21T08:00:00Z',
  updated_at: '2026-07-22T08:00:00Z',
  lock: { locked: false, reason: null, locked_at: null, operator: null },
  listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
  origin_pool: {
    origins: [{ host: '192.0.2.10', port: 80, weight: 1, enabled: true }],
    balance_method: 'round_robin',
    failover_tries: 1,
    connect_timeout_ms: 3000,
    read_timeout_ms: 30000,
  },
  basic: {
    package_id: 'package-1',
    package_name: 'Base package',
    group_id: 'group-1',
    group_name: 'Default group',
    domains: ['www.example.com'],
    http_enabled: true,
    http_listen_ports: ['80'],
    https_listen_ports: ['443'],
    ipv6_enabled: false,
    tls_protocols: ['TLSv1.2', 'TLSv1.3'],
    origins: ['192.0.2.10:80'],
    cname: 'edge.example.net',
    https_enabled: true,
    enabled: true,
    status: 'active',
    sync_status: 'synced',
    is_default: false,
  },
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function authenticate(permissions = ['sites.read', 'sites.manage']) {
  const user = principal({ permissions })
  useSessionStore.getState().setSession(authResponse(user), user)
}

// 基本页的源站状态卡另发 GET /v1/sites/{id}/origin-status；给它一份合法空状态，
// 否则解析失败会弹 FeedbackWhen 错误弹窗，弹窗抢焦点后输入会落空。
const originStatus = {
  site_id: 'site-1', failback_mode: 'auto', active_level: 1, overall: 'unknown', failback_ready: false,
  levels: [], origins: [], switched_at: null, checked_at: null,
}
const siteResponse = (input: RequestInfo | URL) => jsonResponse(String(input).endsWith('/origin-status') ? originStatus : detail)

function renderEdit(initialEntry = '/site/site-1/edit') {
  return renderWithProviders(
    <Routes>
      <Route path="/site/:id/edit" element={<SiteEditPage />} />
      <Route path="/site/list" element={<div>Site list placeholder</div>} />
    </Routes>,
    [initialEntry],
  )
}

describe('SiteEditPage internationalization', () => {
  it.each(['zh-CN', 'en-US', 'qps-ploc'] as const)(
    'renders localized loading, empty, recoverable error/retry, and forbidden states in %s',
    async (locale) => {
      await changeLocale(locale)
      const t = i18n.getFixedT(locale, 'sites')

      authenticate()
      vi.spyOn(globalThis, 'fetch').mockReturnValue(new Promise<Response>(() => undefined))
      const loading = renderEdit()
      expect(screen.getByLabelText(t('edit.loading'))).toBeInTheDocument()
      loading.unmount()

      vi.restoreAllMocks()
      authenticate()
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 204 }))
      const empty = renderEdit()
      expect(await screen.findByText(t('edit.errors.empty'))).toBeInTheDocument()
      empty.unmount()

      vi.restoreAllMocks()
      authenticate()
      const recoverableRaw = `private ${locale} recoverable server detail`
      vi.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(jsonResponse({
          error: { code: 'unavailable', message: recoverableRaw },
        }, 503))
        .mockResolvedValueOnce(jsonResponse(detail))
      const recoverable = renderEdit()
      expect(await screen.findByText(t('edit.errors.loadFailed'))).toBeInTheDocument()
      expect(screen.queryByText(recoverableRaw)).not.toBeInTheDocument()
      await userEvent.click(screen.getByRole('button', { name: t('actions.retry') }))
      expect(await screen.findByRole('heading', { name: 'www.example.com' })).toBeInTheDocument()
      recoverable.unmount()

      vi.restoreAllMocks()
      authenticate()
      const forbiddenRaw = `private ${locale} forbidden server detail`
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({
        error: { code: 'permission_denied', message: forbiddenRaw },
      }, 403))
      const apiForbidden = renderEdit()
      expect(await screen.findByText(t('edit.errors.forbiddenTitle'))).toBeInTheDocument()
      expect(screen.getByText(t('edit.errors.permission_denied'))).toBeInTheDocument()
      expect(screen.queryByText(forbiddenRaw)).not.toBeInTheDocument()
      apiForbidden.unmount()

      vi.restoreAllMocks()
      const malformed = principal({
        scope_kind: 'tenant',
        scope_id: 'tenant-scope-a',
        tenant_id: null,
        permissions: ['sites.read', 'sites.manage'],
      })
      useSessionStore.getState().setSession(authResponse(malformed), malformed)
      const localFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
      renderEdit()
      expect(await screen.findByText(t('edit.errors.forbiddenTitle'))).toBeInTheDocument()
      expect(screen.getByText(t('edit.errors.permission_denied'))).toBeInTheDocument()
      expect(localFetch).not.toHaveBeenCalled()
    },
  )

  it.each(['zh-CN', 'en-US', 'qps-ploc'] as const)(
    'keeps conditional origin, algorithms, headers, upload, and error-page placeholders localized and disabled in %s',
    async (locale) => {
      await changeLocale(locale)
      authenticate(['sites.read', 'sites.manage', 'http_policies.read', 'error_pages.read'])
      vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
        if (String(input).endsWith('/v1/sites/site-1')) return Promise.resolve(jsonResponse(detail))
        // The advanced tab's access-control panel (ge-access) reads its own state.
        if (String(input).endsWith('/v1/sites/site-1/access')) {
          return Promise.resolve(jsonResponse({ site_id: 'site-1', version: 1, https_enabled: false, force_https: false,
            domains: ['www.example.com'], updated_at: null, settings: {
              host_redirects: [], hsts: null, compression: null, limits: null, basic_auth: null, maintenance: null,
              force_https: { status: 301, exclude_hosts: [] } } }))
        }
        return Promise.resolve(jsonResponse({ items: [] }))
      })
      const t = i18n.getFixedT(locale, 'sites')
      const httpPolicyT = i18n.getFixedT(locale, 'httpPolicies')
      const policyT = i18n.getFixedT(locale, 'sitePolicy')
      const user = userEvent.setup()
      renderEdit()
      await screen.findByRole('heading', { name: 'www.example.com' })

      // 条件源站已是独立可用的「条件源站」标签（ConditionalOriginSiteTab），基本信息里不再有禁用占位按钮。
      expect(screen.queryByRole('button', { name: t('edit.actions.addConditionalOrigin') })).not.toBeInTheDocument()
      const balanceGroup = await screen.findByRole('radiogroup', { name: t('edit.basic.aria.balanceMethod') })
      for (const key of ['round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random', 'hash', 'sticky'] as const) {
        expect(within(balanceGroup).getByRole('radio', { name: t(`edit.basic.balanceChoice.${key}.name`) })).toBeInTheDocument()
      }

      await user.click(screen.getByRole('tab', { name: t('edit.tabs.advanced') }))
      // tp-b3c: 高级设置 shows the competitor's groups instead of one HTTP policy section.
      expect(await screen.findByRole('heading', { name: policyT('groupUpload') })).toBeInTheDocument()
      expect(screen.queryByText(httpPolicyT('title'))).not.toBeInTheDocument()
      // The byte input appears only for 自定义; the default 不限制 choice is the disabled control here.
      expect(screen.getByRole('radio', { name: httpPolicyT('uploadMax') })).toBeDisabled()
      expect(screen.getByText(policyT('errorPages'))).toBeInTheDocument()
      // tp-b3c: without error_pages.manage the 新增页面 action is simply absent.
      expect(screen.queryByRole('button', { name: policyT('addPage') })).not.toBeInTheDocument()
      if (locale === 'qps-ploc') {
        expect(policyT('errorPages')).toMatch(/^［.+］$/)
        expect(httpPolicyT('requestHeaders').length).toBeGreaterThan('请求头动作'.length)
      }
    },
  )

  it('renders the competitor-aligned editor tabs and real protection views in English', async () => {
    await changeLocale('en-US')
    authenticate(['sites.read', 'sites.manage', 'security_policies.read', 'security_policies.manage'])
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(jsonResponse(detail)))
    const user = userEvent.setup()

    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })

    expect(screen.getAllByRole('tab').map((tab) => tab.textContent)).toEqual([
      'Basic configuration',
      'Origin settings',
      'HTTPS settings',
      'Cache settings',
      'CC protection',
      'WAF protection',
      'Auto defense',
      'Advanced settings',
    ])
    expect(await screen.findByLabelText('Domain')).toBeInTheDocument()
    expect(screen.getByLabelText('HTTP listen ports')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add origin' })).toBeInTheDocument()
    // fix-siteinstant: no save button, changes save themselves
    expect(screen.queryByRole('button', { name: 'Save changes' })).toBeNull()

    await user.click(screen.getByRole('tab', { name: 'CC protection' }))
    const ccHeading = await screen.findByRole('heading', { name: 'CC protection' })
    expect(ccHeading).toBeInTheDocument()
    // site-parity4：摘要条也显示同名标签，限定在原分区内查找
    expect(within(ccHeading.parentElement as HTMLElement).getByText('Default protection')).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: 'WAF protection' }))
    expect(await screen.findByRole('region', { name: 'Site WAF rule library' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Built-in module protection' })).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: 'HTTPS settings' }))
    // fix-tabperf：基本配置标签隐藏挂载着（也有同名端口框），只在 HTTPS 面板里找。
    const httpsListenPorts = await within(document.querySelector<HTMLElement>('[data-site-edit-tab="https"]')!).findByLabelText('HTTPS listen ports')
    expect(httpsListenPorts).toHaveValue('443')
    // HTTPS 标签已是真实可编辑的配置区（sites.manage 且 HTTPS 已开启时可改端口）。
    expect(httpsListenPorts).toBeEnabled()
  })

  it('maps the legacy security tab URL to CC protection', async () => {
    await changeLocale('en-US')
    authenticate(['sites.read', 'sites.manage', 'security_policies.read', 'security_policies.manage'])
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(jsonResponse(detail)))

    renderEdit('/site/site-1/edit?tab=security')

    expect(await screen.findByRole('heading', { name: 'CC protection' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'CC protection' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.queryByRole('tab', { name: 'Security settings' })).not.toBeInTheDocument()
  })

  it('renders basic validation errors in English without issuing a write', async () => {
    await changeLocale('en-US')
    authenticate()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
    const user = userEvent.setup()

    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const domain = await screen.findByLabelText('Domain')
    await user.clear(domain)
    await user.type(domain, 'not a domain')
    await user.clear(screen.getByLabelText('HTTP listen ports'))
    await user.type(screen.getByLabelText('HTTP listen ports'), '70000')
    fireEvent.blur(screen.getByLabelText('HTTP listen ports'))

    // UX-03: errors stay at the fields, no summary dialog.
    expect(await screen.findByText(/1 to 100 valid unique domains/)).toBeInTheDocument()
    expect(screen.queryByText('Check the highlighted fields')).not.toBeInTheDocument()
    expect(screen.getByText(/unique numbers from 1 to 65535/)).toBeInTheDocument()
    // 只读请求（站点详情、源站状态卡）照常发出；不得有写请求。
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(0)
  })

  it('uses the current locale for the unsaved navigation confirmation', async () => {
    await changeLocale('en-US')
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(siteResponse(input)))
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    const user = userEvent.setup()

    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const domain = await screen.findByLabelText('Domain')
    await user.clear(domain)
    await user.type(domain, 'dirty.example.com')
    await user.click(screen.getByRole('button', { name: 'Return to site list' }))

    expect(confirm).toHaveBeenCalledWith('This page has unsaved changes. Leave anyway?')
    expect(screen.getByRole('heading', { name: 'dirty.example.com' })).toBeInTheDocument()
  })

  it('localizes a stable save error and hides the server message', async () => {
    await changeLocale('en-US')
    authenticate()
    // 按方法区分：基本页的源站状态卡另发只读请求，不能按调用顺序 mock。
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => Promise.resolve(init?.method === 'PATCH'
      ? jsonResponse({ error: { code: 'version_conflict', message: 'internal database revision detail' } }, 409)
      : siteResponse(input)))
    const user = userEvent.setup()

    renderEdit()
    await screen.findByRole('heading', { name: 'www.example.com' })
    const domain = await screen.findByLabelText('Domain')
    await user.clear(domain)
    await user.type(domain, 'draft.example.com')
    fireEvent.blur(domain)

    expect(await screen.findByText('Someone else changed this; the latest values are loaded. Try again.')).toBeInTheDocument()
    expect(screen.queryByText('internal database revision detail')).not.toBeInTheDocument()
  })

  it('SiteEdit review closure renders the English read-only contract with disabled writes', async () => {
    await changeLocale('en-US')
    authenticate(['sites.read'])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
    renderEdit()

    await screen.findByRole('heading', { name: 'www.example.com' })
    expect(screen.getByText('Read-only mode')).toBeInTheDocument()
    expect(screen.getByText(
      'Your account does not have site management permission. You can only view the configuration.',
    )).toBeInTheDocument()
    expect(await screen.findByLabelText('Domain')).toBeDisabled()
    expect(await screen.findByRole('button', { name: 'Add origin' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Save changes' })).toBeNull()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'PATCH')).toHaveLength(0)
  })

  it('SiteEdit review closure localizes an API 403 without exposing its raw message', async () => {
    await changeLocale('en-US')
    authenticate(['sites.read'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({
      error: { code: 'permission_denied', message: 'private site ownership policy detail' },
    }, 403))
    renderEdit()

    expect(await screen.findByText('You cannot view site details')).toBeInTheDocument()
    expect(screen.getByText('Your account cannot view site details')).toBeInTheDocument()
    expect(screen.queryByText('private site ownership policy detail')).not.toBeInTheDocument()
  })

  it('SiteEdit review closure expands the qps-ploc read-only keys and renders them locally', async () => {
    await changeLocale('qps-ploc')
    authenticate(['sites.read'])
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(detail))
    const t = i18n.getFixedT('qps-ploc', 'sites')
    renderEdit()

    await screen.findByRole('heading', { name: 'www.example.com' })
    const title = t('edit.readOnly.title')
    const description = t('edit.readOnly.description')
    expect(title).toMatch(/^［.+］$/)
    expect(description).toMatch(/^［.+］$/)
    expect(title.length).toBeGreaterThan('只读模式'.length)
    expect(description.length).toBeGreaterThan('当前账号缺少网站管理权限，只能查看配置'.length)
    expect(screen.getByText(title)).toBeInTheDocument()
    expect(screen.getByText(description)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: t('edit.actions.save') })).toBeNull()
  })
})
