import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { siteCapturePolicyApi, type SiteCapturePolicy } from '../../api/siteCapturePolicy'
import '../../i18n/siteCapturePolicy'
import { siteCapturePolicyMessages } from '../../i18n/siteCapturePolicy'
import SiteCapturePolicyPanel from './SiteCapturePolicyPanel'

const scopeID = '11111111-1111-4111-8111-111111111111'
const siteID = '22222222-2222-4222-8222-222222222222'
const policy: SiteCapturePolicy = {
  scope_id: scopeID, site_id: siteID, revision: 1, evidence_digest: 'a'.repeat(64), updated_at: '2026-08-08T00:00:00Z',
  updated_by: '33333333-3333-4333-8333-333333333333', request_id: 'request-1',
  document: { enabled: false, methods: [], uri_prefixes: [], request_header_allowlist: [], response_header_allowlist: [],
    request_body_field_allowlist: [], response_body_field_allowlist: [], max_value_bytes: 4096, max_body_bytes: 65536, max_event_bytes: 1048576 },
}

const text = (path: string) => path.split('.').reduce<unknown>((value, key) => (value as Record<string, unknown>)[key], siteCapturePolicyMessages['zh-CN']) as string

function renderPanel(permissions = ['site_capture.read', 'site_capture.manage']) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={client}><SiteCapturePolicyPanel siteId={siteID} scopeId={scopeID} accessToken="token" ownerKey="tenant:user" sessionEpoch={1} permissions={permissions} canManage lockedForTenant={false} /></QueryClientProvider>)
}

beforeEach(() => vi.restoreAllMocks())

describe('SiteCapturePolicyPanel', () => {
  it('keeps capture off by default and requires explicit captured fields before saving', async () => {
    vi.spyOn(siteCapturePolicyApi, 'get').mockResolvedValue(policy)
    const update = vi.spyOn(siteCapturePolicyApi, 'update').mockResolvedValue({ replayed: false, policy: { ...policy, revision: 2,
      document: { ...policy.document, enabled: true, request_header_allowlist: ['Authorization'] } } })
    const user = userEvent.setup()
    renderPanel()
    const toggle = await screen.findByRole('switch', { name: text('fields.enabled') })
    expect(toggle).not.toBeChecked()
    // fix-siteinstant：没有保存按钮；开启但未填字段时校验不通过、不提交。
    expect(screen.queryByRole('button', { name: text('actions.save') })).toBeNull()
    await user.click(toggle)
    expect(screen.getAllByText(text('help.explicit')).length).toBeGreaterThan(0)
    expect(update).not.toHaveBeenCalled()
    const headers = screen.getByLabelText(text('fields.requestHeaders'))
    await user.type(headers, 'Authorization')
    expect(update).not.toHaveBeenCalled()
    fireEvent.blur(headers)
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1))
    expect(update.mock.calls[0][3].document).toMatchObject({ enabled: true, request_header_allowlist: ['Authorization'] })
    expect(update.mock.calls[0][4].idempotencyKey).toMatch(/^capture-/)
  })

  it('shows defaults without any failure prompt when the site never had a policy (state unconfigured)', async () => {
    vi.spyOn(siteCapturePolicyApi, 'get').mockResolvedValue({ scope_id: scopeID, site_id: siteID, state: 'unconfigured', revision: 0, document: policy.document })
    const update = vi.spyOn(siteCapturePolicyApi, 'update').mockResolvedValue({ replayed: false, policy: { ...policy,
      document: { ...policy.document, enabled: true, request_header_allowlist: ['Authorization'] } } })
    const user = userEvent.setup()
    renderPanel(['platform.admin'])
    const toggle = await screen.findByRole('switch', { name: text('fields.enabled') })
    expect(toggle).not.toBeChecked()
    expect(screen.queryByText(text('errors.load'))).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByText(text('states.unconfigured'))).toBeInTheDocument()
    await user.click(toggle)
    await user.type(screen.getByLabelText(text('fields.requestHeaders')), 'Authorization')
    fireEvent.blur(screen.getByLabelText(text('fields.requestHeaders')))
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1))
    expect(update.mock.calls[0][3].expected_revision).toBe(0)
  })

  // A16: 404 now means the site itself is missing or not visible; it must not be
  // swallowed into an editable empty form.
  it('treats 404 site_capture_not_found as a read failure, not as an editable default', async () => {
    vi.spyOn(siteCapturePolicyApi, 'get').mockRejectedValue(new ApiError('not found', 404, 'site_capture_not_found'))
    renderPanel()
    expect(await screen.findByRole('alert')).toHaveTextContent(text('errors.load'))
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
  })

  it('reports a real read failure inline, not as a global dialog', async () => {
    const get = vi.spyOn(siteCapturePolicyApi, 'get').mockRejectedValue(new ApiError('down', 503, 'site_capture_unavailable'))
    const user = userEvent.setup()
    renderPanel()
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(text('errors.load'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    // TECH-03: the shared load-failure state retries with the common 重试 button.
    await user.click(within(alert).getByRole('button', { name: '重试' }))
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
  })

  it('does not render a writable policy without read permission', () => {
    renderPanel([])
    expect(screen.getByText(text('errors.permission_denied'))).toBeInTheDocument()
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
  })
})
