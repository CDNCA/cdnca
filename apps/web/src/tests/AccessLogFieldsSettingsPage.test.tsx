import { fireEvent, screen, waitFor } from '@testing-library/react'

import { useSessionStore } from '../auth/session'
import AccessLogFieldsSettingsPage, { defaultAccessLogFields, estimatedSize } from '../pages/AccessLogFieldsSettingsPage'
import { getBreadcrumbLabels, isImplementedPath } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { auditLogCategories } from '../api/auditLogs'
import type { AccessLogFieldKey } from '../api/systemConfiguration'

const sha = 'a'.repeat(64)

function documentBody(fields: AccessLogFieldKey[], revision: number, status: string, active: number) {
  return {
    schema: 'cdnca.system-configuration/v2', category: 'access_log_fields', head_revision: revision,
    active_revision: active, revision, status, snapshot_sha256: sha,
    pending_categories: revision > active ? ['access_log_fields'] : [], value: { fields },
  }
}

const cleanup = {
  schema: 'cdnca.platform-system-cleanup-settings/v1', revision: 2,
  value: {
    cleanup_cache_days: 7, access_logs_days: 30, node_metrics_days: 7, bandwidth_history_days: 90,
    blacklist_history_days: 30, node_traffic_history_days: 90,
    audit_retention_days: Object.fromEntries(auditLogCategories.map((category) => [category, 0])),
  },
}

function authenticate(permissions: string[]) {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function json(body: unknown) {
  const revision = (body as { head_revision?: number }).head_revision
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (revision !== undefined) headers.ETag = `"${revision}"`
  return new Response(JSON.stringify(body), { status: 200, headers })
}

describe('access log fields settings', () => {
  it('is an admin route under system configuration', () => {
    expect(isImplementedPath('admin', '/config/access-log', ['system_configuration.read'])).toBe(true)
    expect(isImplementedPath('admin', '/config/access-log', ['sites.read'])).toBe(false)
    expect(getBreadcrumbLabels('admin', '/config/access-log').at(-1)).toBe('访问日志字段')
  })

  it('estimates the storage of a selection', () => {
    expect(estimatedSize([])).toBe('22 GB')
    expect(estimatedSize(defaultAccessLogFields)).toBe('50 GB')
  })

  it('shows every group, saves the selection in catalog order and edits the shared retention', async () => {
    authenticate(['system_configuration.read', 'system_configuration.manage'])
    const writes: Array<{ url: string, body: unknown }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      const body = init?.body ? JSON.parse(String(init.body)) as { value: unknown } : null
      if (method === 'PUT') writes.push({ url, body })
      if (url.endsWith('/categories/access_log_fields')) {
        return method === 'PUT'
          ? json(documentBody((body!.value as { fields: AccessLogFieldKey[] }).fields, 1, 'draft', 0))
          : json(documentBody(defaultAccessLogFields, 0, 'draft', 0))
      }
      if (url.endsWith('/v1/admin/system-cleanup-settings')) {
        return method === 'PUT' ? json({ ...cleanup, revision: 3, value: body!.value }) : json(cleanup)
      }
      return new Response('{}', { status: 404 })
    })
    renderWithProviders(<AccessLogFieldsSettingsPage />)
    expect(await screen.findByText('未保存（使用默认字段）')).toBeInTheDocument()
    for (const group of ['客户端', '请求头', '响应头', '回源', '缓存', '安全', 'TLS 指纹']) {
      expect(screen.getByText(group)).toBeInTheDocument()
    }
    expect(screen.getByText(/基础字段（始终记录）/)).toBeInTheDocument()
    expect(screen.getByTestId('access-log-field-referer')).toBeChecked()
    expect(screen.getByTestId('access-log-field-upstream_addr')).not.toBeChecked()
    expect(screen.getByText(/数据分析"热门 Referer"/)).toBeInTheDocument()
    // fix-decide1027b 第1项：是否拦截页可选（默认勾选），写明关闭后计入套餐流量。
    expect(screen.getByTestId('access-log-field-block_page')).toBeChecked()
    expect(screen.getByTestId('access-log-group-security')).toContainElement(screen.getByTestId('access-log-field-block_page'))
    expect(screen.getByText(/关闭后拦截页的流量会计入套餐流量/)).toBeInTheDocument()
    expect(screen.getByText(/基础字段（始终记录）/).closest('.ant-alert')).not.toHaveTextContent('是否拦截页')

    fireEvent.click(screen.getByTestId('access-log-field-upstream_addr'))
    fireEvent.click(screen.getByTestId('access-log-field-client_family'))
    fireEvent.click(screen.getByRole('button', { name: /保存草稿/ }))
    expect(await screen.findByText('草稿 r1')).toBeInTheDocument()
    expect(writes[0]).toEqual({
      url: expect.stringContaining('/categories/access_log_fields'),
      body: { value: { fields: ['client_geo', 'referer', 'user_agent', 'content_type', 'origin_timing', 'upstream_addr', 'block_page', 'ja4'] } },
    })

    const days = await screen.findByLabelText('网站访问日志保留（天）')
    expect(days).toHaveValue('30')
    fireEvent.change(days, { target: { value: '14' } })
    fireEvent.click(screen.getByRole('button', { name: '保存保留天数' }))
    await waitFor(() => expect(writes).toHaveLength(2))
    expect(writes[1]).toEqual({
      url: expect.stringContaining('/v1/admin/system-cleanup-settings'),
      body: { value: { ...cleanup.value, access_logs_days: 14 } },
    })
  })

  it('is read-only without manage permission', async () => {
    authenticate(['system_configuration.read'])
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => String(input).includes('system-cleanup-settings')
      ? json(cleanup) : json(documentBody(defaultAccessLogFields, 2, 'active', 2)))
    renderWithProviders(<AccessLogFieldsSettingsPage />)
    expect(await screen.findByText('已生效 r2')).toBeInTheDocument()
    expect(screen.getByTestId('access-log-field-referer')).toBeDisabled()
    expect(screen.queryByRole('button', { name: /保存草稿/ })).not.toBeInTheDocument()
  })
})
