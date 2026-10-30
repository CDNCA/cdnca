import { fireEvent, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { dnsPlatformApi } from '../api/dnsPlatform'
import { regionsApi } from '../api/nodes'
import { nodeSchedulingApi } from '../api/nodeScheduling'
import { useSessionStore } from '../auth/session'
import StreamOverrideModal from '../pages/StreamOverrideModal'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const region = '77777777-7777-4777-8777-777777777777'
const primary = '88888888-8888-4888-8888-888888888888'
const backup = '99999999-9999-4999-8999-999999999999'

function authenticate() {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['streams.manage', 'streams.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  vi.spyOn(regionsApi, 'list').mockResolvedValue({ count: 1, data: [{ id: region, name: '默认' }] } as never)
  vi.spyOn(nodeSchedulingApi, 'list').mockResolvedValue({ items: [
    { id: primary, name: 'test', region: '默认' }, { id: backup, name: 'backup', region: region },
  ] } as never)
  vi.spyOn(dnsPlatformApi, 'zones').mockResolvedValue({ items: [{ name: 'example.com' }], total: 1 } as never)
}

async function pick(label: string, option: string) {
  fireEvent.mouseDown(screen.getByRole('combobox', { name: label }))
  // Earlier dropdowns stay mounted (hidden); pick from the one just opened.
  await waitFor(() => expect(screen.getAllByTitle(option).length).toBeGreaterThan(0))
  const matches = screen.getAllByTitle(option)
  fireEvent.click(matches[matches.length - 1])
}

// 「更多操作」三个弹窗：修改CNAME域名（域名）、修改CNAME生成模式（模式）、修改线路分组（区域/线路分组/备用线路组）。
describe('StreamOverrideModal', () => {
  afterEach(() => { vi.restoreAllMocks(); useSessionStore.getState().clearSession() })

  it('submits the picked CNAME domain, or "" to follow the website', async () => {
    authenticate()
    const onSubmit = vi.fn()
    renderWithProviders(<StreamOverrideModal action="cname_domain" busy={false} onCancel={vi.fn()} onSubmit={onSubmit} />)
    expect(await screen.findByText('修改CNAME域名')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '确定' })).toBeDisabled()
    await pick('域名', 'example.com')
    fireEvent.click(screen.getByRole('button', { name: '确定' }))
    expect(onSubmit).toHaveBeenLastCalledWith({ action: 'cname_domain', cname_domain: 'example.com' })
    await pick('域名', '跟随套餐')
    fireEvent.click(screen.getByRole('button', { name: '确定' }))
    expect(onSubmit).toHaveBeenLastCalledWith({ action: 'cname_domain', cname_domain: '' })
  })

  it('offers 按网站生成 / 按套餐生成', async () => {
    authenticate()
    const onSubmit = vi.fn()
    renderWithProviders(<StreamOverrideModal action="cname_mode" busy={false} onCancel={vi.fn()} onSubmit={onSubmit} />)
    expect(await screen.findByText('修改CNAME生成模式')).toBeInTheDocument()
    await pick('模式', '按套餐生成')
    fireEvent.click(screen.getByRole('button', { name: '确定' }))
    expect(onSubmit).toHaveBeenLastCalledWith({ action: 'cname_mode', cname_mode: 'package' })
  })

  it('sends region, line group and a different backup group; the backup needs a primary', async () => {
    authenticate()
    const onSubmit = vi.fn()
    renderWithProviders(<StreamOverrideModal action="line_group" busy={false} onCancel={vi.fn()} onSubmit={onSubmit} />)
    expect(await screen.findByText('修改线路分组')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '备用线路组' })).toBeDisabled()
    await waitFor(() => expect(nodeSchedulingApi.list).toHaveBeenCalled())
    await pick('区域', '默认')
    await pick('线路分组', 'test')
    await pick('备用线路组', 'backup')
    fireEvent.click(screen.getByRole('button', { name: '确定' }))
    expect(onSubmit).toHaveBeenLastCalledWith({ action: 'line_group', region_id: region, node_group_id: primary, backup_node_group_id: backup })
  })

  // fix-smallbatch 5：结果未知时回显原选值并禁用输入（与设置状态弹窗一致），确定即按原请求重试。
  it.each([
    ['cname_domain', '修改CNAME域名', { action: 'cname_domain', cname_domain: 'example.com' }, [['域名', 'example.com']]],
    ['cname_mode', '修改CNAME生成模式', { action: 'cname_mode', cname_mode: 'site' }, [['模式', '按网站生成']]],
    ['line_group', '修改线路分组', { action: 'line_group', region_id: region, node_group_id: primary, backup_node_group_id: backup },
      [['区域', '默认'], ['线路分组', 'test'], ['备用线路组', 'backup']]],
  ] as const)('shows and freezes the unknown-outcome %s request, and retries it as is', async (action, title, frozen, fields) => {
    authenticate()
    const onSubmit = vi.fn()
    renderWithProviders(<StreamOverrideModal action={action} busy={false} frozen={frozen} onCancel={vi.fn()} onSubmit={onSubmit} />)
    expect(await screen.findByText(title)).toBeInTheDocument()
    if (action !== 'cname_mode') await waitFor(() => expect(action === 'cname_domain' ? dnsPlatformApi.zones : nodeSchedulingApi.list).toHaveBeenCalled())
    for (const [label, shown] of fields) {
      const box = screen.getByRole('combobox', { name: label })
      expect(box).toBeDisabled()
      await waitFor(() => expect(box.closest('.ant-select')).toHaveTextContent(shown))
    }
    expect(screen.getByRole('button', { name: '确定' })).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: '确定' }))
    expect(onSubmit).toHaveBeenCalledTimes(1)
    expect(onSubmit.mock.calls[0]![0]).toBe(frozen)
  })

  it('ignores a held request of another action', async () => {
    authenticate()
    renderWithProviders(<StreamOverrideModal action="cname_mode" busy={false} frozen={{ action: 'set_status', admin_status: 'locked' }}
      onCancel={vi.fn()} onSubmit={vi.fn()} />)
    expect(await screen.findByText('修改CNAME生成模式')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '模式' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '确定' })).toBeDisabled()
  })
})
