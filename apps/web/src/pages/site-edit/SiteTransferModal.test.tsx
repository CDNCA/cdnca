import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { sitesApi } from '../../api/sites'
import { usersApi } from '../../api/users'
import '../../i18n'
import SiteTransferModal from './SiteTransferModal'

const site = { id: 'site-1', version: 3, domain: 'a.example.com', cname: 'old.cdn.example', ownerID: 'u-old', ownerName: '原用户' }
const target = { id: 'u-new', display_id: 'U2', scope_id: 'scope-new', tenant_id: 't', username: 'bob', display_name: 'Bob',
  status: 'active' }
const owner = { ...target, id: 'u-old', username: 'alice', display_id: 'U1', scope_id: 'scope-old' }

function wrap(node: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>)
}

afterEach(() => vi.restoreAllMocks())

// fix-transfer S4: 更换所属用户 — searchable target user (not the current
// owner; the community edition binds no package), the impact (CNAME changes, DNS repoint), and
// the result with the new CNAME and what to configure again.
describe('SiteTransferModal', () => {
  it('transfers to the chosen user without a package and shows the new CNAME and released items', async () => {
    vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [owner, target], page: 1, limit: 20, total: 2 } as never)
    const transfer = vi.spyOn(sitesApi, 'transfer').mockResolvedValue({
      site: { id: 'site-2', basic: { cname: 'new.cdn.example' } } as never, from_site_id: 'site-1', from_cname: 'old.cdn.example',
      copied: ['http_policy', 'certificate'], released: ['auto_defense', 'js_challenge'],
    })
    const onTransferred = vi.fn()
    wrap(<SiteTransferModal open accessToken="t" site={site} canReadUsers onClose={vi.fn()} onTransferred={onTransferred} />)

    expect(screen.getByText(/CNAME 会变：当前 old\.cdn\.example 不能保留/)).toBeTruthy()
    expect(screen.getByText(/需要把域名的 CNAME 解析改为新值/)).toBeTruthy()
    expect(screen.getByRole('button', { name: '确认更换' }).hasAttribute('disabled')).toBe(true)

    fireEvent.mouseDown(screen.getByRole('combobox', { name: '目标用户' }))
    expect(await screen.findByText('bob（U2）')).toBeTruthy()
    expect(screen.queryByText('alice（U1）')).toBeNull() // the current owner is not a target
    fireEvent.click(screen.getByText('bob（U2）'))
    expect(screen.queryByRole('combobox', { name: '套餐' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: '确认更换' }))

    await waitFor(() => expect(transfer).toHaveBeenCalledTimes(1))
    expect(transfer.mock.calls[0].slice(0, 3)).toEqual(['t', 'site-1',
      { expected_version: 3, target_user_id: 'u-new', target_package_subscription_id: null }])
    expect(await screen.findByText('new.cdn.example')).toBeTruthy()
    expect(screen.getByText('已带过去：HTTP 策略、证书。')).toBeTruthy()
    expect(screen.getByText('需重新配置：自动防御、JS 挑战。')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '知道了' }))
    expect(onTransferred).toHaveBeenCalledWith(expect.objectContaining({ from_site_id: 'site-1' }))
  })

  it('shows why the server refused', async () => {
    vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [target], page: 1, limit: 20, total: 1 } as never)
    const { ApiError } = await import('../../api/auth')
    vi.spyOn(sitesApi, 'transfer').mockRejectedValue(new ApiError('x', 409, 'site_transfer_domain_in_use'))
    wrap(<SiteTransferModal open accessToken="t" site={site} canReadUsers onClose={vi.fn()} onTransferred={vi.fn()} />)
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '目标用户' }))
    fireEvent.click(await screen.findByText('bob（U2）'))
    fireEvent.click(screen.getByRole('button', { name: '确认更换' }))
    expect(await screen.findByText(/原用户还有其他网站在使用该网站已验证的主域名/)).toBeTruthy()
  })
})
