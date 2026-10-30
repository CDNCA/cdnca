import { screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { cnameAllocationsApi } from '../../api/cnameAllocations'
import { renderWithProviders } from '../../test/render'
import CnameFailureReason from './CnameFailureReason'

const siteID = '11111111-1111-4111-8111-111111111111'
const scopeID = '22222222-2222-4222-8222-222222222222'

describe('CnameFailureReason (E6)', () => {
  afterEach(() => vi.restoreAllMocks())

  it('explains diagnose reason codes in Chinese with where to fix them', async () => {
    const diagnose = vi.spyOn(cnameAllocationsApi, 'diagnose').mockResolvedValue({
      site_id: siteID, ready: false, reason_codes: ['lkg_missing', 'default_zone_missing', 'zone_not_found', 'owner_allocation_missing'],
    })
    renderWithProviders(<CnameFailureReason accessToken="t" siteID={siteID} audience={{ kind: 'platform', scopeID }} />)
    const box = await screen.findByTestId('cname-failure-reason')
    expect(diagnose).toHaveBeenCalledWith('t', { kind: 'platform', scopeID }, { siteID })
    expect(box).toHaveTextContent('CNAME 分配失败：默认 DNS 区域缺失、DNS 区域不存在、所有者分配缺失')
    expect(box).toHaveTextContent('未配置默认 CNAME 区，请到 节点管理 → DNS配置 → CNAME域名 配置。')
    expect(box).not.toHaveTextContent('default_zone_missing')
    expect(box).not.toHaveTextContent('没有最近可用分配')
  })

  it('says the reason is unavailable when diagnose fails', async () => {
    vi.spyOn(cnameAllocationsApi, 'diagnose').mockRejectedValue(new Error('boom'))
    renderWithProviders(<CnameFailureReason accessToken="t" siteID={siteID} audience={{ kind: 'tenant' }} />)
    expect(await screen.findByText('CNAME 分配失败，暂时无法获取失败原因')).toBeInTheDocument()
  })
})
