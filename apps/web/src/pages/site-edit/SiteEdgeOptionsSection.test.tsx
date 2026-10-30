import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import type { SiteBasicConfig, SiteOriginPool } from '../../api/sites'
import '../../i18n/siteEdgeOptions'
import SiteEdgeOptionsSection from './SiteEdgeOptionsSection'

vi.mock('../../api/nodeScheduling', () => ({ l2TopologyApi: { configs: vi.fn().mockResolvedValue({ items: [] }) } }))

const pool = (changes: Partial<SiteOriginPool> = {}): SiteOriginPool => ({
  origins: [{ host: '192.0.2.1', port: 80, weight: 1, enabled: true }], balance_method: 'round_robin',
  failover_tries: 1, connect_timeout_ms: 3000, read_timeout_ms: 30000, ...changes,
} as SiteOriginPool)
const basic = { is_default: false } as SiteBasicConfig

function renderPart(part: 'performance' | 'other', options: { admin?: boolean; value?: SiteOriginPool } = {}) {
  const onChange = vi.fn()
  const onBasicChange = vi.fn()
  render(<QueryClientProvider client={new QueryClient()}>
    <SiteEdgeOptionsSection part={part} pool={options.value ?? pool()} basic={basic} admin={options.admin ?? false}
      accessToken="token" onChange={onChange} onBasicChange={onBasicChange} />
  </QueryClientProvider>)
  return { onChange, onBasicChange }
}

describe('SiteEdgeOptionsSection (tp-b3c)', () => {
  it('性能与协议: WebSocket and 搜索引擎回源 cards edit the same pool fields', async () => {
    const user = userEvent.setup()
    const { onChange } = renderPart('performance', { value: pool({ websocket: { enabled: true, allowed_origins: ['https://a.test'] } }) })
    expect(screen.getByRole('heading', { name: 'WebSocket' })).toBeInTheDocument()
    expect(screen.getByLabelText('Origin 白名单')).toHaveValue('https://a.test')
    await user.click(screen.getByRole('switch', { name: 'WebSocket' }))
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ websocket: { enabled: false, allowed_origins: [] } }))

    // off ('' on the wire): no address field until the switch is on
    expect(screen.queryByLabelText('回源地址')).not.toBeInTheDocument()
    await user.click(screen.getByRole('switch', { name: '搜索引擎回源' }))
    expect(onChange).toHaveBeenCalledTimes(1)
    await user.type(screen.getByLabelText('回源地址'), '1')
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ search_engine_origin: '1' }))
  })

  it('其它: the three switches map to acme_passthrough and the inverted buffering fields', async () => {
    const user = userEvent.setup()
    const { onChange } = renderPart('other', { value: pool({ response_buffering: false }) })
    expect(screen.getByRole('switch', { name: '数据实时返回' })).toBeChecked()
    await user.click(screen.getByRole('switch', { name: '源站申请证书' }))
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ acme_passthrough: true }))
    await user.click(screen.getByRole('switch', { name: '数据实时发送' }))
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ request_buffering: false }))
  })

  it('hides 默认站点 and L2 from tenants (the competitor user console has neither)', () => {
    renderPart('other')
    expect(screen.queryByRole('switch', { name: '默认站点' })).not.toBeInTheDocument()
    expect(screen.queryByRole('radiogroup', { name: 'L2 配置' })).not.toBeInTheDocument()
  })

  it('shows 默认站点 and L2 to administrators', async () => {
    const user = userEvent.setup()
    const { onBasicChange } = renderPart('other', { admin: true })
    await user.click(screen.getByRole('switch', { name: '默认站点' }))
    expect(onBasicChange).toHaveBeenLastCalledWith(expect.objectContaining({ is_default: true }))
    expect(screen.getByRole('radio', { name: '当前套餐配置' })).toBeChecked()
  })
})
