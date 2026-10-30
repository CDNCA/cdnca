import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { AppRoutes } from '../App'
import { streamsApi } from '../api/streams'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { stream } from './streamFixture'

describe('stream detail route', () => {
  it.each(['platform', 'tenant'] as const)('loads a %s deep link and selects the parent menu', async (scopeKind) => {
    const actor = principal({ scope_kind: scopeKind, permissions: ['streams.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const get = vi.spyOn(streamsApi, 'get').mockResolvedValue(stream)

    renderWithProviders(<AppRoutes />, [`/stream/list/${stream.id}`])

    expect(await screen.findByRole('heading', { name: '端口 18100' })).toBeInTheDocument()
    expect(get).toHaveBeenCalledWith('memory-only-access-token', stream.id)
    expect(screen.getByRole('menuitem', { name: '转发列表' })).toHaveClass('ant-menu-item-selected')
    expect(screen.getByLabelText('面包屑')).toHaveTextContent('首页/四层转发/转发详情')
    expect(screen.getByLabelText('面包屑')).not.toHaveTextContent('{{')
    expect(screen.getByRole('link', { name: '返回转发列表' })).toHaveAttribute('href', '/stream/list')
    expect(screen.queryByRole('button', { name: '保存' })).not.toBeInTheDocument()
  })

  it('denies an unauthorized deep link before fetching stream facts', async () => {
    const actor = principal({ permissions: [] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const get = vi.spyOn(streamsApi, 'get')

    renderWithProviders(<AppRoutes />, [`/stream/list/${stream.id}`])

    expect(await screen.findByText('无权查看转发列表')).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
  })

  it('rejects an invalid detail ID without requesting a different resource', async () => {
    const actor = principal({ permissions: ['streams.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const get = vi.spyOn(streamsApi, 'get')

    renderWithProviders(<AppRoutes />, ['/stream/list/not-a-stream'])

    expect(await screen.findByText('转发规则不存在')).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
  })
})
