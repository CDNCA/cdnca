import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiError } from '../api/auth'
import { nodesApi } from '../api/nodes'
import { NodeGatewayPortBatchModal } from '../pages/NodeGatewayPortBatchModal'
import { renderWithProviders } from '../test/render'

const nodes = [
  { id: '11111111-1111-4111-8111-111111111111', name: 'edge-a', revision: 3 },
  { id: '22222222-2222-4222-8222-222222222222', name: 'edge-b', revision: 7 },
]

// FX39: 更换通讯端口 for several nodes at once — one transition per node,
// each with that node's revision, and a per-node result.
describe('NodeGatewayPortBatchModal', () => {
  it('creates one transition per selected node and reports each result', async () => {
    const create = vi.spyOn(nodesApi, 'createGatewayPortTransition')
      .mockResolvedValueOnce({} as never)
      .mockRejectedValueOnce(new ApiError('conflict', 409, 'node_port_transition_conflict'))
    const user = userEvent.setup()
    renderWithProviders(<NodeGatewayPortBatchModal open accessToken="token" nodes={nodes} onClose={() => {}} />)
    const dialog = await screen.findByRole('dialog', { name: '为 2 个节点更换主控通讯端口' })
    for (const [label, value] of [['旧公开地址', 'gw.example.com:7443'], ['旧监听地址', '0.0.0.0:7443'], ['旧服务名', 'gw.example.com'],
      ['新公开地址', 'gw.example.com:8443'], ['新监听地址', '0.0.0.0:8443'], ['新服务名', 'gw.example.com']] as const) {
      await user.type(within(dialog).getByLabelText(label), value)
    }
    await user.click(within(dialog).getByRole('button', { name: '创建 2 个切换' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls.map((call) => [call[1], call[2].expected_node_revision])).toEqual([[nodes[0].id, 3], [nodes[1].id, 7]])
    expect(create.mock.calls[0]![2].new_endpoint).toEqual({ address: 'gw.example.com:8443', listen_address: '0.0.0.0:8443', server_name: 'gw.example.com' })
    expect(create.mock.calls[0]![3]).not.toBe(create.mock.calls[1]![3])
    expect(await screen.findByText('成功 1 个，失败 1 个')).toBeInTheDocument()
    expect(screen.getByText('端口切换状态已变化，请刷新后重试')).toBeInTheDocument()
  })
})
