import { screen } from '@testing-library/react'
import type { AdminSitePublication } from '../../api/sitePublications'
import { renderWithProviders } from '../../test/render'
import PublicationLeftOutNodesAlert from './PublicationLeftOutNodesAlert'

const left = ['018cc251-f400-7def-8000-0000000000a1', '018cc251-f400-7def-8000-0000000000a2']
const unsupported = ['018cc251-f400-7def-8000-0000000000b1']
const publication: AdminSitePublication = {
  id: '018cc251-f400-7def-8000-000000000060',
  configuration_scope_id: '018cc251-f400-7def-8000-000000000050',
  source_revision: 7,
  config_version_id: '018cc251-f400-7def-8000-000000000062',
  rollout_id: '018cc251-f400-7def-8000-000000000061',
  canonical_source_sha256: '2'.repeat(64),
  artifact_sha256: '3'.repeat(64),
  target: { kind: 'nodes', resolved_sha256: '4'.repeat(64) },
  node_count: 2,
  created_at: '2026-11-09T08:00:00Z',
}

describe('PublicationLeftOutNodesAlert', () => {
  it('warns that the left-out nodes still run the old configuration and lists them', () => {
    renderWithProviders(<PublicationLeftOutNodesAlert publication={{
      ...publication, key_envelope_oversized_node_ids: left, site_selection_unsupported_node_ids: unsupported,
    }} />)
    const alert = screen.getByTestId('site-publication-left-out-nodes')
    expect(alert).toHaveClass('ant-alert-warning')
    expect(alert).toHaveTextContent(
      '2 台节点仍在用旧配置，本次新屏蔽的站点、删除的转发在这些节点上仍然生效，请升级到支持能力 82 的节点版本，升级后自动补发')
    for (const node of [...left, ...unsupported]) expect(alert).toHaveTextContent(node)
    expect(alert).toHaveTextContent('1 台节点不支持按节点屏蔽站点')
  })

  it('shows only the part a publication has', () => {
    renderWithProviders(<PublicationLeftOutNodesAlert publication={{ ...publication, key_envelope_oversized_node_ids: left }} />)
    const alert = screen.getByTestId('site-publication-left-out-nodes')
    expect(alert).toHaveTextContent('2 台节点仍在用旧配置')
    expect(alert).not.toHaveTextContent('不支持按节点屏蔽站点')
  })

  it('renders nothing when the publication reached every node as intended', () => {
    renderWithProviders(<PublicationLeftOutNodesAlert publication={publication} />)
    expect(screen.queryByTestId('site-publication-left-out-nodes')).not.toBeInTheDocument()
  })
})
