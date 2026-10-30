import { screen } from '@testing-library/react'

import type { NodeMetricsLatest } from '../api/nodes'
import { changeLocale } from '../i18n'
import { NodeXDPCell } from '../pages/NodeListPage'
import { renderWithProviders } from '../test/render'

// PJ-E03/E04: a node whose DDoS protection table failed to apply or
// cannot run shows a protection fault in the node list, not its XDP mode.
describe('node list DDoS protection state', () => {
  const time = '2026-10-24T10:00:00Z'
  const sample = (telemetry: Partial<NonNullable<NodeMetricsLatest['telemetry']>>): NodeMetricsLatest => ({
    node_id: '018f0000-0000-7000-8000-000000000001', node_name: 'Edge one', record_kind: 'host_metric',
    config_revision: 0, active_config_revision: 0, publication_sequence: 1, observed_at: time, ingested_at: time,
    probe_port: 0, healthy: false, probe_succeeded: false, consecutive_failures: 0, consecutive_successes: 0,
    probes_total: 0, probe_failures_total: 0, recovered: false, recovery_notified: false, rolled_back: false,
    known: true, cpu_percent: 0, memory_used_bytes: 0, memory_total_bytes: 1, active_connections: 0,
    rx_bandwidth_bps: 0, tx_bandwidth_bps: 0, total_rx_bytes: 0, total_tx_bytes: 0,
    telemetry: { schema_version: 1, total_rx_bytes: 0, total_tx_bytes: 0, disks: [], network_interfaces: [], ...telemetry },
    puback_stream: 'NODE_MONITORING_STATUS', puback_sequence: 1,
    consumer_durable: 'control_api_node_metrics', consumer_sequence: 1,
  })

  beforeEach(async () => {
    await changeLocale('zh-CN')
  })

  it('shows 防护不可用 when nftables is missing', () => {
    renderWithProviders(<NodeXDPCell sample={sample({
      xdp: { mode: 'disabled', reason: 'disabled' },
      ddos_protection: { state: 'unavailable', reason: 'nft_missing', detail: 'nft command not found: install nftables' },
    })} />)
    const cell = screen.getByRole('status')
    expect(cell).toHaveTextContent('防护不可用')
    expect(cell).toHaveClass('node-ddos-unavailable')
  })

  it('shows 防护异常 when the table failed to apply', () => {
    renderWithProviders(<NodeXDPCell sample={sample({
      xdp: { mode: 'nftables', reason: 'bpf_unavailable' },
      ddos_protection: { state: 'failed', detail: 'nft: Error: Could not process rule' },
    })} />)
    expect(screen.getByRole('status')).toHaveTextContent('防护异常')
  })

  it('keeps the XDP mode when the protection is applied', () => {
    renderWithProviders(<NodeXDPCell sample={sample({
      xdp: { mode: 'native', interfaces: ['eth0=native'] },
      ddos_protection: { state: 'applied' },
    })} />)
    expect(screen.queryByRole('status')).toBeNull()
    expect(screen.getByText('原生 XDP')).toBeInTheDocument()
  })
})
