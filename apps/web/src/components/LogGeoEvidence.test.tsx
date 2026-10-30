import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import LogGeoEvidence from './LogGeoEvidence'
import { renderWithProviders } from '../test/render'

describe('LogGeoEvidence', () => {
  it('loads only on demand and renders explicit provenance', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ data: {
      event_id: 'event-1', occurred_at: '2026-08-08T03:00:00Z',
      site_id: '018f0000-0000-7000-8000-000000000002', node_id: '018f0000-0000-7000-8000-000000000003',
      source_country_code: '', source_carrier: '', country_code: '__unknown__', region: '__unknown__',
      city: '__unknown__', carrier: '__unknown__', asn: 0, address_family: 'ipv4', lookup_reason: 'no_prefix_match',
      resolution: 'unknown', reconciliation: 'match', prefix_length: 0, database_provider: 'example-geo',
      database_version: 'geo-2026.08', database_sha256: 'b'.repeat(64), database_published_at: '2026-08-01T00:00:00Z',
      database_effective_at: '2026-08-02T00:00:00Z',
    } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))

    renderWithProviders(<LogGeoEvidence accessToken="token" audience="tenant" kind="block" event={{
      event_id: 'event-1', occurred_at: '2026-08-08T03:00:00Z',
      site_id: '018f0000-0000-7000-8000-000000000002', node_id: '018f0000-0000-7000-8000-000000000003',
      client_ip: '198.51.100.7',
    }} />)

    expect(fetchSpy).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: '核验 IP 归属' }))
    expect(await screen.findByText('未知')).toBeInTheDocument()
    expect(screen.getByText('geo-2026.08')).toBeInTheDocument()
    expect(screen.getByText('无匹配网段')).toBeInTheDocument()
    expect(screen.getByText('IPv4')).toBeInTheDocument()
    expect(screen.getByText('example-geo')).toBeInTheDocument()
    expect(screen.queryByText('198.51.100.7')).not.toBeInTheDocument()
  })
})
