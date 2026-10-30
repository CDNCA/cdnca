import { nodeInstallationTicketsApi, nodeTicketFrozen, type NodeTicket } from './nodeInstallationTickets'

const id = '018f0000-0000-7000-8000-000000000001'
const ticket = (patch: Partial<NodeTicket> = {}): NodeTicket => ({
  node_id: id, state: 'expired', node_status: 'service_ticket_expired', issued_at: '2026-09-20T00:00:00Z',
  not_after: '2026-10-20T00:00:00Z', days_left: 0, reported_at: '2026-10-21T00:00:00Z', ...patch,
})
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status })

describe('node installation tickets (fix-stoppolicy2)', () => {
  it('reads one exact batch in the requested order', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ observed_at: '2026-10-21T00:00:00Z', items: [ticket()] }))
    await expect(nodeInstallationTicketsApi.get('token', [id])).resolves.toMatchObject({ items: [{ node_id: id, state: 'expired' }] })
    expect(String(fetch.mock.calls[0][0])).toBe(`/v1/nodes/installation-tickets?node_id=${id}`)
  })

  it('refuses a mismatched or malformed answer and bad identifiers before fetch', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ observed_at: '2026-10-21T00:00:00Z', items: [ticket({ node_id: '018f0000-0000-7000-8000-000000000002' })] }))
      .mockResolvedValueOnce(json({ observed_at: '2026-10-21T00:00:00Z', items: [ticket({ state: 'frozen' as never })] }))
      .mockResolvedValueOnce(json({ observed_at: '2026-10-21T00:00:00Z', items: [] }))
    for (let index = 0; index < 3; index++) {
      await expect(nodeInstallationTicketsApi.get('token', [id])).rejects.toMatchObject({ code: 'invalid_response' })
    }
    await expect(nodeInstallationTicketsApi.get('token', ['not-a-uuid'])).rejects.toMatchObject({ code: 'validation_error' })
    await expect(nodeInstallationTicketsApi.get('token', [id, id])).rejects.toMatchObject({ code: 'validation_error' })
    expect(fetch).toHaveBeenCalledTimes(3)
  })

  it('treats an ended ticket as frozen, but not a ban, a valid ticket or a node before its first ticket', () => {
    expect(nodeTicketFrozen(ticket())).toBe(true)
    expect(nodeTicketFrozen(ticket({ node_status: 'serving' }))).toBe(true) // not_after passed, renewal not yet reported
    expect(nodeTicketFrozen(ticket({ state: 'valid', node_status: 'service_ticket_expired' }))).toBe(true)
    expect(nodeTicketFrozen(ticket({ state: 'valid', node_status: 'serving', days_left: 12 }))).toBe(false)
    expect(nodeTicketFrozen(ticket({ node_status: 'banned' }))).toBe(false)
    expect(nodeTicketFrozen(ticket({ state: 'no_ticket', node_status: 'no_ticket', issued_at: null, not_after: null, days_left: null }))).toBe(false)
    expect(nodeTicketFrozen(undefined)).toBe(false)
  })
})
