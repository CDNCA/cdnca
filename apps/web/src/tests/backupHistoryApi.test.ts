import { backupHistoryApi, type BackupHistoryRecord } from '../api/backupHistory'

const record: BackupHistoryRecord = {
  backup_id: 'run-1', started_at: '2026-09-28T01:00:00Z', completed_at: '2026-09-28T01:02:00Z', state: 'succeeded',
  result_code: 'backup_succeeded', manifest_sha256: 'a'.repeat(64), recovery_point_at: '2026-09-28T00:59:00Z', observed_rpo_seconds: 60,
  outcome_unknown: false, signature_valid: true, terminal_state: 'succeeded', reason_code: 'terminal_recorded',
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

it('serializes signed-history filters and validates the immutable response contract', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ schema: 'cdnca.control-backup-history/v1', items: [record], total_count: 2, next_cursor: 'cursor-1', snapshot_at: '2026-09-28T02:00:00Z' }))
  const result = await backupHistoryApi.list('token', { backupId: 'run-1', state: 'succeeded', from: '2026-09-01T00:00:00Z', to: '2026-09-28T00:00:00Z', limit: 30, cursor: 'cursor-0' })
  const [input, init] = fetchSpy.mock.calls[0]
  const params = new URL(String(input), 'https://test').searchParams
  expect(Object.fromEntries(params)).toEqual({ backup_id: 'run-1', state: 'succeeded', from: '2026-09-01T00:00:00Z', to: '2026-09-28T00:00:00Z', limit: '30', cursor: 'cursor-0' })
  expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer token')
  expect(result.items[0]).toMatchObject({ backup_id: 'run-1', outcome_unknown: false })
})

it('compares RFC3339 bounds by time when fractional seconds are present', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ schema: 'cdnca.control-backup-history/v1', items: [], total_count: 0, snapshot_at: '2026-09-28T02:00:00Z' }))
  await backupHistoryApi.list('token', { from: '2026-09-28T01:00:00Z', to: '2026-09-28T01:00:00.900Z' })
  expect(fetchSpy).toHaveBeenCalledOnce()
})

it.each([
  { backupId: 'bad id' }, { state: 'running' }, { limit: 20 }, { limit: 50 }, { limit: 301 }, { from: 'yesterday' }, { cursor: '' }, { backupId: 'x'.repeat(129) },
])('rejects invalid filters without requesting', async (filters) => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
  await expect(backupHistoryApi.list('token', filters as never)).rejects.toMatchObject({ code: 'backup_history_invalid_request' })
  expect(fetchSpy).not.toHaveBeenCalled()
})

it('keeps missing terminal facts visibly unknown and preserves service errors', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ schema: 'cdnca.control-backup-history/v1', items: [{ ...record, completed_at: undefined, state: 'unknown', result_code: 'backup_outcome_unknown', outcome_unknown: true, signature_valid: true, terminal_state: 'unavailable', reason_code: 'terminal_unavailable' }], total_count: 1, snapshot_at: '2026-09-28T02:00:00Z' }))
    .mockResolvedValueOnce(json({ error: { code: 'backup_history_unavailable' } }, 503))
  const page = await backupHistoryApi.list('token', {})
  expect(page.items[0]).toMatchObject({ state: 'unknown', outcome_unknown: true })
  expect(page.items[0].completed_at).toBeUndefined()
  await expect(backupHistoryApi.list('token', {})).rejects.toMatchObject({ code: 'backup_history_unavailable', status: 503 })
})

it('rejects malformed signed-history records', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ schema: 'cdnca.control-backup-history/v1', items: [{ ...record, signature_valid: 'yes' }], total_count: 1, snapshot_at: '2026-09-28T02:00:00Z' }))
  await expect(backupHistoryApi.list('token', {})).rejects.toMatchObject({ code: 'invalid_response' })
})


it('accepts 300 records and rejects a response exceeding the page maximum', async () => {
  const page = { schema: 'cdnca.control-backup-history/v1', items: Array.from({ length: 300 }, (_, index) => ({ ...record, backup_id: `run-${index}` })), total_count: 301, next_cursor: 'next', snapshot_at: '2026-09-28T02:00:00Z' }
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(page)).mockResolvedValueOnce(json({ ...page, items: [...page.items, { ...record, backup_id: 'run-300' }] }))
  expect((await backupHistoryApi.list('token', { limit: 300 })).items).toHaveLength(300)
  await expect(backupHistoryApi.list('token', { limit: 300 })).rejects.toMatchObject({ code: 'invalid_response' })
})
