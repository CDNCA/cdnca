import { describe, expect, it, vi } from 'vitest'

import { createApprovalFetch } from './approvalFetch'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const required = (rule: string) => json({ error: { code: 'approval_required', details: { rule } } }, 428)
const submitted = () => json({ code: 'approval_submitted', approval: { id: 'a' } }, 202)

describe('approval fetch wrapper', () => {
  it('passes every other response through untouched (center off never answers 428)', async () => {
    const response = json({ ok: true })
    const base = vi.fn(async () => response)
    const prompt = vi.fn()
    const wrapped = createApprovalFetch(base as unknown as typeof fetch, prompt, vi.fn())
    expect(await wrapped('/v1/sites/batch-action', { method: 'POST' })).toBe(response)
    expect(prompt).not.toHaveBeenCalled()
    const other428 = json({ error: { code: 'mfa_step_up_required' } }, 428)
    base.mockResolvedValueOnce(other428)
    expect(await wrapped('/v1/x')).toBe(other428)
    expect(prompt).not.toHaveBeenCalled()
  })

  it('asks for a reason and resends with the URL-encoded reason header', async () => {
    const base = vi.fn<typeof fetch>().mockResolvedValueOnce(required('firewall.policy')).mockResolvedValueOnce(submitted())
    const notice = vi.fn()
    const wrapped = createApprovalFetch(base, async () => '修复误封', notice)
    const response = await wrapped('/v1/firewall/policy', { method: 'PUT', body: '{}', headers: { 'Idempotency-Key': 'k1' } })
    expect(base).toHaveBeenCalledTimes(2)
    const headers = new Headers(base.mock.calls[1]![1]!.headers)
    expect(headers.get('X-Approval-Reason')).toBe(encodeURIComponent('修复误封'))
    expect(headers.get('Idempotency-Key')).toBe('k1')
    expect(headers.get('X-Approval-Group')).toBeNull()
    expect(base.mock.calls[1]![1]!.body).toBe('{}')
    // The caller sees a failure, never a 202 it would parse as the business result.
    expect(response.status).toBe(409)
    expect(await response.json()).toMatchObject({ error: { code: 'approval_submitted' } })
    expect(notice).toHaveBeenCalledWith('submitted', 'firewall.policy')
  })

  it('returns the 428 when the reason dialog is cancelled', async () => {
    const original = required('user.delete')
    const base = vi.fn<typeof fetch>().mockResolvedValueOnce(original)
    const notice = vi.fn()
    const response = await createApprovalFetch(base, async () => null, notice)('/v1/admin/users/x', { method: 'DELETE' })
    expect(response).toBe(original)
    expect(base).toHaveBeenCalledTimes(1)
    expect(notice).toHaveBeenCalledWith('cancelled', 'user.delete')
  })

  it('reuses the reason and group for the per-stream deletes of one batch', async () => {
    const base = vi.fn<typeof fetch>()
    for (let index = 0; index < 3; index += 1) base.mockResolvedValueOnce(required('stream.batch_delete')).mockResolvedValueOnce(submitted())
    const prompt = vi.fn(async () => 'cleanup')
    const notice = vi.fn()
    let now = 1_000
    const wrapped = createApprovalFetch(base, prompt, notice, () => now)
    await wrapped('/v1/streams/1', { method: 'DELETE' })
    await wrapped('/v1/streams/2', { method: 'DELETE' })
    now += 3 * 60 * 1000 // after the window a new batch prompts again
    await wrapped('/v1/streams/3', { method: 'DELETE' })
    expect(prompt).toHaveBeenCalledTimes(2)
    const groups = [1, 3, 5].map((call) => new Headers(base.mock.calls[call]![1]!.headers).get('X-Approval-Group'))
    expect(groups[0]).toMatch(/^ac-/)
    expect(groups[1]).toBe(groups[0])
    expect(groups[2]).not.toBe(groups[0])
    expect(notice).toHaveBeenCalledTimes(2)
  })
})
