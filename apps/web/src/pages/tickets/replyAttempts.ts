import { useRef, useSyncExternalStore } from 'react'

import type { Principal } from '../../api/auth'
import { newIdempotencyKey } from '../../api/market'
import type { ReplyTicketInput, TicketAttachment, TicketMode } from '../../api/tickets'

// 回复的草稿与未决尝试按 身份+mode+工单 各自保存（页面级，列表与详情来回切换不丢）。
// 一次尝试 = 一把 Idempotency-Key + 发起时冻结的输入；结果未知时保留，回到同一工单、同一内容就用原 key 重放；
// 成功或确定拒绝只删这一次尝试。成功后再发相同正文是新尝试（新 key），不按正文永久去重。

export interface ReplyDraft { body: string; internal: boolean; attachments: TicketAttachment[] }

interface ReplyAttempt { fingerprint: string; key: string; unknown: boolean }

export interface ReplySlot {
  draft: ReplyDraft
  attempts: ReplyAttempt[]
  version: number
  listeners: Set<() => void>
}

// changed：槽位变化通知当前挂着的详情（含原视图卸载后重新打开的同一工单）。
function changed(slot: ReplySlot) {
  slot.version++
  for (const listener of slot.listeners) listener()
}

export function setDraft(slot: ReplySlot, draft: ReplyDraft) {
  slot.draft = draft
  changed(slot)
}

export function useSlot(slot: ReplySlot): number {
  return useSyncExternalStore((listener) => {
    slot.listeners.add(listener)
    return () => { slot.listeners.delete(listener) }
  }, () => slot.version)
}

export const emptyDraft = (): ReplyDraft => ({ body: '', internal: false, attachments: [] })

export function replyInputOf(draft: ReplyDraft): ReplyTicketInput {
  return {
    body: draft.body, ...(draft.internal ? { internal: true } : {}),
    ...(draft.attachments.length ? { attachment_ids: draft.attachments.map((item) => item.id) } : {}),
  }
}

export const fingerprintOf = (input: ReplyTicketInput) => JSON.stringify(input)

// identityOf：同一浏览器里代登录/切换账号后，前一身份的未决内容不能被后一身份复用。
export function identityOf(principal: Principal | null | undefined): string {
  if (!principal) return ''
  return [principal.user_id, principal.scope_id, principal.impersonation?.grant_id ?? ''].join('|')
}

export const slotKeyOf = (identity: string, mode: TicketMode, id: string) => `${identity}|${mode}|${id}`

// keyFor 取该内容已有尝试（未知或在途）的 key，没有就新开一次尝试。
export function keyFor(slot: ReplySlot, fingerprint: string): string {
  const found = slot.attempts.find((attempt) => attempt.fingerprint === fingerprint)
  if (found) return found.key
  const key = newIdempotencyKey('ticket-reply')
  slot.attempts.push({ fingerprint, key, unknown: false })
  changed(slot)
  return key
}

export function markUnknown(slot: ReplySlot, key: string) {
  const found = slot.attempts.find((attempt) => attempt.key === key)
  if (found) found.unknown = true
  changed(slot)
}

export function settle(slot: ReplySlot, key: string) {
  slot.attempts = slot.attempts.filter((attempt) => attempt.key !== key)
  changed(slot)
}

export const isUnknown = (slot: ReplySlot, fingerprint: string) =>
  slot.attempts.some((attempt) => attempt.unknown && attempt.fingerprint === fingerprint)

export function useReplySlots() {
  const slots = useRef(new Map<string, ReplySlot>())
  return (key: string): ReplySlot => {
    let slot = slots.current.get(key)
    if (!slot) {
      slot = { draft: emptyDraft(), attempts: [], version: 0, listeners: new Set() }
      slots.current.set(key, slot)
    }
    return slot
  }
}
