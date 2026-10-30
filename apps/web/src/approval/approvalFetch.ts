// 平台审批中心的前端拦截：包装全局 fetch，只处理 428 approval_required。
// 弹窗填原因后带 X-Approval-Reason 原样重发；服务端存为待审单返回 202，这里把它换成
// 一个非 2xx 的 approval_submitted 响应，调用方按失败处理、不会把 202 当业务结果解析。
// 审批中心关闭时服务端永不返回 428，包装器对所有请求零影响。

export type ApprovalPrompt = (rule: string) => Promise<string | null>
export type ApprovalNotice = (result: 'submitted' | 'cancelled', rule: string) => void

// Grouped rules (the L4 batch delete sends one DELETE per stream) reuse the
// reason and group of the first prompt for this long, so one batch makes one request.
const groupWindowMs = 2 * 60 * 1000
const groupedRules = new Set(['stream.batch_delete'])

interface GroupMemo { rule: string; reason: string; group: string; until: number }

export function createApprovalFetch(base: typeof fetch, prompt: ApprovalPrompt, notice: ApprovalNotice, now: () => number = Date.now): typeof fetch {
  let memo: GroupMemo | null = null
  return async (input, init) => {
    // A Request body can be read once: keep a copy for the resend.
    const retry = input instanceof Request ? input.clone() : input
    const response = await base(input, init)
    if (response.status !== 428) return response
    const rule = await approvalRule(response.clone())
    if (!rule) return response
    let reason: string | null
    let group: string | undefined
    let prompted = false
    if (memo && memo.rule === rule && memo.until > now()) {
      reason = memo.reason
      group = memo.group
    } else {
      reason = await prompt(rule)
      prompted = true
      if (reason === null) {
        notice('cancelled', rule)
        return response
      }
      if (groupedRules.has(rule)) {
        group = `ac-${globalThis.crypto.randomUUID()}`
        memo = { rule, reason, group, until: now() + groupWindowMs }
      }
    }
    const headers = new Headers(init?.headers ?? (retry instanceof Request ? retry.headers : undefined))
    headers.set('X-Approval-Reason', encodeURIComponent(reason))
    if (group) headers.set('X-Approval-Group', group)
    const resent = await base(retry, { ...init, headers })
    if (resent.status !== 202) return resent
    if (prompted) notice('submitted', rule)
    return new Response(JSON.stringify({ error: { code: 'approval_submitted', message: 'submitted for approval' } }), {
      status: 409, headers: { 'Content-Type': 'application/json' },
    })
  }
}

async function approvalRule(response: Response): Promise<string | null> {
  try {
    const body = await response.json() as { error?: { code?: unknown; details?: { rule?: unknown } } }
    if (body?.error?.code !== 'approval_required') return null
    return typeof body.error.details?.rule === 'string' ? body.error.details.rule : ''
  } catch {
    return null
  }
}
