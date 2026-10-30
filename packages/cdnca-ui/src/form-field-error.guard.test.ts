// Guard (fix-feedbackui2, warn only): a form page whose submit failure may be
// a field refusal (validation_error / invalid_request) but goes straight to the
// shared dialog instead of useFormSubmitError / applyFormSubmitError /
// applyApiFieldError / form.setFields. It never fails: it prints the remaining
// pages so they can be scheduled. Rules: ../COMPONENTS.md "字段错误就地显示".
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = join(__dirname, '..', '..', '..')
const ends = ['apps/web/src', 'apps/operator-console/src', 'apps/license-portal/src', 'apps/seller-portal/src']

function sources(dir: string): string[] {
  let names: string[]
  try { names = readdirSync(dir) } catch { return [] }
  return names.flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === 'node_modules' || name === 'dist' || name === 'i18n' ? [] : sources(path)
    return /\.tsx$/.test(name) && !/\.test\.tsx$/.test(name) ? [path] : []
  })
}

const formPage = /\bForm\.useForm\b/
const fieldAware = /\b(?:useFormSubmitError|applyFormSubmitError|applyApiFieldError)\b|\.setFields\(\s*\[/
// A submit failure handler that opens the dialog (onError: …feedback.error(…) / catch { feedback.error(…) }).
const dialogOnFailure = /(?:onError\s*[:=(]|\bcatch\s*\(?)[^]{0,240}?\bfeedback\.error\(/g

// Not a form submit (fix-fielderr-be5, judged one by one): a row / toolbar
// button, a switch, an upload, a confirm-and-act on a selection, or a form
// whose field is never named by the server. The handler is named by the
// mutation / function it belongs to, so line moves do not matter.
// Keep the reason with each entry; a page that gets a fillable submit later
// is not covered here (only the listed handler names are). A page that uses
// the field hooks anywhere is not scanned at all, so its row buttons (accounts
// verify/delete, supply retire, binding remove, IP intel check, migration
// confirm/control/decide/clear, release transitions, brand upload) need no entry.
export const notFormSubmit: Record<string, Record<string, string>> = {
  'apps/web/src/pages/aggregated-edge/AggregatedEdgeImportPage.tsx': { refresh: '导入列表行「刷新」按钮', remove: '导入列表行「删除」按钮' },
  'apps/web/src/pages/aggregated-edge/AggregatedEdgeSyncPage.tsx': {
    sync: '详情抽屉「同步」按钮（无表单字段）', observe: '详情抽屉「观测」按钮', retry: '详情抽屉「重试校验」按钮',
    refreshFallback: '账号列表行「刷新回源」按钮',
  },
  'apps/web/src/pages/domain-trust/DomainSecurityPage.tsx': {
    remove: '黑名单行「删除」按钮', exportCSV: '导出 CSV 下载', disable: '命中列表批量停用所选站点',
    revoke: '所有权列表行「撤销」按钮', release: '停用列表行「解除」按钮',
  },
  'apps/web/src/pages/node-market/OfferListingForm.tsx': {
    submit: '批量上架：结果按节点逐行返回在结果表里，市场拒绝是 listing.refused.* 码而非字段',
    saveTemplate: '「另存为模板」名称输入在独立小弹窗（非 Form），名称超长由 maxLength 拦住',
  },
  'apps/web/src/pages/node-scheduling/EscalateLineGroupsPanel.tsx': { tierMutation: '线路组行档位下拉即时保存', revokeMutation: '授权列表行「撤销」按钮' },
  'apps/web/src/pages/plugin-providers/PluginProvidersPage.tsx': { action: '插件行「启用/停用/跑契约」按钮；高风险确认弹窗自带错误条（confirmation 分支不弹窗）' },
  'apps/web/src/pages/security/ChallengePoliciesPanel.tsx': { publicationAction: '策略行「发布/刷新/推进」按钮' },
  'apps/operator-console/src/pages/IdentityProofSettingsPage.tsx': { save: '「供货方须实名」开关即时保存（SwitchRow）' },
}

// The mutation / function a handler belongs to: the last `const x = useMutation(`,
// `const x = async`, `const x = (` or `function x` before it.
function handlerName(before: string): string {
  const names = [...before.matchAll(/(?:const|let)\s+(?:\{[^}]*\}|(\w+))\s*=\s*(?:useMutation|async|\(|useCallback)|function\s+(\w+)/g)]
  const last = names.at(-1)
  return last?.[1] ?? last?.[2] ?? ''
}

/** Form pages that show a submit failure in the dialog and never mark a field: file:line of each handler. */
export function fieldErrorDialogs(file: string, text: string): string[] {
  if (!formPage.test(text) || fieldAware.test(text)) return []
  return [...text.matchAll(dialogOnFailure)].map((match) => `${file}:${text.slice(0, match.index).split('\n').length}`)
}

/** fieldErrorDialogs without the handlers listed in notFormSubmit. */
export function remainingFieldErrorDialogs(file: string, text: string): string[] {
  const allowed = notFormSubmit[file] ?? {}
  return fieldErrorDialogs(file, text).filter((entry) => {
    const line = Number(entry.slice(entry.lastIndexOf(':') + 1))
    return !Object.prototype.hasOwnProperty.call(allowed, handlerName(text.split('\n').slice(0, line).join('\n')))
  })
}

describe('form submit errors are marked on fields (fix-feedbackui2, warn only)', () => {
  it('flags a form page whose onError only opens the dialog', () => {
    const page = 'const [form] = Form.useForm()\nuseMutation({ onError: (error) => feedback.error(errorText(error)) })'
    expect(fieldErrorDialogs('a.tsx', page)).toEqual(['a.tsx:2'])
    expect(fieldErrorDialogs('a.tsx', `${page}\nconst mark = useFormSubmitError(form)`)).toEqual([])
    expect(fieldErrorDialogs('a.tsx', 'useMutation({ onError: (e) => feedback.error(x) })')).toEqual([])
  })

  it('skips a listed non-form handler but still flags a new one on the same page', () => {
    const file = 'apps/web/src/pages/domain-trust/DomainSecurityPage.tsx'
    const page = 'const [form] = Form.useForm()\nconst remove = useMutation({ onError: (e) => feedback.error(x) })\nconst rename = useMutation({ onError: (e) => feedback.error(x) })'
    expect(remainingFieldErrorDialogs(file, page)).toEqual([`${file}:3`])
  })

  it('every allow-list entry has a reason', () => {
    for (const [file, handlers] of Object.entries(notFormSubmit)) {
      for (const [name, reason] of Object.entries(handlers)) expect(reason.length, `${file} ${name}`).toBeGreaterThan(4)
    }
  })

  it('lists the remaining form pages', () => {
    const found = ends.flatMap((end) => sources(join(root, end)))
      .flatMap((path) => remainingFieldErrorDialogs(relative(root, path), readFileSync(path, 'utf8')))
    if (found.length > 0) {
      console.warn(`[fix-feedbackui2] ${found.length} 处表单提交失败仍直接弹窗、未挂字段（剩余清单，不判失败；非表单提交见 notFormSubmit）：\n${found.join('\n')}`)
    }
    expect(Array.isArray(found)).toBe(true)
  })
})
