import { App } from 'antd'
import { useCallback, useEffect, useRef, useState, type FocusEvent, type KeyboardEvent } from 'react'
import { useTranslation } from 'react-i18next'

import '../../i18n/siteEditV4'

// fix-siteinstant：网站编辑页“改动即生效”。选择类控件（开关、单选、下拉、卡片、标签）改动即提交；
// 文本/数字输入在失焦或回车时提交（多行文本只在失焦时）；成功给“操作成功”轻提示（约 2 秒），
// 失败给错误提示并由调用方把控件回滚到服务端值。

/** 正在键入的控件：文本框、数字框、多行文本（下拉的搜索框不算）。 */
export function isTypingElement(element: EventTarget | null | undefined): boolean {
  if (element instanceof HTMLTextAreaElement) return true
  if (!(element instanceof HTMLInputElement)) return false
  if (element.closest('.ant-select')) return false
  return ['text', 'number', 'search', 'password', 'url', 'email', 'tel'].includes(element.type)
}

/** 焦点在键入控件里：这次改动等失焦/回车再提交。 */
export function typingNow(): boolean {
  return typeof document !== 'undefined' && isTypingElement(document.activeElement)
}

export const instantToastSeconds = 2

/** “操作成功”与失败提示（antd App message，不用静态 API）。 */
export function useInstantFeedback() {
  const { message } = App.useApp()
  const { t } = useTranslation('siteEditV4')
  return {
    // 没有 antd App 上下文（个别单测直接渲染卡片）时 message 是空对象，不提示。
    success: useCallback(() => { void message.success?.(t('instant.success'), instantToastSeconds) }, [message, t]),
    warning: useCallback((text: string) => { void message.warning?.(text, 4) }, [message]),
    failure: useCallback((text?: string) => { void message.error?.(text || t('instant.failed'), 4) }, [message, t]),
  }
}

/**
 * 提交请求：改动后调用 request（或 requestUnlessTyping），下一次渲染后用最新状态调用 commit。
 * 串行化：busy（请求进行中）时只记下“还有一次”，结束后用那时的最新状态再提交一次，
 * 所以快速连改只发最后一次。commit 自己负责“有改动、校验通过”才发。
 * typingProps 挂在面板容器上：键入控件失焦、单行输入回车时提交。
 */
export function useCommitRequest(commit: () => void, busy = false) {
  const [tick, setTick] = useState(0)
  const servedRef = useRef(0)
  const commitRef = useRef(commit)
  commitRef.current = commit
  useEffect(() => {
    if (busy || tick === servedRef.current) return
    servedRef.current = tick
    commitRef.current()
  }, [tick, busy])
  const request = useCallback(() => setTick((value) => value + 1), [])
  const requestUnlessTyping = useCallback(() => {
    if (!typingNow()) setTick((value) => value + 1)
  }, [])
  return { request, requestUnlessTyping, typingProps: typingCommitProps(request) }
}

/**
 * 服务端值更新后重建草稿：提交发出后用户又改过的字段（与发出时不同）保留，等下一次提交；
 * 其余字段取服务端值。没有在途提交（sent 为空）就整份取服务端值。
 */
export function rebaseDraft<T extends object>(stored: T, current: T, sent: T | null): T {
  if (!sent) return stored
  const next = { ...stored }
  for (const key of Object.keys(current) as (keyof T)[]) {
    if (JSON.stringify(current[key]) !== JSON.stringify(sent[key])) next[key] = current[key]
  }
  return next
}

/**
 * 一块设置的“改动即生效”草稿：set 改字段（选择类立即提交，键入类等失焦/回车）；
 * submit 由调用方发请求（只在有改动且校验通过时调用）。busy 期间（请求进行中、
 * 或刚保存后重读服务端值）不发，结束后用最新草稿与版本号再发一次。
 * 服务端值更新时，发出后又改过的字段保留，其余取服务端值；revert 回滚到服务端值。
 */
export function useInstantDraft<T extends object>(stored: T, options: {
  busy: boolean
  isChanged?: (draft: T, stored: T) => boolean
  isValid?: (draft: T) => boolean
  submit: (draft: T) => void
}) {
  const [draft, setDraftState] = useState<T>(stored)
  const sentRef = useRef<T | null>(null)
  const storedKey = JSON.stringify(stored)
  const storedRef = useRef(stored)
  storedRef.current = stored
  useEffect(() => {
    setDraftState((current) => rebaseDraft(storedRef.current, current, sentRef.current))
    sentRef.current = null
  }, [storedKey])
  const commit = () => {
    const changed = options.isChanged ? options.isChanged(draft, stored) : JSON.stringify(draft) !== storedKey
    if (!changed || options.isValid?.(draft) === false) return
    sentRef.current = draft
    options.submit(draft)
  }
  const { request, requestUnlessTyping, typingProps } = useCommitRequest(commit, options.busy)
  const set = useCallback((patch: Partial<T>) => {
    setDraftState((current) => ({ ...current, ...patch }))
    requestUnlessTyping()
  }, [requestUnlessTyping])
  const revert = useCallback(() => {
    sentRef.current = null
    setDraftState(storedRef.current)
  }, [])
  return { draft, set, setDraft: setDraftState, request, typingProps, revert }
}

/** 容器上的失焦/回车提交；多行文本按回车是换行，不提交。 */
export function typingCommitProps(flush: () => void) {
  return {
    onBlur: (event: FocusEvent<HTMLElement>) => {
      if (isTypingElement(event.target)) flush()
    },
    onKeyDown: (event: KeyboardEvent<HTMLElement>) => {
      if (event.key !== 'Enter' || event.nativeEvent.isComposing) return
      if (event.target instanceof HTMLInputElement && isTypingElement(event.target)) flush()
    },
  }
}
