import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'

import { systemSettingsApi } from '../api/systemSettings'
import { useSessionStore } from '../auth/session'
import { applyScriptNonce } from './scriptNonce'

// 安全模式：地址带 ?safe_mode=1 后，本标签页不再加载全站 JS（sessionStorage 记住，关闭标签页即失效；?safe_mode=0 关闭）。
const safeModeStorageKey = 'cdnca:global-js-safe-mode'
const injectedMarker = 'data-cdnca-global-js'

// eslint-disable-next-line react-refresh/only-export-components
export function globalScriptSafeMode(location: Pick<Location, 'search'> = window.location): boolean {
  const flag = new URLSearchParams(location.search).get('safe_mode')
  try {
    if (flag === '1') window.sessionStorage.setItem(safeModeStorageKey, '1')
    if (flag === '0') window.sessionStorage.removeItem(safeModeStorageKey)
    return window.sessionStorage.getItem(safeModeStorageKey) === '1'
  } catch {
    return flag === '1'
  }
}

/**
 * 把系统设置里的“全站JS代码”注入用户端页面。纯 JS 包成 <script>；以 “<” 开头时按 HTML 片段处理，
 * 其中的 <script> 重新创建以便执行（统计代码常见写法）。每个 <script> 带页面 CSP nonce（不依赖 unsafe-inline）。返回的函数移除已注入的节点。
 */
// eslint-disable-next-line react-refresh/only-export-components
export function injectGlobalScript(code: string, target: HTMLElement = document.body): () => void {
  const nodes: Node[] = []
  const source = code.trim()
  if (!source) return () => undefined
  if (!source.startsWith('<')) {
    const script = applyScriptNonce(document.createElement('script'))
    script.setAttribute(injectedMarker, '')
    script.text = source
    nodes.push(script)
  } else {
    const template = document.createElement('template')
    template.innerHTML = source
    for (const node of Array.from(template.content.childNodes)) {
      if (node instanceof HTMLScriptElement) {
        const script = document.createElement('script')
        for (const attribute of Array.from(node.attributes)) {
          if (attribute.name !== 'nonce') script.setAttribute(attribute.name, attribute.value)
        }
        applyScriptNonce(script)
        script.setAttribute(injectedMarker, '')
        script.text = node.text
        nodes.push(script)
      } else {
        if (node instanceof Element) node.setAttribute(injectedMarker, '')
        nodes.push(node)
      }
    }
  }
  for (const node of nodes) target.appendChild(node)
  return () => {
    for (const node of nodes) node.parentNode?.removeChild(node)
  }
}

/** 只在租户用户（非代登录）会话加载；管理端从不加载，坏脚本不会锁死后台。 */
export function GlobalScript() {
  const principal = useSessionStore((state) => state.principal)
  const token = useSessionStore((state) => state.accessToken)
  const enabled = Boolean(token && principal?.scope_kind === 'tenant' && !principal.impersonation && !globalScriptSafeMode())
  const query = useQuery({
    queryKey: ['system-settings', 'public', token],
    queryFn: () => systemSettingsApi.public(token!),
    enabled, retry: false, staleTime: 60_000,
  })
  const code = enabled ? query.data?.global_js ?? '' : ''
  useEffect(() => {
    if (!code) return
    try {
      return injectGlobalScript(code)
    } catch {
      return undefined
    }
  }, [code])
  return null
}
