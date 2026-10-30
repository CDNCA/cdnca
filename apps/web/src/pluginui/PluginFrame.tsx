import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { pluginProxy, type PluginUIPage } from '../api/pluginUI'
import { roleForPrincipal, useSessionStore } from '../auth/session'
import {
  frameURL,
  handleBridgeRequest,
  isHello,
  newNonce,
  protocolVersion,
  sandboxTokens,
  type BridgeHost,
} from './bridge'

interface Props {
  page: PluginUIPage
  siteID?: string
  title: string
}

/**
 * PluginFrame mounts one ui_page plugin page (PA-19): a sandboxed iframe on
 * the plugin's own origin (no allow-same-origin: opaque origin, no access
 * to this app's cookies or storage) and a private MessageChannel that only
 * answers the whitelisted bridge methods.
 */
export function PluginFrame({ page, siteID, title }: Props) {
  const frame = useRef<HTMLIFrameElement>(null)
  const navigate = useNavigate()
  const { i18n } = useTranslation()
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  // One nonce per mount (callers key the frame by plugin, page and site, so
  // another page is another mount with a fresh nonce).
  const [nonce] = useState(newNonce)
  const src = useMemo(() => frameURL(page.url, nonce), [page.url, nonce])
  const hostRef = useRef<BridgeHost | null>(null)

  hostRef.current = principal ? {
    context: () => ({
      protocol: protocolVersion,
      plugin_id: page.plugin_id,
      page_id: page.page_id,
      user: { id: principal.user_id, display_name: principal.display_name, role: roleForPrincipal(principal) },
      tenant: { scope_id: principal.scope_id, scope_kind: principal.scope_kind },
      site_id: siteID ?? null,
      locale: i18n.resolvedLanguage ?? 'zh-CN',
      theme: document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light',
    }),
    navigate: (path) => navigate(path),
    apiRequest: (request) => pluginProxy(accessToken ?? '', page.plugin_id, {
      ...request, page_id: page.page_id, ...(siteID ? { site_id: siteID } : {}),
    }),
  } : null

  useEffect(() => {
    let port: MessagePort | null = null
    const onMessage = (event: MessageEvent) => {
      // Only this frame's window, and only once: the origin of a sandboxed
      // frame is "null", so the window identity plus the nonce decide.
      const target = frame.current?.contentWindow
      if (port || !target || event.source !== target || !isHello(event.data, nonce)) return
      const channel = new MessageChannel()
      port = channel.port1
      port.onmessage = (portEvent) => {
        const host = hostRef.current
        if (!host) return
        void handleBridgeRequest(nonce, portEvent.data, host).then((response) => {
          if (response) port?.postMessage(response)
        })
      }
      // targetOrigin "*" is required for an opaque-origin frame; the port
      // goes to that frame's window only.
      target.postMessage({ protocol: protocolVersion, type: 'cdnca.ready', nonce }, '*', [channel.port2])
    }
    window.addEventListener('message', onMessage)
    return () => {
      window.removeEventListener('message', onMessage)
      port?.close()
    }
  }, [nonce])

  return (
    <iframe
      ref={frame}
      className="plugin-ui-frame"
      title={title}
      src={src}
      sandbox={sandboxTokens.join(' ')}
      referrerPolicy="no-referrer"
      allow=""
      loading="lazy"
      style={{ width: '100%', minHeight: 640, border: 0, display: 'block' }}
    />
  )
}
