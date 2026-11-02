import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { themeColor } from '../theme/themeColor'

export type TerminalStatus = 'connecting' | 'open' | 'closed' | 'error'

export interface TerminalLogin {
  port: number
  username?: string
  password?: string
  private_key?: string
  use_saved: boolean
  remember: boolean
}

// NodeSSHTerminal is the xterm.js view of one session. The login travels in
// the first WebSocket frame (never in the URL) and is dropped from memory
// once sent; keystrokes go to the node as binary frames.
export default function NodeSSHTerminal({ socketURL, accessToken, login, onStatus, label }: {
  socketURL: string
  accessToken: string
  login: TerminalLogin
  /** remembered: the login was saved on the controller for the next connection. */
  onStatus: (status: TerminalStatus, code?: string, opened?: { remembered: boolean }) => void
  label: string
}) {
  const container = useRef<HTMLDivElement>(null)
  const [ready, setReady] = useState(false)
  const status = useRef(onStatus)
  status.current = onStatus

  useEffect(() => {
    const element = container.current
    if (!element) return
    const terminal = new Terminal({
      cursorBlink: true, convertEol: false, scrollback: 5000, fontSize: 13,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
      theme: { background: themeColor('--cdnca-color-bg-dark', '#0f172a'), foreground: themeColor('--cdnca-color-text-dark', '#e5e7eb') },
    })
    const fit = new FitAddon()
    terminal.loadAddon(fit)
    terminal.open(element)
    fit.fit()
    const socket = new WebSocket(socketURL)
    socket.binaryType = 'arraybuffer'
    let opened = false
    // The WebSocket itself came up (the open frame was sent): a close or an
    // error before that is the handshake failing (proxy, network), not SSH.
    let connected = false
    let pendingLogin: TerminalLogin | null = login
    const encoder = new TextEncoder()
    let failed = false
    const fail = (code: string) => {
      if (failed) return
      failed = true
      status.current('error', code)
    }
    socket.onopen = () => {
      connected = true
      if (!pendingLogin) return
      socket.send(JSON.stringify({ type: 'open', access_token: accessToken, ...pendingLogin, cols: terminal.cols, rows: terminal.rows }))
      // The secret is not kept once sent.
      pendingLogin = null
    }
    socket.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        terminal.write(new Uint8Array(event.data))
        return
      }
      let frame: { type?: string; code?: string; reason?: string; remembered?: boolean }
      try {
        frame = JSON.parse(String(event.data))
      } catch {
        return
      }
      if (frame.type === 'error') failed = true
      if (frame.type === 'opened') {
        opened = true
        setReady(true)
        status.current('open', undefined, { remembered: frame.remembered === true })
        terminal.focus()
      } else if (frame.type === 'error') {
        status.current('error', frame.code)
      } else if (frame.type === 'closed') {
        status.current('closed', frame.reason)
      }
    }
    socket.onclose = () => {
      setReady(false)
      if (opened) status.current('closed')
      else if (!connected) fail('websocket_failed')
    }
    socket.onerror = () => {
      if (!opened) fail(connected ? 'unavailable' : 'websocket_failed')
    }
    const input = terminal.onData((data) => {
      if (socket.readyState === WebSocket.OPEN && opened) socket.send(encoder.encode(data))
    })
    const sendSize = () => {
      fit.fit()
      if (socket.readyState === WebSocket.OPEN && opened) {
        socket.send(JSON.stringify({ type: 'resize', cols: terminal.cols, rows: terminal.rows }))
      }
    }
    const observer = new ResizeObserver(() => sendSize())
    observer.observe(element)
    status.current('connecting')
    return () => {
      observer.disconnect()
      input.dispose()
      pendingLogin = null
      socket.close()
      terminal.dispose()
    }
    // The session is opened once per mount; a new login remounts it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return <div className="node-ssh-terminal-frame" data-ready={ready}>
    <div ref={container} className="node-ssh-terminal" role="application" aria-label={label} />
  </div>
}
