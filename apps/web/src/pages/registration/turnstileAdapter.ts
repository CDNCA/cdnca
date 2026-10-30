import { applyScriptNonce } from '../../components/scriptNonce'

interface TurnstileAPI {
  render(container: HTMLElement, options: Record<string, unknown>): string
  remove(widgetId: string): void
}

type TurnstileWindow = Window & { turnstile?: TurnstileAPI }

export interface TurnstileMountOptions {
  siteKey: string
  language: string
  onToken(token: string): void
  onExpired(): void
  onError(): void
}

export interface TurnstileAdapter {
  mount(container: HTMLElement, options: TurnstileMountOptions): Promise<() => void>
}

const scriptSelector = 'script[data-cdnca-turnstile="true"]'
let scriptLoad: Promise<TurnstileAPI> | null = null

function currentAPI(): TurnstileAPI | undefined {
  return (window as TurnstileWindow).turnstile
}

function loadTurnstile(): Promise<TurnstileAPI> {
  const ready = currentAPI()
  if (ready) return Promise.resolve(ready)
  if (scriptLoad) return scriptLoad

  scriptLoad = new Promise<TurnstileAPI>((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(scriptSelector)
    const script = existing ?? applyScriptNonce(document.createElement('script'))
    const complete = () => {
      const api = currentAPI()
      if (api) resolve(api)
      else reject(new Error('Turnstile API unavailable'))
    }
    const failed = () => reject(new Error('Turnstile script unavailable'))
    script.addEventListener('load', complete, { once: true })
    script.addEventListener('error', failed, { once: true })
    if (!existing) {
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
      script.async = true
      script.defer = true
      script.dataset.cdncaTurnstile = 'true'
      document.head.append(script)
    }
  }).catch((error: unknown) => {
    scriptLoad = null
    throw error
  })
  return scriptLoad
}

export const browserTurnstileAdapter: TurnstileAdapter = {
  async mount(container, options) {
    const api = await loadTurnstile()
    const widgetId = api.render(container, {
      sitekey: options.siteKey,
      language: options.language,
      theme: 'auto',
      callback: options.onToken,
      'expired-callback': options.onExpired,
      'error-callback': options.onError,
    })
    return () => api.remove(widgetId)
  },
}
