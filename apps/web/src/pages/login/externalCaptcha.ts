import type { LoginCaptchaConfig } from '../../api/passwordLoginChallenge'
import { applyScriptNonce } from '../../components/scriptNonce'

// Browser side of the Tencent CAPTCHA and GeeTest v4 widgets. The server
// verifies the proof (accountloginchallenge/external_captcha.go); the token is
// a JSON object whose fields match that verifier exactly.

interface TencentCaptchaResult { ret: number; ticket?: string; randstr?: string }
type TencentCaptchaConstructor = new (appId: string, callback: (result: TencentCaptchaResult) => void,
  options?: Record<string, unknown>) => { show(): void; destroy?(): void }

interface GeetestCaptcha {
  onReady(callback: () => void): void
  onSuccess(callback: () => void): void
  onError(callback: () => void): void
  onClose?(callback: () => void): void
  getValidate(): { lot_number: string; captcha_output: string; pass_token: string; gen_time: string } | false
  showCaptcha(): void
  destroy?(): void
}
type GeetestInit = (options: Record<string, unknown>, callback: (captcha: GeetestCaptcha) => void) => void

type CaptchaWindow = Window & { TencentCaptcha?: TencentCaptchaConstructor; initGeetest4?: GeetestInit }

const scripts: Record<LoginCaptchaConfig['provider'], string> = {
  tencent: 'https://turing.captcha.qcloud.com/TCaptcha.js',
  geetest_v4: 'https://static.geetest.com/v4/gt4.js',
}
const loads = new Map<string, Promise<void>>()

function loadScript(src: string): Promise<void> {
  const cached = loads.get(src)
  if (cached) return cached
  const load = new Promise<void>((resolve, reject) => {
    const script = applyScriptNonce(document.createElement('script'))
    script.src = src
    script.async = true
    script.dataset.cdncaCaptcha = 'true'
    script.addEventListener('load', () => resolve(), { once: true })
    script.addEventListener('error', () => reject(new Error('CAPTCHA script unavailable')), { once: true })
    document.head.append(script)
  }).catch((error: unknown) => {
    loads.delete(src)
    throw error
  })
  loads.set(src, load)
  return load
}

export interface ExternalCaptchaRun {
  config: LoginCaptchaConfig
  language: string
  onToken(token: string): void
  onError(): void
  /** The user closed the widget without finishing it. */
  onCancel(): void
}

export interface ExternalCaptchaAdapter {
  /** Opens the provider widget; resolves to a cleanup function. */
  run(options: ExternalCaptchaRun): Promise<() => void>
}

export const browserExternalCaptchaAdapter: ExternalCaptchaAdapter = {
  async run({ config, language, onToken, onError, onCancel }) {
    await loadScript(scripts[config.provider])
    const captchaWindow = window as CaptchaWindow
    if (config.provider === 'tencent') {
      const TencentCaptcha = captchaWindow.TencentCaptcha
      if (typeof TencentCaptcha !== 'function') throw new Error('Tencent CAPTCHA unavailable')
      const captcha = new TencentCaptcha(config.appId, (result) => {
        if (result.ret === 0 && typeof result.ticket === 'string' && typeof result.randstr === 'string') {
          onToken(JSON.stringify({ ticket: result.ticket, randstr: result.randstr }))
        } else if (result.ret === 2) { // 2 = the user closed the widget
          onCancel()
        } else {
          onError()
        }
      }, { userLanguage: language.toLowerCase().startsWith('zh') ? 'zh-cn' : 'en' })
      captcha.show()
      return () => captcha.destroy?.()
    }
    const initGeetest4 = captchaWindow.initGeetest4
    if (typeof initGeetest4 !== 'function') throw new Error('GeeTest unavailable')
    let instance: GeetestCaptcha | null = null
    let disposed = false
    initGeetest4({ captchaId: config.appId, product: 'bind', language: language.toLowerCase().startsWith('zh') ? 'zho' : 'eng' }, (captcha) => {
      if (disposed) {
        captcha.destroy?.()
        return
      }
      instance = captcha
      // product 'bind' shows the challenge as a popup once the SDK is ready.
      captcha.onReady(() => captcha.showCaptcha())
      captcha.onSuccess(() => {
        const result = captcha.getValidate()
        if (!result) {
          onError()
          return
        }
        const { lot_number, captcha_output, pass_token, gen_time } = result
        onToken(JSON.stringify({ lot_number, captcha_output, pass_token, gen_time }))
      })
      captcha.onError(onError)
      captcha.onClose?.(onCancel)
    })
    return () => {
      disposed = true
      instance?.destroy?.()
    }
  },
}
