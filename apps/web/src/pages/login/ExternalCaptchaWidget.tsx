import { useEffect, useRef, useState } from 'react'
import { Button, Form } from 'antd'

import type { LoginCaptchaConfig } from '../../api/passwordLoginChallenge'
import type { ExternalCaptchaAdapter } from './externalCaptcha'

interface ExternalCaptchaWidgetProps {
  adapter: ExternalCaptchaAdapter
  config: LoginCaptchaConfig
  label: string
  doneLabel: string
  unavailableLabel: string
  language: string
  resetKey: number
  onToken(token: string): void
  onError(): void
}

/** Opens the Tencent or GeeTest popup on click; the proof stays in memory only. */
export function ExternalCaptchaWidget({
  adapter, config, label, doneLabel, unavailableLabel, language, resetKey, onToken, onError,
}: ExternalCaptchaWidgetProps) {
  const [state, setState] = useState<'idle' | 'running' | 'done' | 'failed'>('idle')
  const cleanup = useRef<(() => void) | undefined>(undefined)
  const callbacks = useRef({ onToken, onError })
  callbacks.current = { onToken, onError }

  useEffect(() => {
    setState('idle')
    return () => {
      cleanup.current?.()
      cleanup.current = undefined
    }
  }, [config.provider, config.appId, resetKey])

  const start = () => {
    cleanup.current?.()
    cleanup.current = undefined
    setState('running')
    void adapter.run({
      config, language,
      onToken: (token) => {
        setState('done')
        callbacks.current.onToken(token)
      },
      onError: () => {
        setState('failed')
        callbacks.current.onError()
      },
      onCancel: () => setState('idle'),
    }).then((dispose) => {
      cleanup.current = dispose
    }).catch(() => {
      setState('failed')
      callbacks.current.onError()
    })
  }

  return (
    <Form.Item
      validateStatus={state === 'failed' ? 'error' : undefined}
      help={state === 'failed' ? unavailableLabel : undefined}
    >
      <Button block onClick={start} loading={state === 'running'} disabled={state === 'done'}>
        {state === 'done' ? doneLabel : label}
      </Button>
    </Form.Item>
  )
}
