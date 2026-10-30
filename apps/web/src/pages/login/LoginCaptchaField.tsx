import { useEffect, useState } from 'react'
import { Button, Input, Space } from 'antd'
import { RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { issueLoginCaptcha, type LoginCaptchaChallenge } from '../../api/loginCaptcha'

interface LoginCaptchaFieldProps {
  /** Changing the key fetches a new image (after a wrong or used answer). */
  resetKey: number
  disabled?: boolean
  onChange(value: { id: string; answer: string } | null): void
}

/** Built-in sign-in CAPTCHA, shown once the server asks for it. */
export function LoginCaptchaField({ resetKey, disabled, onChange }: LoginCaptchaFieldProps) {
  const { t } = useTranslation('passwordLoginChallenge')
  const [challenge, setChallenge] = useState<LoginCaptchaChallenge | null>(null)
  const [answer, setAnswer] = useState('')
  const [failed, setFailed] = useState(false)
  const [refresh, setRefresh] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    setChallenge(null)
    setAnswer('')
    setFailed(false)
    onChange(null)
    issueLoginCaptcha(controller.signal).then(setChallenge, () => {
      if (!controller.signal.aborted) setFailed(true)
    })
    return () => controller.abort()
    // onChange is a state setter owned by the page.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resetKey, refresh])

  const update = (value: string) => {
    const normalized = value.replace(/[^A-Za-z0-9]/g, '').slice(0, 8)
    setAnswer(normalized)
    onChange(challenge && normalized ? { id: challenge.id, answer: normalized } : null)
  }

  return (
    <div className="login-captcha">
      <div className="login-notice">{t('captchaHint')}</div>
      <Space.Compact block>
        <Input
          value={answer}
          onChange={event => update(event.target.value)}
          placeholder={t('captchaPlaceholder')}
          aria-label={t('captcha')}
          autoComplete="off"
          maxLength={8}
          disabled={disabled || !challenge}
        />
        {challenge ? <img src={challenge.image} alt={t('captchaImage')} width={120} height={40} style={{ height: 32, width: 'auto' }} /> : null}
        <Button aria-label={t('captchaRefresh')} title={t('captchaRefresh')} disabled={disabled}
          icon={<RefreshCw size={14} aria-hidden="true" />} onClick={() => setRefresh(value => value + 1)} />
      </Space.Compact>
      {failed ? <div role="alert" className="login-captcha-error">{t('errors.login_security_unavailable')}</div> : null}
    </div>
  )
}
