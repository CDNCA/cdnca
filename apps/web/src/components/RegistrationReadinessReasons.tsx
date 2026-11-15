import { Alert } from 'antd'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import type { AccountRegistrationReason } from '../api/accountRegistration'
import '../i18n/accountRegistration'

type ReadinessLink = 'mail' | 'account'

// where each reason is fixed (system settings tabs).
const reasonLinks: Record<AccountRegistrationReason, ReadinessLink | null> = {
  registration_disabled: 'account',
  notification_runtime_disabled: null,
  sender_build_failed: 'mail',
  email_sender_unavailable: 'mail',
  sms_sender_unavailable: 'mail',
  email_template_missing: 'account',
  sms_template_missing: 'account',
  sms_template_unmapped: 'mail',
  turnstile_not_configured: 'account',
  verification_channel_unavailable: null,
}

const linkTargets: Record<ReadinessLink, string> = {
  mail: '/sys/setting?tab=mail',
  account: '/sys/setting?tab=account',
}

/**
 * What keeps sign-up verification from being ready, each with where to fix it
 * (administrators only).
 */
export function RegistrationReadinessReasons({ reasons, title, className }: {
  reasons: readonly AccountRegistrationReason[]
  title?: string
  className?: string
}) {
  const { t } = useTranslation('accountRegistration')
  if (reasons.length === 0) return null
  return (
    <Alert
      className={className}
      type="warning"
      showIcon
      data-testid="registration-readiness-reasons"
      message={title ?? t('readiness.title')}
      description={(
        <ul style={{ margin: 0, paddingInlineStart: 18 }}>
          {reasons.map((reason) => {
            const link = reasonLinks[reason]
            return (
              <li key={reason} data-reason={reason}>
                {t(`readiness.reasons.${reason}`)}
                {link ? <> <Link to={linkTargets[link]}>{t(`readiness.links.${link}`)}</Link></> : null}
              </li>
            )
          })}
        </ul>
      )}
    />
  )
}
