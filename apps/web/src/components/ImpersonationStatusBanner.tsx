import { useEffect, useState } from 'react'
import { Alert, Button, Space } from 'antd'
import { LogOut, RotateCcw, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, authApi } from '../api/auth'
import {
  createImpersonationWriteMetadata,
  impersonationApi,
  type ImpersonationWriteMetadata,
  type RevokeImpersonationInput,
} from '../api/impersonation'
import { useSessionStore } from '../auth/session'
import '../i18n/adminImpersonation'
import { FeedbackWhen } from '@cdnca/ui'

interface ExitAttempt {
  ownerEpoch: number
  accessToken: string
  grantID: string
  input: RevokeImpersonationInput
  metadata: ImpersonationWriteMetadata
}

function outcomeUnknown(error: ApiError): boolean {
  return error.status === 0 || error.status === 408 || error.status === 429 || error.status >= 500
}

export function ImpersonationStatusBanner() {
  const { t, i18n } = useTranslation('adminImpersonation')
  const principal = useSessionStore((state) => state.principal)
  const marker = principal?.impersonation
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const [exiting, setExiting] = useState(false)
  const [failure, setFailure] = useState<'unknown' | 'failed' | null>(null)
  const [attempt, setAttempt] = useState<ExitAttempt | null>(null)

  useEffect(() => {
    if (!marker) return
    const remaining = Date.parse(marker.expires_at) - Date.now()
    const restore = async () => {
      const current = useSessionStore.getState()
      if (!current.accessToken || current.sessionEpoch !== sessionEpoch) return
      try {
        const restored = await authApi.me(current.accessToken)
        useSessionStore.getState().transitionPrincipal(sessionEpoch, restored)
      } catch {
        setFailure('failed')
      }
    }
    if (remaining <= 0) { void restore(); return }
    const timer = window.setTimeout(() => void restore(), Math.min(remaining, 2_147_483_647))
    return () => window.clearTimeout(timer)
  }, [marker, sessionEpoch])

  if (!principal || !marker) return null

  const ownsAttempt = (current: ExitAttempt): boolean => {
    const state = useSessionStore.getState()
    return state.sessionEpoch === current.ownerEpoch &&
      state.principal?.impersonation?.grant_id === current.grantID
  }

  const finishExit = async (current: ExitAttempt) => {
    if (!ownsAttempt(current)) return
    setExiting(true)
    setFailure(null)
    try {
      await impersonationApi.revoke(current.accessToken, current.grantID, current.input, current.metadata)
      if (!ownsAttempt(current)) return
      const restored = await authApi.me(current.accessToken)
      if (restored.scope_kind !== 'platform' || restored.tenant_id !== null ||
        restored.user_id !== marker.actor_user_id || restored.impersonation || !ownsAttempt(current)) {
        throw new ApiError('Invalid restored principal', 502, 'invalid_response')
      }
      if (ownsAttempt(current)) {
        setAttempt(null)
        setFailure(null)
        useSessionStore.getState().transitionPrincipal(current.ownerEpoch, restored)
      }
    } catch (caught) {
      if (!ownsAttempt(current)) return
      const error = caught instanceof ApiError ? caught : new ApiError('Request failed')
      if (outcomeUnknown(error)) {
        setAttempt(current)
        setFailure('unknown')
      } else {
        setAttempt(null)
        setFailure('failed')
      }
    } finally {
      setExiting(false)
    }
  }

  const exit = () => {
    const primary = useSessionStore.getState()
    if (!primary.accessToken || primary.sessionEpoch !== sessionEpoch) return
    const current: ExitAttempt = {
      ownerEpoch: sessionEpoch,
      accessToken: primary.accessToken,
      grantID: marker.grant_id,
      input: {
        tenant_id: marker.tenant_id,
        tenant_scope_id: principal.scope_id,
        reason: 'operator_exit',
      },
      metadata: createImpersonationWriteMetadata('revoke'),
    }
    setAttempt(current)
    void finishExit(current)
  }

  const expiresAt = new Intl.DateTimeFormat(i18n.language, {
    dateStyle: 'short', timeStyle: 'medium',
  }).format(new Date(marker.expires_at))

  return (
    <div role="status" aria-live="polite" style={{ minWidth: 0 }}>
      {failure ? <FeedbackWhen type={failure === 'unknown' ? 'warning' : 'error'} title={failure === 'unknown' ? t('status.unknown') : t('errors.exit')} /> : null}
      <Alert
        banner
        showIcon
        type={failure ? 'error' : 'warning'}
        message={failure === 'unknown' ? t('status.unknown') : failure === 'failed' ? t('errors.exit') : t('status.banner', {
          actor: marker.actor_display_name,
          subject: marker.subject_display_name,
          expiresAt,
        })}
        description={failure ? t('status.banner', {
          actor: marker.actor_display_name,
          subject: marker.subject_display_name,
          expiresAt,
        }) : undefined}
        action={failure === 'unknown' && attempt ? (
          <Space wrap>
            <Button
              danger
              size="small"
              icon={<RotateCcw size={14} />}
              loading={exiting}
              onClick={() => void finishExit(attempt)}
            >
              {t('actions.retryExact')}
            </Button>
            <Button
              size="small"
              icon={<X size={14} />}
              disabled={exiting}
              onClick={() => { setAttempt(null); setFailure(null) }}
            >
              {t('actions.abandon')}
            </Button>
          </Space>
        ) : (
          <Button
            danger
            size="small"
            icon={<LogOut size={14} />}
            loading={exiting}
            onClick={exit}
          >
            {exiting ? t('status.exiting') : t('actions.exit')}
          </Button>
        )}
      />
    </div>
  )
}
