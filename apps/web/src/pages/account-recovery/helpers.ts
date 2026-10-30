import type { MutableRefObject } from 'react'

import { ApiError } from '../../api/auth'

export interface RecoveryAttempt<T extends object = object> {
  key: string
  body: T
}

export function keyForAttempt<T extends object>(
  attempt: MutableRefObject<RecoveryAttempt<T> | null>,
  operation: 'request' | 'confirm',
  body: T,
): string {
  if (attempt.current === null) {
    attempt.current = {
      key: `account-recovery-${operation}-${crypto.randomUUID()}`,
      body,
    }
  }
  return attempt.current.key
}

export function isUnknownResult(error: unknown): boolean {
  if (!(error instanceof ApiError)) return true
  return error.status === 0 || error.status === 408 ||
    error.status >= 500 || error.code === 'invalid_response' || [
    'account_recovery_request_cancelled',
    'account_recovery_timeout',
    'account_recovery_unavailable',
  ].includes(error.code)
}

export function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length
}
