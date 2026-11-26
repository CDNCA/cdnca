import i18next from 'i18next'

import { networkApiError, responseApiError } from './auth'

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

// The console language decides which template language the
// signed-in user's notifications use.
export async function setAccountLocale(accessToken: string, locale: string): Promise<void> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/account/locale`, {
      method: 'PUT', credentials: 'include', cache: 'no-store',
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ locale }),
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
}

// requestLanguage is sent as Accept-Language on sign-in, registration and
// recovery code requests, whose messages go to someone not signed in yet.
export function requestLanguage(): string {
  return i18next.resolvedLanguage ?? i18next.language ?? 'zh-CN'
}

let synced = ''

// syncAccountLocale saves the language once per user and language; a failed
// save is retried on the next call.
export function syncAccountLocale(accessToken: string, userID: string, locale: string): void {
  const key = `${userID}:${locale}`
  if (synced === key) return
  synced = key
  setAccountLocale(accessToken, locale).catch(() => {
    if (synced === key) synced = ''
  })
}

export function resetAccountLocaleSync(): void {
  synced = ''
}
