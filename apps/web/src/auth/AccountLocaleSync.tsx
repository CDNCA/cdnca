import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'

import { syncAccountLocale } from '../api/accountLocale'
import { userLocales } from '../i18n'
import { useSessionStore } from './session'

// AccountLocaleSync saves the console language of the signed-in user after
// sign-in and on every language switch, so notifications to that user are
// sent in that language. Nothing is shown to the user.
export function AccountLocaleSync() {
  const { i18n } = useTranslation()
  const accessToken = useSessionStore((state) => state.accessToken)
  // An administrator impersonating a user must not change that user's language.
  const userID = useSessionStore((state) => state.principal?.impersonation ? undefined : state.principal?.user_id)
  const locale = i18n.resolvedLanguage
  useEffect(() => {
    if (!accessToken || !userID || !locale || !userLocales.some((item) => item === locale)) return
    syncAccountLocale(accessToken, userID, locale)
  }, [accessToken, userID, locale])
  return null
}
