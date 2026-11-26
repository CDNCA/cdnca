import { useEffect, type PropsWithChildren, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { LanguageMenu } from '../../components/LanguageMenu'
import { useAuthStyle } from '../../theme/authStyle'
import { useBrandName } from '../../theme/runtime'

// `heading` makes the task name the page's h1 (top of the card); the brand
// then stays as a visual logo instead of the heading. Pages without it keep
// the brand as h1.
export function AccountRecoveryLayout({
  title,
  heading,
  children,
}: PropsWithChildren<{ title: string; heading?: ReactNode }>) {
  const { t, i18n } = useTranslation('auth')
  const brandName = useBrandName(i18n.resolvedLanguage ?? 'zh-CN')
  // Theme plugin C: the user console plugin's sign-in page CSS (style only).
  useAuthStyle()

  useEffect(() => {
    const previousTitle = document.title
    document.title = title
    return () => {
      document.title = previousTitle
    }
  }, [title])

  return (
    <div className="recovery-page">
      <LanguageMenu className="recovery-language-trigger" />
      <main className="recovery-main">
        <section className="recovery-container" aria-labelledby="recovery-title">
          {heading === undefined ? (
            <h1 id="recovery-title" className="recovery-brand">{brandName}</h1>
          ) : (
            <div className="recovery-brand">{brandName}</div>
          )}
          <div className="recovery-panel">
            {heading === undefined ? null : (
              <h1 id="recovery-title" className="recovery-tab">{heading}</h1>
            )}
            {children}
            <div className="recovery-login-link">
              <Link to="/login">{t('recovery.returnToLogin')}</Link>
            </div>
          </div>
        </section>
      </main>
      <footer className="recovery-footer">
        <div>{t('recovery.copyright')}</div>
      </footer>
    </div>
  )
}
