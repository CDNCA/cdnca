import { useEffect, type PropsWithChildren } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { LanguageMenu } from '../../components/LanguageMenu'
import { useAuthStyle } from '../../theme/authStyle'
import { useBrandName } from '../../theme/runtime'

export function AccountRecoveryLayout({
  title,
  children,
}: PropsWithChildren<{ title: string }>) {
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
          <h1 id="recovery-title">{brandName}</h1>
          <div className="recovery-panel">
            {children}
            <div className="recovery-login-link">
              <Link to="/login">{t('recovery.returnToLogin')}</Link>
            </div>
          </div>
        </section>
      </main>
      <footer className="recovery-footer">
        <div className="recovery-footer-links" aria-label={t('recovery.footerLinks')}>
          <span>{t('recovery.officialSite')}</span>
          <span>{t('recovery.community')}</span>
          <span>{t('recovery.contactUs')}</span>
        </div>
        <div>{t('recovery.copyright')}</div>
      </footer>
    </div>
  )
}
