import { Dropdown, Tooltip, type MenuProps } from 'antd'
import { Languages } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { changeLocale, type UserLocale } from '../i18n'

interface LanguageMenuProps {
  className?: string
}

export function LanguageMenu({ className = 'header-icon-button' }: LanguageMenuProps) {
  const { i18n, t } = useTranslation('common')
  const resolved = i18n.resolvedLanguage ?? 'zh-CN'
  const selected: UserLocale = resolved === 'en-US' ? 'en-US' : resolved === 'zh-TW' ? 'zh-TW' : 'zh-CN'
  const menu: MenuProps = {
    items: [
      { key: 'zh-CN', label: t('simplifiedChinese') },
      { key: 'zh-TW', label: t('traditionalChinese') },
      { key: 'en-US', label: t('english') },
    ],
    selectable: true,
    selectedKeys: [selected],
    onClick: ({ key }) => void changeLocale(key as UserLocale),
  }

  return (
    <Dropdown menu={menu} placement="bottomRight" trigger={['click']}>
      <Tooltip title={t('language')}>
        <button className={className} type="button" aria-label={t('languageMenu')}>
          <Languages size={17} strokeWidth={1.7} aria-hidden="true" />
        </button>
      </Tooltip>
    </Dropdown>
  )
}
