import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Ellipsis } from 'lucide-react'
import type { ConfigProviderProps } from 'antd'

// antd's default overflow icon reads as the English "ellipsis"; every tab bar's 更多
// trigger takes its accessible name from this localized icon instead (pages may still pass a more specific one).
export function useTabsConfig(): ConfigProviderProps['tabs'] {
  const { t } = useTranslation()
  return useMemo(() => ({ more: { icon: <span role="img" aria-label={t('tabsMore')}><Ellipsis size={16} aria-hidden /></span> } }), [t])
}
