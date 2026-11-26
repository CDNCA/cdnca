import { SearchInput as SharedSearchInput, type SearchInputProps } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

// 控制台的搜索框取 @cdnca/ui 的
// SearchInput（图标按钮带本地化名称、图标退出可访问树），名称用本应用的界面文案。
export type { SearchInputProps }

export function SearchInput({ searchLabel, clearLabel, ...props }: SearchInputProps) {
  const { t } = useTranslation()
  return <SharedSearchInput {...props} searchLabel={searchLabel ?? t('searchButton')} clearLabel={clearLabel ?? t('clearInput')} />
}
