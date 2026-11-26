import { useContext, type Ref } from 'react'
import { Button, ConfigProvider, Input, type InputRef } from 'antd'
import type { SearchProps } from 'antd/es/input'

// antd Input.Search 的图标按钮
// 没有文字，读屏名取自图标的英文名 search（清除按钮同理读作 close-circle），ConfigProvider 也不能配置这两个名称。
// 各前端的搜索框统一从这里取：图标按钮带本地化名称、图标退出可访问树；外观与 antd 默认按钮一致（同一图标、同一默认按钮）。
// 页面传文字 enterButton 时按钮已有文字名称，原样交给 antd。名称默认按 ConfigProvider 的 antd locale 取，页面可传自己的文案。
// label 为空时图标只作装饰（aria-hidden），按钮名称由按钮自己给。
function SvgIcon({ name, d, label, evenOdd }: { name: string; d: string; label?: string; evenOdd?: boolean }) {
  return (
    <span className={`anticon anticon-${name}`} {...(label ? { role: 'img', 'aria-label': label } : { 'aria-hidden': true })}>
      <svg viewBox="64 64 896 896" width="1em" height="1em" fill="currentColor" focusable="false" fillRule={evenOdd ? 'evenodd' : undefined}>
        <path d={d} />
      </svg>
    </span>
  )
}

const searchPath = 'M909.6 854.5L649.9 594.8C690.2 542.7 712 479 712 412c0-80.2-31.3-155.4-87.9-212.1-56.6-56.7-132-87.9-212.1-87.9s-155.5 31.3-212.1 87.9C143.2 256.5 112 331.8 112 412c0 80.1 31.3 155.5 87.9 212.1C256.5 680.8 331.8 712 412 712c67 0 130.6-21.8 182.7-62l259.7 259.6a8.2 8.2 0 0011.6 0l43.6-43.5a8.2 8.2 0 000-11.6zM570.4 570.4C528 612.7 471.8 636 412 636s-116-23.3-158.4-65.6C211.3 528 188 471.8 188 412s23.3-116.1 65.6-158.4C296 211.3 352.2 188 412 188s116.1 23.2 158.4 65.6S636 352.2 636 412s-23.3 116.1-65.6 158.4z'
const clearPath = 'M512 64c247.4 0 448 200.6 448 448S759.4 960 512 960 64 759.4 64 512 264.6 64 512 64zm127.98 274.82h-.04l-.08.06L512 466.75 384.14 338.88c-.04-.05-.06-.06-.08-.06a.12.12 0 00-.07 0c-.03 0-.05.01-.09.05l-45.02 45.02a.2.2 0 00-.05.09.12.12 0 000 .07v.02a.27.27 0 00.06.06L466.75 512 338.88 639.86c-.05.04-.06.06-.06.08a.12.12 0 000 .07c0 .03.01.05.05.09l45.02 45.02a.2.2 0 00.09.05.12.12 0 00.07 0c.02 0 .04-.01.08-.05L512 557.25l127.86 127.87c.04.04.06.05.08.05a.12.12 0 00.07 0c.03 0 .05-.01.09-.05l45.02-45.02a.2.2 0 00.05-.09.12.12 0 000-.07v-.02a.27.27 0 00-.05-.06L557.25 512l127.87-127.86c.04-.04.05-.06.05-.08a.12.12 0 000-.07c0-.03-.01-.05-.05-.09l-45.02-45.02a.2.2 0 00-.09-.05.12.12 0 00-.07 0z'

const texts = {
  'zh-CN': { search: '搜索', clear: '清除' },
  'zh-TW': { search: '搜尋', clear: '清除' },
  'en-US': { search: 'Search', clear: 'Clear' },
}

export type SearchInputProps = SearchProps & {
  /** 搜索按钮的读屏名称；默认按 antd locale 的「搜索」。 */
  searchLabel?: string
  /** 清除按钮的读屏名称；默认按 antd locale 的「清除」。 */
  clearLabel?: string
  ref?: Ref<InputRef>
}

export function SearchInput({ searchLabel, clearLabel, enterButton, allowClear, loading, disabled, variant, ...props }: SearchInputProps) {
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  const text = texts[locale === 'en' ? 'en-US' : locale === 'zh-tw' ? 'zh-TW' : 'zh-CN']
  const clear = allowClear === true
    ? { clearIcon: <SvgIcon name="close-circle" d={clearPath} label={clearLabel ?? text.clear} evenOdd /> }
    : allowClear
  if (enterButton !== undefined && enterButton !== false) {
    return <Input.Search {...props} enterButton={enterButton} allowClear={clear} loading={loading} disabled={disabled} variant={variant} />
  }
  const button = (
    <Button aria-label={searchLabel ?? text.search} icon={<SvgIcon name="search" d={searchPath} />} loading={loading} disabled={disabled}
      variant={variant === 'borderless' || variant === 'filled' || variant === 'underlined' ? 'text' : undefined} />
  )
  return <Input.Search {...props} enterButton={button} allowClear={clear} loading={loading} disabled={disabled} variant={variant} />
}
