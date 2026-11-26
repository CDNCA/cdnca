import { useRef, useState } from 'react'
import { Tabs as AntTabs, type TabsProps } from 'antd'
import { useTranslation } from 'react-i18next'

import './Tabs.css'

// rc-tabs 溢出「更多」展开列表的可访问名取自 locale.dropdownAriaLabel，默认是英文 "expanded dropdown"，
// ConfigProvider 的 tabs 配置又不支持 locale；全站页签统一从这里取 antd Tabs，默认注入本地化名称（页面仍可自行覆盖）。
// antd 不为从未激活的页签生成面板外壳，aria-controls 指空。
// 每个页签默认 forceRender 出带 id、role=tabpanel 的隐藏外壳；正文仍只在激活过后挂载（销毁模式下只挂当前页签），
// 不多挂内容、不多发请求。页面显式设置的 forceRender 优先。
// 根类 cdnca-tabs 让 rc-tabs 硬编码的英文「Tab N of M」播报退出可访问树（见 Tabs.css）。
export function Tabs({ locale, className, items, activeKey, defaultActiveKey, onChange, destroyOnHidden, destroyInactiveTabPane, ...props }: TabsProps) {
  const { t } = useTranslation()
  const [innerKey, setInnerKey] = useState(defaultActiveKey)
  const visited = useRef(new Set<string>())
  const requested = activeKey ?? innerKey
  // 与 rc-tabs 一致：非受控且所指页签不存在时显示第一个。
  const current = items?.some((item) => item.key === requested) || activeKey !== undefined ? requested : items?.[0]?.key
  if (current !== undefined) visited.current.add(current)
  const mergedItems = items?.map((item) => {
    if (item.forceRender !== undefined) return item
    const destroy = item.destroyOnHidden ?? destroyOnHidden ?? destroyInactiveTabPane
    const mounted = item.key === current || (!destroy && visited.current.has(item.key))
    return { ...item, forceRender: true, children: mounted ? item.children : null }
  })
  return <AntTabs
    {...props}
    className={className ? `cdnca-tabs ${className}` : 'cdnca-tabs'}
    items={mergedItems}
    activeKey={activeKey}
    defaultActiveKey={defaultActiveKey}
    destroyOnHidden={destroyOnHidden}
    destroyInactiveTabPane={destroyInactiveTabPane}
    onChange={(key) => {
      setInnerKey(key)
      onChange?.(key)
    }}
    locale={{ dropdownAriaLabel: t('tabsMoreList'), ...locale }}
  />
}
