import { describe, expect, it } from 'vitest'

import css from '../pages/SystemGlobalSettingsV2.css?raw'

// （390px 实测）：rc-tabs 用导航盒外宽减「更多」算可见区，导航盒自己的
// 左右内边距不在计算里，放不下时选中的最后一项被裁 40px。放不下的宽度（≤1199px）导航盒不留左右内边距。
describe('system settings top tabs', () => {
  it('drop the nav inline inset where the tabs overflow into 更多', () => {
    const style = document.createElement('style')
    style.textContent = css
    document.head.append(style)
    const rules = [...(style.sheet?.cssRules ?? [])]
    style.remove()
    const nav = '.sys-setting-v2 .system-settings-baseline-page.sys-setting.sys-setting-reference-page > .ant-tabs > .ant-tabs-nav'
    const narrow = rules
      .filter((rule): rule is CSSMediaRule => 'conditionText' in rule && rule.conditionText === '(max-width: 1199px)')
      .flatMap((media) => [...media.cssRules])
      .filter((rule): rule is CSSStyleRule => 'selectorText' in rule && rule.selectorText === nav)
      .at(-1)
    expect(narrow?.style.getPropertyValue('padding-inline')).toBe('0')
    expect(narrow?.style.getPropertyValue('margin-inline')).toBe('0')
  })
})
