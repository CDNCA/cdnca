import i18n from './index'
import { streamQuickCreateMessages } from './streamQuickCreate'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) =>
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))))
}

describe('streamQuickCreateMessages', () => {
  it('registers complete Chinese, English, and expanded pseudo-locale trees', () => {
    const zh = flatten(streamQuickCreateMessages['zh-CN'])
    expect(zh).toEqual(expect.objectContaining({
      title: '批量添加监听端口',
      'validation.duplicate': '同一协议的监听端口不能重复',
      'validation.conflict': '监听端口已被当前规则占用',
      'partial.retry': '重试 {{count}} 条失败规则',
      'unknown.title': '创建结果尚未确认',
    }))
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'streamQuickCreate')).toBe(true)
      expect(Object.keys(flatten(streamQuickCreateMessages[locale])).sort()).toEqual(Object.keys(zh).sort())
    }
    expect(streamQuickCreateMessages['qps-ploc'].title.length)
      .toBeGreaterThan(streamQuickCreateMessages['zh-CN'].title.length)
  })
})
