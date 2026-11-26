import css from '../pages/SystemGlobalSettingsPage.css?raw'
import source from '../pages/SystemGlobalSettingsPage.tsx?raw'
// @ts-expect-error plain ESM helper shared with node --test
import { declarations } from '../../scripts/defaultLook.mjs'

// 系统配置表单卡片的控件列曾固定 760px（标签 170px），768px 打开侧栏后内容区
// 不足 930px，控件列掉到标签下方并撑出整页横向滚动。jsdom 不算布局，这里锁住规则本身：
// 卡片表单的控件列不得用固定像素宽度或 flex-basis，表单相关规则不得有像素 min-width，
// 窄卡片按卡片自身宽度（@container）纵排。
const lines = declarations(css) as string[]
const parse = (line: string) => {
  const match = line.match(/^(.*) \{ ([\w-]+): (.*) \}$/)
  if (!match) throw new Error(`unparsed declaration ${line}`)
  return { selector: match[1], property: match[2], value: match[3] }
}
const controlColumn = /\.ant-form-item-control(-input(-content)?)?$/

it('sizes the card form control column by the space left, not a fixed pixel width', function cardControlsShrink() {
  const fixed = lines.map(parse).filter(({ selector, property, value }) => selector.includes('.system-settings-config-card')
    && selector.split(/,| >> /).some((part) => controlColumn.test(part.trim()))
    && ['width', 'inline-size', 'flex', 'flex-basis'].includes(property) && /\d+px/.test(value))
  expect(fixed).toEqual([])
})

it('never pins a form container or control to a pixel min-width', function noPixelMinWidth() {
  const pinned = lines.map(parse).filter(({ property, value }) => /^min-(width|inline-size)$/.test(property) && /[1-9]\d*px/.test(value))
  expect(pinned).toEqual([])
})

it('stacks label over control when the settings card itself is narrow', function narrowCardsStack() {
  expect(lines).toContain('.system-settings-baseline-page.sys-setting.sys-setting-reference-page .system-settings-config-card { container: sys-setting-card / inline-size }')
  const stacked = lines.filter((line) => line.startsWith('@container sys-setting-card (width < 560px) >> '))
  expect(stacked.some((line) => /\.ant-form-item-row \{ display: block \}$/.test(line))).toBe(true)
  expect(stacked.some((line) => line.includes('.ant-form-item-control,') && line.endsWith('{ inline-size: 100% !important }'))).toBe(true)
})

// 复验：同一份规则在文件中靠后者生效（选择器相同、特异性相同，媒体查询不加权）。
const effective = (selector: string, property: string) => lines.map(parse)
  .filter((rule) => rule.selector.split(' >> ').pop() === selector && rule.property === property).pop()?.value
const page = '.system-settings-baseline-page.sys-setting.sys-setting-reference-page'
const card = `${page} .system-settings-baseline-form > .system-settings-config-card`

it('lets the form hint line follow the control column instead of a fixed pixel width', function hintLineShrinks() {
  const fixed = lines.map(parse).filter(({ selector, property, value }) => /\.ant-form-item-(extra|additional)\b/.test(selector)
    && ['width', 'inline-size', 'min-width', 'min-inline-size'].includes(property) && /\d+px/.test(value))
  expect(fixed).toEqual([])
  expect(effective(`${card} .ant-form-item-additional`, 'max-inline-size')).toBe('760px')
  expect(effective(`${card} .ant-form-item-extra`, 'overflow-wrap')).toBe('anywhere')
})

it('wraps every horizontal Space', function horizontalSpacesWrap() {
  // 横排 Space（非 vertical、非 Space.Compact）一律允许换行。
  expect(source.match(/<Space(?![^>]*\b(wrap\b|direction="vertical"))[ >][^>]*>/g) ?? []).toEqual([])
  expect(source).not.toContain('wrap={false}')
  const items = `${page} .system-settings-config-card .ant-space-horizontal > .ant-space-item`
  expect(effective(items, 'min-inline-size')).toBe('0')
  expect(effective(items, 'max-inline-size')).toBe('100%')
  expect(effective(`${page} .system-settings-config-card .ant-tag`, 'white-space')).toBe('normal')
})

it('wraps the in-page section navigation so no item hides behind a scroll offset', function sectionNavigationWraps() {
  const navigation = source.slice(source.indexOf('function SectionNavigation'), source.indexOf('</nav>'))
  expect(navigation).toMatch(/<Space wrap /)
  const nav = `${page} .system-settings-section-nav`
  expect(effective(nav, 'height')).toBe('auto')
  expect(effective(`${nav} .ant-space`, 'flex-wrap')).toBe('wrap')
  expect(effective(`${nav} .ant-space`, 'width')).toBe('100%')
  expect(effective(`${nav} .ant-space`, 'min-width')).toBe('0')
})
