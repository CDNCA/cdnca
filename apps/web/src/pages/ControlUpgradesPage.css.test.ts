import globalStylesRaw from '../styles.css?raw'
import maintenanceStylesRaw from './ControlUpgradesPage.css?raw'
import { defaultLookCSS } from '../test/defaultLookCSS'

const globalStyles = defaultLookCSS(globalStylesRaw)
const maintenanceStyles = defaultLookCSS(maintenanceStylesRaw)

function maintenanceContainerRules(styles: string) {
  const sheet = document.createElement('style')
  sheet.textContent = styles
  document.head.append(sheet)
  const rules = [...sheet.sheet!.cssRules]
  sheet.remove()
  return rules
}

describe.each([
  ['page first', maintenanceStyles, globalStyles],
  ['page last', globalStyles, maintenanceStyles],
])('maintenance container CSS contract: %s', (_order, first, second) => {
  it.each([390, 1440])('overrides shared identity padding at %ipx regardless of loading order', (width) => {
    const rules = maintenanceContainerRules(`${first}\n${second}`)
    const rootRules = rules.filter((rule): rule is CSSStyleRule => 'selectorText' in rule)
    const shared = rootRules.find((rule) => rule.selectorText === '.identity-page')!
    const mobile = rules.find((rule): rule is CSSMediaRule => 'conditionText' in rule && rule.conditionText === '(max-width: 767px)')!
    const sharedMobile = [...mobile.cssRules].find((rule): rule is CSSStyleRule => 'selectorText' in rule && rule.selectorText === '.identity-page')!
    const activeShared = width <= 767 ? sharedMobile : shared
    const maintenance = rootRules.find((rule) => rule.selectorText === '.identity-page.maintenance-page')

    expect(activeShared.style.getPropertyValue('padding')).toBe(width <= 767 ? '12px' : '16px')
    expect(maintenance).toBeDefined()
    expect(maintenance!.style.getPropertyValue('padding')).toBe('0')
    expect(maintenance!.style.getPropertyValue('border')).toBe('0')
    // jsdom does not compute selector specificity. Lock these exact two-class
    // versus one-class rules; real browser computed values are checked separately.
    expect(maintenance!.selectorText.split('.').filter(Boolean)).toHaveLength(2)
    expect(activeShared.selectorText.split('.').filter(Boolean)).toHaveLength(1)
    expect(maintenance!.style.getPropertyPriority('padding')).toBe('')
    expect(activeShared.style.getPropertyPriority('padding')).toBe('')
  })
})

describe('maintenance density CSS contract', () => {
  it.each([
    ['.maintenance-section-heading h2', '17px'],
    ['.maintenance-stat-grid strong', '16px'],
  ])('uses the observed compact font for %s', (selector, size) => {
    const rule = maintenanceContainerRules(maintenanceStyles)
      .find((item): item is CSSStyleRule => 'selectorText' in item && item.selectorText === selector)!
    expect(rule.style.getPropertyValue('font-size')).toBe(size)
  })

  it('keeps the existing desktop and narrow-screen overview spacing', () => {
    const rules = maintenanceContainerRules(maintenanceStyles)
    const overview = rules.find((rule): rule is CSSStyleRule => 'selectorText' in rule && rule.selectorText === '.maintenance-overview')!
    const mobile = rules.find((rule): rule is CSSMediaRule => 'conditionText' in rule && rule.conditionText === '(max-width: 720px)')!
    const mobileOverview = [...mobile.cssRules].find((rule): rule is CSSStyleRule => 'selectorText' in rule && rule.selectorText === '.maintenance-overview')!
    expect(overview.style.getPropertyValue('padding')).toBe('17px 21px 22px')
    expect(mobileOverview.style.getPropertyValue('padding')).toBe('14px')
  })

  it('matches the compact tabs, summary proportions, and inset card spacing', () => {
    const rules = maintenanceContainerRules(maintenanceStyles)
      .filter((rule): rule is CSSStyleRule => 'selectorText' in rule)
    const style = (selector: string) => rules.find((rule) => rule.selectorText === selector)!.style
    expect(style('.maintenance-overview-tabs button').getPropertyValue('min-width')).toBe('88px')
    expect(style('.maintenance-overview-tabs button').getPropertyValue('height')).toBe('32px')
    expect(style('.maintenance-overview-tabs button').getPropertyValue('font-weight')).toBe('500')
    expect(style('.maintenance-overview').getPropertyValue('padding')).toBe('17px 21px 22px')
    expect(style('.maintenance-overview-tabs').getPropertyValue('margin-bottom')).toBe('15px')
    expect(style('.maintenance-overview-tabs').getPropertyValue('flex-wrap')).toBe('wrap')
    expect(style('.maintenance-section-heading h2').getPropertyValue('line-height')).toBe('1.35')
    expect(style('.maintenance-section-heading h2').getPropertyValue('font-weight')).toBe('600')
    expect(style('.maintenance-section-heading h2').getPropertyValue('color')).toBe('var(--cdnca-color-title)')
    expect(style('.maintenance-section-heading h2').getPropertyValue('position')).toBe('relative')
    expect(style('.maintenance-section-heading h2').getPropertyValue('padding-left')).toBe('14px')
    expect(style('.maintenance-section-heading h2').getPropertyValue('border-left')).toBe('')
    expect(style('.maintenance-section-heading h2::before').getPropertyValue('width')).toBe('4px')
    expect(style('.maintenance-section-heading h2::before').getPropertyValue('height')).toBe('18px')
    expect(style('.maintenance-section-heading h2::before').getPropertyValue('top')).toBe('2px')
    expect(style('.maintenance-section-heading h2::before').getPropertyValue('border-radius')).toBe('999px')
    expect(style('.maintenance-section-heading p').getPropertyValue('margin')).toBe('4px 0 0 14px')
    expect(style('.maintenance-section-heading p').getPropertyValue('font-size')).toBe('12px')
    expect(style('.maintenance-section-heading p').getPropertyValue('line-height')).toBe('18px')
    expect(style('.maintenance-card').getPropertyValue('padding')).toBe('18px 20px')
    expect(style('.maintenance-card + .maintenance-card').getPropertyValue('margin-top')).toBe('22px')
    expect(style('.maintenance-stat-grid').getPropertyValue('grid-template-columns')).toBe('minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1.25fr)')
    expect(style('.maintenance-stat-grid > div').getPropertyValue('min-height')).toBe('74px')
    expect(style('.maintenance-stat-grid > div').getPropertyValue('box-sizing')).toBe('border-box')
    expect(style('.maintenance-stat-grid > div').getPropertyValue('padding')).toBe('12px 14px')
    expect(style('.maintenance-stat-grid > div').getPropertyValue('gap')).toBe('6px')
    expect(style('.maintenance-stat-grid > div').getPropertyValue('justify-content')).toBe('flex-start')
    expect(style('.maintenance-stat-grid > div > span:not(.ant-tag)').getPropertyValue('font-size')).toBe('12px')
    expect(style('.maintenance-stat-grid strong').getPropertyValue('font-weight')).toBe('600')
  })

  it('keeps idle portal space flat and current-version feedback mint green with a filled library check', () => {
    const rules = maintenanceContainerRules(maintenanceStyles)
      .filter((rule): rule is CSSStyleRule => 'selectorText' in rule)
    const style = (selector: string) => rules.find((rule) => rule.selectorText === selector)!.style
    expect(style('.native-upgrade-panel--idle').getPropertyValue('margin-top')).toBe('0')
    expect(style('.maintenance-page .maintenance-current-status').getPropertyValue('color')).toBe('var(--cdnca-color-success)')
    expect(style('.maintenance-page .maintenance-current-status').getPropertyValue('background')).toBe('#edfbf3')
    expect(style('.maintenance-page .maintenance-current-status').getPropertyValue('border-color')).toBe('#c8efd9')
    expect(style('.maintenance-current-status svg').getPropertyValue('fill')).toBe('currentColor')
    expect(style('.maintenance-current-status svg').getPropertyValue('stroke')).toBe('#fff')
    expect(style('.native-upgrade-panel .ant-btn, .native-upgrade-modal .ant-btn, .maintenance-native-actions .ant-btn').getPropertyValue('white-space')).toBe('normal')
    expect(style('.native-upgrade-panel .ant-btn > span, .native-upgrade-modal .ant-btn > span, .maintenance-native-actions .ant-btn > span').getPropertyValue('overflow-wrap')).toBe('anywhere')
  })

  it('uses open table edges and removes only decorative header dividers', () => {
    const rules = maintenanceContainerRules(maintenanceStyles)
      .filter((rule): rule is CSSStyleRule => 'selectorText' in rule)
    const style = (selector: string) => rules.find((rule) => rule.selectorText === selector)!.style
    expect(style('.maintenance-node-table').getPropertyValue('border')).toBe('0')
    expect(style('.maintenance-node-table').getPropertyValue('border-radius')).toBe('0')
    expect(style('.maintenance-node-table .ant-table-thead > tr > th:not(:last-child)::before').getPropertyValue('display')).toBe('none')
    expect(style('.maintenance-node-table .ant-table-thead > tr > th').getPropertyValue('background')).toBe('#fbfcfe')
    expect(style('.maintenance-node-table .ant-tag').getPropertyValue('white-space')).toBe('normal')
    expect(style('.maintenance-node-table .ant-table-cell').getPropertyValue('overflow-wrap')).toBe('anywhere')
  })

  it('allows long credential-reference labels to wrap legibly without compressing lines', () => {
    const rules = maintenanceContainerRules(maintenanceStyles)
      .filter((rule): rule is CSSStyleRule => 'selectorText' in rule)
    const style = (selector: string) => rules.find((rule) => rule.selectorText === selector)!.style
    expect(style('.maintenance-operation-form .ant-form-item-label').getPropertyValue('padding')).toBe('0 12px 0 0')
    expect(style('.maintenance-operation-form .ant-form-item-label').getPropertyValue('min-height')).toBe('32px')
    expect(style('.maintenance-operation-form .ant-form-item-label > label').getPropertyValue('line-height')).toBe('1.5')
    expect(style('.maintenance-operation-form .ant-form-item-label > label').getPropertyValue('word-break')).toBe('keep-all')
    expect(style('.maintenance-operation-form .ant-form-item-label > label').getPropertyValue('overflow-wrap')).toBe('anywhere')
  })
})

// C06/X06: the migration host-key row shrinks the field instead of pushing it out of the panel.
it('lets the migration host-key field shrink inside the panel', () => {
  const rules = maintenanceContainerRules(maintenanceStyles).filter((rule): rule is CSSStyleRule => 'selectorText' in rule)
  const row = rules.find((rule) => rule.selectorText === '.control-backup-hostkey')!
  const field = rules.find((rule) => rule.selectorText === '.control-backup-hostkey > .ant-space-item:first-child')!
  expect(row.style.getPropertyValue('width')).toBe('100%')
  expect(field.style.getPropertyValue('min-width')).toBe('0')
  expect(field.style.getPropertyValue('max-width')).toBe('460px')
})
