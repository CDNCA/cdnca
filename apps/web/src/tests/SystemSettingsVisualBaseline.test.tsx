import { defaultLookCSS } from '../test/defaultLookCSS'

const styles = defaultLookCSS(Object.values(import.meta.glob('../styles.css', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string)

function lastStyleRule(selector: string): CSSStyleRule {
  const style = document.createElement('style')
  style.textContent = styles
  document.head.append(style)
  const rules = [...(style.sheet?.cssRules ?? [])]
  style.remove()
  const rule = rules
    .filter((candidate): candidate is CSSStyleRule => 'selectorText' in candidate)
    .filter((candidate) => candidate.selectorText.split(',').map((part) => part.trim()).includes(selector))
    .at(-1)
  expect(rule, `missing CSS rule ${selector}`).toBeDefined()
  return rule as CSSStyleRule
}

function mobileStyleRule(selector: string): CSSStyleRule | undefined {
  const style = document.createElement('style')
  style.textContent = styles
  document.head.append(style)
  const rule = [...(style.sheet?.cssRules ?? [])]
    .filter((candidate): candidate is CSSMediaRule => 'conditionText' in candidate && candidate.conditionText === '(max-width: 767px)')
    .flatMap((media) => [...media.cssRules])
    .filter((candidate): candidate is CSSStyleRule => 'selectorText' in candidate)
    .filter((candidate) => candidate.selectorText.split(',').map((part) => part.trim()).includes(selector))
    .at(-1)
  style.remove()
  return rule
}

describe('system settings visual baseline', () => {
  it('locks the observed card shell, form grid, and section titles', () => {
    const page = lastStyleRule('.system-settings-baseline-page.sys-setting')
    expect(page.style.getPropertyValue('padding')).toBe('18px 20px 20px')
    expect(page.style.getPropertyValue('background')).toBe('var(--setting-bg)')
    expect(page.style.getPropertyValue('border')).toBe('1px solid transparent')
    expect(page.style.getPropertyValue('border-radius')).toBe('10px')

    const topTabWrap = lastStyleRule('.system-settings-baseline-page.sys-setting > .ant-tabs .ant-tabs-nav-wrap')
    expect(topTabWrap.style.getPropertyValue('overflow-x')).toBe('auto')

    const topTab = lastStyleRule('.system-settings-baseline-page.sys-setting > .ant-tabs .ant-tabs-tab')
    expect(topTab.style.getPropertyValue('margin')).toBe('0 6px 0 0')
    expect(topTab.style.getPropertyValue('padding')).toBe('6px 16px')
    expect(topTab.style.getPropertyValue('border-radius')).toBe('8px')
    const activeTopTab = lastStyleRule('.system-settings-baseline-page.sys-setting > .ant-tabs .ant-tabs-tab-active')
    expect(activeTopTab.style.getPropertyValue('background')).toBe('rgb(45 140 240 / 12%)')
    expect(activeTopTab.style.getPropertyValue('font-weight')).toBe('600')
    const topTabInk = lastStyleRule('.system-settings-baseline-page.sys-setting > .ant-tabs .ant-tabs-ink-bar')
    expect(topTabInk.style.getPropertyValue('display')).toBe('none')

    const card = lastStyleRule('.system-settings-baseline-page.sys-setting .system-settings-config-card')
    expect(card.style.getPropertyValue('max-width')).toBe('1120px')
    expect(card.style.getPropertyValue('padding')).toBe('18px 20px')
    expect(card.style.getPropertyValue('border')).toBe('1px solid var(--setting-border-strong)')
    expect(card.style.getPropertyValue('border-radius')).toBe('8px')

    const control = lastStyleRule('.system-settings-baseline-page.sys-setting .system-settings-baseline-form .ant-form-item-control')
    expect(control.style.getPropertyValue('flex')).toBe('0 0 760px')
    expect(control.style.getPropertyValue('max-width')).toBe('760px')

    const title = lastStyleRule('.system-settings-baseline-page.sys-setting .system-settings-config-card-title')
    expect(title.style.getPropertyValue('font-size')).toBe('17px')
    expect(title.style.getPropertyValue('font-weight')).toBe('600')
    const prefix = lastStyleRule('.system-settings-baseline-page.sys-setting .system-settings-config-card-title::before')
    expect(prefix.style.getPropertyValue('width')).toBe('4px')
    expect(prefix.style.getPropertyValue('height')).toBe('16px')
    expect(prefix.style.getPropertyValue('background')).toBe('var(--setting-primary)')

    const brandGrid = lastStyleRule('.system-settings-baseline-page.sys-setting .system-settings-brand-grid')
    expect(brandGrid.style.getPropertyValue('display')).toBe('grid')
    expect(brandGrid.style.getPropertyValue('grid-template-columns')).toBe('repeat(3, minmax(0, 1fr))')
    const brandCard = lastStyleRule('.system-settings-baseline-page.sys-setting .system-settings-brand-asset-card')
    expect(brandCard.style.getPropertyValue('padding')).toBe('14px')
    expect(brandCard.style.getPropertyValue('border')).toBe('1px solid var(--setting-border-strong)')
    expect(brandCard.style.getPropertyValue('border-radius')).toBe('8px')

    const paymentGrid = lastStyleRule('.system-settings-baseline-page.sys-setting .system-settings-payment-grid')
    expect(paymentGrid.style.getPropertyValue('grid-template-columns')).toBe('repeat(3, minmax(0, 1fr))')
    expect(paymentGrid.style.getPropertyValue('gap')).toBe('12px')
    const paymentCard = lastStyleRule('.system-settings-baseline-page.sys-setting .system-settings-payment-card')
    expect(paymentCard.style.getPropertyValue('padding')).toBe('14px')
    expect(paymentCard.style.getPropertyValue('border')).toBe('1px solid var(--setting-border)')
    expect(paymentCard.style.getPropertyValue('border-radius')).toBe('6px')
  })

  it('switches the form to a full-width stacked layout on narrow screens', () => {
    const page = mobileStyleRule('.system-settings-baseline-page.sys-setting')
    expect(page?.style.getPropertyValue('padding')).toBe('0 14px 14px')
    const row = mobileStyleRule('.system-settings-baseline-page.sys-setting .system-settings-baseline-form .ant-form-item-row')
    expect(row?.style.getPropertyValue('display')).toBe('block')
    const control = mobileStyleRule('.system-settings-baseline-page.sys-setting .system-settings-baseline-form .ant-form-item-control')
    expect(control?.style.getPropertyValue('width')).toBe('100%')
    const brandGrid = mobileStyleRule('.system-settings-baseline-page.sys-setting .system-settings-brand-grid')
    expect(brandGrid?.style.getPropertyValue('grid-template-columns')).toBe('minmax(0, 1fr)')
    const paymentGrid = mobileStyleRule('.system-settings-baseline-page.sys-setting .system-settings-payment-grid')
    expect(paymentGrid?.style.getPropertyValue('grid-template-columns')).toBe('minmax(0, 1fr)')
  })
})
