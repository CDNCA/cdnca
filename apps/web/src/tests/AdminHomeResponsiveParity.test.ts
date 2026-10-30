import { defaultLookCSS } from '../test/defaultLookCSS'

const referenceStyles = defaultLookCSS(Object.values(import.meta.glob('../styles/adminHomeReference.css', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string)

function layoutAt(width: number, selector: string, property: string) {
  const element = document.createElement('style')
  element.textContent = referenceStyles
  document.head.append(element)
  let value = ''
  const visit = (rules: CSSRuleList) => {
    for (const rule of [...rules]) {
      if ('conditionText' in rule) {
        const media = rule as CSSMediaRule
        const maximum = /max-width:\s*([\d.]+)px/.exec(media.conditionText)
        if (maximum && width <= Number(maximum[1])) visit(media.cssRules)
      } else if ('selectorText' in rule) {
        const style = rule as CSSStyleRule
        if (style.selectorText.split(',').some((part) => part.trim() === selector)) {
          value = style.style.getPropertyValue(property) || value
        }
      }
    }
  }
  visit(element.sheet!.cssRules)
  element.remove()
  return value
}

describe('administrator overview responsive parity', () => {
  it('applies the dark surface to the chart canvas instead of leaving a white chart', () => {
    const canvas = '.app-shell.is-dark .admin-overview .dashboard-operation-chart__canvas'
    expect(layoutAt(1200, canvas, 'background')).toBe('#111c2e')
    expect(layoutAt(1200, canvas, 'border-color')).toBe('#1f2a3d')
  })

  it('wraps expanded mobile range labels without scrolling the whole card sideways', () => {
    const range = '.admin-overview .dashboard-block-extra > .dashboard-range-control'
    expect(layoutAt(390, range, 'max-width')).toBe('100%')
    expect(layoutAt(390, range, 'flex-wrap')).toBe('wrap')
    expect(layoutAt(390, range, 'height')).toBe('auto')
    expect(layoutAt(390, '.admin-overview .dashboard-block-extra', 'height')).toBe('auto')
    expect(layoutAt(390, '.admin-overview .dashboard-block-extra', 'min-height')).toBe('34px')
  })

  it.each([390, 760, 767, 768, 1200, 1340])('stacks all three dashboard grids at %ipx', (width) => {
    for (const grid of ['reference-layout', 'monitoring-grid', 'operation-panels']) {
      expect(layoutAt(width, `.admin-overview .dashboard-${grid}`, 'grid-template-columns')).toBe('minmax(0, 1fr)')
    }
    expect(layoutAt(width, '.admin-overview .dashboard-operation-panels', 'height')).toBe('auto')
  })

  it.each([1341, 1440, 1920])('retains the wide desktop grid at %ipx', (width) => {
    for (const grid of ['reference-layout', 'monitoring-grid']) {
      expect(layoutAt(width, `.admin-overview .dashboard-${grid}`, 'grid-template-columns')).toBe('minmax(0, calc(66.666667% - 5.333333px)) minmax(0, calc(33.333333% - 10.666667px))')
    }
    expect(layoutAt(width, '.admin-overview .dashboard-operation-panels', 'grid-template-columns')).toBe('repeat(3, minmax(0, 1fr))')
    expect(layoutAt(width, '.admin-overview .dashboard-operation-panels', 'height')).toBe('262px')
  })
})
