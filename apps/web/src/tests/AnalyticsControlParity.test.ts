const styles = Object.values(import.meta.glob('../styles/analyticsControlParity.css', {
  eager: true, import: 'default', query: '?raw',
}))[0] as string | undefined

function declarations(selector: string): CSSStyleDeclaration | undefined {
  const element = document.createElement('style')
  element.textContent = styles ?? ''
  document.head.append(element)
  const rule = [...element.sheet!.cssRules]
    .filter((candidate): candidate is CSSStyleRule => 'selectorText' in candidate)
    .find((candidate) => candidate.selectorText.split(',').some((part) => part.trim() === selector))
  element.remove()
  return rule?.style
}

describe('realtime quick-range control parity', () => {
  it('centers the layer-4 time range without affecting other radio buttons', () => {
    const label = declarations('.l4-realtime-baseline-page .l4-realtime-baseline-range .ant-radio-button-wrapper')
    expect(label?.height).toBe('32px')
    expect(label?.display).toBe('inline-flex')
    expect(label?.getPropertyValue('align-items')).toBe('center')
    expect(label?.getPropertyValue('justify-content')).toBe('center')
    expect(label?.getPropertyValue('line-height')).toBe('20px')
    expect(styles).not.toMatch(/transform\s*:|translateY/)
  })
})
