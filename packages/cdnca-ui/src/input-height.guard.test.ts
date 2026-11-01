// Guard: IdOrNameInput and the TimeRangeFilter custom box stay 32px high
// next to the toolbar's Select / Button. Page toolbars force `.ant-input { height: 32px !important }`,
// which also hits the input inside antd's affix wrapper (clear icon / suffix): the field grew to 43px and
// the time box's text overflowed to its bottom left. The shared styles must reset that inner input.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const css = readFileSync(join(__dirname, 'styles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')
const body = (selector: string) => {
  const at = css.indexOf(`${selector} {`)
  expect(at, selector).toBeGreaterThanOrEqual(0)
  return css.slice(at, css.indexOf('}', at)).replace(/\s+/g, ' ')
}

describe('shared filter inputs keep the 32px toolbar height', () => {
  it.each([
    '.cdnca-id-or-name .ant-input-affix-wrapper > input.ant-input',
    '.cdnca-time-range .cdnca-time-range-input input.ant-input',
  ])('%s resets page-forced input height', (selector) => {
    const rule = body(selector)
    expect(rule).toContain('height: auto !important')
    expect(rule).toContain('min-height: 0 !important')
  })

  it('the custom box itself is 32px', () => {
    expect(body('.cdnca-time-range .cdnca-time-range-input')).toContain('height: 32px')
  })
})
