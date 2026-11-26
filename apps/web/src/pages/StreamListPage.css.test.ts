import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// the create modal's Form.Item hidden fields (protocol, ports, upstream mode,
// target scope) stay out of the layout; a later display rule for form items must not bring them back.
const css = readFileSync(join(__dirname, 'StreamListPage.css'), 'utf8')

describe('stream modal hidden form items', () => {
  it('keeps hidden items out of the layout at every width', () => {
    // A rule more specific than any display rule for .stream-modal .ant-form-item (0,3,0 against 0,2,0).
    expect(css).toMatch(/\.stream-modal \.ant-form-item\.ant-form-item-hidden\s*\{\s*display:\s*none;/)
    for (const rule of css.matchAll(/([^{}]+)\{([^{}]*display:[^{}]*)\}/g)) {
      const selectors = rule[1].split(',').map((part) => part.trim())
      for (const selector of selectors) {
        // Nothing reaches the hidden item with a stronger selector than the hidden rule.
        expect(/\.ant-form-item-hidden/.test(selector) || !/\.stream-modal [^ ]*\.ant-form-item[.:#\[]/.test(selector), selector).toBe(true)
      }
    }
  })
})
