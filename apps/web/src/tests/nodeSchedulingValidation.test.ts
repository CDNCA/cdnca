import { validCodePointLength } from '../pages/node-scheduling/shared'

describe('node scheduling Unicode validation', () => {
  it('uses a raw code-point upper bound and a trimmed nonblank lower bound', () => {
    expect(validCodePointLength(`  ${'🙂'.repeat(124)}  `, 1, 128)).toBe(true)
    expect(validCodePointLength(`  ${'🙂'.repeat(125)}  `, 1, 128)).toBe(false)
    expect(validCodePointLength('   ', 1, 128)).toBe(false)
    expect(validCodePointLength('', 0, 64)).toBe(true)
  })
})
