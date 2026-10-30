import {
  trimUnicodeWhiteSpace,
  validCodePointLength,
  validStableKey,
} from '../pages/node-scheduling/shared'

describe('node scheduling Unicode White_Space contract', () => {
  it('matches Go Unicode White_Space and keeps labels control-free', () => {
    expect(validCodePointLength('\u0085', 1, 1024)).toBe(false)
    expect(validCodePointLength('\ufeff', 1, 1024)).toBe(true)
    expect(validCodePointLength('\u0085线路', 1, 128)).toBe(false)
    expect(validCodePointLength('\u00a0线路\u3000', 2, 4)).toBe(true)
  })

  it('applies the maximum to raw code points before boundary trimming', () => {
    expect(validCodePointLength(`\u00a0${'界'.repeat(127)}`, 1, 128)).toBe(true)
    expect(validCodePointLength(`\u00a0${'界'.repeat(128)}`, 1, 128)).toBe(false)
    expect(validCodePointLength(`${'界'.repeat(127)}\ufeff`, 1, 128)).toBe(true)
    expect(validCodePointLength(`${'界'.repeat(128)}\ufeff`, 1, 128)).toBe(false)
  })

  it('separates control-free labels from stable-key selection semantics', () => {
    expect(trimUnicodeWhiteSpace('\u0085\u00a0key\u3000')).toBe('key')
    expect(trimUnicodeWhiteSpace('\ufeffkey\ufeff')).toBe('\ufeffkey\ufeff')
    expect(validStableKey('\u0085', 1024)).toBe(false)
    expect(validStableKey('\ufeff', 1024)).toBe(true)
    expect(validStableKey('key\u0000', 1024)).toBe(true)
    expect(validStableKey(`${'键'.repeat(1024)}\u0085`, 1024)).toBe(false)
  })
})
