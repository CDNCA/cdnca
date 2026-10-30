import { describe, expect, it } from 'vitest'

import { conditionValues } from './conditionValues'

describe('conditionValues', () => {
  it('keeps commas inside regex quantifiers', () => {
    expect(conditionValues('(\\.\\./|\\.\\.\\\\){2,}')).toEqual(['(\\.\\./|\\.\\.\\\\){2,}'])
    expect(conditionValues('^/a\\d{1,3}$')).toEqual(['^/a\\d{1,3}$'])
  })

  it('splits one value per line and drops blanks', () => {
    expect(conditionValues(' 10.0.0.0/8 \n\n(\\.\\./){2,}\r\n192.168.0.1 ')).toEqual(['10.0.0.0/8', '(\\.\\./){2,}', '192.168.0.1'])
  })
})
