import { describe, expect, it } from 'vitest'
import { sitePublicationsMessages } from './sitePublications'

function text(locale: keyof typeof sitePublicationsMessages, path: string): string {
  let value: unknown = sitePublicationsMessages[locale]
  for (const segment of path.split('.')) {
    if (typeof value !== 'object' || value === null) throw new Error(`missing ${locale}:${path}`)
    value = (value as Record<string, unknown>)[segment]
  }
  if (typeof value !== 'string') throw new Error(`missing ${locale}:${path}`)
  return value
}

describe('site publications line switch locale contract', () => {
  it.each([
    'lineSwitch.unknown.title',
    'lineSwitch.unknown.description',
    'lineSwitch.actions.retryExact',
    'lineSwitch.actions.abandonRefresh',
    'lineSwitch.actions.retryRead',
    'lineSwitch.errors.forbidden',
    'lineSwitch.errors.invalid',
  ])('provides %s for zh-CN, en-US, and the pseudo locale', (path) => {
    expect(text('zh-CN', path)).toBeTruthy()
    expect(text('en-US', path)).toBeTruthy()
    expect(text('qps-ploc', path)).toContain('［')
    expect(text('qps-ploc', path).length).toBeGreaterThan(text('zh-CN', path).length)
  })

  it.each([
    'rollout.strategy',
    'rollout.canarySize',
    'rollout.batchSize',
    'rollout.failureThreshold',
    'rollout.releasedCohort',
    'actions.start',
    'actions.pause',
    'actions.resume',
    'pauseReasons.failure_threshold',
  ])('provides rollout cohort key %s for every locale', (path) => {
    expect(text('zh-CN', path)).toBeTruthy()
    expect(text('en-US', path)).toBeTruthy()
    expect(text('qps-ploc', path)).toContain('［')
  })
})
