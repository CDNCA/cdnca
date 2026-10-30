import { enUS, zhCN } from './siteRealtime'

function keys(value: unknown, prefix = ''): string[] {
  if (!value || typeof value !== 'object') return [prefix]
  return Object.entries(value).flatMap(([key, child]) => keys(child, prefix ? `${prefix}.${key}` : key))
}

it('keeps the site realtime locale surfaces structurally complete', () => {
  expect(keys(enUS).sort()).toEqual(keys(zhCN).sort())
})
