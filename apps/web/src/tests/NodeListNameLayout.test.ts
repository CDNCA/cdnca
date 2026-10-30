import css from '../pages/NodeListPage.css?raw'

it('keeps the beginning of long node names visible instead of centering clipped button text', function nodeNamePreservesBeginning() {
  const rule = css.match(/\.node-list-name-link\s*\{([^}]+)\}/)?.[1]
  expect(rule).toBeDefined()
  expect(rule).toMatch(/display:\s*block;/)
  expect(rule).toMatch(/text-align:\s*left;/)
  expect(rule).toMatch(/max-width:\s*100%;/)
  expect(rule).toMatch(/text-overflow:\s*ellipsis;/)
})
