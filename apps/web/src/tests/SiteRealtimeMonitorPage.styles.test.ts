const css = Object.values(import.meta.glob('../pages/SiteRealtimeMonitorPage.css', {
  eager: true, import: 'default', query: '?raw',
}))[0] as string

it('preserves the accepted 1340px single-column breakpoint for site realtime charts', () => {
  expect(css).toMatch(/@media\s*\(max-width:\s*1340px\)\s*\{\s*\.analytics-realtime-page \.analytics-realtime-chart-grid\s*\{\s*grid-template-columns:\s*minmax\(0,\s*1fr\);/)
  expect(css).not.toMatch(/@media\s*\(max-width:\s*900px\)/)
})
