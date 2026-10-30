// antd 5 Segmented 切换时先播滑块动画，动画结束（onMotionEnd）才给新项加 -selected 类。
// 若把 .ant-segmented-thumb 设为 display:none，动画永远不结束，点击后选中态不出现（10-27 实时监控时间范围点了没反馈）。
const css = Object.values(import.meta.glob('../styles.css', { eager: true, import: 'default', query: '?raw' }))[0] as string

it('never hides the Segmented thumb with display:none', () => {
  const rules = [...css.matchAll(/([^{}]*\.ant-segmented-thumb[^{}]*)\{([^}]*)\}/g)]
  expect(rules.length).toBeGreaterThan(0)
  for (const [, selector, body] of rules) {
    expect(body, selector.trim()).not.toMatch(/display:\s*none/)
  }
})
