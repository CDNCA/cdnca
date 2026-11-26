import { describe, expect, it } from 'vitest'

import styles from '../styles.css?raw'

// （用户列表、节点列表真实 Tab 轨迹，/390/1440px 浏览器对照）：scroll.x 时
// rc-table 测宽行复制了一份表头全选框，键盘停两次。测宽行内容 visibility: hidden 后不再可聚焦，列宽不变。
describe('table measure row', () => {
  it('hides the measured copy of the header so its checkbox takes no focus', () => {
    expect(styles).toMatch(/\.ant-table-measure-row \.ant-table-measure-cell-content\s*\{\s*visibility:\s*hidden;\s*\}/)
  })
})
