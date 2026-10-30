import css from '../pages/NodeListPage.css?raw'
import tsx from '../pages/NodeListPage.tsx?raw'
import sharedCSS from '../../../../packages/cdnca-ui/src/styles.css?raw'

// 编辑节点弹窗：antd 把 wrapperCol flex: 1 展开成 "1 1 auto"，行又默认 flex-wrap: wrap，
// 带长说明文字的行（区域、类型、外部探测…）控件列会整体掉到标签下面、从最左侧开始。
// 同一页所有行都是 80px 右对齐标签 + 右侧控件，说明文字与输入框左对齐。
function rule(selector: string) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return css.match(new RegExp(`(?:^|\\n|,\\s*)${escaped}\\s*(?:,[^{]*)?\\{([^}]+)\\}`))?.[1]
}

it('keeps every edit-node row as label + control instead of wrapping the control below', function editRowsDoNotWrap() {
  expect(rule('.node-list-edit-form .ant-form-item-row')).toMatch(/flex-wrap:\s*nowrap;/)
  expect(rule('.node-list-edit-form .ant-form-item-control')).toMatch(/min-width:\s*0;/)
})

it('does not double the modal padding, so the five tabs fit like the reference', function editModalPadding() {
  expect(rule('.node-list-modal .ant-modal-body')).toMatch(/padding:\s*22px 0 8px;/)
  // 字体更宽时 tab 横向滚动，不再折叠成 "…" 下拉。
  expect(rule('.node-list-modal .ant-tabs-nav-operations')).toMatch(/display:\s*none !important;/)
})

// 节点设置顶部蓝色提示框字号过大（antd 带 description 时标题 16px），
// 弹窗内提示框统一用共享紧凑样式，字号与同页说明文字一致（12px / 18px），标题不加粗不放大。
it('keeps every edit-node alert compact, matching the dialog help text', function editAlertsCompact() {
  const source = tsx.slice(tsx.indexOf('function NodeEditModal('), tsx.indexOf('function NodeFormModal('))
  const alerts = source.match(/<Alert\b[^>]*?(?:\/>|>)/gs) ?? []
  expect(alerts.length).toBeGreaterThanOrEqual(4)
  for (const alert of alerts) expect(alert).toMatch(/className="node-modal-alert cdnca-alert-compact"/)
  const compact = sharedCSS.match(/\.ant-alert\.cdnca-alert-compact \.ant-alert-message[^{]*\{([^}]+)\}/)?.[1] ?? ''
  expect(compact).toMatch(/font-size:\s*12px;/)
  expect(compact).toMatch(/font-weight:\s*400;/)
  const description = sharedCSS.match(/\.ant-alert\.cdnca-alert-compact \.ant-alert-description\s*\{([^}]+)\}/)?.[1] ?? ''
  expect(description).toMatch(/font-size:\s*12px;/)
  expect(description).toMatch(/line-height:\s*18px;/)
  expect(rule('.node-list-edit-form .ant-form-item-extra')).toMatch(/font-size:\s*12px;\s*line-height:\s*18px;/)
})

it('wraps long labels in the 80px column instead of overlapping the control', function editLabelsWrap() {
  const source = tsx.slice(tsx.indexOf('function NodeEditModal('), tsx.indexOf('function NodeFormModal('))
  expect(source.match(/layout="horizontal"\n\s+colon=\{false\}\n\s+labelWrap\n/g)).toHaveLength(5)
})
