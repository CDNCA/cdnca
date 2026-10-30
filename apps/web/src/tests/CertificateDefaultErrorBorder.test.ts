import toolbarCSS from '../styles/compact-toolbar.css?raw'

// fix-fielderr-be5（截图核对发现）：compact-toolbar 给 .app-shell / .ant-modal-root 里所有单选 Select 设了中性边框色，
// 优先级高于 antd 的错误态，被拒的选择框（证书默认设置的 DNS API 等）只剩下方红字、边框不变红。
// 共享层须为错误态恢复红色边框，且优先级不低于中性边框规则、写在其后。
const neutral = '.app-shell .ant-select-single:not(.ant-select-sm):not(.ant-select-customize-input) .ant-select-selector,'
const refused = '.app-shell .ant-select-single.ant-select-status-error:not(.ant-select-customize-input) .ant-select-selector[class],'

it('keeps the error border on a refused select inside the app shell and modals', function refusedSelectBorder() {
  const at = toolbarCSS.indexOf(refused)
  expect(at).toBeGreaterThan(toolbarCSS.indexOf(neutral))
  const block = toolbarCSS.slice(at, toolbarCSS.indexOf('}', at))
  expect(block).toContain('.ant-modal-root .ant-select-single.ant-select-status-error:not(.ant-select-customize-input) .ant-select-selector[class]')
  expect(block).toMatch(/border-color:\s*var\(--cdnca-color-error\);/)
})
