// Shared by the default-look lock tests: expands the theme variables that
// apps/web CSS wraps around its hard-coded colors back to the default values,
// so a stylesheet can be compared declaration by declaration with its
// pre-theme text.
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// import.meta.url is a file: URL under node --test, an http one under vitest+jsdom.
const here = import.meta.url.startsWith('file:') ? dirname(fileURLToPath(import.meta.url)) : resolve(process.cwd(), 'scripts')
const sharedStyles = resolve(here, '../../../packages/cdnca-ui/src/styles.css')

/** The --cdnca-* defaults declared on :root by @cdnca/ui/styles.css. */
export function defaultVariables() {
  const css = readFileSync(sharedStyles, 'utf8')
  const root = css.slice(css.indexOf(':root {'), css.indexOf('}', css.indexOf(':root {')))
  const variables = new Map()
  for (const match of root.matchAll(/^\s*(--cdnca-[a-z0-9-]+):\s*([^;]+);/gm)) variables.set(match[1], match[2].trim())
  return variables
}

// var(--cdnca-x, fallback) with one level of nested parentheses in fallback.
export const wrappedVariable = /var\((--cdnca-[a-z0-9-]+),\s*((?:[^()]|\([^()]*\))+)\)/g

const hex2 = (n) => Number(n).toString(16).padStart(2, '0')
const alphaText = (a) => String(Math.round(a * 1e6) / 1e6)

// Translucent colors compare by computed value: rgba(45, 140, 240, .1),
// rgb(45 140 240 / 10%) and color-mix(in srgb, #2d8cf0 10%, transparent)
// (how a theme-derived translucent color is written) all become
// "#2d8cf0/0.1"; an opaque rgb() becomes its hex.
function canonicalColors(value) {
  return value
    .replace(/color-mix\(in srgb,\s*#([0-9a-fA-F]{6})\s+([\d.]+)%,\s*transparent\)/g, (_, h, p) => `#${h.toLowerCase()}/${alphaText(parseFloat(p) / 100)}`)
    .replace(/rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)\s*(?:[,/]\s*([\d.]+)(%?)\s*)?\)/g, (_, r, g, b, a, pct) => {
      const hex = `#${hex2(r)}${hex2(g)}${hex2(b)}`
      if (a === undefined) return hex
      const alpha = pct ? parseFloat(a) / 100 : parseFloat(a)
      return alpha === 1 ? hex : `${hex}/${alphaText(alpha)}`
    })
}

export function normalizeValue(value) {
  return canonicalColors(value
    .replace(/#([0-9a-fA-F]{3})\b/g, (_, h) => `#${[...h].map((c) => c + c).join('')}`))
    .replace(/#([0-9a-fA-F]{6})\b/g, (_, h) => `#${h.toLowerCase()}`)
    .replace(/\s+/g, ' ')
    .trim()
}

/** Replaces every var(--cdnca-x, fallback) by its fallback. */
export function expandFallbacks(css) {
  let previous
  let current = css
  do {
    previous = current
    current = current.replace(wrappedVariable, (_, _name, fallback) => fallback.trim())
  } while (current !== previous)
  return current
}

/** Flat list "selector { property: value }" of a stylesheet, comments dropped. */
export function declarations(css) {
  const text = css.replace(/\/\*[\s\S]*?\*\//g, '')
  const result = []
  const stack = []
  let buffer = ''
  for (const char of text) {
    if (char === '{') {
      stack.push(buffer.trim().replace(/\s+/g, ' '))
      buffer = ''
    } else if (char === '}' || char === ';') {
      const body = buffer.trim()
      if (body) {
        const colon = body.indexOf(':')
        result.push(`${stack.join(' >> ')} { ${body.slice(0, colon).trim()}: ${normalizeValue(body.slice(colon + 1))} }`)
      }
      buffer = ''
      if (char === '}') stack.pop()
    } else {
      buffer += char
    }
  }
  return result
}

// themeColor('--cdnca-x', 'fallback') / themeColorAlpha('--cdnca-x', 'fallback', alpha)
// in apps/web scripts (src/theme/themeColor.ts).
export const scriptVariable = /themeColor(?:Alpha)?\('(--cdnca-[a-z0-9-]+)',\s*'([^']+)'/g

// A color literal left in a stylesheet or script, outside var(--cdnca-*, …)
// and themeColor(…): what the "no hard-coded color" check counts.
const colorLiteral = /#[0-9a-fA-F]{8}\b|#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3}\b|rgba?\([^)]*\)/g

/** Color literals of a stylesheet (css) or script, comments and theme reads removed. */
export function hardCodedColors(text, css) {
  let body = text.replace(/\/\*[\s\S]*?\*\//g, '')
  if (!css) body = body.replace(/(^|[^:'"`])\/\/.*$/gm, '$1')
  body = css ? expandAway(body) : body.replace(scriptVariable, '')
  return body.match(colorLiteral) ?? []
}

function expandAway(css) {
  let previous
  let current = css
  do {
    previous = current
    current = current.replace(wrappedVariable, 'VAR')
  } while (current !== previous)
  return current
}

// Allowed literals: the tech look's own fixed colors (tech-look.css is the
// tech theme, not the default look), fully transparent black (no color to
// theme) and themeColorAlpha's rgba() template. theme/customize.ts writes
// theme token values (shadow text), it paints nothing itself.
export const colorExceptions = { files: ['apps/web/src/styles/tech-look.css', 'apps/web/src/theme/themeColor.ts', 'apps/web/src/theme/customize.ts'], literals: ['rgba(0, 0, 0, 0)'] }

/** "file: literal" for every hard-coded color apps/web still has. */
export function leftoverColors(files, read) {
  const result = []
  for (const file of files) {
    if (colorExceptions.files.includes(file) || !/\.(css|tsx?)$/.test(file) || /\.test\.|\/tests?\//.test(file)) continue
    for (const literal of hardCodedColors(read(file), file.endsWith('.css'))) {
      if (!colorExceptions.literals.includes(literal)) result.push(`${file}: ${literal}`)
    }
  }
  return result
}

// Single list for src/tests/DefaultLookLock.test.ts and scripts/default-look-lock.test.mjs.
// Base declarations removed on purpose (fixing a defect of the old look), by
// file and selector prefix, each with its reason.
export const intentionalRemovals = [
  // cdncaCE：社区版去掉计费/套餐面板，管理首页操作区由三列改为一列。
  { file: 'apps/web/src/styles/adminHomeReference.css', selector: '.admin-overview .dashboard-operation-panels { grid-template-columns:' },
  // 系统设置充值方式卡片加 USDT，网格由 3 列改为 4 列（窄屏 2 列）。
  { file: 'apps/web/src/styles.css', selector: '.system-settings-baseline-page.sys-setting .system-settings-payment-grid { grid-template-columns: repeat(3,' },
  // 操作记录页工具栏移到标签行右侧（SiteCacheTabs extra），不再单独占一行，故去掉行距与两端对齐。
  { file: 'apps/web/src/pages/CacheOperationHistoryPage.css', selector: '.cache-operation-history-toolbar { justify-content:' },
  { file: 'apps/web/src/pages/CacheOperationHistoryPage.css', selector: '.cache-operation-history-toolbar { margin-bottom:' },
  // 一张表只留一个横向滚动容器。表格自带 scroll.x（.ant-table-content 横滚），
  // 外层包装的 overflow-x:auto 与把 .ant-table 撑宽的 min-width 去掉，否则表格下一条、分页下又一条。
  { file: 'apps/web/src/pages/AccountApiKeysPage.css', selector: '.account-api-keys-page .identity-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/AccountApiKeysPage.css', selector: '.account-api-keys-page .identity-table-scroll { overscroll-behavior-inline:' },
  { file: 'apps/web/src/pages/AccountIdentityVerificationPage.css', selector: '.account-identity-verification-page .ant-table { min-width:' },
  { file: 'apps/web/src/pages/AccountIdentityVerificationPage.css', selector: '.account-identity-verification-page .ant-table-wrapper { overflow-x:' },
  { file: 'apps/web/src/pages/AccountIdentityVerificationPage.css', selector: '@media (max-width: 767px) >> .account-identity-verification-page .ant-table { min-width:' },
  { file: 'apps/web/src/pages/AccountMessagesPage.css', selector: '.account-messages-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/AccountOrdersPage.css', selector: '.account-orders-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/AccountSubscriptionsPage.css', selector: '.account-subscriptions-page .identity-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/pages/AccountSubscriptionsPage.css', selector: '.account-subscriptions-page .identity-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/AccountSubscriptionsPage.css', selector: '.account-subscriptions-page .identity-table-scroll { overscroll-behavior-inline:' },
  { file: 'apps/web/src/pages/AccountSubscriptionsPage.css', selector: '@media (max-width: 767px) >> .account-subscriptions-page .identity-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/pages/AdminMessageQueryPage.css', selector: '.admin-message-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/AnnouncementManagementPage.css', selector: '.announcement-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/CacheOperationHistoryPage.css', selector: '.cache-operation-history-table { overflow-x:' },
  { file: 'apps/web/src/pages/CacheOperationHistoryPage.css', selector: '@media (max-width: 900px) >> .cache-operation-history-table { overflow-x:' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '.certificate-page .identity-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '.certificate-page .identity-table-scroll { overscroll-behavior-inline:' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '@media (max-width: 767px) >> .certificate-page .identity-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-node-table { overflow-x:' },
  { file: 'apps/web/src/pages/FinanceOrdersPage.css', selector: '.finance-orders-page .identity-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/FinanceOrdersPage.css', selector: '.finance-orders-page .identity-table-scroll { overscroll-behavior-inline:' },
  { file: 'apps/web/src/pages/IdentitySessionsPage.css', selector: '.identity-sessions-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/pages/IdentitySessionsPage.css', selector: '.identity-sessions-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/IdentitySessionsPage.css', selector: '@media (max-width: 767px) >> .identity-sessions-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/pages/L4RealtimeMonitorPage.css', selector: '.l4-realtime-baseline-ranking-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/NodeIsolationPage.css', selector: '.node-isolation-page > .ant-table-wrapper .ant-table { min-width:' },
  { file: 'apps/web/src/pages/NodeIsolationPage.css', selector: '.node-isolation-page > .ant-table-wrapper { overflow-x:' },
  { file: 'apps/web/src/pages/NodeL2TopologyDetailPage.css', selector: '.node-line-resolution-detail-page .node-line-resolution-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/pages/NodeL2TopologyDetailPage.css', selector: '.node-line-resolution-detail-page .node-line-resolution-table-scroll[data-testid=\'configured-line-ip-table-scroll\'] .ant-table { min-width:' },
  { file: 'apps/web/src/pages/NodeL2TopologyDetailPage.css', selector: '.node-line-resolution-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/pages/NodeL2TopologyDetailPage.css', selector: '.node-line-resolution-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/NodeL2TopologyDetailPage.css', selector: '.node-line-resolution-table-scroll[data-testid=\'configured-line-ip-table-scroll\'] .ant-table { min-width:' },
  { file: 'apps/web/src/pages/NodeL2TopologyPage.css', selector: '.node-l2-nodes-panes .ant-table-wrapper { overflow-x:' },
  { file: 'apps/web/src/pages/NodeLineGroupsPage.css', selector: '.node-line-groups-page .ant-table { min-width:' },
  { file: 'apps/web/src/pages/NodeLineGroupsPage.css', selector: '@media (max-width: 767px) >> .node-line-groups-page .node-line-groups-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/pages/NodeLineGroupsPage.css', selector: '@media (max-width: 767px) >> .node-line-groups-page .node-line-groups-table-scroll .ant-table { width:' },
  { file: 'apps/web/src/pages/NodeListPage.css', selector: '.node-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/pages/NodeListPage.css', selector: '.node-table-scroll--failed .ant-table { min-width:' },
  { file: 'apps/web/src/pages/NodeListPage.css', selector: '.node-table-scroll--pending .ant-table { min-width:' },
  { file: 'apps/web/src/pages/NodeListPage.css', selector: '.node-table-scroll--regions .ant-table { min-width:' },
  { file: 'apps/web/src/pages/NodeSchedulingPage.css', selector: '.node-scheduling-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/pages/NodeSchedulingPage.css', selector: '.node-scheduling-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/SecurityPoliciesPage.css', selector: '.acl-rule-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/SecurityPoliciesPage.css', selector: '.cc-rule-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/SecurityPoliciesPage.css', selector: '.waf-rule-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/SiteAccessLogPage.css', selector: '.analytics-log-page.site-access-log-page .analytics-log-table { overflow-x:' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '.analytics-analysis-page .analytics-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '.analytics-analysis-page .analytics-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '.analytics-analysis-page .analytics-table-scroll { overflow-y:' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '@media (max-width: 767px) >> .analytics-analysis-page .analytics-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-page .identity-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-page .identity-table-scroll .ant-table { width:' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-page .identity-table-scroll .ant-table-container, .stream-page .identity-table-scroll .ant-table-content { min-width:' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-page .identity-table-scroll .ant-table-container, .stream-page .identity-table-scroll .ant-table-content { width:' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-page .identity-table-scroll .ant-table-content > table { min-width:' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-page .identity-table-scroll .ant-table-content > table { width:' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-page .identity-table-scroll .ant-table-content { overflow:' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '@media (max-width: 767px) >> .stream-page .identity-table-scroll { overflow-x:' },
  { file: 'apps/web/src/pages/TrafficPackageProductsPage.css', selector: '.traffic-package-products-page .ant-table table { min-width:' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-log-table { overflow-x:' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-table-scroll { overflow-x:' },
  { file: 'apps/web/src/styles.css', selector: '.identity-table-scroll { overflow-x:' },
  { file: 'apps/web/src/styles.css', selector: '.node-table-scroll { overflow-x:' },
  { file: 'apps/web/src/styles.css', selector: '.node-table-scroll { overscroll-behavior-inline:' },
  { file: 'apps/web/src/styles.css', selector: '.package-table-scroll { overflow-x:' },
  { file: 'apps/web/src/styles.css', selector: '.package-table-scroll { overscroll-behavior-inline:' },
  { file: 'apps/web/src/styles.css', selector: '.site-origin-table, .site-locked-table { overflow-x:' },
  { file: 'apps/web/src/styles.css', selector: '.site-table-scroll { overflow-x:' },
  { file: 'apps/web/src/styles.css', selector: '.site-table-scroll { overscroll-behavior-inline:' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .dashboard-table-wrap { overflow-x:' },
  { file: 'apps/web/src/styles/adminHomeReference.css', selector: '.admin-overview .dashboard-reference-top .dashboard-table-wrap { overflow:' },
  { file: 'apps/web/src/styles/userHomeReference.css', selector: '.user-top-card .dashboard-table-wrap { overflow:' },
  // 10-27 display:none on the Segmented thumb kept antd from ever marking the clicked item selected (motion never ends); now opacity 0.
  { file: 'apps/web/src/styles.css', selector: '.panel-heading .ant-segmented-thumb' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-range-control .ant-segmented-thumb' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-realtime-primary-fields > .ant-segmented .ant-segmented-thumb' },
  // Merge batch 10-25: rules this file's own fix removed (see git log of adminHomeReference.css).
  { file: 'apps/web/src/styles/adminHomeReference.css', selector: '.admin-overview .dashboard-reference-layout .dashboard-reference-side > .dashboard-entitlement-card' },
  // Merge batch 10-25: rules this file's own fix removed (see git log of NodeMonitorSettingsPage.css).
  { file: 'apps/web/src/pages/NodeMonitorSettingsPage.css', selector: '.node-monitor-switch-log-filters' },
  { file: 'apps/web/src/pages/NodeMonitorSettingsPage.css', selector: '.node-monitor-switch-log-filters > .ant-btn' },
  { file: 'apps/web/src/pages/NodeMonitorSettingsPage.css', selector: '.node-monitor-switch-log-filters > .ant-btn > span' },
  // S3 A07: the node-settings draft form (no executor behind it) was removed with its styles.
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '@media (max-width: 1100px) >> .maintenance-migration-grid, .maintenance-settings-bottom' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '@media (max-width: 1100px) >> .maintenance-node-setting-row' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '@media (max-width: 720px) >> .maintenance-node-admin-password' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-log-button' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-node-admin-password' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-node-admin-password label' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-node-setting-copy' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-node-setting-copy label' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-node-setting-copy label strong' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-node-setting-copy p' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-node-setting-list' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-node-setting-row' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-node-setting-value' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-node-setting-value .ant-input' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-operation-warning' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-operation-warning .ant-alert-message' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-operation-warning span' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-operation-warning strong' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-settings-bottom' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-settings-bottom .ant-alert' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-summary-box' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-summary-box > strong' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-summary-values' },
  { file: 'apps/web/src/pages/ControlUpgradesPage.css', selector: '.maintenance-summary-values span' },
  // TF-R01: the 1px clip hid the analysis window / snapshot / watermark line from sighted users; it is back in normal flow.
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '.analytics-analysis-page .analytics-analysis-advanced-filter, .analytics-analysis-page > .analytics-panel > .analytics-meta {' },
  // WAF trend legend entries became toggle buttons; the span rule moved to `button`.
  { file: 'apps/web/src/pages/WafLogsPage.css', selector: '.waf-overview-trend-legend span' },
  // C21 (u4-pages d20cc9793): the inset bar also marked selected submenu items next to their ::before mark; only top-level items keep it (child combinator).
  { file: 'apps/web/src/components/AppShell.css', selector: ':root[data-cdnca-theme] .app-shell:not(.is-dark) .shell-menu.ant-menu-inline .ant-menu-item-selected { box-shadow:' },
  { file: 'apps/web/src/styles.css', selector: '.app-shell.is-dark .shell-menu.ant-menu-inline .ant-menu-item-selected { box-shadow:' },
  // L1 C32: the 1px-clipped audience fields became the expandable 高级受众 block.
  { file: 'apps/web/src/pages/AnnouncementManagementPage.css', selector: '.announcement-compat-hidden-fields' },
  // live-click-A E5: the 1px clip hid the 自动申请 tab and the toolbar refresh button.
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '.certificate-toolbar > .ant-btn:last-child' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '.certificate-page .certificate-section-content > .ant-tabs' },
  // 批 1：危险按钮/弹窗顺序统一，用户已批准。线路分组「删除」改 default+danger，去掉实心红底、红色悬停与 primary 禁用态。
  { file: 'apps/web/src/pages/NodeLineGroupsPage.css', selector: '.node-line-groups-page .node-line-delete-action { background:' },
  { file: 'apps/web/src/pages/NodeLineGroupsPage.css', selector: '.node-line-groups-page .node-line-delete-action { border-color:' },
  { file: 'apps/web/src/pages/NodeLineGroupsPage.css', selector: '.node-line-groups-page .node-line-delete-action:not(:disabled):hover' },
  { file: 'apps/web/src/pages/NodeLineGroupsPage.css', selector: '.node-line-groups-page .node-line-delete-action.ant-btn-primary:disabled' },
  // 批 1：危险按钮/弹窗顺序统一，用户已批准。升级包「删除」改 default+danger，去掉禁用时的实心红底。
  { file: 'apps/web/src/pages/package-commerce/PackageAddonsPage.css', selector: '.addon-toolbar .ant-btn-dangerous:disabled' },
  // 批 1：危险按钮/弹窗顺序统一，用户已批准。新增/编辑用户弹窗页脚去掉 row-reverse，改为取消在左、确定在右。
  { file: 'apps/web/src/styles.css', selector: '.user-form-modal .ant-modal-footer { flex-direction: row-reverse' },
  // .app-sidebar and .shell-menu both scrolled (two side-by-side
  // scrollbars once the page has a horizontal scrollbar); only .shell-menu scrolls now,
  // its height comes from the sidebar flex column instead of 100vh.
  { file: 'apps/web/src/styles.css', selector: '.app-sidebar { overflow-y: auto }' },
  { file: 'apps/web/src/styles.css', selector: '.shell-menu { height: calc(100vh - 64px) }' },
  // WAF 分区标题右侧状态/操作区横排（窄屏占满一行、右对齐），不再挤成逐字一列。
  { file: 'apps/web/src/pages/site-edit/SiteProtectionTabs.css', selector: '.site-protection-section-head > div:last-child { display: flex' },
  { file: 'apps/web/src/pages/site-edit/SiteProtectionTabs.css', selector: '.site-protection-section-head > div:last-child { gap: 8px' },
  { file: 'apps/web/src/pages/site-edit/SiteProtectionTabs.css', selector: '@media (max-width: 760px) >> .site-protection-section-head > div:last-child { width: 100%' },
  { file: 'apps/web/src/pages/site-edit/SiteProtectionTabs.css', selector: '@media (max-width: 760px) >> .site-protection-section-head > div:last-child { justify-content: flex-end' },
  // 缓存设置分组标题 15px/24px 改为 DESIGN.md 分组标题 14px/600/22px，与其它 tab 统一。
  { file: 'apps/web/src/pages/site-edit/CacheSiteTab.css', selector: '.cache-policy-heading h2, .cache-policy-section h3, .cache-policy-history h3 { font-size: 15px' },
  { file: 'apps/web/src/pages/site-edit/CacheSiteTab.css', selector: '.cache-policy-heading h2, .cache-policy-section h3, .cache-policy-history h3 { line-height: 24px' },
  // HTTPS 关闭提示左缩进 110→136px，对齐 120px 标签列 + 16px 间距的控件列。
  { file: 'apps/web/src/pages/site-edit/HttpsSiteTab.css', selector: '.site-https-disabled-note { margin: 16px 0 0 110px' },
  // CC/WAF 设置行标签列 116→120px、间距 18→16px、行距 22→20px（与基本/高级 tab 的 FormRow 一致）；WAF 分组由贴边改为与 CC 相同的 20px 缩进。
  { file: 'apps/web/src/pages/site-edit/SiteProtectionTabs.css', selector: '.site-protection-setting-row { grid-template-columns: 116px' },
  { file: 'apps/web/src/pages/site-edit/SiteProtectionTabs.css', selector: '.site-protection-setting-row { gap: 18px' },
  { file: 'apps/web/src/pages/site-edit/SiteProtectionTabs.css', selector: '.site-protection-setting-row { margin-top: 22px' },
  { file: 'apps/web/src/pages/site-edit/SiteProtectionTabs.css', selector: '.site-protection-section--waf { padding-inline: 0' },
  // 删除站点基本信息页底部 CNAME 状态 Alert（改为 CNAME 字段就地「生成失败」标记），其样式随组件删除。
  { file: 'apps/web/src/styles.css', selector: '.site-basic-cname-state { margin: 16px 0' },
  // n6b 92e9bd944：缓存规则行改顶端对齐，浏览器 TTL 的说明文字不再把同行输入框顶上去。
  { file: 'apps/web/src/pages/site-edit/CacheSiteTab.css', selector: '.cache-policy-rule { align-items: end' },
  // 编辑节点弹窗：正文去掉叠加的 24px 左右内边距（表单宽 472）；页签横向滚动由仅移动端改为所有宽度；移动端 16px 内边距从正文移到弹窗内容区。
  { file: 'apps/web/src/pages/NodeListPage.css', selector: '.node-list-modal .ant-modal-body { padding: 22px 24px 8px' },
  { file: 'apps/web/src/pages/NodeListPage.css', selector: '@media (max-width: 767px) >> .node-list-modal .ant-tabs-nav' },
  { file: 'apps/web/src/pages/NodeListPage.css', selector: '@media (max-width: 767px) >> .node-list-modal .ant-modal-body { padding-' },
  // 账户中心日志查询不再包一层共用 LoginLogPage（identity-page/工具栏/表格滚动/分页），改为本页自带登录日志/操作日志标签、筛选行与右侧分页（account-log-tabs/filters/pager），旧包装层样式没有对象了。
  { file: 'apps/web/src/pages/AccountLogPage.css', selector: '.account-log-page > .identity-page' },
  { file: 'apps/web/src/pages/AccountLogPage.css', selector: '.account-log-page .identity-page' },
  { file: 'apps/web/src/pages/AccountLogPage.css', selector: '.account-log-page .identity-toolbar' },
  { file: 'apps/web/src/pages/AccountLogPage.css', selector: '.account-log-page .identity-table-scroll' },
  { file: 'apps/web/src/pages/AccountLogPage.css', selector: '.account-log-page .identity-pagination' },
  { file: 'apps/web/src/pages/AccountLogPage.css', selector: '@media (max-width: 767px) >> .account-log-page .identity-' },
  // 转发列表把添加转发/批量修改从抽屉改为弹窗+折叠分组；抽屉体、创建页签、高级切换、开关行、抽屉底栏、批量分组样式随组件删除；筛选栅格 3→4 列、弹窗表单项间距 14→26px、标签改由 antd 横排布局。
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-filter-grid { grid-template-columns: repeat(3' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-filter-grid label, .stream-batch-section label' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-filter-grid .ant-select, .stream-batch-section .ant-select' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-modal .ant-drawer-body, .stream-batch-modify-drawer .ant-drawer-body' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-modal .ant-form { margin-top: 16px' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-modal .stream-form-grid' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-modal .ant-form-item { margin-bottom: 14px' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-modal .ant-form-item-label {' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-create-tabs' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-advanced-toggle' },
  // stream-be2 删 StreamQuickCreatePanel 引用后组件与其两条内嵌样式一并删除（死代码）。
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-quick-create-embedded > p' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-quick-create-embedded > label' },
  // fp-bill da900ad1e BILL-13：套餐购买页去掉假分组页签（无后端分组字段），.package-purchase-groups 样式随之删除。
  { file: 'apps/web/src/pages/package-commerce/PackagePurchasePage.css', selector: '.package-purchase-groups' },
  { file: 'apps/web/src/pages/package-commerce/PackagePurchasePage.css', selector: '@media (max-width: 767px) >> .package-purchase-groups' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-form-grid.is-advanced + .stream-advanced-toggle' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-switch-row' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-drawer-footer' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-batch-section' },
  // 基本配置重排，回源规则卡片与站点元信息行随组件删除；分组选择器去掉这两个类后其余规则的声明不变。
  { file: 'apps/web/src/styles.css', selector: '.site-basic-section-heading p, .site-basic-rule-card p' },
  { file: 'apps/web/src/styles.css', selector: '.site-basic-metadata' },
  { file: 'apps/web/src/styles.css', selector: '.site-basic-access-grid, .site-basic-rule-grid' },
  { file: 'apps/web/src/styles.css', selector: '.site-basic-rule-card' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .site-basic-facts, .site-basic-access-grid, .site-basic-rule-grid' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .site-basic-rule-card' },
  // 消费记录重写为订单与账本合并流水，兼容工具栏（隐藏的旧筛选/翻页控件）、旧工具栏与当前页码、页头 h1 样式随组件删除；筛选改日期区间+下拉（.ant-picker/.ant-select），不再有输入框筛选。
  { file: 'apps/web/src/pages/AccountOrdersPage.css', selector: '.account-orders-heading h1' },
  { file: 'apps/web/src/pages/AccountOrdersPage.css', selector: '.account-orders-page .account-orders-compatibility-toolbar' },
  { file: 'apps/web/src/pages/AccountOrdersPage.css', selector: '.account-orders-compatibility-toolbar' },
  { file: 'apps/web/src/pages/AccountOrdersPage.css', selector: '.account-orders-reference-filters .ant-input' },
  { file: 'apps/web/src/pages/AccountOrdersPage.css', selector: '.account-orders-reference-filters .ant-select-selector, .account-orders-reference-filters .ant-input' },
  { file: 'apps/web/src/pages/AccountOrdersPage.css', selector: '.account-orders-toolbar' },
  { file: 'apps/web/src/pages/AccountOrdersPage.css', selector: '.account-orders-pagination .account-orders-current-page' },
  { file: 'apps/web/src/pages/AccountOrdersPage.css', selector: '@media (max-width: 767px) >> .account-orders-compatibility-toolbar' },
  { file: 'apps/web/src/pages/AccountOrdersPage.css', selector: '@media (max-width: 767px) >> .account-orders-reference-filters .ant-input' },
  { file: 'apps/web/src/pages/AccountOrdersPage.css', selector: '@media (max-width: 767px) >> .account-orders-reference-filters .ant-select, .account-orders-reference-filters .ant-input' },
  // 刷新预热操作记录工具栏改为「重新提交选中」+ 类型/搜索 flex 行，旧的网格筛选表单与页头样式随之删除；表格最小宽度随 6 列收窄。
  { file: 'apps/web/src/pages/CacheOperationHistoryPage.css', selector: '.cache-operation-history-header' },
  { file: 'apps/web/src/pages/CacheOperationHistoryPage.css', selector: '.cache-operation-history-toolbar' },
  { file: 'apps/web/src/pages/CacheOperationHistoryPage.css', selector: '.cache-operation-history-table .ant-table { min-width: 1180px' },
  { file: 'apps/web/src/pages/CacheOperationHistoryPage.css', selector: '@media (max-width: 900px) >> .cache-operation-history-toolbar' },
  // 系统日志（/sys/log）并入日志中心，SystemLogPage 删除；它独有的页框/胶囊标签/操作筛选/日期框/用户与时间/富文本单元格/变更弹窗样式随组件删除。备份与发送记录面板共用的工具栏、表格、分页样式保留在原文件。
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '.system-log-page' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '.system-log-tabs' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '.system-log-toolbar--operation' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '.system-log-date-picker' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '.system-log-table-scroll .system-log-user-cell' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '.system-log-time' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '.system-log-rich-cell' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '.system-log-change' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '.system-log-recorded-text' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '@media (max-width: 720px) >> .system-log-page' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '@media (max-width: 720px) >> .system-log-tabs' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '@media (max-width: 720px) >> .system-log-toolbar--operation' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '@media (max-width: 720px) >> .system-log-date-picker' },
  { file: 'apps/web/src/pages/SystemLogPage.css', selector: '@media (max-width: 720px) >> .system-log-toolbar > *, .system-log-toolbar > .ant-select, .system-log-labeled-input, .system-log-labeled-input .ant-input, .system-log-date-picker' },
  // CC 规则组统计胶囊由 span 改为可点击筛选的 button，同样式移到 .cc-rule-summary > button。
  { file: 'apps/web/src/pages/SecurityPoliciesPage.css', selector: '.cc-rule-summary > span' },
  // 消息查询重排，页内 h1 只留给读屏（视觉隐藏），旧页头、输入框/下拉定宽工具栏、标签与未读加粗、自绘翻页条样式随组件删除，改用 antd 分页（offset + total）。
  { file: 'apps/web/src/pages/AccountMessagesPage.css', selector: '.account-messages-heading' },
  { file: 'apps/web/src/pages/AccountMessagesPage.css', selector: '.account-messages-toolbar > .ant-input' },
  { file: 'apps/web/src/pages/AccountMessagesPage.css', selector: '.account-messages-toolbar > .ant-select' },
  { file: 'apps/web/src/pages/AccountMessagesPage.css', selector: '.account-messages-toolbar .ant-input, .account-messages-toolbar .ant-select-selector, .account-messages-toolbar .ant-btn' },
  { file: 'apps/web/src/pages/AccountMessagesPage.css', selector: '.account-messages-toolbar .ant-checkbox-wrapper' },
  { file: 'apps/web/src/pages/AccountMessagesPage.css', selector: '.account-messages-table-scroll .ant-tag' },
  { file: 'apps/web/src/pages/AccountMessagesPage.css', selector: '.account-messages-table-scroll .account-message-status-unread' },
  { file: 'apps/web/src/pages/AccountMessagesPage.css', selector: '.account-messages-pagination' },
  { file: 'apps/web/src/pages/AccountMessagesPage.css', selector: '@media (max-width: 767px) >> .account-messages-toolbar > .ant-input, .account-messages-toolbar > .ant-select' },
  { file: 'apps/web/src/pages/AccountMessagesPage.css', selector: '@media (max-width: 767px) >> .account-messages-toolbar > .ant-checkbox-wrapper' },
  { file: 'apps/web/src/pages/AccountMessagesPage.css', selector: '@media (max-width: 767px) >> .account-messages-pagination' },
  // 消息订阅三张表合成一张（提醒项 + 手机/邮件开关列），卡片圆角 10px + shadowCard 投影，h3 标题换成带蓝条的页头，开关列定宽与复选框尺寸覆盖随之删除。
  { file: 'apps/web/src/pages/AccountSubscriptionsPage.css', selector: '.account-subscriptions-page > .identity-page { border-radius: 4px' },
  { file: 'apps/web/src/pages/AccountSubscriptionsPage.css', selector: '.account-subscriptions-page > .identity-page { box-shadow:' },
  { file: 'apps/web/src/pages/AccountSubscriptionsPage.css', selector: '.account-subscriptions-page .ant-typography.ant-typography-h3' },
  { file: 'apps/web/src/pages/AccountSubscriptionsPage.css', selector: '.account-subscriptions-page .identity-table-scroll .ant-table-thead > tr > th:nth-child(1)' },
  { file: 'apps/web/src/pages/AccountSubscriptionsPage.css', selector: '.account-subscriptions-page .identity-table-scroll .ant-table-thead > tr > th:nth-child(2)' },
  { file: 'apps/web/src/pages/AccountSubscriptionsPage.css', selector: '.account-subscriptions-page .identity-table-scroll .ant-checkbox' },
  { file: 'apps/web/src/pages/AccountSubscriptionsPage.css', selector: '@media (max-width: 767px) >> .account-subscriptions-page .identity-table-scroll .ant-table-thead > tr > th:nth-child(1)' },
  { file: 'apps/web/src/pages/AccountSubscriptionsPage.css', selector: '@media (max-width: 767px) >> .account-subscriptions-page .identity-table-scroll .ant-table-thead > tr > th:nth-child(2)' },
  // 添加网站弹窗标签列 78px→112px 并单行（“HTTPS 监听端口”等不再折两行），页签与高级设置分隔线随标签列右移到 122px。
  { file: 'apps/web/src/pages/SiteCreateModal.css', selector: '.site-create-modal .site-filter-field { grid-template-columns: 78px' },
  { file: 'apps/web/src/pages/SiteCreateModal.css', selector: '.site-create-modal .site-create-tabs { margin-left: 88px' },
  { file: 'apps/web/src/pages/SiteCreateModal.css', selector: '.site-create-modal .site-create-advanced-toggle { margin-left: 88px' },
  // fix-ui1026b 第 2 项：网站列表改为固定列宽（tableLayout=fixed，列宽按内容实测），去掉 1180px 最小宽与 max-content 撑宽；单元格内边距 12→8、行内操作间距 12→8 以在 1440 内放下全部列。
  { file: 'apps/web/src/styles.css', selector: '.site-table-scroll .ant-table { min-width:' },
  { file: 'apps/web/src/styles.css', selector: '.site-table-scroll .ant-table-thead > tr > th { padding:' },
  { file: 'apps/web/src/styles.css', selector: '.site-table-scroll .ant-table-tbody > tr > td { padding:' },
  { file: 'apps/web/src/styles.css', selector: '.site-row-actions { gap:' },
  { file: 'apps/web/src/styles.css', selector: '.site-table-scroll .ant-table { width:' },
  { file: 'apps/web/src/styles.css', selector: '.site-table-scroll .ant-table-container, .site-table-scroll .ant-table-content' },
  { file: 'apps/web/src/styles.css', selector: '.site-table-scroll .ant-table-content { overflow:' },
  { file: 'apps/web/src/styles.css', selector: '.site-table-scroll .ant-table-content > table' },
  // 全站时间范围换成 @cdnca/ui TimeRangeFilter，页面自带的 Segmented 快捷项、
  // 自定义 RangePicker / datetime-local 及其弹层样式随之删除（选择器列表里去掉已不存在的 class 也算删除）。
  { file: 'apps/web/src/pages/L4RealtimeMonitorPage.css', selector: '.l4-realtime-baseline-time {' },
  { file: 'apps/web/src/pages/L4RealtimeMonitorPage.css', selector: '.l4-realtime-baseline-time .ant-input {' },
  { file: 'apps/web/src/pages/L4RealtimeMonitorPage.css', selector: '@media (max-width: 920px) >> .l4-realtime-baseline-port, .l4-realtime-baseline-search, .l4-realtime-baseline-time {' },
  { file: 'apps/web/src/pages/L4RealtimeMonitorPage.css', selector: '@media (max-width: 920px) >> .l4-realtime-baseline-range {' },
  { file: 'apps/web/src/pages/NodeRealtimePage.css', selector: '.node-realtime-control-group--monitor-range.node-realtime-control-group--custom-range {' },
  { file: 'apps/web/src/pages/NodeRealtimePage.css', selector: '.node-realtime-control-group--traffic-range.node-realtime-control-group--custom-range {' },
  { file: 'apps/web/src/pages/NodeRealtimePage.css', selector: '.node-realtime-control-group--custom-range .node-realtime-range-control > .ant-radio-group {' },
  { file: 'apps/web/src/pages/NodeRealtimePage.css', selector: '.node-realtime-custom-range {' },
  { file: 'apps/web/src/pages/NodeRealtimePage.css', selector: '.node-realtime-custom-range .ant-picker {' },
  { file: 'apps/web/src/pages/NodeRealtimePage.css', selector: '.node-realtime-custom-range .ant-picker-input, .node-realtime-custom-range .ant-picker-range-separator {' },
  { file: 'apps/web/src/pages/NodeRealtimePage.css', selector: '.node-realtime-custom-range-value {' },
  { file: 'apps/web/src/pages/NodeRealtimePage.css', selector: '.node-realtime-custom-range-value--filled {' },
  { file: 'apps/web/src/pages/NodeRealtimePage.css', selector: '@media (max-width: 767px) >> .node-realtime-control-group--custom-range .node-realtime-range-control > .ant-radio-group {' },
  { file: 'apps/web/src/pages/NodeRealtimePage.css', selector: '@media (max-width: 767px) >> .node-realtime-custom-range {' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '.analytics-analysis-page .analytics-range-control .ant-segmented-item {' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '.analytics-analysis-page .analytics-range-control .ant-segmented-item-label {' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '.analytics-analysis-page .analytics-range-control .ant-segmented-item:has(.ant-segmented-item-input:checked) {' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '.analytics-analysis-page .analytics-custom-range, .analytics-analysis-page .analytics-analysis-range-picker {' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '.analytics-analysis-range-popup .ant-picker-cell:not(.ant-picker-cell-disabled):hover .ant-picker-cell-inner {' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '.analytics-analysis-range-popup .ant-picker-cell-in-view.ant-picker-cell-selected .ant-picker-cell-inner, .analytics-analysis-range-popup .ant-picker-cell-in-view.ant-picker-cell-range-start .ant-picker-cell-inner, .analytics-analysis-range-popup .ant-picker-cell-in-view.ant-picker-cell-range-end .ant-picker-cell-inner {' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '.analytics-analysis-range-popup .ant-picker-cell-disabled {' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '@media (max-width: 767px) >> .analytics-analysis-page .analytics-range-control .ant-segmented {' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '@media (max-width: 767px) >> .analytics-analysis-page .analytics-range-control .ant-segmented-group {' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '@media (max-width: 767px) >> .analytics-analysis-page .analytics-range-control .ant-segmented-item {' },
  { file: 'apps/web/src/pages/SiteAnalysisPage.css', selector: '@media (max-width: 767px) >> .analytics-analysis-page .analytics-analysis-search-input, .analytics-analysis-page .analytics-analysis-search-type, .analytics-analysis-page .analytics-custom-range, .analytics-analysis-page .analytics-analysis-range-picker {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-filter-field, .analytics-range-control, .analytics-custom-range > label {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-filter-field > span, .analytics-range-control > span, .analytics-custom-range label > span {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-range-control .ant-segmented {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-range-control .ant-segmented-item {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-range-control .ant-segmented-item:last-child {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-range-control .ant-segmented-item-selected {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-custom-range {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-custom-range .ant-input {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-realtime-primary-fields > .ant-segmented {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-realtime-primary-fields > .ant-segmented .ant-segmented-item {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-realtime-primary-fields > .ant-segmented .ant-segmented-item-label {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-realtime-primary-fields > .ant-segmented .ant-segmented-item:last-child {' },
  { file: 'apps/web/src/styles.css', selector: '.analytics-realtime-primary-fields > .ant-segmented .ant-segmented-item-selected {' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .analytics-filter-field .ant-input, .analytics-custom-range .ant-input {' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .analytics-range-control .ant-segmented {' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .analytics-custom-range {' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .analytics-realtime-primary-fields > .ant-input:first-child, .analytics-realtime-primary-fields > .ant-input:nth-child(2), .analytics-realtime-primary-fields > .ant-segmented, .analytics-realtime-primary-fields > .ant-btn {' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .analytics-realtime-primary-fields > .ant-segmented .ant-segmented-group {' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .analytics-realtime-primary-fields > .ant-segmented .ant-segmented-item-label {' },
  { file: 'apps/web/src/styles/analyticsControlParity.css', selector: '.analytics-realtime-page .analytics-realtime-primary-fields > .ant-segmented {' },
  { file: 'apps/web/src/styles/analyticsControlParity.css', selector: '.analytics-realtime-page .analytics-realtime-primary-fields > .ant-segmented .ant-segmented-item-label {' },
  { file: 'apps/web/src/pages/FinanceOrdersPage.css', selector: '.finance-orders-reference-toolbar .ant-btn, .finance-orders-reference-toolbar .ant-input, .finance-orders-reference-toolbar .ant-picker, .finance-orders-reference-toolbar .ant-select-selector, .finance-orders-target-toolbar .ant-btn, .finance-orders-target-toolbar .ant-input, .finance-orders-target-toolbar .ant-select-selector {' },
  { file: 'apps/web/src/pages/FinanceOrdersPage.css', selector: '.finance-orders-reference-toolbar > .ant-picker {' },
  { file: 'apps/web/src/pages/FinanceOrdersPage.css', selector: '@media (max-width: 767px) >> .finance-orders-reference-toolbar > .ant-picker, .finance-orders-reference-toolbar > .finance-orders-user-search {' },
  { file: 'apps/web/src/pages/TrafficPackageUsagePage.css', selector: '.admin-usage-subscription-input .ant-input-affix-wrapper, .admin-usage-subscription-input .ant-picker {' },
  { file: 'apps/web/src/pages/TrafficPackageUsagePage.css', selector: '.admin-usage-range .ant-btn {' },
  { file: 'apps/web/src/pages/TrafficPackageUsagePage.css', selector: '.admin-usage-range .ant-btn.is-active {' },
  // fix-l4flow2/3：四层详情源站池改为页内逐行编辑，原源站弹窗及其样式删除（.stream-origin-modal 已无引用）。
  { file: 'apps/web/src/pages/StreamDetailPage.css', selector: '.stream-origin-modal ' },
  // 已售套餐筛选行换成共享 AdvancedFilters（.package-sold-advfilters），旧容器已不存在；
  // 暗色表头规则仍在，只是与之合写的选择器换成了新容器。
  { file: 'apps/web/src/pages/package-commerce/PackageSoldPage.css', selector: '.package-sold-actions' },
  { file: 'apps/web/src/pages/package-commerce/PackageSoldPage.css', selector: ':lang(qps-ploc) .package-sold-actions' },
  { file: 'apps/web/src/pages/package-commerce/PackageSoldPage.css', selector: ":root[data-theme='dark'] .identity-page.package-sold-page .ant-table-thead > tr > th, :root[data-theme='dark'] .package-sold-actions" },
  { file: 'apps/web/src/pages/package-commerce/PackageSoldPage.css', selector: '@media (max-width: 600px) >> .package-sold-actions' },
  { file: 'apps/web/src/pages/package-commerce/PackageSoldPage.css', selector: '@media (max-width: 600px) >> .package-sold-page .package-sold-actions' },
  // 网站列表工具栏整行放进共享 AdvancedFilters：自制「筛选」按钮与高级搜索面板（.site-advanced-search/
  // .site-filter-grid/.site-filter-actions）删除；按钮不再是 .site-toolbar 直接子元素（改指 .cdnca-adv-filters-primary/extra）；
  // 查询按钮从快速搜索框里移到组件的查询/重置组，框宽 340→256、左距 24→16 并补右侧圆角（管理员 1440 宽一行放下 操作+快速搜索+查询/重置/高级筛选+导出/域名安全）。
  { file: 'apps/web/src/styles.css', selector: '.site-toolbar > .ant-dropdown-trigger' },
  { file: 'apps/web/src/styles.css', selector: '.site-toolbar > .site-filter-trigger' },
  { file: 'apps/web/src/styles.css', selector: '.site-quick-search { width:' },
  { file: 'apps/web/src/styles.css', selector: '.site-quick-search { min-width:' },
  { file: 'apps/web/src/styles.css', selector: '.site-quick-search { flex:' },
  { file: 'apps/web/src/styles.css', selector: '.site-quick-search { margin-left:' },
  { file: 'apps/web/src/styles.css', selector: '.site-quick-search .ant-btn' },
  { file: 'apps/web/src/styles.css', selector: '.site-toolbar .site-filter-trigger' },
  { file: 'apps/web/src/styles.css', selector: '.site-advanced-search' },
  { file: 'apps/web/src/styles.css', selector: '.site-filter-grid' },
  { file: 'apps/web/src/styles.css', selector: '.site-filter-actions' },
  { file: 'apps/web/src/styles.css', selector: '@media (min-width: 768px) and (max-width: 1199px) >> .site-filter-grid' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .site-toolbar .site-filter-trigger' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .site-advanced-search' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .site-filter-grid' },
  { file: 'apps/web/src/styles.css', selector: '@media (max-width: 767px) >> .site-filter-actions' },
  // 证书列表工具栏整行放进共享 AdvancedFilters：按钮不再是 .certificate-toolbar 直接子元素（改指 .cdnca-adv-filters-primary/extra），
  // 搜索框不再自带查询按钮（Input.Search → Input，查询在组件的查询/重置组）且不再顶到右侧（宽 520→360），自制高级面板删除。
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '.certificate-toolbar > .ant-btn' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '.certificate-toolbar .identity-search { width:' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '.certificate-toolbar .identity-search { min-width:' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '.certificate-toolbar .identity-search { flex:' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '.certificate-toolbar .identity-search { margin-left:' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '.certificate-toolbar .identity-search .ant-input-search-button' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '.certificate-advanced-filter' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '.certificate-filter-' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '@media (max-width: 767px) >> .certificate-advanced-filter' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '@media (max-width: 767px) >> .certificate-filter-' },
  { file: 'apps/web/src/pages/CertificateListPage.css', selector: '@media (max-width: 767px) >> .certificate-toolbar > .ant-btn' },
  // 转发列表工具栏整行放进共享 AdvancedFilters：自制「筛选」按钮（.stream-toolbar-search）与筛选面板（.stream-filter-*）删除，
  // 快捷查询的查询按钮移到组件查询/重置组（.stream-search-control > .ant-btn 删除）；移动端顺序改由 .stream-toolbar .stream-search-control 承担。
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-search-control > .ant-btn' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-toolbar-search' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-filter-' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '@media (max-width: 980px) >> .stream-toolbar-search' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '@media (max-width: 980px) >> .stream-filter-grid' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '@media (max-width: 767px) >> .stream-toolbar-actions, .stream-toolbar-search' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '@media (max-width: 767px) >> .stream-search-control { width:' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '@media (max-width: 767px) >> .stream-search-control { order:' },
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '@media (max-width: 767px) >> .stream-filter-grid' },
  // 发信日志筛选行换成共享 AdvancedFilters，控件不再是 .system-sent-log-filters 的直接子元素（改指 .cdnca-adv-filters-primary）。
  { file: 'apps/web/src/pages/SystemSentLogPanel.css', selector: '.system-sent-log-filters { gap:' },
  { file: 'apps/web/src/pages/SystemSentLogPanel.css', selector: '.system-sent-log-filters > .ant-select' },
  { file: 'apps/web/src/pages/SystemSentLogPanel.css', selector: '.system-sent-log-filters .system-log-labeled-input' },
  { file: 'apps/web/src/pages/SystemSentLogPanel.css', selector: '@media (max-width: 720px) >> .system-sent-log-filters > .ant-select' },
  // 四层默认设置说明文字移进工具条与按钮同一行，下边距由工具条承担。
  { file: 'apps/web/src/pages/StreamListPage.css', selector: '.stream-panel-description { margin: 0 0 16px' },
  // 缓存设置页签改为分组设置行（CacheSettingRow），旧两列表单网格 .cache-policy-form-grid 已不再使用。
  { file: 'apps/web/src/pages/site-edit/CacheSiteTab.css', selector: '.cache-policy-form-grid {' },
  { file: 'apps/web/src/pages/site-edit/CacheSiteTab.css', selector: '.cache-policy-form-grid > h3 {' },
  { file: 'apps/web/src/pages/site-edit/CacheSiteTab.css', selector: '.cache-policy-rule label, .cache-policy-form-grid label {' },
  { file: 'apps/web/src/pages/site-edit/CacheSiteTab.css', selector: '.cache-policy-rule label > span, .cache-policy-form-grid label > span {' },
  { file: 'apps/web/src/pages/site-edit/CacheSiteTab.css', selector: '.cache-policy-rule .ant-input-number, .cache-policy-form-grid .ant-input-number, .cache-policy-rule .ant-select, .cache-policy-form-grid .ant-select {' },
  { file: 'apps/web/src/pages/site-edit/CacheSiteTab.css', selector: '@media (max-width: 720px) >> .cache-policy-rule, .cache-policy-form-grid, .cache-policy-comparison {' },
  { file: 'apps/web/src/pages/site-edit/CacheSiteTab.css', selector: '@media (max-width: 720px) >> .cache-policy-form-grid > h3 {' },
  // 线路组名称列被挤成竖排，改单行省略（全名见 Tooltip）；名称/地址合写的换行规则拆开，地址列原三条声明单独保留。
  { file: 'apps/web/src/pages/NodeL2TopologyDetailPage.css', selector: '.node-line-resolution-detail-page .node-line-resolution-table-scroll td.node-line-resolution-name, .node-line-resolution-detail-page .node-line-resolution-table-scroll td.node-line-resolution-address {' },
  // 插件商店：卡片不再用 antd Card actions，操作条 .market-store-action 换成贴底的 .market-store-footer，源码已无该类。
  { file: 'apps/web/src/pages/market/MarketStorePage.css', selector: '.market-store-action {' },
]
export const removedOnPurpose = (file, line) => intentionalRemovals.some((entry) => entry.file === file && line.startsWith(entry.selector))
