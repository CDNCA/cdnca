// Guard：页面内容不得直接铺在外壳灰底（.app-main 的
// --cdnca-color-bg-layout 渐变）上，必须放进白底内容卡。
// 从 App.tsx 里每个懒加载的路由页面出发，沿同一文件内的组件往下走，找出页面
// 实际渲染的根：根必须是标准白底容器——@cdnca/ui 的 <PageSection>、antd <Card>，
// 或 className 带一个 CSS 里 background 为 var(--cdnca-color-bg-container) 的类
// （存量 .identity-page、.site-list-page 等）。<Result>/<Spin>/<DataState>/
// <FeedbackWhen>/<Alert> 等状态占位不算根；返回另一个同文件组件时继续往下找。
// 全屏页（注册；登录/找回密码/冻结页不经 import('./pages/…') 懒加载，本守卫看不到）与页面自己画白底分块的页面登记在
// exempt 里，每条写原因。新页面不登记就必须用 PageSection。
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const src = join(__dirname, '..')
const uiStyles = join(src, '..', '..', '..', 'packages', 'cdnca-ui', 'src', 'styles.css')

const exempt: Record<string, string> = {
  'pages/RegisterPage.tsx#RegisterPage': '全屏注册页（AccountRecoveryLayout）',
  'pages/UserHomePage.tsx#UserHomePage': '服务概览：多块白底 .user-dashboard-card 分块，根是网格',
  'pages/AdminHomePage.tsx#AdminHomePage': '运营数据：根 .overview-card 白底',
  'pages/AccountSubscriptionsPage.tsx': '消息订阅：包一层 NotificationSettingsPage，其根 .identity-page 由 .account-subscriptions-page > .identity-page 上白底',
  'pages/SiteAnalysisPage.tsx': '统计分析：analytics-page 系列，筛选条与图表各自是白底面板',
  'pages/SiteAccessLogPage.tsx': '同上（analytics-log-page）',
  'pages/SiteBlockLogPage.tsx': '同上（analytics-log-page）',
  'pages/SiteBlockEventLogPage.tsx': '同上（analytics-log-page）',
  'pages/CCCoordinationPage.tsx': '同上（analytics-log-page）',
  'pages/WafLogsPage.tsx': '同上（waf-logs-page）',
  'pages/SiteRealtimeMonitorPage.tsx': '同上（analytics-realtime-page）',
  'pages/L4RealtimeMonitorPage.tsx': '四层监控：l4-realtime-baseline-page，面板各自白底',
  'pages/L4SessionPanels.tsx#L4AccessLogPage': '同上',
  'pages/L4SessionPanels.tsx#L4LiveConnectionsPage': '同上',
  'pages/SystemGlobalSettingsPage.tsx': '系统配置：sys-setting-v2 设置面板，各分区白底',
  'pages/NodeMonitorSettingsPage.tsx': '节点监控设置：route-loading 只是加载占位，内容根 .node-monitor-settings-page 白底',
  'pages/NodeInventoryDetailPage.tsx': '节点详情：data-state 只是占位，详情内容根 .identity-page',
  'pages/NodeL2TopologyDetailPage.tsx': '转发给 NodeLineResolutionPage / NodeL2NodesPage（各自已受检）',
  'pages/FrontendLogPage.tsx': '转发给 ObservabilityLogsPage（已受检）',
  'pages/CachePolicyHistoryPage.tsx': '转发给 CacheOperationHistoryPage（已受检）',
  'pages/AnnouncementManagementPage.tsx': '平台公告分支转发 GlobalAnnouncementManagement（identity-page 白底）',
  'pages/plugin-webhooks/PluginWebhooksRoute.tsx': '转发给 PluginWebhooksPage（已受检）',
}

// 标题在白底页卡里这一条的豁免：只有不在外壳里的全屏页。
const titleExempt: Record<string, string> = {
  'pages/RegisterPage.tsx#RegisterPage': '全屏注册页（AccountRecoveryLayout）',
}

function files(dir: string, ext: RegExp): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === 'node_modules' ? [] : files(path, ext)
    return ext.test(name) && !/\.test\./.test(name) ? [path] : []
  })
}

// Classes whose own rule paints the card background (last compound of a selector).
function surfaceClasses(): Set<string> {
  const css = [...files(src, /\.css$/), uiStyles].map((file) => readFileSync(file, 'utf8')).join('\n').replace(/\/\*[\s\S]*?\*\//g, '')
  const classes = new Set<string>()
  for (const [, selectors, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (!/(^|;)\s*background(-color)?:\s*var\((--surface,\s*var\()?--cdnca-color-bg-container/.test(body)) continue
    for (const selector of selectors.split(',')) {
      if (/:(hover|focus|active)|::|\[/.test(selector)) continue
      const last = selector.trim().split(/[\s>+~]+/).pop() ?? ''
      const names = [...last.matchAll(/\.([a-z0-9_-]+)/gi)].map((match) => match[1])
      if (names.length) classes.add(names[names.length - 1])
    }
  }
  return classes
}

const placeholders = new Set(['Result', 'Spin', 'Navigate', 'DataState', 'FeedbackWhen', 'Alert', 'Skeleton', 'Empty'])
const surfaceTags = new Set(['PageSection', 'Card'])

type Fn = ts.FunctionLikeDeclaration

function componentFunctions(source: ts.SourceFile): Map<string, Fn> {
  const fns = new Map<string, Fn>()
  for (const statement of source.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name) {
      fns.set(statement.name.text, statement)
      if (statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword)) fns.set('default', statement)
    }
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        let init = declaration.initializer
        if (init && ts.isCallExpression(init) && init.arguments[0]) init = init.arguments[0]
        if (ts.isIdentifier(declaration.name) && init && (ts.isArrowFunction(init) || ts.isFunctionExpression(init))) fns.set(declaration.name.text, init)
      }
    }
    if (ts.isExportAssignment(statement) && ts.isIdentifier(statement.expression)) {
      const target = fns.get(statement.expression.text)
      if (target) fns.set('default', target)
    }
  }
  return fns
}

// The page roots that are not a standard white surface.
export function bareRoots(file: string, exported: string, surfaces: Set<string>): string[] {
  const source = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const fns = componentFunctions(source)
  const bare: string[] = []
  const seen = new Set<Fn>()
  const fromExpression = (node: ts.Expression, depth: number): void => {
    let expression = node
    while (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression)) expression = expression.expression
    if (ts.isConditionalExpression(expression)) { fromExpression(expression.whenTrue, depth); fromExpression(expression.whenFalse, depth); return }
    if (ts.isBinaryExpression(expression)) { fromExpression(expression.right, depth); return }
    if (ts.isJsxFragment(expression)) {
      for (const child of expression.children) {
        if (ts.isJsxElement(child) || ts.isJsxSelfClosingElement(child)) fromExpression(child, depth)
        else if (ts.isJsxExpression(child) && child.expression) fromExpression(child.expression, depth)
      }
      return
    }
    if (ts.isJsxElement(expression) || ts.isJsxSelfClosingElement(expression)) {
      const opening = ts.isJsxElement(expression) ? expression.openingElement : expression
      const tag = opening.tagName.getText()
      const className = opening.attributes.properties.find((attribute) => attribute.name?.getText() === 'className')
      const text = className && ts.isJsxAttribute(className) ? className.initializer?.getText() ?? '' : ''
      const words = [...text.matchAll(/[a-z][a-z0-9_-]*/gi)].map((match) => match[0])
      if (surfaceTags.has(tag) || words.some((word) => surfaces.has(word))) return
      if (placeholders.has(tag)) return
      if (fns.has(tag) && depth < 5) { resolve(tag, depth + 1); return }
      // Context Provider 不渲染 DOM：看它的子元素。
      if (/\.Provider$/.test(tag) && ts.isJsxElement(expression)) {
        for (const child of expression.children) {
          if (ts.isJsxElement(child) || ts.isJsxSelfClosingElement(child)) fromExpression(child, depth)
          else if (ts.isJsxExpression(child) && child.expression) fromExpression(child.expression, depth)
        }
        return
      }
      const line = source.getLineAndCharacterOfPosition(opening.getStart()).line + 1
      bare.push(`<${tag}${text ? ` className=${text}` : ''}> 第 ${line} 行`)
      return
    }
    if (expression.kind === ts.SyntaxKind.NullKeyword) return
    const line = source.getLineAndCharacterOfPosition(expression.getStart()).line + 1
    bare.push(`${expression.getText().slice(0, 40)} 第 ${line} 行`)
  }
  const resolve = (name: string, depth: number) => {
    const fn = fns.get(name)
    if (!fn?.body || seen.has(fn)) return
    seen.add(fn)
    if (!ts.isBlock(fn.body)) { fromExpression(fn.body, depth); return }
    const visit = (node: ts.Node) => {
      if (node !== fn && ts.isFunctionLike(node)) return
      if (ts.isReturnStatement(node) && node.expression) fromExpression(node.expression, depth)
      ts.forEachChild(node, visit)
    }
    ts.forEachChild(fn.body, visit)
  }
  resolve(exported, 0)
  return [...new Set(bare)]
}

const headingTags = new Set(['h1', 'h2', 'h3', 'h4', 'PageHeader', 'Typography.Title', 'Title'])
// 浮层自带白底，里面的标题不算。
const overlayTags = new Set(['Modal', 'Drawer', 'Popover', 'Popconfirm', 'Tooltip', 'Dropdown'])

// 标题也必须在白底页卡里（参考 /sys/user 用户列表）。从页面根往下走，
// 碰到白底容器就停；在碰到白底之前出现的标题（h1–h4、Typography.Title、PageHeader）算落在灰底上。
// 视觉隐藏的读屏标题（className 含 visually-hidden）不算。
export function headingsOutside(file: string, exported: string, surfaces: Set<string>): string[] {
  const source = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const fns = componentFunctions(source)
  const found: string[] = []
  const seen = new Set<Fn>()
  const children = (node: ts.Node, depth: number) => ts.forEachChild(node, (child) => {
    if (ts.isJsxElement(child) || ts.isJsxSelfClosingElement(child) || ts.isJsxFragment(child)) fromNode(child, depth)
    else if (ts.isJsxExpression(child) && child.expression) fromNode(child.expression, depth)
    else if (!ts.isJsxAttributes(child) && !ts.isJsxOpeningElement(child) && !ts.isFunctionLike(child)) children(child, depth)
  })
  const fromNode = (node: ts.Node, depth: number): void => {
    if (ts.isFunctionLike(node)) return
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
      const opening = ts.isJsxElement(node) ? node.openingElement : node
      const tag = opening.tagName.getText()
      const attr = (name: string) => opening.attributes.properties.find((a) => a.name?.getText() === name)
      const className = attr('className')
      const text = className && ts.isJsxAttribute(className) ? className.initializer?.getText() ?? '' : ''
      const words = [...text.matchAll(/[a-z][a-z0-9_-]*/gi)].map((match) => match[0])
      if (surfaceTags.has(tag) || overlayTags.has(tag) || words.some((word) => surfaces.has(word))) return
      if (headingTags.has(tag) && !words.includes('visually-hidden')) {
        const line = source.getLineAndCharacterOfPosition(opening.getStart()).line + 1
        found.push(`<${tag}> 第 ${line} 行`)
        return
      }
      if (fns.has(tag) && depth < 5) { resolve(tag, depth + 1); return }
      // Tabs items / 其它属性里的 JSX 也会渲染出来，一并往下走。
      for (const property of opening.attributes.properties) {
        if (ts.isJsxAttribute(property) && property.initializer && ts.isJsxExpression(property.initializer) && property.initializer.expression) children(property.initializer, depth)
      }
      if (ts.isJsxElement(node)) for (const child of node.children) fromNode(child, depth)
      return
    }
    if (ts.isJsxFragment(node)) { for (const child of node.children) fromNode(child, depth); return }
    if (ts.isJsxExpression(node)) { if (node.expression) fromNode(node.expression, depth); return }
    children(node, depth)
  }
  const resolve = (name: string, depth: number) => {
    const fn = fns.get(name)
    if (!fn?.body || seen.has(fn)) return
    seen.add(fn)
    if (!ts.isBlock(fn.body)) { fromNode(fn.body, depth); return }
    const visit = (node: ts.Node) => {
      if (node !== fn && ts.isFunctionLike(node)) return
      if (ts.isReturnStatement(node) && node.expression) { fromNode(node.expression, depth); return }
      ts.forEachChild(node, visit)
    }
    ts.forEachChild(fn.body, visit)
  }
  resolve(exported, 0)
  return [...new Set(found)]
}

function routedPages(): { key: string; file: string; exported: string }[] {
  const app = readFileSync(join(src, 'App.tsx'), 'utf8')
  const seen = new Map<string, { key: string; file: string; exported: string }>()
  for (const match of app.matchAll(/import\('\.\/(pages\/[^']+)'\)(?:\.then\(\(module\) => \(\{ default: module\.(\w+) \}\)\))?/g)) {
    const [, path, named] = match
    const file = [join(src, `${path}.tsx`), join(src, path)].find((candidate) => existsSync(candidate) && statSync(candidate).isFile())
    if (!file) continue
    const key = named ? `${path}.tsx#${named}` : `${path}.tsx`
    seen.set(key, { key, file, exported: named ?? 'default' })
  }
  return [...seen.values()]
}

describe('page surface guard', () => {
  const surfaces = surfaceClasses()
  const pages = routedPages()

  it('finds the routed pages and the white surface classes', () => {
    expect(pages.length).toBeGreaterThan(80)
    expect(surfaces.has('identity-page')).toBe(true)
    expect(surfaces.has('cdnca-page-section')).toBe(true)
  })

  it('every routed page renders inside a white content card', () => {
    const violations = pages.filter((page) => !exempt[page.key])
      .map((page) => ({ page: page.key, roots: bareRoots(page.file, page.exported, surfaces) }))
      .filter((entry) => entry.roots.length > 0)
    expect(violations, '页面根必须是 <PageSection>（@cdnca/ui）或白底容器；全屏页等登记到 exempt 并写原因').toEqual([])
  })

  it('every page title sits inside the white page card', () => {
    const violations = pages.filter((page) => !titleExempt[page.key])
      .map((page) => ({ page: page.key, headings: headingsOutside(page.file, page.exported, surfaces) }))
      .filter((entry) => entry.headings.length > 0)
    expect(violations, '标题（h1–h4 / Typography.Title / PageHeader）必须在白底页卡里：页面根用 <PageSection>，标题放进去').toEqual([])
  })

  it('no exemption lets the page header sit outside the card', () => {
    expect(Object.entries(exempt).filter(([, reason]) => /页头在外|在卡外|页头/.test(reason)).map(([key]) => key)).toEqual([])
  })

  it('keeps the exemption list in step with the routes', () => {
    const keys = new Set(pages.map((page) => page.key))
    expect(Object.keys(exempt).filter((key) => !keys.has(key))).toEqual([])
  })
})
