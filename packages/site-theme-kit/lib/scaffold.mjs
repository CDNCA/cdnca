// 脚手架：生成 user+site、user、site 三种模板的工程目录。
//
//   theme.config.json       主题元数据 + applies_to + 各部分来源文件（pack 读它）
//   console-theme.json      用户端外观（cdnca.theme/v1；只写 tokens 与 tokens_by_role.user）
//   site/                   官网页面包（index.html + assets）
//   auth/auth.css           平台登录/注册页样式（只能写样式）
//   content-schema.json     官网可编辑字段声明
//   plugin.manifest.json    市场 manifest 模板（pack 填 entrypoint.sha256 与版本）
//   schemas/config.schema.json  插件配置 Schema（主题不需要配置，空对象 Schema）
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

export const TEMPLATES = ['user+site', 'user', 'site']

const PLUGIN_ID = /^[a-z][a-z0-9]*([.-][a-z0-9]+)+$/

const SITE_HTML = (title) => `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <link rel="stylesheet" href="assets/site.css">
</head>
<body>
  <header class="site-header">
    <a class="site-brand" href="./" data-bind="brand_name">${title}</a>
    <nav class="site-nav" aria-label="主导航">
      <a href="/dashboard/login" target="_top">登录</a>
      <a class="site-button" href="/dashboard/register" target="_top">免费注册</a>
    </nav>
  </header>
  <main>
    <section class="site-hero">
      <h1 data-bind="hero_title">${title}</h1>
      <p data-bind="hero_subtitle">一句话介绍你的服务。</p>
      <a class="site-button" href="/dashboard/register" target="_top" data-bind="hero_cta">立即开始</a>
    </section>
    <section class="site-features" aria-label="特性">
      <ul data-list="features"></ul>
    </section>
  </main>
  <footer class="site-footer"><span data-bind="footer_text">© 示例公司</span></footer>
  <script type="module" src="assets/site.js"></script>
</body>
</html>
`

const SITE_CSS = `:root { --brand: #2563eb; --ink: #0f172a; --muted: #64748b; --radius: 8px; }
* { box-sizing: border-box; }
body { margin: 0; font-family: system-ui, "PingFang SC", "Microsoft YaHei", sans-serif; color: var(--ink); background: #fff; }
.site-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 24px; border-bottom: 1px solid #e2e8f0; }
.site-brand { font-weight: 700; color: var(--ink); text-decoration: none; }
.site-nav { display: flex; gap: 16px; align-items: center; }
.site-nav a { color: var(--ink); text-decoration: none; }
.site-button { display: inline-block; padding: 8px 16px; border-radius: var(--radius); background: var(--brand); color: #fff !important; text-decoration: none; }
.site-hero { padding: 72px 24px; text-align: center; background: linear-gradient(180deg, #eff6ff, #fff); }
.site-hero h1 { margin: 0 0 12px; font-size: 40px; }
.site-hero p { margin: 0 0 24px; color: var(--muted); }
.site-features ul { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; list-style: none; padding: 24px; margin: 0 auto; max-width: 1080px; }
.site-features li { padding: 20px; border: 1px solid #e2e8f0; border-radius: var(--radius); }
.site-features h3 { margin: 0 0 8px; }
.site-footer { padding: 24px; text-align: center; color: var(--muted); border-top: 1px solid #e2e8f0; }
@media (max-width: 640px) { .site-hero h1 { font-size: 28px; } .site-header { padding: 12px 16px; } }
`

// 页面脚本以 <script type="module"> 加载：包内的模块、字体、JSON 都可以按相对路径引用。
const SITE_JS = `// 读取官网内容接口，把 content_schema 声明的字段（plugin_content）填进页面。
// 只能请求两个公开接口：/v1/control-site/content 与 /v1/control-site/assets/<sha256>。
const CONTENT = '/v1/control-site/content'

// 图片字段的值是 "asset:<sha256>"，换成公开图片地址。
function imageURL(ref) {
  const m = /^asset:([0-9a-f]{64})$/.exec(ref || '')
  return m ? '/v1/control-site/assets/' + m[1] : ''
}

function text(node, value) {
  if (typeof value === 'string' && value) node.textContent = value
}

function render(doc) {
  const values = doc.plugin_content || {}
  for (const node of document.querySelectorAll('[data-bind]')) {
    const key = node.getAttribute('data-bind')
    text(node, key === 'brand_name' ? doc.brand && doc.brand.name : values[key])
  }
  const list = document.querySelector('[data-list="features"]')
  if (list && Array.isArray(values.features)) {
    list.textContent = ''
    for (const item of values.features) {
      const li = document.createElement('li')
      const src = imageURL(item.icon)
      if (src) {
        const img = document.createElement('img')
        img.src = src
        img.alt = ''
        img.width = 40
        img.height = 40
        li.appendChild(img)
      }
      const h = document.createElement('h3')
      h.textContent = item.title || ''
      const p = document.createElement('p')
      p.textContent = item.body || ''
      li.append(h, p)
      list.appendChild(li)
    }
  }
}

fetch(CONTENT, { credentials: 'omit', headers: { Accept: 'application/json' } })
  .then((response) => (response.ok ? response.json() : null))
  .then((doc) => { if (doc && doc.enabled) render(doc) })
  .catch(() => { /* 内容接口不可用时保留页面里的默认文案 */ })
`

const AUTH_CSS = `/* 平台登录/注册页的样式。只能写样式：表单由平台提供，页面包拿不到密码。
   禁止导入外部样式、引用外链地址、反斜线转义和管理端选择器（规则见开发者文档）。
   图片用 auth_style.images 里的槽位，平台以 CSS 变量 --cdnca-auth-image-<槽位> 提供。 */
.cdnca-auth { background: linear-gradient(135deg, #eff6ff 0%, #ffffff 60%); }
.cdnca-auth-card { border-radius: 12px; box-shadow: 0 12px 32px rgb(15 23 42 / 12%); }
.cdnca-auth-brand { background-image: var(--cdnca-auth-image-logo); background-repeat: no-repeat; background-size: contain; }
`

const CONSOLE_THEME = (id, name) => ({
  schema: 'cdnca.theme/v1',
  id,
  version: '1.0.0',
  name: { 'zh-CN': name },
  tokens: { colorPrimary: '#2563eb', colorLink: '#2563eb', borderRadius: 6 },
  tokens_by_role: { user: { colorSidebarDark: '#0f172a' } },
  layout_slots: { login_layout: 'centered', sidebar: 'dark' },
})

const CONTENT_SCHEMA = [
  { key: 'hero_title', type: 'text', label: { 'zh-CN': '首屏标题', 'en-US': 'Hero title' }, required: true, max_length: 40 },
  { key: 'hero_subtitle', type: 'textarea', label: { 'zh-CN': '首屏副标题', 'en-US': 'Hero subtitle' }, max_length: 200 },
  { key: 'hero_cta', type: 'text', label: { 'zh-CN': '首屏按钮文字', 'en-US': 'Hero button' }, max_length: 12 },
  {
    key: 'features', type: 'list', label: { 'zh-CN': '特性列表', 'en-US': 'Features' }, max_items: 6,
    fields: [
      { key: 'icon', type: 'image', label: { 'zh-CN': '图标', 'en-US': 'Icon' } },
      { key: 'title', type: 'text', label: { 'zh-CN': '标题', 'en-US': 'Title' }, max_length: 20 },
      { key: 'body', type: 'textarea', label: { 'zh-CN': '说明', 'en-US': 'Description' }, max_length: 120 },
    ],
  },
  { key: 'footer_text', type: 'text', label: { 'zh-CN': '页脚文字', 'en-US': 'Footer text' }, max_length: 80 },
]

/** 本地预览用的官网内容示例（模拟 GET /v1/control-site/content）。 */
const MOCK_CONTENT = {
  schema: 'cdnca.control-site/v1',
  enabled: true,
  brand: { name: '示例云', title: '示例云 · 安全加速', description: '示例描述' },
  plugin_content: {
    hero_title: '更快、更稳的网站加速',
    hero_subtitle: '全球节点、智能调度、一键开启 HTTPS。',
    hero_cta: '免费试用',
    features: [
      { title: '全球加速', body: '就近接入，降低延迟。', icon: '' },
      { title: '安全防护', body: 'WAF 与 CC 防护开箱即用。', icon: '' },
      { title: '实时监控', body: '流量、命中率与告警一目了然。', icon: '' },
    ],
    footer_text: '© 2026 示例云',
  },
}

const CONFIG_SCHEMA = { $schema: 'http://json-schema.org/draft-07/schema#', type: 'object', additionalProperties: false, properties: {} }

function manifest(pluginID, namespace, name) {
  return {
    api_version: 'marketplace.cdnca.io/v1',
    kind: 'Plugin',
    metadata: {
      id: pluginID,
      version: '1.0.0',
      name: { 'zh-CN': name },
      description: { 'zh-CN': `${name}：官网与用户端主题` },
      publisher: { id: namespace, name: namespace, support_url: 'https://example.com/support' },
    },
    spec: {
      categories: ['theme'],
      compatibility: { control_api: '>=1.0.35 <2.0.0' },
      entrypoint: { type: 'theme', path: 'theme.json', sha256: '<pack 自动填写>' },
      permissions: ['platform.themes.provide'],
      configuration_schema: { path: 'schemas/config.schema.json', sha256: '<pack 自动填写>' },
      supply_chain: { sbom_sha256: '<SBOM 的 SHA-256>', provenance_sha256: '<构建来源证明的 SHA-256>' },
    },
  }
}

const json = (value) => `${JSON.stringify(value, null, 2)}\n`

/**
 * 生成模板文件清单（不落盘），便于测试。返回 {path: 内容}。
 * pluginID 形如 acme.dev.ocean（命名空间 acme.dev + 名称）。
 */
export function scaffoldFiles({ template, pluginID, name }) {
  if (!TEMPLATES.includes(template)) throw new Error(`template must be one of ${TEMPLATES.join(', ')}`)
  if (!PLUGIN_ID.test(pluginID ?? '') || pluginID.length > 96) throw new Error('plugin id must look like <namespace>.<name>, e.g. acme.dev.ocean')
  const namespace = pluginID.slice(0, pluginID.lastIndexOf('.'))
  if (!namespace.includes('.') && !namespace.includes('-')) throw new Error('plugin id must be <namespace>.<name> where the namespace has a dot or dash, e.g. acme.dev.ocean')
  const title = name || pluginID
  const id = `market.${pluginID}`
  const scopes = template.split('+')
  const user = scopes.includes('user')
  const site = scopes.includes('site')
  const config = {
    schema: 'cdnca.site-theme/v2',
    id,
    version: '1.0.0',
    name: { 'zh-CN': title },
    description: { 'zh-CN': `${title} 主题` },
    applies_to: scopes,
    ...(user ? { console_theme: 'console-theme.json' } : {}),
    ...(site ? { site_bundle: { dir: 'site', entry: 'index.html' }, content_schema: 'content-schema.json' } : {}),
    auth_style: { css: 'auth/auth.css', images: {} },
    // 不进 content：pack 用这两个文件的 SHA-256 填 manifest spec.supply_chain。
    supply_chain: { sbom: 'supply-chain/sbom.cdx.json', provenance: 'supply-chain/provenance.json' },
  }
  const files = {
    'supply-chain/sbom.cdx.json': json({ bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
      metadata: { component: { type: 'application', name: pluginID, version: '1.0.0' } }, components: [] }),
    'supply-chain/provenance.json': json({ _type: 'https://in-toto.io/Statement/v1', subject: [{ name: 'theme.json' }],
      predicateType: 'https://slsa.dev/provenance/v1', predicate: { buildDefinition: { buildType: 'cdnca-site-theme pack' } } }),
    'theme.config.json': json(config),
    'plugin.manifest.json': json(manifest(pluginID, namespace, title)),
    'schemas/config.schema.json': json(CONFIG_SCHEMA),
    'auth/auth.css': AUTH_CSS,
    '.gitignore': 'dist/\n*.key\n',
  }
  if (user) files['console-theme.json'] = json(CONSOLE_THEME(id, title))
  if (site) {
    files['site/index.html'] = SITE_HTML(title)
    files['site/assets/site.css'] = SITE_CSS
    files['site/assets/site.js'] = SITE_JS
    files['content-schema.json'] = json(CONTENT_SCHEMA)
    files['preview/content.json'] = json(MOCK_CONTENT)
  }
  return files
}

/** 写入目录；目录必须不存在或为空。 */
export function scaffold(dir, options) {
  if (existsSync(dir) && readdirSync(dir).length > 0) throw new Error(`${dir} is not empty`)
  const files = scaffoldFiles(options)
  for (const [path, content] of Object.entries(files)) {
    const full = join(dir, path)
    mkdirSync(dirname(full), { recursive: true })
    writeFileSync(full, content)
  }
  return Object.keys(files).sort()
}

export { MOCK_CONTENT }
