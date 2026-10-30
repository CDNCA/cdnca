import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { render, screen, within } from '@testing-library/react'
import { App } from '../App'
import type { Block } from '../content/docs'
import { CATEGORIES } from '../content/developers'
import { GUIDES, GUIDES_PATH, REVIEW_RULES_PATH, SECTION_TITLES, UI_SDK_PATH } from '../content/devGuides'
import { ANALYZERS, BUILTIN_SUFFIX, REVIEW_RULES, RULE_TEXT, ruleText } from '../content/reviewRules'
import { PROXY_SIGNATURE_DOMAIN, SDK_SOURCE, UI_CONTEXT_SCHEMA, UI_METHODS, UI_PROTOCOL, UI_SDK_BLOCKS } from '../content/uiSdk'
import { urls } from '../entry-server'
import type { L } from '../i18n'

const repo = resolve(__dirname, '../../../..')
const read = (f: string) => readFileSync(resolve(repo, f), 'utf8')
const text = (blocks: Block[]) => JSON.stringify(blocks)
const goStrings = (src: string, name: string) => [...src.match(new RegExp(`${name}\\s*=\\s*(?:\\[\\]string|map\\[string\\]bool)\\{([^}]*)\\}`))![1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1])

/** 中英两份结构必须一致：块类型、命令原文、列表与表格行数、表格首列（字段名）。 */
function shape(b: Block): unknown {
  if ('cmd' in b) return { cmd: b.cmd }
  if ('list' in b) return { list: b.list.length, ordered: !!b.ordered }
  if ('table' in b) return { table: b.table.rows.length, head: b.table.head.length }
  return Object.keys(b)[0]
}
function eachL(blocks: Block[], fn: (l: L) => void) {
  for (const b of blocks) {
    if ('p' in b) fn(b.p)
    else if ('h' in b) fn(b.h)
    else if ('note' in b) fn(b.note)
    else if ('list' in b) b.list.forEach(fn)
    else if ('table' in b) { b.table.head.forEach(fn); b.table.rows.flat().forEach(fn) }
    else if (b.label) fn(b.label)
  }
}

describe('按类型开发指南：中英对齐', () => {
  const all = [...GUIDES.flatMap((g) => g.sections.flat()), ...UI_SDK_BLOCKS]

  it('四页覆盖 rule_pack、theme、provider、external_service + ui_page，每页恰好 7 节', () => {
    expect(GUIDES.flatMap((g) => g.kinds).sort()).toEqual(['external_service', 'provider', 'rule_pack', 'theme', 'ui_page'])
    for (const g of GUIDES) expect(g.sections, g.slug).toHaveLength(SECTION_TITLES.length)
    expect(SECTION_TITLES.map((t) => t.zh)).toEqual(['快速开始', 'manifest 示例与字段', '协议与接口', '打包与上传字段', '审核规则', '版本与兼容', '本地调试'])
  })

  it('每段中英文都非空，英文不含中文标点（表格里的统一线路名除外）', () => {
    eachL(all, (l) => {
      expect(l.zh.trim(), l.en).not.toBe('')
      expect(l.en.trim(), l.zh).not.toBe('')
      expect(l.en.replace(/默认\/电信\/联通\/移动\/境外/g, ''), l.en).not.toMatch(/[，。：；（）、]/)
    })
  })

  it('同一块的中英文结构一致（每个 Block 只有一份，L 内两种语言；表格行列数一致）', () => {
    for (const b of all) {
      if ('table' in b) for (const r of b.table.rows) expect(r.length, JSON.stringify(r[0])).toBe(b.table.head.length)
      expect(shape(b)).toBeTruthy()
    }
  })

  it('中英文页面渲染出相同数量的标题、表格行、列表项与代码块', () => {
    for (const path of [...GUIDES.map((g) => `${GUIDES_PATH}/${g.slug}`), UI_SDK_PATH, REVIEW_RULES_PATH]) {
      const count = (p: string) => {
        const { container, unmount } = render(<App pathname={p} />)
        const c = ['h2', 'tr', 'li', 'pre'].map((t) => container.querySelectorAll(`main ${t}`).length)
        unmount()
        return c
      }
      expect(count(`/en${path}`), path).toEqual(count(path))
    }
  })
})

describe('开发指南与源码一致', () => {
  const guide = (slug: string) => text(GUIDES.find((g) => g.slug === slug)!.sections.flat())

  it('入口类型与 schema oneOf 一致', () => {
    const schema = JSON.parse(read('api/schemas/marketplace/v1/plugin-manifest.schema.json'))
    const types = (schema.definitions.spec.properties.entrypoint.oneOf as { properties: { type: { const?: string; enum?: string[] } } }[])
      .flatMap((o) => o.properties.type.const ? [o.properties.type.const] : o.properties.type.enum!)
    expect(types.sort()).toEqual(['external_https', 'rule_pack', 'theme', 'ui_page'])
    const categories = schema.definitions.spec.properties.categories.items.enum as string[]
    for (const c of categories) expect(guide('rule-pack')).toContain(c)
    const ui = schema.definitions.spec.properties.entrypoint.oneOf[2].properties.pages.items.properties
    for (const p of ui.menu_parent.enum as string[]) expect(guide('external-service')).toContain(p)
  })

  it('rule_pack 预算、引擎与示例文件和 libs/rulepack 一致', () => {
    const budget = read('libs/rulepack/budget.go')
    expect(budget).toContain('PackBudget = Budget{Rules: 256, Regexes: 64, Units: 4096}')
    expect(budget).toContain('SiteBudget = Budget{Rules: 1024, Regexes: 256, Units: 16384}')
    expect(budget).toContain('maxCCRules         = 128')
    const pack = read('libs/rulepack/pack.go')
    expect(pack).toContain('EngineWAFV2: 1, EngineACL: 1, EngineCCV2: 6, EngineChallenge: 6, EngineModSecurity: 1')
    expect(pack).toContain('MaxPackBytes     = 1 << 20')
    expect(pack).toContain('maxParams        = 32')
    const t = guide('rule-pack')
    for (const e of ['waf_v2', 'acl', 'cc_v2', 'challenge', 'modsecurity']) expect(t).toContain(e)
    const example = GUIDES[0].sections[0].find((b) => 'cmd' in b) as { cmd: string }
    expect(example.cmd).toBe(read('docs/plugins/examples/rulepack.src.json'))
    expect(JSON.parse(example.cmd).pack_id).toBe('dev/acme.dev/sqli-extra')
  })

  it('theme 槽位、MIME、模板变量与 libs/themepack 一致，示例为 docs/plugins/examples/theme.json', () => {
    const t = guide('theme')
    const slots = [...read('libs/themepack/static.go').match(/BrandSlots = \[\]string\{([^}]*)\}/)![1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1])
    for (const slot of slots) expect(t).toContain(slot)
    for (const mime of ['image/x-icon', 'image/vnd.microsoft.icon', 'image/png', 'image/jpeg']) expect(t).toContain(mime)
    const render = read('libs/themepack/render.go')
    for (const v of ['status', 'title', 'message', 'footer_text', 'subject', 'lines']) expect(render).toContain(`"${v}"`)
    const model = read('libs/themepack/model.go')
    for (const v of ['"split", "centered", "background"', '"light", "dark"', '"classic", "tech"', '"off", "subtle", "rich"']) expect(model).toContain(v)
    expect(model).toContain('MaxPackageSize = 8 << 20')
    const example = GUIDES[1].sections[0].find((b) => 'cmd' in b) as { cmd: string }
    expect(example.cmd).toBe(read('docs/plugins/examples/theme.json'))
    expect(JSON.parse(example.cmd).id).toBe('market.acme.dev.ocean')
  })

  it('provider 协议头、签名域、动作、错误码、沙箱值、契约用例与 pluginprovider 一致', () => {
    const pp = read('libs/entitlement/pluginprovider/pluginprovider.go')
    const wire = read('libs/entitlement/pluginprovider/wire.go')
    const payment = read('libs/entitlement/pluginprovider/payment.go')
    const contract = read('libs/entitlement/pluginprovider/contract.go')
    const t = guide('provider')
    for (const m of pp.matchAll(/Header[A-Za-z]+\s*=\s*"(X-Cdnca-Provider-[A-Za-z-]+)"/g)) expect(t).toContain(m[1])
    for (const d of ['cdnca-provider-request/v1', 'cdnca-provider-response/v1', 'cdnca.provider/v1', '/cdnca-provider/v1/']) {
      expect(pp).toContain(`"${d}"`)
      expect(t).toContain(d)
    }
    expect(pp).toContain('MaxClockSkewSeconds = 300')
    for (const code of goStrings(pp, 'ErrorCodes')) expect(t).toContain(code)
    const actions = pp.slice(pp.indexOf('var Actions'), pp.indexOf('// Error codes a plugin'))
    for (const m of actions.matchAll(/"([a-z_]+)"/g)) expect(t, m[1]).toContain(m[1])
    for (const m of (wire + payment).matchAll(/Sandbox[A-Za-z]+\s*=\s*"([^"]+)"/g)) expect(t).toContain(m[1])
    for (const m of contract.matchAll(/add\((?:Kind[A-Za-z]+|kind), "([a-z_]+)"/g)) expect(t, m[1]).toContain(m[1])
    // 主控开放的 kind：dns/icp/mail/payment/sms；notify 不在其中（页面标“即将开放”）。
    const open = pp.match(/var Kinds = \[\]string\{([^}]*)\}/)![1]
    expect(open).not.toContain('notify')
    expect(t).toContain('notify')
    expect(t).toContain('providers.<kind>.provide')
    expect(pp).toContain('func Permission(kind string) string { return "providers." + kind + ".provide" }')
  })
})

describe('审核规则清单', () => {
  it('每条规则都有中英说明，没有多余说明；每条都归入一个分组', () => {
    const ids = new Set(REVIEW_RULES.map((r) => r.id))
    for (const r of REVIEW_RULES) {
      const l = ruleText(r)
      expect(l, r.id).toBeDefined()
      expect(l.zh && l.en, r.id).toBeTruthy()
      expect(ANALYZERS.map((a) => a.id), r.id).toContain(r.analyzer)
    }
    for (const id of Object.keys(RULE_TEXT)) expect(ids.has(id), id).toBe(true)
    expect(Object.keys(BUILTIN_SUFFIX).sort()).toEqual(['scanner_error', 'skipped'])
  })

  it('页面按分组列出全部规则，标出拒绝 / 隔离 / 试运行，中英文都预渲染', () => {
    expect(urls()).toEqual(expect.arrayContaining([REVIEW_RULES_PATH, `/en${REVIEW_RULES_PATH}`]))
    const { container } = render(<App pathname={REVIEW_RULES_PATH} />)
    expect(screen.getByRole('heading', { level: 1, name: '审核规则清单' })).toBeInTheDocument()
    expect(container.querySelectorAll('tr[data-rule]')).toHaveLength(REVIEW_RULES.length)
    const row = container.querySelector('tr[data-rule="secrets.jwt"]') as HTMLElement
    expect(within(row).getByText('隔离（转人工）')).toBeInTheDocument()
    expect(within(row).getByText('试运行（只记录）')).toBeInTheDocument()
    expect(within(container.querySelector('tr[data-rule="rulepack.not_canonical"]') as HTMLElement).getByText('拒绝')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 2, name: '必须人工审核的情况' })).toBeInTheDocument()
    expect(container.textContent).toContain('engine_module、module、provider')
  })
})

describe('开发者页入口与 notify', () => {
  it('开发者页链到开发指南与审核规则；四个指南页与 SDK 页中英文都预渲染', () => {
    render(<App pathname="/developers" />)
    expect(screen.getByRole('link', { name: '开发指南' })).toHaveAttribute('href', GUIDES_PATH)
    expect(screen.getByRole('link', { name: '审核规则' })).toHaveAttribute('href', REVIEW_RULES_PATH)
    const all = urls()
    for (const p of [GUIDES_PATH, UI_SDK_PATH, ...GUIDES.map((g) => `${GUIDES_PATH}/${g.slug}`)]) {
      expect(all).toContain(p)
      expect(all).toContain(`/en${p}`)
    }
  })

  it('通知渠道标“即将开放”，与 pluginprovider Kinds（主控开放的协议）一致', () => {
    const open = read('libs/entitlement/pluginprovider/pluginprovider.go').match(/var Kinds = \[\]string\{([^}]*)\}/)![1]
    const kindName: Record<string, string> = { KindDNS: 'dns', KindICP: 'icp', KindMail: 'mail', KindPayment: 'payment', KindSMS: 'sms' }
    const opened = [...open.matchAll(/Kind[A-Za-z]+/g)].map((m) => kindName[m[0]])
    expect(opened.sort()).toEqual(['dns', 'icp', 'mail', 'payment', 'sms'])
    for (const c of CATEGORIES.filter((x) => x.kind === 'provider' && !x.officialOnly)) {
      expect([c.provides, !!c.comingSoon]).toEqual([c.provides, !opened.includes(c.provides!)])
    }
    render(<App pathname="/developers/categories" />)
    expect(within(screen.getByRole('row', { name: /通知渠道/ })).getByText('即将开放')).toBeInTheDocument()
    render(<App pathname="/en/developers" />)
    expect(screen.getAllByText('Coming soon').length).toBeGreaterThan(0)
  })

  it('外部服务文案不再声称用工作负载身份调主控（第三方公开凭据端点未发布）', () => {
    const t = JSON.stringify(CATEGORIES) + JSON.stringify(GUIDES)
    expect(t).not.toMatch(/经 OpenAPI 与工作负载身份|with a workload identity/)
    expect(read('docs/developer/release-status.md')).toContain('第三方服务调用主控目前只能用租户 API Key')
  })
})

describe('ui_page SDK 页', () => {
  it('嵌入的 SDK 源码与仓库文件一致，协议常量与 SDK、主控一致', () => {
    expect(SDK_SOURCE).toBe(read('docs/developer/examples/plugin-ui-sdk/cdnca-plugin-ui.mjs'))
    expect(SDK_SOURCE).toContain(`export const PROTOCOL = '${UI_PROTOCOL}'`)
    for (const m of UI_METHODS) expect(SDK_SOURCE).toContain(`'${m}'`)
    const backend = read('docs/developer/examples/plugin-ui-sdk/verify-backend.mjs')
    expect(backend).toContain(`SIGNATURE_DOMAIN = '${PROXY_SIGNATURE_DOMAIN}'`)
    expect(backend).toContain(`CONTEXT_SCHEMA = '${UI_CONTEXT_SCHEMA}'`)
    expect(read('services/control-api/internal/pluginuihttp/handler.go')).toContain('SigningKeyRoute = "/v1/plugin-ui/signing-key"')
  })

  it('DOC-NAV-01：外部服务指南第七节正文直达 SDK，SDK 页返回落回第七节（中英）', () => {
    for (const [prefix, sdkName, back] of [['', 'ui_page 开发者 SDK', /外部服务/], ['/en', 'ui_page developer SDK', /External service/]] as const) {
      const { container, unmount } = render(<App pathname={`${prefix}${GUIDES_PATH}/external-service`} />)
      const s7 = container.querySelector('section#s7') as HTMLElement
      expect(within(s7).getByRole('link', { name: new RegExp(sdkName) })).toHaveAttribute('href', `${prefix}${UI_SDK_PATH}`)
      unmount()
      const sdk = render(<App pathname={`${prefix}${UI_SDK_PATH}`} />)
      expect(screen.getByRole('link', { name: back })).toHaveAttribute('href', `${prefix}${GUIDES_PATH}/external-service#s7`)
      sdk.unmount()
    }
  })

  it('WWW-GUIDE-ANCHOR-01：指南直属锚点 section 避让固定页头（88px）', () => {
    const { container } = render(<App pathname={`${GUIDES_PATH}/external-service`} />)
    const sections = [...container.querySelectorAll('section[id^="s"]')]
    expect(sections.map((s) => s.id)).toEqual(SECTION_TITLES.map((_, i) => `s${i + 1}`))
    for (const s of sections) expect(s).toHaveClass('guide-section')
    expect(read('apps/www/src/styles.css')).toMatch(/\.guide-section \{ scroll-margin-top: 88px; \}/)
  })

  it('页面渲染协议说明与两段源码', () => {
    render(<App pathname={UI_SDK_PATH} />)
    expect(screen.getByRole('heading', { level: 1, name: 'ui_page 开发者 SDK' })).toBeInTheDocument()
    expect(screen.getByLabelText('cdnca-plugin-ui.mjs（框内 SDK）')).toHaveTextContent('export function connect')
    expect(screen.getByLabelText('verify-backend.mjs（后端验签）')).toHaveTextContent('createVerifier')
  })
})
