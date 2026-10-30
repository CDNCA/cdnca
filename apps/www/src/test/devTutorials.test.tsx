import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { render, screen, within } from '@testing-library/react'
import { App } from '../App'
import { getGroupDetail } from '../content/apiCatalog'
import type { Block } from '../content/docs'
import { GUIDES, GUIDES_PATH } from '../content/devGuides'
import { TUTORIAL_API_PATH, TUTORIALS, TUTORIALS_PATH } from '../content/devTutorials'
import { PLUGIN_CLI_DOWNLOADS, PLUGIN_CLI_FILES } from '../content/pluginSigning'
import { urls } from '../entry-server'
import type { L } from '../i18n'

const repo = resolve(__dirname, '../../../..')
const read = (f: string) => readFileSync(resolve(repo, f), 'utf8')
const allBlocks = TUTORIALS.flatMap((t) => t.sections.flatMap((s) => s.blocks))
const cmds = allBlocks.flatMap((b) => ('cmd' in b ? [b.cmd] : []))
const allText = JSON.stringify(TUTORIALS)

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

describe('任务式教程：结构与中英对齐', () => {
  it('九篇按任务顺序覆盖入驻到卸载，slug 与锚点唯一', () => {
    expect(TUTORIALS.map((t) => t.slug)).toEqual(['onboarding', 'signing', 'build', 'integrate', 'review', 'publish', 'install', 'api', 'lifecycle'])
    for (const t of TUTORIALS) {
      const ids = t.sections.map((s) => s.id)
      expect(new Set(ids).size, t.slug).toBe(ids.length)
    }
    expect(`${TUTORIALS_PATH}/api`).toBe(TUTORIAL_API_PATH)
  })

  it('每段中英文都非空，英文不含中文标点', () => {
    for (const t of TUTORIALS) {
      for (const l of [t.nav, t.title, t.lead, ...t.sections.map((s) => s.title)]) {
        expect(l.zh.trim()).not.toBe('')
        expect(l.en, l.zh).not.toMatch(/[，。：；（）、]/)
      }
      for (const sec of t.sections) {
        eachL(sec.blocks, (l) => {
          expect(l.zh.trim(), l.en).not.toBe('')
          expect(l.en.trim(), l.zh).not.toBe('')
          expect(l.en, l.zh).not.toMatch(/[，。：；（）、]/)
        })
        for (const b of sec.blocks) if ('table' in b) for (const r of b.table.rows) expect(r.length).toBe(b.table.head.length)
      }
    }
  })

  it('命令块不含中文（中英文页面共用同一份命令；清单里 zh-CN 字段的值除外）', () => {
    for (const c of cmds) expect(c.replace(/"zh-CN": "[^"]*"/g, ''), c).not.toMatch(/[一-鿿]/)
  })

  it('正文不写源码路径、提交号或内部编号', () => {
    expect(allText).not.toMatch(/\b(?:libs|services|apps|packages|tools|scripts)\/[\w.-]+\//)
    expect(allText).not.toMatch(/\.go\b|\.tsx?\b/)
    expect(allText).not.toMatch(/\bADR[ -]?\d{4}\b|\b(?:PA|RS|AD|GW|ML|RI|FX|NF|DOC)-\d+/)
    expect(allText).not.toMatch(/\b[0-9a-f]{9,40}\b/)
  })

  it('中英文页面渲染出相同数量的标题、表格行、列表项与代码块', () => {
    for (const t of TUTORIALS) {
      const count = (p: string) => {
        const { container, unmount } = render(<App pathname={p} />)
        const c = ['h2', 'tr', 'li', 'pre'].map((tag) => container.querySelectorAll(`main ${tag}`).length)
        unmount()
        return c
      }
      const path = `${TUTORIALS_PATH}/${t.slug}`
      expect(count(`/en${path}`), path).toEqual(count(path))
    }
  })
})

describe('任务式教程：命令与源码一致', () => {
  it('ui_page 上传说明写明上传签名清单和配置 Schema，不说“不带任何文件”', () => {
    const t = JSON.stringify(TUTORIALS)
    expect(t).not.toMatch(/不带任何文件或包|no file or package/)
    expect(t).toContain('只上传签名清单和配置 Schema')
    expect(t).toContain('upload only the signed manifest and the configuration schema')
  })

  it('cdnca-site-theme 只用 usage 里的子命令、参数与模板', () => {
    const src = read('packages/site-theme-kit/bin/cdnca-site-theme.mjs')
    const kitUsage = src.slice(src.indexOf('const USAGE'), src.indexOf('`', src.indexOf('const USAGE') + 20))
    const templates = read('packages/site-theme-kit/lib/scaffold.mjs').match(/TEMPLATES = \[([^\]]+)\]/)![1]
    let seen = 0
    for (const c of cmds) {
      for (const m of c.replace(/\\\n/g, ' ').matchAll(/node "\$CDNCA_THEME_TOOL" ([a-z]+)([^\n]*)/g)) {
        seen++
        expect(kitUsage, m[0]).toContain(`cdnca-site-theme ${m[1]}`)
        for (const f of m[2].matchAll(/(--[a-z-]+)/g)) expect(kitUsage, m[0]).toContain(f[1])
        const t = m[2].match(/--template (\S+)/)
        if (t) expect(templates).toContain(`'${t[1]}'`)
      }
    }
    expect(seen).toBe(4)
    expect(allText).not.toMatch(/npm (install|i) |npx |pnpm (add|dlx)/)
  })

  it('下载地址与文件名和签名页一致', () => {
    const dl = cmds.filter((c) => /CDNCA_DOWNLOADS|\$CdncaDownloads/.test(c))
    expect(dl).toHaveLength(3)
    for (const c of dl) expect(c).toContain(PLUGIN_CLI_DOWNLOADS)
    const files = PLUGIN_CLI_FILES.map((f) => f.file)
    for (const f of ['cdnca-plugin-linux-amd64', 'cdnca-plugin-linux-arm64', 'cdnca-plugin-darwin-arm64', 'cdnca-plugin-windows-amd64.exe']) {
      expect(files).toContain(f)
      expect(cmds.join('\n')).toContain(f)
    }
  })

  it('主控页面路径与主控路由一致', () => {
    const nav = read('apps/web/src/routes/navigation.ts') + read('apps/web/src/App.tsx')
    const paths = [...allText.matchAll(/\/dashboard(\/[a-z/-]+)/g)].map((m) => m[1])
    expect(new Set(paths)).toEqual(new Set(['/sys/plugin-store', '/sys/plugin-market', '/sys/themes', '/site/rule-packs', '/sys/plugin-providers', '/account/api-key', '/sys/plugin-webhooks']))
    for (const p of paths) expect(nav, p).toContain(`"${p}"`)
  })

  it('接口路径、权限码与生成的接口详情一致', () => {
    const op = (group: string, id: string) => getGroupDetail(group)!.operations.find((o) => o.operation_id === id)!
    const key = op('account', 'createSelfAPIKey')
    expect(key.path).toBe('/v1/account/api-keys')
    expect(key.auth).toEqual(['bearer'])
    expect(key.description).toContain('api_keys.self.manage')
    expect(key.params!.map((p) => p.name).sort()).toEqual(['Idempotency-Key', 'If-Match'])
    const list = op('security-policies', 'listSecurityPolicies')
    expect(list.auth).toContain('apiKey')
    expect(list.description).toContain('security_policies.read')
    expect(op('tenant-scopes', 'createPluginWebhookSubscription').permissions).toEqual(['plugin_webhooks.manage'])
    expect(op('tenant-scopes', 'listPluginWebhookDeliveries').permissions).toEqual(['plugin_webhooks.read'])
    const revoke = op('tenant-scopes', 'revokePluginWebhookSubscription')
    expect(revoke.responses!.map((r) => r.status)).toEqual(expect.arrayContaining(['412', '428']))
    const states = op('tenant-scopes', 'listPluginInstallations').params!.find((p) => p.name === 'status')!.type
    for (const st of ['pending_confirmation', 'authorized', 'installing', 'enabled', 'disabled', 'upgrade_failed_lkg_preserved', 'uninstalled']) {
      expect(states).toContain(st)
      expect(allText).toContain(st)
    }
    expect(op('tenant-scopes', 'uninstallPluginInstallation').body!.fields!.map((f) => f.name)).toEqual(['reason'])
    for (const p of ['/v1/account/api-keys', '/v1/security-policies', '/plugin-webhook-subscriptions', '/test-deliveries', '/delivery-replays', '/replays']) expect(allText).toContain(p)
  })
})

describe('任务式教程：停止接入（DEV-PLUG-02/B）', () => {
  // 主控事实：停用/卸载只改安装状态与身份代次，不碰租户 API Key；test-only 订阅不绑定安装（pluginwebhookcontrol 创建时拒绝绑定）。
  it('停用卸载后的处理列出独立 API Key、测试订阅与业务订阅各自的撤销步骤', () => {
    const control = read('services/control-api/internal/pluginwebhookcontrol/operations.go')
    expect(control).toContain('if input.InstallationAuthorizationID != nil {')
    const lifecycle = TUTORIALS.find((t) => t.slug === 'lifecycle')!
    const section = lifecycle.sections.find((sec) => sec.id === 'uninstall')!
    const zh = JSON.stringify(section.blocks.map((b) => ('list' in b ? b.list.map((l) => l.zh) : 'p' in b ? b.p.zh : '')))
    const en = JSON.stringify(section.blocks.map((b) => ('list' in b ? b.list.map((l) => l.en) : 'p' in b ? b.p.en : '')))
    expect(zh).toContain('不会自动撤销')
    for (const step of ['/dashboard/account/api-key', '/dashboard/sys/plugin-webhooks', '测试订阅', '共用', '旧 Key']) expect(zh, step).toContain(step)
    for (const step of ['/dashboard/account/api-key', '/dashboard/sys/plugin-webhooks', 'test-only', 'shared', 'old key']) expect(en, step).toContain(step)
    expect(section.blocks.some((b) => 'list' in b && b.ordered)).toBe(true)
    expect(zh).not.toContain('卸载后页面、调用与事件全部停止')
  })
})

describe('任务式教程：导航与互链', () => {
  it('开发者首页、教程索引与每篇教程都预渲染中英文', () => {
    const all = urls()
    for (const p of [TUTORIALS_PATH, ...TUTORIALS.map((t) => `${TUTORIALS_PATH}/${t.slug}`)]) {
      expect(all).toContain(p)
      expect(all).toContain(`/en${p}`)
    }
  })

  it('开发者首页列出全部教程', () => {
    render(<App pathname="/developers" />)
    expect(screen.getByRole('link', { name: '开发教程' })).toHaveAttribute('href', TUTORIALS_PATH)
    for (const t of TUTORIALS) expect(screen.getAllByRole('link', { name: new RegExp(t.nav.zh) })[0]).toHaveAttribute('href', `${TUTORIALS_PATH}/${t.slug}`)
  })

  it('教程页：步骤导航标出当前篇，上一篇/下一篇，相关类型指南', () => {
    render(<App pathname={`${TUTORIALS_PATH}/build`} />)
    const steps = screen.getByRole('navigation', { name: '教程目录' })
    expect(within(steps).getAllByRole('link')).toHaveLength(TUTORIALS.length)
    expect(within(steps).getByRole('link', { name: '制作第一个插件' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('link', { name: /上一篇/ })).toHaveAttribute('href', `${TUTORIALS_PATH}/signing`)
    expect(screen.getByRole('link', { name: /下一篇/ })).toHaveAttribute('href', `${TUTORIALS_PATH}/integrate`)
    for (const g of GUIDES) expect(screen.getByRole('link', { name: g.title.zh })).toHaveAttribute('href', `${GUIDES_PATH}/${g.slug}`)
  })

  it('类型指南页回链到引用它的教程；教程引用的类型指南都存在', () => {
    for (const t of TUTORIALS) for (const g of t.guides) expect(GUIDES.map((x) => x.slug)).toContain(g)
    for (const g of GUIDES) {
      const refs = TUTORIALS.filter((t) => t.guides.includes(g.slug))
      expect(refs.length, g.slug).toBeGreaterThan(0)
      const { unmount } = render(<App pathname={`/en${GUIDES_PATH}/${g.slug}`} />)
      for (const t of refs) expect(screen.getAllByRole('link', { name: t.nav.en })[0]).toHaveAttribute('href', `/en${TUTORIALS_PATH}/${t.slug}`)
      unmount()
    }
  })

  it('API 目录与分组页都链到“调用开放接口”教程', () => {
    const { unmount } = render(<App pathname="/developers/api" />)
    expect(screen.getByRole('link', { name: /第一次调用/ })).toHaveAttribute('href', TUTORIAL_API_PATH)
    unmount()
    render(<App pathname="/developers/api/sites" />)
    expect(screen.getByRole('link', { name: /第一次调用/ })).toHaveAttribute('href', TUTORIAL_API_PATH)
  })
})
