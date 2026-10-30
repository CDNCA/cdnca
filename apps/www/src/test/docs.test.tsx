import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { render, screen, within } from '@testing-library/react'
import { App } from '../App'
import type { DocBlock as Block } from '../content/docs'
import { DOC_GROUPS, DOCS_HOME, docGroupOf } from '../content/docsIndex'
import { parseMarkdown, plainText } from '../content/markdown'
import { NODE_UNINSTALL, SERVICE_PREFIX, SERVICES } from '../content/ops'
import { SEED } from '../content/siteContent'
import { CONTROL_EXAMPLE_DOMAIN, CONTROL_INSTALL_COMMAND } from '../site'

// 防漂移校验针对种子内容（site-content-seed.json = 授权端迁移 110 的初始内容）。运营之后在后台改的
// 文档不经过这里，编辑时以安装脚本 usage() 为准。
type Script = 'install-control.sh' | 'install-node.sh' | 'uninstall.sh'
const repo = resolve(__dirname, '../../../..')
const SCRIPT_FILES: Record<Script, string> = {
  'install-control.sh': 'scripts/install-control.sh',
  'install-node.sh': 'scripts/install-node.sh',
  'uninstall.sh': 'agents/edge-agent/packaging/scripts/uninstall.sh',
}

/** 脚本 usage() 函数体（含 heredoc 或 printf）里出现的全部 --参数 */
function usageFlags(file: string): Set<string> {
  const src = readFileSync(resolve(repo, file), 'utf8')
  const start = src.search(/^usage\(\) \{/m)
  expect(start, `${file} has usage()`).toBeGreaterThanOrEqual(0)
  const body = src.slice(start, src.indexOf('\n}\n', start))
  return new Set([...body.matchAll(/--[a-z][a-z0-9-]*/g)].map((m) => m[0]))
}

function flagsIn(cmd: string): string[] {
  // 只看命令参数（以空格开头的 --x），忽略 curl 自身参数
  const afterCurl = cmd.replace(/curl [^)]*\)/g, '')
  return [...afterCurl.matchAll(/(?:^|\s)(--[a-z][a-z0-9-]*)/g)].map((m) => m[1])
}

/** 命令属于哪个脚本：按命令里出现的脚本名判断；不调用三个脚本的命令（systemctl 等）不校验。 */
function scriptOf(cmd: string): Script | undefined {
  if (cmd.includes('migrate-from')) return undefined // 子命令写法单独校验（下面 migrate-from 用例）
  if (cmd.includes('install-control.sh')) return 'install-control.sh'
  if (cmd.includes('install-node.sh')) return 'install-node.sh'
  if (cmd.includes('uninstall.sh')) return 'uninstall.sh'
  return undefined
}

const DOCS = SEED.docs.map((d) => ({ slug: d.slug, title: d.title, blocks: { zh: parseMarkdown(d.body.zh), en: parseMarkdown(d.body.en) } }))
const cmdBlocks = DOCS.flatMap((d) => (['zh', 'en'] as const).flatMap((l) => d.blocks[l].filter((b): b is Extract<Block, { cmd: string }> => 'cmd' in b).map((b) => ({ doc: `${d.slug}/${l}`, script: scriptOf(b.cmd), cmd: b.cmd }))))
const tableFlags = DOCS.flatMap((d) => d.blocks.zh.flatMap((b) => ('table' in b ? b.table.rows.map((r) => plainText(r[0].zh)) : [])).filter((x) => x.startsWith('--')).map((x) => ({ doc: d.slug, flag: x.split(' ')[0] })))

describe('文档命令防漂移（种子内容）', () => {
  it('中英文正文的命令块逐字一致（命令不翻译）', () => {
    for (const d of DOCS) {
      const cmds = (l: 'zh' | 'en') => d.blocks[l].flatMap((b) => ('cmd' in b ? [b.cmd] : []))
      expect(cmds('en'), d.slug).toEqual(cmds('zh'))
    }
  })

  it('主控安装命令与授权门户生成规则一致，卸载脚本路径与 ops.ts 一致', () => {
    const all = cmdBlocks.map((b) => b.cmd)
    expect(all).toContain(CONTROL_INSTALL_COMMAND)
    expect(all).toContain(NODE_UNINSTALL)
    expect(all).toContain(`${NODE_UNINSTALL} --purge`)
  })

  // 种子里的主控安装命令用 --licensing-server：社区版 usage() 只列 --release-server，别名仍可解析，不在此校验。
  it.each(cmdBlocks.filter((b) => b.script && !b.cmd.includes('--licensing-server')).map((b) => [b.doc, b.script!, b.cmd] as const))('%s：%s 命令参数都在 usage() 里', (_doc, script, cmd) => {
    const known = usageFlags(SCRIPT_FILES[script])
    const flags = flagsIn(cmd)
    for (const f of flags) expect(known, `${f} not in ${script} usage()`).toContain(f)
  })

  it('节点安装参数表里的每个参数都在 install-node.sh usage() 里', () => {
    const known = usageFlags(SCRIPT_FILES['install-node.sh'])
    expect(tableFlags.length).toBeGreaterThan(0)
    for (const t of tableFlags) expect(known, t.flag).toContain(t.flag)
  })

  it('migrate-from 子命令写法与 install-control.sh usage() 一致', () => {
    const src = readFileSync(resolve(repo, SCRIPT_FILES['install-control.sh']), 'utf8')
    expect(src).toContain('install-control.sh migrate-from root@旧主控 [--ssh-port 22] [--wait-nodes 10m]')
  })

  it('服务名与安装脚本常量一致（brand-rename 合入后改 ops.ts 的 SERVICE_PREFIX）', () => {
    const ctl = readFileSync(resolve(repo, SCRIPT_FILES['install-control.sh']), 'utf8')
    const node = readFileSync(resolve(repo, SCRIPT_FILES['install-node.sh']), 'utf8')
    expect(ctl).toContain(`readonly SERVICE_NAME="${SERVICES.controlApi}"`)
    expect(ctl).toContain(`readonly GATEWAY_SERVICE_NAME="${SERVICES.gateway}"`)
    expect(ctl).toContain(`readonly NATS_SERVICE_NAME="${SERVICES.nats}"`)
    expect(ctl).toContain(`readonly WEB_SERVICE_NAME="${SERVICES.web}"`)
    expect(node).toContain(`readonly SERVICE_NAME="${SERVICES.edgeAgent}"`)
    // native-unit-fix：节点不再有独立 OpenResty 单元，安装器不声明 NATIVE_SERVICE。
    expect(node).not.toContain('readonly NATIVE_SERVICE=')
    const inst = readFileSync(resolve(repo, 'agents/edge-agent/packaging/scripts/install.sh'), 'utf8')
    expect(inst).toContain(`/usr/libexec/${SERVICE_PREFIX}-edge-agent/`)
  })

  it('网关端口文案与安装器一致', () => {
    const ctl = readFileSync(resolve(repo, SCRIPT_FILES['install-control.sh']), 'utf8')
    // ADR 0013 §3.5：不填 --gateway-ports 时在 20000–29999 随机两个空闲端口，安装结束时告知（文档按此写）。
    expect(ctl).toMatch(/--gateway-ports 注册,通道 .*20000–29999 随机选两个空闲端口，安装完成时告知/)
    expect(ctl).toMatch(/\$GATEWAY_ENROLLMENT_PORT:节点注册" "\$GATEWAY_AGENT_PORT:节点通道/)
  })
})

describe('文档目录与站内链接（种子内容）', () => {
  const anchors = (blocks: Block[]) => new Set(blocks.flatMap((b) => ('h' in b && b.id ? [b.id] : [])))
  const links = (blocks: Block[]): string[] => blocks.flatMap((b) => {
    const rich = 'p' in b ? [b.p.zh] : 'note' in b ? [b.note.zh] : 'list' in b ? b.list.map((x) => x.zh) : 'table' in b ? b.table.rows.flat().map((c) => c.zh) : []
    return rich.flatMap((r) => (typeof r === 'string' ? [] : r.flatMap((x) => (typeof x === 'string' ? [] : [x.href]))))
  })

  it('保留原有 6 篇 slug，并按角色分册扩充', () => {
    for (const slug of ['requirements', 'install-control', 'install-node', 'plugins', 'operations', 'troubleshooting']) expect(SEED.docs.map((d) => d.slug)).toContain(slug)
    expect(SEED.docs.length).toBeGreaterThanOrEqual(16)
  })

  it('每篇文档都登记在侧栏分组里，分组里的 slug 都存在', () => {
    const slugs = SEED.docs.map((d) => d.slug)
    for (const s of slugs) expect(docGroupOf(s), s).toBeDefined()
    for (const g of DOC_GROUPS) for (const s of g.slugs) expect(slugs, `${g.id}/${s}`).toContain(s)
  })

  it('正文与首页入口表里的每个链接都指向存在的文档和锚点（中英文）', () => {
    const bySlug = new Map(DOCS.map((d) => [d.slug, { zh: anchors(d.blocks.zh), en: anchors(d.blocks.en) }]))
    const check = (from: string, lang: 'zh' | 'en', href: string) => {
      const [path, hash] = href.split('#')
      const slug = path ? path.replace('/docs/', '') : from
      const target = bySlug.get(slug)
      expect(target, `${from}/${lang} → ${href}`).toBeDefined()
      if (hash) expect(target![lang].has(hash), `${from}/${lang} → ${href}`).toBe(true)
    }
    let count = 0
    for (const d of DOCS) for (const lang of ['zh', 'en'] as const) for (const h of links(d.blocks[lang])) { check(d.slug, lang, h); count++ }
    for (const r of [...DOCS_HOME.roles, ...DOCS_HOME.tasks]) for (const lang of ['zh', 'en'] as const) check('', lang, r.target)
    expect(count).toBeGreaterThan(40)
  })

  it('中英文正文的锚点集合一致（显式 {#id} 两种语言相同）', () => {
    for (const d of SEED.docs) {
      const explicit = (l: 'zh' | 'en') => [...d.body[l].matchAll(/^#{1,6} .*\{#([a-z0-9][a-z0-9._-]*)\}\s*$/gm)].map((m) => m[1]).sort()
      expect(explicit('en'), d.slug).toEqual(explicit('zh'))
      expect(explicit('zh').length, d.slug).toBeGreaterThan(0)
    }
  })

  it('正文不出现内部术语、源码路径、问题编号或真实客户域名', () => {
    for (const d of DOCS) for (const lang of ['zh', 'en'] as const) {
      const text = JSON.stringify(SEED.docs.find((x) => x.slug === d.slug)!.body[lang])
      expect(text, d.slug).not.toMatch(/\b(?:apps|services|internal)\/[a-z]|\.tsx?\b|\b(?:G0\d|G10|DOC-[A-Z]+-\d+|INSTALL-DOC|MKT-|PA-\d|RS-0\d)\b|example\.com|868yun|ikvm/)
    }
  })
})

describe('文档页', () => {
  it('侧栏按分组列出全部文档，键盘可达且当前页高亮', () => {
    render(<App pathname="/docs/install-node" />)
    const nav = screen.getByRole('navigation', { name: '文档目录' })
    expect(within(nav).getAllByRole('link')).toHaveLength(SEED.docs.length + 1)
    for (const g of DOC_GROUPS) expect(within(nav).getByRole('list', { name: g.title.zh })).toBeInTheDocument()
    expect(within(within(nav).getByRole('list', { name: '入门与安装' })).getByRole('link', { name: '节点安装' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('heading', { level: 1, name: '节点安装' })).toBeInTheDocument()
  })

  it('首页有“按角色查阅”“按要做的事查阅”两张入口表，链接到对应文档', () => {
    render(<App pathname="/docs" />)
    expect(screen.getByRole('heading', { level: 2, name: '按角色查阅' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 2, name: '按要做的事查阅' })).toBeInTheDocument()
    const tables = screen.getAllByRole('table')
    expect(within(tables[0]).getByRole('link', { name: '网站用户手册' })).toHaveAttribute('href', '/docs/tenant-guide')
    expect(within(tables[1]).getByRole('link', { name: '刷新与预热' })).toHaveAttribute('href', '/docs/tenant-guide#cache')
  })

  it('长文有本页目录，标题带锚点，正文站内链接可点击', () => {
    const { container } = render(<App pathname="/docs/tenant-guide" />)
    const toc = screen.getByRole('navigation', { name: '本页目录' })
    expect(within(toc).getByRole('link', { name: '刷新与预热' })).toHaveAttribute('href', '#cache')
    expect(container.querySelector('h2#cache')).not.toBeNull()
    expect(container.querySelector('a[href="/docs/plugins#tenant"]')).not.toBeNull()
  })

  it('英文页的站内链接带 /en 前缀', () => {
    const { container } = render(<App pathname="/en/docs/install-control" />)
    expect(container.querySelector('a[href="/en/docs/requirements"]')).not.toBeNull()
    expect(container.querySelector('article a[href^="/docs/"]')).toBeNull()
  })

  it('主控域名示例用 console.cdnca.com，不再出现旧的管理端域名写法', () => {
    const { container } = render(<App pathname="/docs/install-control" />)
    expect(container.textContent).toContain(CONTROL_EXAMPLE_DOMAIN)
    expect(CONTROL_EXAMPLE_DOMAIN).toBe('console.cdnca.com')
    expect(container.textContent).not.toMatch(/--master-host cdnca\.com/)
  })

  it('运维页包含重启、日志、卸载节点、主控无卸载脚本与迁移命令', () => {
    const { container } = render(<App pathname="/docs/operations" />)
    const t = container.textContent!
    expect(t).toContain(`systemctl restart ${SERVICES.edgeAgent}`)
    expect(t).not.toContain('openresty-native')
    expect(t).toContain(`journalctl -u ${SERVICES.controlApi}`)
    expect(t).toContain('uninstall.sh --purge')
    expect(t).toContain('主控没有卸载脚本')
    expect(t).toContain('migrate-from root@')
  })

  it('英文文档页可渲染', () => {
    render(<App pathname="/en/docs/troubleshooting" />)
    expect(screen.getByRole('heading', { level: 1, name: 'Troubleshooting' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: 'Installer download returns 403' })).toBeInTheDocument()
  })

  it('安装失败按步骤处理，不默认建议重装系统', () => {
    for (const lang of ['zh', 'en'] as const) {
      const body = SEED.docs.find((d) => d.slug === 'install-control')!.body[lang]
      expect(body).not.toMatch(/最稳妥的做法是重装|safest path is to reinstall/)
      expect(body).toMatch(/第 1–4 步|Steps 1–4/)
    }
  })
})
