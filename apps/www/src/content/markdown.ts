// 文档正文用的受限 Markdown（运营后台编辑，授权端保存，官网渲染）。没有 HTML，也没有加粗等行内格式；
// 唯一的行内语法是站内链接。解析结果是 DocBlock 结构，由 renderBlock 以 React 文本节点和受控的 <a>
// 输出（自动转义），所以任何输入都只会显示成文字。授权端另外拒收代码块以外的 HTML 标签（纵深防御）。
//
//   ## 标题 / ### 小标题   → { h, level, id }（# 当作 ##，####… 当作 ###）
//   ## 标题 {#id}          → 显式锚点；没写时按标题文字自动生成（规则见 headingId）
//   > 提示                 → { note }（连续多行合并）
//   - 项 / * 项            → 无序列表；1. 项 → 有序列表
//   ```标签 … ```           → 命令块（可选标签作可访问名称；块内不解析链接）
//   | 表头 | … |            → 表格（第二行 | --- | 分隔；单元格内不能有 |）
//   其他行                 → 段落（空行分段，同段多行以空格连接）
//
// 站内链接（段落、提示、列表项、表格单元格里可用）：
//   [文字](/docs/<slug>)  [文字](/docs/<slug>#<id>)  [文字](#<id>)
// slug、id 只能是小写字母、数字和连字符（id 另允许 . 和 _）。其他任何目标（http(s):、//、javascript:、
// mailto:、data:、相对路径、带空格或引号……）都不是链接：整段 [文字](目标) 原样按文字显示。
import type { DocBlock, Inline, Rich } from './docs'
import type { L } from '../i18n'

const mono = <T,>(value: T): L<T> => ({ zh: value, en: value })

function cells(line: string): string[] {
  return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim())
}

const SEPARATOR = /^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/
/** 允许的链接目标：站内文档页（可带锚点）或本页锚点。 */
export const DOC_LINK_TARGET = /^(?:\/docs\/[a-z0-9][a-z0-9-]{0,63}(?:#[a-z0-9][a-z0-9._-]{0,63})?|#[a-z0-9][a-z0-9._-]{0,63})$/
const LINK = /\[([^[\]\n]+)\]\(([^)\n]*)\)/g
const ANCHOR = /\s*\{#([a-z0-9][a-z0-9._-]{0,63})\}\s*$/

/** 行内解析：只认合法站内链接，其余（含非法链接的整段原文）都是文字。 */
export function parseInline(source: string): Rich {
  const out: Inline[] = []
  let last = 0
  for (const m of source.matchAll(LINK)) {
    if (!DOC_LINK_TARGET.test(m[2])) continue
    if (m.index > last) out.push(source.slice(last, m.index))
    out.push({ text: m[1], href: m[2] })
    last = m.index + m[0].length
  }
  if (!out.length) return source
  if (last < source.length) out.push(source.slice(last))
  return out
}

/** 去掉链接语法后的纯文字（目录、锚点、测试用）。 */
export function plainText(rich: Rich): string {
  return typeof rich === 'string' ? rich : rich.map((x) => (typeof x === 'string' ? x : x.text)).join('')
}

/**
 * 标题锚点：标题末尾写 {#id} 时用 id；否则取标题文字，转小写，空白换成 -，只留字母（含中文）、数字、- 和 _，
 * 去掉首尾 -。同一页重复时依次加 -2、-3。底稿里的 <a id="x"></a> 写法改成标题后的 {#x}。
 */
export function headingId(text: string): string {
  return text.toLowerCase().replace(/\s+/g, '-').replace(/[^\p{L}\p{N}_-]/gu, '').replace(/-+/g, '-').replace(/^-|-$/g, '') || 'section'
}

/** 解析成单语言 DocBlock（每个文本的 zh/en 相同，renderBlock 按语言取值即可）。 */
export function parseMarkdown(source: string): DocBlock[] {
  const lines = source.replace(/\r\n?/g, '\n').split('\n')
  const out: DocBlock[] = []
  const ids = new Map<string, number>()
  let para: string[] = []
  const flush = () => {
    if (para.length) out.push({ p: mono(parseInline(para.join(' '))) })
    para = []
  }
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const trimmed = line.trim()
    if (trimmed.startsWith('```')) {
      flush()
      const label = trimmed.slice(3).trim()
      const body: string[] = []
      for (i++; i < lines.length && lines[i].trim() !== '```'; i++) body.push(lines[i])
      out.push(label ? { cmd: body.join('\n'), label: mono(label) } : { cmd: body.join('\n') })
      continue
    }
    if (!trimmed) { flush(); continue }
    const heading = /^(#{1,6})\s+(.*)$/.exec(trimmed)
    if (heading) {
      flush()
      const explicit = ANCHOR.exec(heading[2])
      const text = (explicit ? heading[2].slice(0, explicit.index) : heading[2]).trim()
      const base = explicit ? explicit[1] : headingId(text)
      const seen = ids.get(base) ?? 0
      ids.set(base, seen + 1)
      out.push({ h: mono(text), level: heading[1].length >= 3 ? 3 : 2, id: seen ? `${base}-${seen + 1}` : base })
      continue
    }
    if (trimmed.startsWith('>')) {
      flush()
      const note: string[] = []
      for (; i < lines.length && lines[i].trim().startsWith('>'); i++) note.push(lines[i].trim().replace(/^>\s?/, ''))
      i--
      out.push({ note: mono(parseInline(note.join(' '))) })
      continue
    }
    const bullet = /^([-*]|\d+[.)])\s+/
    const first = bullet.exec(trimmed)
    if (first) {
      flush()
      const ordered = /\d/.test(first[1])
      const items: L<Rich>[] = []
      for (; i < lines.length; i++) {
        const m = bullet.exec(lines[i].trim())
        if (!m || /\d/.test(m[1]) !== ordered) break
        items.push(mono(parseInline(lines[i].trim().slice(m[0].length).trim())))
      }
      i--
      out.push(ordered ? { list: items, ordered: true } : { list: items })
      continue
    }
    if (trimmed.startsWith('|')) {
      flush()
      const rows: string[][] = []
      for (; i < lines.length && lines[i].trim().startsWith('|'); i++) {
        if (!SEPARATOR.test(lines[i].trim())) rows.push(cells(lines[i]))
      }
      i--
      const [head = [], ...body] = rows
      out.push({ table: { head: head.map((c) => mono(c)), rows: body.map((r) => r.map((c) => mono(parseInline(c)))) } })
      continue
    }
    para.push(trimmed)
  }
  flush()
  return out
}
