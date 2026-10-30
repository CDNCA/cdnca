// 使用文档的块结构（www-design.md §3.8）。文档正文由运营在授权端「官网内容」用受限 Markdown 编辑
// （content/markdown.ts 解析成 DocBlock），初始内容与预渲染兜底在 site-content-seed.json。
// docs.test.tsx 校验种子：每个命令块里出现的 --参数 都在对应脚本 usage() 里。
// 主控域名示例用 console.cdnca.com。
import type { L } from '../i18n'

/** 手写内容（开发者页等）的块：全部是纯文字。 */
export type Block =
  | { p: L }
  | { h: L }
  | { list: L[]; ordered?: boolean }
  | { cmd: string; label?: L }
  | { note: L }
  | { table: { head: L[]; rows: L[][] } }

/** 行内片段：纯文字，或站内链接（href 只会是 /docs/<slug>、/docs/<slug>#<id> 或 #<id>，见 markdown.ts）。 */
export type Inline = string | { text: string; href: string }
/** 一段文字：纯字符串，或含站内链接的行内片段数组。 */
export type Rich = string | Inline[]

/** 文档正文（受限 Markdown 解析结果）的块：段落、提示、列表项、表格单元格可含站内链接；标题带层级与锚点。 */
export type DocBlock =
  | { p: L<Rich> }
  | { h: L; level: 2 | 3; id: string }
  | { list: L<Rich>[]; ordered?: boolean }
  | { cmd: string; label?: L }
  | { note: L<Rich> }
  | { table: { head: L[]; rows: L<Rich>[][] } }
