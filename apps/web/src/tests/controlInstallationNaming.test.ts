import { describe, expect, it } from 'vitest'

// fix-authportal3：主控安装的稳定标识（installation_id）在门户、运营端、主控里一律叫"主控编号"
// （英文 Control installation ID），不再混用"主控 ID / 安装 ID / 主控实例 / 安装实例 / 主控安装编号"。
// 这里扫主控全部 i18n 源；运营端、门户各有同样的扫描用例。
const sources = import.meta.glob(['../i18n/*.ts', '!../i18n/*.test.ts'], { eager: true, import: 'default', query: '?raw' }) as Record<string, string>

// 只抓编号标签；"所在主控"（名称）、"安装实例"作数量统计（installs）、作用域枚举「主控 / Installation」都不是编号，不在此列。
const legacy = /主控 ?ID|安装 ?ID|主控实例 ?ID|主控安装编号|主控安装 ID|installation(?:Id)?: '(?:安装实例|主控实例|Controller)'|Master ID|'Installation ID'/

describe('主控编号叫法统一', () => {
  it('主控文案不再出现旧叫法', () => {
    const hits = Object.entries(sources).flatMap(([file, text]) =>
      text.split('\n').flatMap((line, index) => (legacy.test(line) ? [`${file}:${index + 1}: ${line.trim().slice(0, 120)}`] : [])))
    expect(hits).toEqual([])
  })
})
