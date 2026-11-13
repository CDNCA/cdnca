import { el } from './dom'

// 事件正文的安全渲染：只认三种写法，一律按文本处理（textContent），不使用 innerHTML。
//   「## 」开头的行 = 小标题；「- 」开头的连续行 = 列表；其余行 = 段落，段内换行保留。
// 其他任何标记（HTML、Markdown 链接等）都原样显示成文字。
export function renderBody(source: string): HTMLElement {
  const box = el('div', { class: 'st-body' })
  let para: string[] = []
  let list: HTMLElement | null = null
  const flushPara = () => {
    if (!para.length) return
    const p = el('p')
    para.forEach((line, index) => {
      if (index) p.append(document.createElement('br'))
      p.append(document.createTextNode(line))
    })
    box.append(p)
    para = []
  }
  for (const raw of source.replace(/\r\n?/g, '\n').split('\n')) {
    const line = raw.replace(/\s+$/, '')
    if (line.startsWith('## ')) {
      flushPara(); list = null
      box.append(el('h5', {}, line.slice(3).trim()))
    } else if (line.startsWith('- ')) {
      flushPara()
      if (!list) { list = el('ul'); box.append(list) }
      list.append(el('li', {}, line.slice(2).trim()))
    } else if (line.trim() === '') {
      flushPara(); list = null
    } else {
      list = null
      para.push(line)
    }
  }
  flushPara()
  return box
}
