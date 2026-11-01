// 全部语言的全量资源与测试用伪语言。生产不导入本文件：按当前语言加载
// resources.zhCN.ts / resources.enUS.ts（i18n/index.ts loadFullResources）。
import { pseudoNodeScheduling } from '../pages/node-scheduling/messages'
import { zhCN } from './resources.zhCN'

export { zhCN } from './resources.zhCN'
export { enUS } from './resources.enUS'

type TranslationTree = { [key: string]: string | TranslationTree }

function pseudoText(value: string): string {
  const expanded = value
    // 插值 {{x}} 与 HTML 标记 <p>/<script> 原样保留，只给可见文字加 ~
    .split(/({{[^}]+}}|<[^>]+>)/g)
    .map((part) =>
      (part.startsWith('{{') && part.endsWith('}}')) || (part.startsWith('<') && part.endsWith('>'))
        ? part
        : [...part]
            .map((character) => (/\s|\d/.test(character) ? character : `${character}~`))
            .join(''),
    )
    .join('')
  return `［${expanded}］`
}

function pseudoTree(tree: TranslationTree): TranslationTree {
  return Object.fromEntries(
    Object.entries(tree).map(([key, value]) => [
      key,
      typeof value === 'string' ? pseudoText(value) : pseudoTree(value),
    ]),
  )
}

export const pseudoCN = {
  ...pseudoTree(zhCN),
  nodeScheduling: pseudoNodeScheduling,
}
