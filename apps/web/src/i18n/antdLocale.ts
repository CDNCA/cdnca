import type { Locale } from 'antd/es/locale'
// es 版与 antd/locale/*（CommonJS，会再带一份 lib 版 rc-picker 等语言包）内容相同，只是能摇树。
import antdEnUS from 'antd/es/locale/en_US'
import antdZhCN from 'antd/es/locale/zh_CN'
import antdZhTW from 'antd/es/locale/zh_TW'

// antd's Chinese form messages substitute the raw rule type into
// "${label}不是一个有效的${type}", so an email rule reads "…不是一个有效的email".
// Give every rule type a Chinese name; the rest of antd's messages stay as is.
type ValidateTypes = NonNullable<NonNullable<NonNullable<Locale['Form']>['defaultValidateMessages']>['types']>
type RuleType = keyof ValidateTypes

const zhCNTypeNames: Record<RuleType, string> = {
  string: '文本', method: '函数', array: '列表', object: '对象', number: '数字', date: '日期', boolean: '布尔值',
  integer: '整数', float: '数字', regexp: '正则表达式', email: '邮箱地址', url: '网址', hex: '十六进制值',
}

const zhTWTypeNames: Record<RuleType, string> = {
  string: '文字', method: '函式', array: '清單', object: '物件', number: '數字', date: '日期', boolean: '布林值',
  integer: '整數', float: '數字', regexp: '正規表示式', email: '電子郵件地址', url: '網址', hex: '十六進位值',
}

function withTypeNames(locale: Locale, template: string, names: Record<RuleType, string>): Locale {
  const types = Object.fromEntries(Object.entries(names).map(([type, name]) => [type, template.replace('${type}', name)]))
  return {
    ...locale,
    Form: {
      ...locale.Form,
      defaultValidateMessages: { ...locale.Form?.defaultValidateMessages, types },
    },
  }
}

export const antdZhCNLocale = withTypeNames(antdZhCN, '${label}不是一个有效的${type}', zhCNTypeNames)
export const antdZhTWLocale = withTypeNames(antdZhTW, '${label}不是一個有效的${type}', zhTWTypeNames)

/** The antd locale for the resolved UI language; Chinese is the default. */
export function antdLocaleFor(language: string | undefined): Locale {
  return language === 'en-US' ? antdEnUS : language === 'zh-TW' ? antdZhTWLocale : antdZhCNLocale
}
