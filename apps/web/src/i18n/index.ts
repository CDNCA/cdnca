import i18n, { type Resource } from 'i18next'
import { initReactI18next } from 'react-i18next'

import { coreEnUS, coreZhCN } from './coreResources'
import { traditionalize } from './traditional'

export const localeStorageKey = 'cdnca.locale'
export const userLocales = ['zh-CN', 'zh-TW', 'en-US'] as const
export type UserLocale = (typeof userLocales)[number] | 'qps-ploc'

const failOnMissingKey = !import.meta.env.PROD
const testOnlyResources = import.meta.env.MODE === 'test'
// 生产首包只带登录、找回密码和路由兜底用的 common/auth/errors；其余命名空间由
// loadFullResources() 随控制台壳加载。开发和测试仍一次装全，缺键检查照常生效。
const fullResources = import.meta.env.PROD ? undefined : await import('./resources')
const zhCN: Resource[string] = fullResources?.zhCN ?? coreZhCN
const enUS: Resource[string] = fullResources?.enUS ?? coreEnUS
const resources: Resource = {
  'zh-CN': zhCN,
  'zh-TW': structuredClone(zhCN),
  'en-US': enUS,
}
if (testOnlyResources && fullResources) {
  // Test-only pseudo-locale; never registered in production builds.
  resources['qps-ploc'] = fullResources.pseudoCN
  resources['qps-Ploc'] = fullResources.pseudoCN
}

/**
 * Pseudo-localization is a test oracle only.  Page modules still expose their
 * qps bundles so Vitest can exercise text expansion, but those bundles must
 * never enter the production i18next store.
 */
export function shouldRegisterLocaleBundle(locale: string, production = import.meta.env.PROD): boolean {
  const isPseudoLocale = /^qps(?:-|$)/i.test(locale)
  // Pseudo-localization is only a Vitest oracle. Keep it out of both the
  // development server and production bundles so it can never become a user
  // selectable or persisted application language.
  return !isPseudoLocale || (!production && import.meta.env.MODE === 'test')
}

function isUserLocale(value: string | null): value is UserLocale {
  return value !== null && userLocales.some((locale) => locale === value)
}

function initialLocale(): UserLocale {
  if (typeof window === 'undefined') return 'zh-CN'
  try {
    const stored = window.localStorage.getItem(localeStorageKey)
    if (isUserLocale(stored)) return stored
    if (stored !== null) window.localStorage.setItem(localeStorageKey, 'zh-CN')
    return 'zh-CN'
  } catch {
    return 'zh-CN'
  }
}

void i18n.use(initReactI18next).init({
  resources,
  lng: initialLocale(),
  fallbackLng: failOnMissingKey ? false : 'zh-CN',
  supportedLngs: testOnlyResources ? [...userLocales, 'qps-ploc', 'qps-Ploc'] : [...userLocales],
  defaultNS: 'common',
  ns: Object.keys(zhCN),
  interpolation: { escapeValue: false },
  initAsync: false,
  returnEmptyString: false,
  saveMissing: failOnMissingKey,
  missingKeyHandler: (_languages, namespace, key) => {
    throw new Error(`Missing translation key: ${namespace}:${key}`)
  },
})

const addResourceBundle = i18n.addResourceBundle.bind(i18n)
let traditionalLocaleReady = false
let traditionalLocaleRequested = false
i18n.addResourceBundle = ((locale, namespace, resources, deep, overwrite) => {
  if (!shouldRegisterLocaleBundle(locale)) return i18n
  const result = addResourceBundle(locale, namespace, resources, deep, overwrite)
  // zh-TW 一经请求（转换尚在进行时也算），之后注册的简体命名空间都要转一份繁体，
  // 否则转换开始后才注册的模块在 zh-TW 下缺键。
  // 繁体转换是异步的（opencc 懒加载）：转完之前 zh-TW 先放简体原文，同步注册后立即渲染的组件
  // 不缺键（与启动时 zh-TW 先克隆简体同理）；overwrite=false 不覆盖已转好的繁体。
  if (locale === 'zh-CN' && (traditionalLocaleReady || traditionalLocaleRequested)) {
    addResourceBundle('zh-TW', namespace, structuredClone(resources), true, false)
    void traditionalize(resources).then((converted) => {
      addResourceBundle('zh-TW', namespace, converted, deep, overwrite)
    })
  }
  return result
}) as typeof i18n.addResourceBundle

// 全量资源按语言分文件：只加载当前语言那一份，zh-TW 用简体那份转换；
// 切换语言时再补载目标语言。
type FullLocale = 'zh-CN' | 'en-US'
const fullLoaders: Record<FullLocale, () => Promise<Resource[string]>> = {
  'zh-CN': () => import('./resources.zhCN').then((module) => module.zhCN),
  'en-US': () => import('./resources.enUS').then((module) => module.enUS),
}
const fullLoads = new Map<FullLocale, Promise<void>>()
let fullResourcesWanted = false
const fullLocaleOf = (locale: string | undefined): FullLocale => (locale === 'en-US' ? 'en-US' : 'zh-CN')

function loadFullLocale(locale: FullLocale): Promise<void> {
  let load = fullLoads.get(locale)
  if (load) return load
  // overwrite=false：页面补充模块（如 i18n/securityPolicies*.ts）往同一命名空间追加或覆盖的键
  // 已在 store 里时保留补充值，与原先“基础资源先装、补充模块后覆盖”的结果一致。
  load = fullLoaders[locale]().then(async (full) => {
    for (const [namespace, bundle] of Object.entries(full)) addResourceBundle(locale, namespace, bundle, true, false)
    if (locale === 'zh-CN' && (traditionalLocaleReady || traditionalLocaleRequested)) {
      const converted = await traditionalize(full)
      for (const [namespace, bundle] of Object.entries(converted as Record<string, unknown>)) {
        addResourceBundle('zh-TW', namespace, bundle, true, false)
      }
    }
  })
  load.catch(() => { fullLoads.delete(locale) })
  fullLoads.set(locale, load)
  return load
}

/** 装入当前语言的全部命名空间（控制台壳加载前调用；重复调用只加载一次）。 */
export function loadFullResources(): Promise<void> {
  fullResourcesWanted = true
  return loadFullLocale(fullLocaleOf(i18n.resolvedLanguage))
}

if (typeof document !== 'undefined') {
  const documentLocale = (language: string) => import.meta.env.MODE === 'test' && language.toLowerCase() === 'qps-ploc'
    ? 'qps-ploc'
    : language
  document.documentElement.lang = documentLocale(i18n.resolvedLanguage ?? 'zh-CN')
  i18n.on('languageChanged', (language) => {
    document.documentElement.lang = documentLocale(language)
  })
}

if (i18n.resolvedLanguage === 'zh-TW') {
  void changeLocale('zh-TW')
}

export async function changeLocale(locale: UserLocale): Promise<void> {
  const nextLocale = import.meta.env.MODE === 'test' || userLocales.includes(locale as (typeof userLocales)[number])
    ? locale
    : 'zh-CN'
  try {
    window.localStorage.setItem(localeStorageKey, nextLocale)
  } catch {
    // Language switching remains available when storage is blocked.
  }
  if (nextLocale === 'zh-TW') traditionalLocaleRequested = true
  // 控制台壳已要过全量资源时，先补载目标语言再切换，切过去的页面不缺键。
  if (fullResourcesWanted && userLocales.includes(nextLocale as (typeof userLocales)[number])) {
    await loadFullLocale(fullLocaleOf(nextLocale)).catch(() => undefined)
  }
  if (nextLocale === 'zh-TW') {
    const bundles = i18n.store.data['zh-CN'] ?? {}
    const convertedBundles = await traditionalize(bundles)
    for (const [namespace, resources] of Object.entries(convertedBundles as Record<string, unknown>)) {
      addResourceBundle('zh-TW', namespace, resources, true, true)
    }
    traditionalLocaleReady = true
  }
  await i18n.changeLanguage(nextLocale)
}

export default i18n
