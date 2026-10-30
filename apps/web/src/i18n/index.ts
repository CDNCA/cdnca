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
  if (locale === 'zh-CN' && traditionalLocaleReady) {
    void traditionalize(resources).then((converted) => {
      addResourceBundle('zh-TW', namespace, converted, deep, overwrite)
    })
  }
  return result
}) as typeof i18n.addResourceBundle

let fullResourcesLoad: Promise<void> | undefined

/** 装入 resources.ts 的全部命名空间（控制台壳加载前调用；重复调用只加载一次）。 */
export function loadFullResources(): Promise<void> {
  // overwrite=false：页面补充模块（如 i18n/securityPolicies*.ts）往同一命名空间追加或覆盖的键
  // 已在 store 里时保留补充值，与原先“基础资源先装、补充模块后覆盖”的结果一致。
  fullResourcesLoad ??= import('./resources').then(async (full) => {
    for (const [namespace, bundle] of Object.entries(full.enUS)) addResourceBundle('en-US', namespace, bundle, true, false)
    for (const [namespace, bundle] of Object.entries(full.zhCN)) addResourceBundle('zh-CN', namespace, bundle, true, false)
    if (traditionalLocaleReady || traditionalLocaleRequested) {
      const converted = await traditionalize(full.zhCN)
      for (const [namespace, bundle] of Object.entries(converted as Record<string, unknown>)) {
        addResourceBundle('zh-TW', namespace, bundle, true, false)
      }
    }
  }).catch((error: unknown) => {
    fullResourcesLoad = undefined
    throw error
  })
  return fullResourcesLoad
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
  if (nextLocale === 'zh-TW') {
    traditionalLocaleRequested = true
    await fullResourcesLoad?.catch(() => undefined)
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
