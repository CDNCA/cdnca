import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { App, ConfigProvider, message, type AppProps, type ConfigProviderProps, type ThemeConfig } from 'antd'

import { FeedbackProvider } from './feedback'
import tokens from './tokens.json'

// The shared look of every cdnca front end (web, operator-console,
// license-portal, seller-portal). tokens.json equals the defaults in
// libs/themepack/tokens.go (checked by libs/themepack/shared_ui_test.go), so
// the default theme package and the built-in look are the same thing.

export interface CdncaAntdTokens {
  colorPrimary: string
  colorLink: string
  colorLinkHover: string
  colorText: string
  colorTextSecondary: string
  colorBorder: string
  colorBgLayout: string
  colorBgContainer: string
  borderRadius: number
  controlHeight: number
  fontSize: number
  lineHeight: number
  fontFamily: string
}

export const defaultAntdTokens: CdncaAntdTokens = tokens.antd

/** Tokens outside ConfigProvider; styles.css reads them as --cdnca-* variables. */
export const defaultCSSTokens = tokens.css

/** Where and how long every end shows message / notification feedback. */
export const feedbackConfig: Required<Pick<AppProps, 'message' | 'notification'>> = {
  message: { top: 64, duration: 3, maxCount: 3 },
  notification: { placement: 'topRight', top: 64, duration: 4.5, maxCount: 4 },
}

/**
 * The look of the ends that never load a theme package: "classic" is the
 * tokens.json default (web), "console" the built-in look of the licensing
 * ends (operator console, customer portal, seller site). Its CSS side is
 * @cdnca/ui/console.css; keep the two in step.
 */
export type CdncaVariant = 'classic' | 'console'

export const consoleAntdTokens: CdncaAntdTokens = {
  colorPrimary: '#2563eb',
  colorLink: '#2563eb',
  colorLinkHover: '#3b82f6',
  colorText: '#334155',
  colorTextSecondary: '#64748b',
  colorBorder: '#cbd5e1',
  colorBgLayout: '#f3f5f9',
  colorBgContainer: '#ffffff',
  borderRadius: 6,
  controlHeight: 34,
  fontSize: 14,
  lineHeight: 1.5715,
  fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Helvetica Neue", Arial, sans-serif',
}

const consoleSidebar = '#0b1220'

// consoleTheme: the console variant's extra antd tokens on top of cdncaTheme.
function consoleTheme(base: ThemeConfig): ThemeConfig {
  const shadow = '0 1px 2px rgb(15 23 42 / 4%), 0 1px 3px rgb(15 23 42 / 6%)'
  return {
    token: {
      ...base.token,
      colorTextHeading: '#0f172a',
      colorBorderSecondary: '#e2e8f0',
      colorSplit: '#e2e8f0',
      colorSuccess: '#16a34a',
      colorWarning: '#d97706',
      colorError: '#dc2626',
      colorInfo: '#2563eb',
      colorFillAlter: '#f8fafc',
      borderRadiusLG: 8,
      borderRadiusSM: 4,
      boxShadowTertiary: shadow,
      controlOutline: 'rgb(37 99 235 / 18%)',
      controlOutlineWidth: 3,
    },
    components: {
      ...base.components,
      Button: { ...base.components?.Button, fontWeight: 500, borderRadiusLG: 8, contentFontSizeLG: 15 },
      Menu: {
        ...base.components?.Menu,
        itemBorderRadius: 6,
        itemHeight: 40,
        itemMarginInline: 8,
        itemMarginBlock: 2,
        subMenuItemBorderRadius: 6,
        iconSize: 16,
        darkItemBg: consoleSidebar,
        darkSubMenuItemBg: consoleSidebar,
        darkPopupBg: '#111a2e',
        darkItemColor: 'rgb(203 213 225 / 82%)',
        darkItemHoverColor: '#ffffff',
        darkItemHoverBg: 'rgb(255 255 255 / 6%)',
        darkItemSelectedBg: '#2563eb',
        darkItemSelectedColor: '#ffffff',
        darkGroupTitleColor: 'rgb(148 163 184 / 70%)',
      },
      Table: {
        headerBg: '#f8fafc', headerColor: '#475569', headerSplitColor: 'transparent', borderColor: '#eef2f6',
        rowHoverBg: '#f5f8ff', cellPaddingBlock: 12, cellPaddingInline: 14, headerBorderRadius: 0,
      },
      Layout: { headerBg: '#ffffff', headerHeight: 56, headerPadding: '0 20px', siderBg: consoleSidebar, bodyBg: '#f3f5f9' },
      Card: { boxShadowTertiary: shadow },
      Tabs: { horizontalItemPadding: '14px 2px', horizontalItemGutter: 28, titleFontSize: 14 },
      Tag: { borderRadiusSM: 4 },
      Alert: { borderRadiusLG: 8, withDescriptionPadding: '14px 16px' },
      Modal: { titleFontSize: 16, borderRadiusLG: 10 },
      Drawer: { footerPaddingBlock: 12 },
      Message: { contentPadding: '10px 16px' },
    },
  }
}

// cdncaTheme maps the whitelisted tokens onto ConfigProvider.theme, plus the
// component tokens derived from them. A white-label theme (web, PA-17/PA-26)
// passes its own tokens; everything below follows them.
export function cdncaTheme(theme: CdncaAntdTokens = defaultAntdTokens, reducedMotion = false, variant: CdncaVariant = 'classic'): ThemeConfig {
  const base = classicTheme(theme, reducedMotion)
  return variant === 'console' ? consoleTheme(base) : base
}

function classicTheme(theme: CdncaAntdTokens, reducedMotion: boolean): ThemeConfig {
  const { colorPrimary, colorText, colorBgContainer, colorBgLayout, borderRadius, controlHeight } = theme
  return {
    // Status colors (K1): antd's own green/orange/red would differ from the
    // --cdnca-color-* ones. They are CSS-group tokens (tokens.json "css"), so
    // antd gets their defaults; info follows the primary color.
    token: {
      motion: !reducedMotion,
      colorSuccess: defaultCSSTokens.colorSuccess,
      colorWarning: defaultCSSTokens.colorWarning,
      colorError: defaultCSSTokens.colorError,
      colorInfo: colorPrimary,
      ...theme,
    },
    components: {
      Button: { controlHeight, borderRadiusLG: borderRadius, primaryShadow: 'none', defaultShadow: 'none', dangerShadow: 'none' },
      Input: { controlHeight, borderRadiusLG: borderRadius },
      InputNumber: { controlHeight, borderRadiusLG: borderRadius },
      Select: { controlHeight, borderRadiusLG: borderRadius, optionSelectedBg: selectedBackground(colorPrimary) },
      DatePicker: { controlHeight, borderRadiusLG: borderRadius },
      Menu: {
        itemBorderRadius: 0,
        itemHeight: 49,
        itemSelectedBg: selectedBackground(colorPrimary),
        itemSelectedColor: colorPrimary,
        darkItemBg: defaultCSSTokens.colorSidebarDark,
        darkSubMenuItemBg: defaultCSSTokens.colorSidebarDark,
        darkItemSelectedBg: colorPrimary,
      },
      Segmented: { itemSelectedColor: colorPrimary },
      // Header background follows --cdnca-color-table-header (a theme package sets it).
      Table: { headerBg: `var(--cdnca-color-table-header, ${defaultCSSTokens.colorTableHeader})`, headerColor: colorText, headerSplitColor: 'transparent', cellPaddingBlock: 11, cellPaddingInline: 12 },
      Layout: { headerBg: colorBgContainer, headerHeight: 50, headerPadding: '0 16px', siderBg: defaultCSSTokens.colorSidebarDark, bodyBg: colorBgLayout },
      Modal: { titleFontSize: 16 },
    },
  }
}

// The default primary keeps its measured tint; other primaries use an 8% wash.
function selectedBackground(colorPrimary: string): string {
  return colorPrimary === defaultAntdTokens.colorPrimary ? '#f0faff' : `${colorPrimary}14`
}

/**
 * Follows prefers-reduced-motion. It starts as true so antd's MotionProvider
 * is mounted from the first render: a later preference change then does not
 * insert a provider and remount the application's stateful children.
 */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(true)
  useEffect(() => {
    const preference = window.matchMedia?.('(prefers-reduced-motion: reduce)')
    if (!preference) {
      setReduced(false)
      return
    }
    const update = () => setReduced(preference.matches)
    update()
    preference.addEventListener('change', update)
    return () => preference.removeEventListener('change', update)
  }, [])
  return reduced
}

/**
 * A message instance owned by the calling component, with the shared
 * placement and duration. Use it instead of message.useMessage() where the
 * notices must disappear with the component (e.g. a page keyed by session
 * owner); render the returned holder. Elsewhere use App.useApp().message.
 */
export function useFeedbackMessage() {
  return message.useMessage(feedbackConfig.message)
}

export * from './components'
export * from './CdncaGlyph'
export * from './feedback'
export * from './formErrors'
export * from './reviewRules'
export * from './PasswordStrength'
export * from './staleChunk'
export * from './TimeRangeFilter'
export * from './AdvancedFilters'
export * from './PriceBadge'
export * from './PromoPlanFields'
export * from './liveFilter'
export * from './IdOrNameInput'

export type CdncaProviderProps = Omit<ConfigProviderProps, 'theme'> & {
  children: ReactNode
  /** White-label tokens (web theme package); missing ones use the defaults. */
  tokens?: CdncaAntdTokens | null
  /** "console" for the licensing ends; with it, also import @cdnca/ui/console.css. */
  look?: CdncaVariant
}

/**
 * Root of every front end: the shared ConfigProvider theme and antd App, so
 * App.useApp() message / notification / modal look and sit the same in all
 * four ends. Errors and warnings go through useFeedback() (dialogs); success
 * hints through App.useApp().message. Never antd's static API.
 */
export function CdncaProvider({ children, tokens: overrides, look = 'classic', ...config }: CdncaProviderProps) {
  const reducedMotion = useReducedMotion()
  const theme = useMemo(() => cdncaTheme(
    overrides ?? (look === 'console' ? consoleAntdTokens : defaultAntdTokens), reducedMotion, look,
  ), [overrides, reducedMotion, look])
  // rc-dialog hard-codes aria-label="Close" on the Modal ×; antd only replaces it
  // with aria props from the closable config, so hand it the locale's own word
  // (Drawer already reads locale.global.close). Modals with closable={false} stay closed off.
  const closeLabel = config.locale?.global?.close
  const modal = useMemo(() => (
    closeLabel && config.modal?.closable === undefined
      ? { ...config.modal, closable: { 'aria-label': closeLabel } }
      : config.modal
  ), [closeLabel, config.modal])
  return (
    <ConfigProvider button={{ autoInsertSpace: false }} {...config} modal={modal} theme={theme}>
      <App className={look === 'console' ? 'cdnca-app cdnca-console' : 'cdnca-app'} message={feedbackConfig.message} notification={feedbackConfig.notification}>
        <FeedbackProvider>{children}</FeedbackProvider>
      </App>
    </ConfigProvider>
  )
}
