import { describe, expect, it } from 'vitest'
import { defaultLookCSS } from '../test/defaultLookCSS'

const css = defaultLookCSS(Object.values(import.meta.glob('../styles/compact-toolbar.css', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string)
const baseCSS = defaultLookCSS(Object.values(import.meta.glob('../styles.css', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string)
const siteListSource = Object.values(import.meta.glob('../pages/SiteListPage.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}))[0] as string

describe('compact toolbar visual baseline', () => {
  it('uses one centered competitor-style select arrow everywhere', () => {
    expect(css).toMatch(/\.app-shell \.ant-select-single:not\(\.ant-select-sm\):not\(\.ant-select-customize-input\) \.ant-select-selector,[\s\S]*height: 32px !important;[\s\S]*min-height: 32px;[\s\S]*padding: 0 !important;[\s\S]*border-color: var\(--cdnca-color-border\);/)
    expect(css).toMatch(/\.app-shell \.ant-select-single:not\(\.ant-select-sm\):not\(\.ant-select-customize-input\) \.ant-select-selection-item,[\s\S]*padding-inline: 8px 24px !important;/)
    expect(css).toMatch(/\.app-shell \.ant-select-single:not\(\.ant-select-sm\):not\(\.ant-select-customize-input\) \.ant-select-selection-search,[\s\S]*inset-inline: 8px 24px;/)
    expect(css).not.toContain('.ant-select-single:not(.ant-select-customize-input) .ant-select-selector')
    expect(baseCSS).not.toContain('.app-main .ant-select-single:not(.ant-select-customize-input) .ant-select-arrow')
    expect(css).toMatch(/\.app-shell \.ant-select\[class\] \.ant-select-arrow,[\s\S]*top: 50% !important;[\s\S]*right: 9px !important;[\s\S]*width: 14px;[\s\S]*height: 14px;[\s\S]*margin-top: 0 !important;[\s\S]*color: var\(--cdnca-color-text-secondary\);[\s\S]*font-family: 'CdnBaselineIcons';[\s\S]*font-size: 14px;[\s\S]*line-height: 14px;[\s\S]*transform: translateY\(-50%\) !important;/)
    expect(css).toMatch(/\.app-shell \.ant-select\[class\] \.ant-select-arrow > \*,[\s\S]*display: none !important;/)
    expect(css).toMatch(/\.app-shell \.ant-select\[class\] \.ant-select-arrow::before,[\s\S]*content: '\\f116';/)
    expect(css).toContain('.app-shell .ant-select.ant-select-open[class] .ant-select-arrow')
    expect(css).toContain('translateY(-50%) rotate(180deg) !important')
  })

  it('replaces Ant dropdown lucide chevrons with the baseline glyph and button color', () => {
    expect(css).toMatch(/\.app-shell \.ant-dropdown-trigger\.ant-btn > \.lucide-chevron-down,[\s\S]*display: none;/)
    expect(css).toMatch(/\.app-shell \.ant-dropdown-trigger\.ant-btn:has\(> \.lucide-chevron-down\)::after,[\s\S]*width: 14px;[\s\S]*height: 14px;[\s\S]*color: currentcolor;[\s\S]*font-family: 'CdnBaselineIcons';[\s\S]*font-size: 14px;[\s\S]*line-height: 14px;[\s\S]*content: '\\f116';/)
    expect(css).not.toContain("[class*='toolbar'] .ant-dropdown-trigger")
    expect(css).not.toContain('.shell-menu .lucide-chevron-down')
  })

  it('scopes the site-list select and popup geometry to the competitor baseline', () => {
    expect(css).not.toMatch(/\.site-list-page[\s\S]*width: 20px;/)
    expect(css).not.toMatch(/\.site-list-page \.ant-select\[class\] \.ant-select-arrow > \*/)
    expect(baseCSS).toMatch(/\.site-quick-search \.ant-select \{[\s\S]*width: 60px;[\s\S]*flex: 0 0 60px;/)
    expect(baseCSS).toMatch(/\.site-quick-field-popup\.ant-select-dropdown \{[\s\S]*width: 143px !important;[\s\S]*padding: 5px 0;[\s\S]*box-shadow: 0 1px 6px/)
    expect(baseCSS).toMatch(/\.site-toolbar-more-popup \{[^}]*min-width: 110px !important;[^}]*max-height: 200px;[^}]*overflow-y: auto;/)
    expect(baseCSS).toMatch(/\.site-toolbar-more-popup::-webkit-scrollbar \{[^}]*width: 11px;/)
    expect(baseCSS).not.toMatch(/\.site-toolbar-more-popup \{[^}]*margin-left:/)
    expect(baseCSS).not.toMatch(/\.site-toolbar-more-popup \{[^}]*translate:/)
    expect(baseCSS).toMatch(/\.site-toolbar-more-popup \.ant-dropdown-menu\[class\] \.ant-dropdown-menu-item \{[\s\S]*min-height: 34px !important;[\s\S]*padding: 7px 16px !important;[\s\S]*white-space: nowrap;/)
    // fix-advfilter2：高级条件改由共享 AdvancedFilters 四列栅格承载。
    expect(siteListSource).toMatch(/storageKey="site-list"\s+columns=\{4\}/)
    expect(baseCSS).toContain('.site-toolbar-more-popup .ant-dropdown-menu-item.site-more-mobile-only')
  })

  it('keeps toolbar controls on a 32px row and prevents flex overlap', () => {
    expect(css).toContain('.analytics-filter-bar')
    expect(css).toContain('.site-toolbar .site-quick-search')
    expect(css).toMatch(/\.waf-rule-toolbar-actions \.ant-btn[\s\S]*flex: 0 0 auto;/)
    expect(css).toMatch(/\.identity-toolbar \.ant-select-selector[\s\S]*height: 32px !important;/)
    expect(css).toContain('@media (max-width: 767px)')
  })

  it('uses the reference Select dropdown spacing, selection and hover states globally', () => {
    expect(css).toMatch(/\.ant-select-dropdown\[class\]\[class\] \{[\s\S]*padding: 5px 0 !important;[\s\S]*box-shadow: 0 1px 6px rgb\(0 0 0 \/ 20%\);/)
    expect(css).toMatch(/\.ant-select-dropdown\[class\] \.ant-select-item\[class\] \{[\s\S]*height: 34px !important;[\s\S]*min-height: 34px !important;[\s\S]*padding: 7px 16px !important;[\s\S]*align-items: center;[\s\S]*line-height: normal !important;[\s\S]*border-radius: 0 !important;/)
    expect(css).toMatch(/\.ant-select-item-option-selected:not\(\.ant-select-item-option-disabled\)[\s\S]*color: var\(--cdnca-color-primary\) !important;[\s\S]*font-weight: 400 !important;[\s\S]*background: #fff !important;/)
    expect(css).toMatch(/\.ant-select-item-option-active:not\(\.ant-select-item-option-disabled\)[\s\S]*background: rgb\(243 243 243 \/ 48%\) !important;/)
  })
})
