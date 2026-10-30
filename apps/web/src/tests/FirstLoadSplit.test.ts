import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// 首包拆分守卫（web-perf 1.0.35）：控制台壳、首页、注册页、横幅和全量 i18n 资源
// 不能再被入口静态导入，否则会把菜单引用的几十个页面命名空间和 resources.ts 全部拖回首包。
const source = (path: string) => readFileSync(resolve(__dirname, '..', path), 'utf8')
const staticImports = (text: string) =>
  [...text.matchAll(/^\s*import\s+(?!type\b)[^'"]*?['"]([^'"]+)['"]/gm)].map((match) => match[1])

describe('first-load bundle split', () => {
  it('loads the console shell, home pages, registration and banners lazily', () => {
    const imports = staticImports(source('App.tsx'))
    for (const lazyModule of [
      './components/AppShell',
      './pages/AdminHomePage',
      './pages/UserHomePage',
      './pages/RegisterPage',
      './components/ImpersonationStatusBanner',
      './components/InstallationLockBanner',
      './pages/LoginPage',
      './pages/account-recovery/RequestPage',
      './pages/account-recovery/ResetPage',
    ]) {
      expect(imports).not.toContain(lazyModule)
    }
  })

  it('loads the password-change and session-region dialogs only when they open', () => {
    for (const gate of ['components/PasswordChangeGate.tsx', 'components/SessionRegionGate.tsx']) {
      expect(staticImports(source(gate))).not.toContain('antd')
    }
  })

  it('keeps only the core namespaces in the static i18n graph', () => {
    const imports = staticImports(source('i18n/index.ts'))
    expect(imports).toContain('./coreResources')
    expect(imports).not.toContain('./resources')
  })

  it('uses the tree-shakable antd locale modules', () => {
    const imports = staticImports(source('i18n/antdLocale.ts'))
    expect(imports.filter((path) => path.startsWith('antd/locale/'))).toEqual([])
  })
})
