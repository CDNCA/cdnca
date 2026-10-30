import i18n from './index'

const bundles = {
  'zh-CN': { systemSettings: '系统设置', refreshPage: '刷新页面' },
  'en-US': { systemSettings: 'System settings', refreshPage: 'Refresh page' },
  'qps-ploc': { systemSettings: '［系统设置～～］', refreshPage: '［刷新页面～～］' },
  'qps-Ploc': { systemSettings: '［系统设置～～］', refreshPage: '［刷新页面～～］' },
}

for (const [locale, messages] of Object.entries(bundles)) {
  i18n.addResourceBundle(locale, 'appShellReference', messages, true, true)
}
