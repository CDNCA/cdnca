import i18n from './index'

// 管理员自定义 CNAME 主机名/前缀编辑器的中英词条（i18nSafety：界面文案放在 i18n 模块，不写在组件里）。
const zhCN = {
  hostname: '主机名',
  prefix: '前缀',
  hostnamePlaceholder: '例如 shop',
  prefixPlaceholder: '例如 gd',
  previewLabel: '预览',
  domainPlaceholder: 'CNAME 域名',
  hostnameHelp: '留空则自动生成。保存后会按这个主机名重新生成 CNAME，旧地址约 24 小时后失效，请先把域名解析改为新地址。',
  prefixHelp: '新分配的 CNAME 会以「前缀-随机字符」命名。已有的 CNAME 不变，需要时点「按新前缀重新生成」。',
  saveHostname: '保存主机名',
  savePrefix: '保存前缀',
  saved: '已保存',
  regenerate: '按新前缀重新生成',
  regenerateTitle: '按新前缀重新生成 CNAME',
  regenerateConfirm: '将重新生成 {{count}} 个网站的 CNAME，旧地址约 24 小时后失效，需要把这些网站的域名解析改为新地址。',
  regenerateNone: '没有需要按新前缀重新生成的网站。',
  regenerateDone: '已提交 {{count}} 个网站的 CNAME 重新生成',
  confirm: '确认重新生成',
  cancel: '取消',
  loadFailed: '读取失败，请刷新后重试',
  copy: '复制',
}

const enUS: typeof zhCN = {
  hostname: 'Hostname',
  prefix: 'Prefix',
  hostnamePlaceholder: 'for example shop',
  prefixPlaceholder: 'for example gd',
  previewLabel: 'Preview',
  domainPlaceholder: 'CNAME domain',
  hostnameHelp: 'Leave empty to generate one. Saving regenerates the CNAME with this hostname, and the old address stops working after about 24 hours, so point the domain to the new address first.',
  prefixHelp: 'New CNAMEs are named "prefix-random characters". Existing CNAMEs stay as they are; select "Regenerate with the new prefix" to change them.',
  saveHostname: 'Save hostname',
  savePrefix: 'Save prefix',
  saved: 'Saved',
  regenerate: 'Regenerate with the new prefix',
  regenerateTitle: 'Regenerate CNAMEs with the new prefix',
  regenerateConfirm: 'This regenerates the CNAME of {{count}} sites. The old addresses stop working after about 24 hours, so point their domains to the new addresses.',
  regenerateNone: 'No site needs to be regenerated with the new prefix.',
  regenerateDone: 'CNAME regeneration was submitted for {{count}} sites',
  confirm: 'Regenerate',
  cancel: 'Cancel',
  loadFailed: 'Could not read it. Refresh and try again.',
  copy: 'Copy',
}

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': zhCN, 'qps-Ploc': zhCN })) {
  i18n.addResourceBundle(locale, 'cnameLabel', messages, true, true)
}
