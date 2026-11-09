import i18n from './index'

// PublicationLeftOutNodesAlert 的中英词条（i18nSafety：界面文案放在 i18n 模块，不写在组件里）。
const zhCN = {
  title: '部分节点未按本次发布生效',
  oversized: '{{count}} 台节点仍在用旧配置，本次新屏蔽的站点、删除的转发在这些节点上仍然生效，请升级到支持能力 82 的节点版本，升级后自动补发',
  unsupported: '{{count}} 台节点不支持按节点屏蔽站点（未声明能力 82），仍会收到并服务该租户的全部站点，请升级到支持能力 82 的节点版本',
  nodes: '节点：{{nodes}}',
  tag: '{{count}} 台仍用旧配置',
  unsupportedTag: '{{count}} 台不支持按节点屏蔽',
}
const enUS: typeof zhCN = {
  title: 'Some nodes did not take this release as intended',
  oversized: '{{count}} nodes still run the old configuration: websites withheld and forwards deleted by this release still serve there. Upgrade them to a version with capability 82; the release is then redelivered automatically',
  unsupported: '{{count}} nodes cannot withhold websites per node (no capability 82) and still receive and serve every website of the tenant. Upgrade them to a version with capability 82',
  nodes: 'Nodes: {{nodes}}',
  tag: '{{count}} on the old configuration',
  unsupportedTag: '{{count}} cannot withhold websites',
}
for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': zhCN, 'qps-Ploc': zhCN })) {
  i18n.addResourceBundle(locale, 'sitePublicationLeftOutNodes', messages, true, true)
}
