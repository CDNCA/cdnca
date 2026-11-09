import i18n from './index'

// NodeStaleConfigurationTag 的中英词条（i18nSafety：界面文案放在 i18n 模块，不写在组件里）。
const zhCN = {
  tag: '旧配置仍生效',
  title: '该节点仍在使用旧配置',
  reason: '租户 {{tenant}} 的第 {{revision}} 版发布（{{time}}）未下发到该节点：节点版本过旧（未声明能力 82 SITE_SELECTION），本次密钥文档超出其上限。',
  effect: '本次及之后新屏蔽的站点、删除的转发在该节点上仍然生效，直到它拿到新版本。',
  remedy: '处理：把节点升级到支持能力 82 的版本，升级后系统自动补发。',
  platform: '平台',
}
const enUS: typeof zhCN = {
  tag: 'Old configuration in effect',
  title: 'The node still runs an old configuration',
  reason: 'Release {{revision}} of tenant {{tenant}} ({{time}}) did not reach this node: its Agent predates capability 82 (SITE_SELECTION) and the key document is larger than it takes.',
  effect: 'Websites withheld and forwards deleted since then still serve on this node until it gets a later release.',
  remedy: 'Upgrade the node to a version with capability 82; the release is then redelivered automatically.',
  platform: 'platform',
}
for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': zhCN, 'qps-Ploc': zhCN })) {
  i18n.addResourceBundle(locale, 'nodeStaleConfiguration', messages, true, true)
}
