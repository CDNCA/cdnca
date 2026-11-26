import i18n from './index'

// refusals the scope's own facts decide end
// the automatic request instead of retrying (edgeautopublish terminal codes).
const zhCN = {
  package_subscription_inactive: '套餐订阅未生效：同一用户有网站或转发仍绑定未生效的套餐订阅（如已取消）。续费、换绑套餐，或停用、删除它们后会自动重新发布。',
  package_resource_quota_exceeded: '超出套餐额度：网站或转发的域名、端口数量超出了所绑套餐的额度。升级套餐或减少资源后会自动重新发布。',
  package_feature_denied: '套餐不含所用功能：同一用户有网站使用了所绑套餐不含的功能。升级套餐或关闭该功能后会自动重新发布。',
  entitlement_feature_denied: '授权不含所需模块：配置用到了当前授权不含的模块。重新获得授权或去掉相关配置后会自动重新发布。',
  site_l2_unavailable: '网站自定义 L2 没有节点：同一用户有网站的 L2 配置里没有本次发布的节点。调整后会自动重新发布。',
  rule_pack_out_of_profile: '规则包超出 CRS 档位：同一用户有网站挂载的规则包超出了它的 CRS 防护档位。调整后会自动重新发布。',
  sdk_shield_port_shared: 'SDK 盾端口被共用：SDK 盾转发的端口与其他转发或网站共用。调整端口后会自动重新发布。',
}

const enUS: typeof zhCN = {
  package_subscription_inactive: 'Package subscription not in effect: a site or forward of the same user is still bound to a package subscription not in effect (such as a cancelled one). It is republished automatically after a renewal or package change, or once they are disabled or deleted.',
  package_resource_quota_exceeded: 'Over the package quota: the domains or ports of the sites or forwards exceed their package quota. It is republished automatically after an upgrade or once resources are removed.',
  package_feature_denied: 'The package lacks a feature in use: a site of the same user uses a feature its package does not include. It is republished automatically after an upgrade or once the feature is turned off.',
  entitlement_feature_denied: 'The entitlement lacks a module: the configuration uses a module the current entitlement does not grant. It is republished automatically once the module is granted again or the setting is removed.',
  site_l2_unavailable: "A site's custom L2 has no node: a site of the same user has an L2 configuration without a node in this publication. It is republished automatically once that is changed.",
  rule_pack_out_of_profile: "A rule pack is outside the CRS profile: a site of the same user mounts a rule pack outside its CRS profile. It is republished automatically once that is changed.",
  sdk_shield_port_shared: 'SDK shield port shared: an SDK shield forward shares its port with another forward or site. It is republished automatically once the port is changed.',
}

for (const [locale, failures] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': zhCN, 'qps-Ploc': zhCN })) {
  i18n.addResourceBundle(locale, 'streams', { publication: { failures } }, true, true)
}
