import i18n from './index'

// WAF 规则库编辑器里的快速屏蔽系统规则说明（G3-d #13）。
// regionNotice：WAF 规则页的区域屏蔽入口（wafgeo-check 删掉了不下发的独立地区策略面板）。
const zhCN = {
  quickBlock: {
    regionNotice: '按国家/地区屏蔽：在下方 WAF 规则库里新增规则，条件字段选「国家」，国家由节点 IP 情报库判定。',
    editorNotice: '本规则库开启了快速屏蔽，对应的系统规则排在最前面、不在这里显示；请到站点“防护”页的“规则库快速屏蔽（默认值）”卡片里修改。各站点还可以在“本站快速屏蔽”里逐项跟随、开启或关闭，只影响该站点。',
  },
  errors: {
    quick_block_site_override_conflict: '有站点单独设置了快速屏蔽，这次修改后这些站点的设置无法生效。请先把这些站点的对应项改回“跟随规则库”，或调整本次修改。',
  },
}

const enUS: typeof zhCN = {
  quickBlock: {
    regionNotice: 'To block by country/region, add a rule to a WAF rule library below with a Country condition. Nodes resolve the country with the IP intelligence library.',
    editorNotice: 'This library has a quick block. Its system rules run first and are not shown here; change them on the site protection page ("Rule library quick block (defaults)" card). Each site can also follow, turn on or turn off each item under "This site\'s quick block", for that site only.',
  },
  errors: {
    quick_block_site_override_conflict: 'Some sites have their own quick block settings that would no longer apply after this change. Set those items back to "Follow the rule library" on those sites, or adjust this change.',
  },
}

const bracket = (messages: Record<string, string>) => Object.fromEntries(Object.entries(messages).map(([key, value]) => [key, `［${value}］`]))
const pseudo = { quickBlock: bracket(zhCN.quickBlock), errors: bracket(zhCN.errors) }

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo, 'qps-Ploc': pseudo })) {
  i18n.addResourceBundle(locale, 'securityPolicies', messages, true, true)
}
