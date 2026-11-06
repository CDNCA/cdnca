import i18n from './index'

// 节点市场订阅两端对账用的订阅短号（订阅编号前 8 位）：买家「已购供给」、卖家「订阅者」列表与卖家网站列表里的受限账号名都带它。
const zhCN = {
  subscriptionCode: '订阅短号 {{code}}',
  subscriptionCodeHelp: '订阅短号是这条订阅在市场上的编号前 8 位，固定不变；卖家「订阅者」列表与卖家网站列表里的「市场订阅 · … · {{code}}」就是这条订阅，报这个号即可对上。',
  sellerTenant: '这是节点市场订阅方在本主控的受限账号。「市场订阅 · 供给组名 · 订阅短号」：供给组名是你上架时起的名字；订阅短号是买家订阅编号的前 8 位（转售来的订阅为市场给的 d- 开头编号），是确定值不是随机值，同一订阅永远一样，与「订阅者」列表里的短号一致。买家身份不在这里显示。',
  subscriberCode: '订阅短号',
  subscriberCodeDownstream: '同订阅方编号',
  subscriberCodeHelp: '订阅编号的前 8 位（转售来的为市场给的 d- 编号），固定不变。你网站列表里该订阅方的用户名「市场订阅 · … · 短号」与这里一致；买家在「已购供给」看到的也是这个号。',
}
type Messages = typeof zhCN

const enUS: Messages = {
  subscriptionCode: 'Subscription {{code}}',
  subscriptionCodeHelp: 'The first 8 characters of this subscription’s market id; it never changes. The seller’s Subscribers list and site list show “市场订阅 · … · {{code}}” for this subscription.',
  sellerTenant: 'The restricted account of a node-market subscriber on this controller. “市场订阅 · supply group · code”: the supply group is the name you listed it under; the code is the first 8 characters of the buyer’s subscription id (a resold subscription gets the market’s d- reference). It is fixed, not random, and matches the Subscribers list. The buyer’s identity is not shown here.',
  subscriberCode: 'Code',
  subscriberCodeDownstream: 'The subscriber reference',
  subscriberCodeHelp: 'First 8 characters of the subscription id (the market’s d- reference for a resold one); it never changes. The subscriber’s user on your site list, “市场订阅 · … · code”, carries the same code, and so does the buyer’s purchased supply.',
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value} · ${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}
const pseudoCN = pseudoTree(zhCN) as Messages

export const marketNamesMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudoCN, 'qps-Ploc': pseudoCN }

for (const [locale, messages] of Object.entries(marketNamesMessages)) {
  i18n.addResourceBundle(locale, 'marketNames', messages, true, true)
}
