// 使用文档的目录结构：侧栏分组与 /docs 首页两张入口表（按角色、按要做的事）。
// 文档正文在官网内容（运营可编辑）；这里只登记 slug 属于哪个分组、入口表指向哪里。
// 运营新增、这里没登记的 slug 显示在侧栏“其他”；入口表只列当前存在的文档。
// 分组参考底稿的七类读者，以及“安装 / 管理员 / 用户”分开的读者分层。
import type { L } from '../i18n'

export interface DocGroup { id: string; title: L; slugs: string[] }

export const DOC_GROUPS: DocGroup[] = [
  { id: 'start', title: { zh: '入门与安装', en: 'Getting started' }, slugs: ['getting-started', 'requirements', 'install-control', 'install-node'] },
  { id: 'admin', title: { zh: '主控管理', en: 'Control-plane admin' }, slugs: ['admin-sites', 'admin-users-packages', 'admin-system', 'operations'] },
  { id: 'tenant', title: { zh: '网站用户', en: 'Site users' }, slugs: ['tenant-guide'] },
  { id: 'license', title: { zh: '授权与门户', en: 'Licences & portal' }, slugs: ['license-portal', 'license-operator'] },
  { id: 'market', title: { zh: '节点市场', en: 'Node market' }, slugs: ['market-supplier', 'market-subscriber', 'market-problems'] },
  { id: 'plugins', title: { zh: '插件', en: 'Plugins' }, slugs: ['plugins'] },
  { id: 'help', title: { zh: '问题处理', en: 'Help' }, slugs: ['troubleshooting'] },
]

export function docGroupOf(slug: string): string | undefined {
  return DOC_GROUPS.find((g) => g.slugs.includes(slug))?.id
}

interface EntryRow { who: L; what: L; link: L; target: string }

const row = (who: L, what: L, link: L, target: string): EntryRow => ({ who, what, link, target })

export const DOCS_HOME = {
  rolesTitle: { zh: '按角色查阅', en: 'By role' },
  rolesHead: [{ zh: '你的角色', en: 'Your role' }, { zh: '可办理的事情', en: 'What you can do' }, { zh: '从这里开始', en: 'Start here' }],
  roles: [
    row({ zh: '客户主控管理员', en: 'Control-plane administrator' }, { zh: '安装主控和节点，管理网站、用户、套餐和系统', en: 'Install the control plane and nodes; manage sites, users, plans and settings' }, { zh: '主控安装', en: 'Install the control plane' }, '/docs/install-control'),
    row({ zh: '网站用户', en: 'Site user' }, { zh: '管理自己的网站、源站、HTTPS、缓存、防护和账户', en: 'Manage your own sites, origins, HTTPS, cache, protection and account' }, { zh: '网站用户手册', en: 'Site user guide' }, '/docs/tenant-guide'),
    row({ zh: '授权门户客户', en: 'Licence portal customer' }, { zh: '查看和续费授权、生成安装命令、充值和查看订单', en: 'View and renew licences, generate install commands, top up and check orders' }, { zh: '授权门户', en: 'Licence portal' }, '/docs/license-portal'),
    row({ zh: '平台授权运营人员', en: 'Licensing operator' }, { zh: '管理客户、授权、实名审核、收款和市场审核', en: 'Manage customers, licences, identity reviews, payments and market reviews' }, { zh: '授权运营后台', en: 'Licensing console' }, '/docs/license-operator'),
    row({ zh: '节点供货商', en: 'Node supplier' }, { zh: '申请供货、发布报价、服务买家、结算和退出', en: 'Apply, publish offers, serve buyers, settle and exit' }, { zh: '节点供货商', en: 'Node supplier' }, '/docs/market-supplier'),
    row({ zh: '节点订阅方', en: 'Node subscriber' }, { zh: '选择节点、充值购买、接入网站、查看用量与停止使用', en: 'Choose nodes, top up and buy, use them for sites, track usage and stop' }, { zh: '节点订阅方', en: 'Node subscriber' }, '/docs/market-subscriber'),
    row({ zh: '插件使用者', en: 'Plugin user' }, { zh: '获取、安装、启用、升级和停用插件', en: 'Get, install, enable, upgrade and disable plugins' }, { zh: '插件安装与使用', en: 'Plugins' }, '/docs/plugins'),
  ],
  tasksTitle: { zh: '按要做的事查阅', en: 'By task' },
  tasksHead: [{ zh: '要做什么', en: 'Task' }, { zh: '由谁操作', en: 'Who' }, { zh: '从这里开始', en: 'Start here' }],
  tasks: [
    row({ zh: '第一次安装主控', en: 'Install the control plane for the first time' }, { zh: '主控管理员', en: 'Administrator' }, { zh: '主控安装', en: 'Install the control plane' }, '/docs/install-control'),
    row({ zh: '安装自己的节点并上线', en: 'Install your own node and bring it online' }, { zh: '主控管理员', en: 'Administrator' }, { zh: '节点安装', en: 'Install a node' }, '/docs/install-node'),
    row({ zh: '把网站接入平台', en: 'Put a site on the platform' }, { zh: '主控管理员', en: 'Administrator' }, { zh: '添加网站与域名接入', en: 'Add a site and point the domain' }, '/docs/admin-sites#add-site'),
    row({ zh: '网站更新后仍看到旧内容', en: 'Visitors still see old content' }, { zh: '网站用户', en: 'Site user' }, { zh: '刷新与预热', en: 'Purge and prewarm' }, '/docs/tenant-guide#cache'),
    row({ zh: '更换网站源站', en: 'Change the origin' }, { zh: '网站用户', en: 'Site user' }, { zh: '修改源站', en: 'Change the origin' }, '/docs/tenant-guide#origin'),
    row({ zh: 'HTTPS 打不开或证书快到期', en: 'HTTPS fails or the certificate is expiring' }, { zh: '网站用户', en: 'Site user' }, { zh: 'HTTPS 与证书', en: 'HTTPS and certificates' }, '/docs/tenant-guide#https'),
    row({ zh: '正常访问被防护拦截', en: 'Legitimate requests are blocked' }, { zh: '网站用户', en: 'Site user' }, { zh: '处理误拦截', en: 'Handle false positives' }, '/docs/tenant-guide#security'),
    row({ zh: '查看用量、账单或套餐到期', en: 'Check usage, bills or plan expiry' }, { zh: '网站用户', en: 'Site user' }, { zh: '套餐与账单', en: 'Plans and billing' }, '/docs/tenant-guide#billing'),
    row({ zh: '添加用户、套餐或代理商', en: 'Add users, plans or resellers' }, { zh: '主控管理员', en: 'Administrator' }, { zh: '用户、套餐与代理商', en: 'Users, plans and resellers' }, '/docs/admin-users-packages'),
    row({ zh: '重启、升级、备份或迁移主控', en: 'Restart, upgrade, back up or migrate' }, { zh: '主控管理员', en: 'Administrator' }, { zh: '重启、升级、卸载与迁移', en: 'Operations' }, '/docs/operations'),
    row({ zh: '申请出售自己的节点', en: 'Sell your own nodes' }, { zh: '节点供货商', en: 'Supplier' }, { zh: '节点供货商', en: 'Node supplier' }, '/docs/market-supplier'),
    row({ zh: '为自己的主控订阅节点', en: 'Subscribe to nodes for your control plane' }, { zh: '节点订阅方', en: 'Subscriber' }, { zh: '节点订阅方', en: 'Node subscriber' }, '/docs/market-subscriber'),
    row({ zh: '多级转售中上游节点或余额异常', en: 'Upstream nodes or balances fail in a resale chain' }, { zh: '供货商、订阅方', en: 'Supplier, subscriber' }, { zh: '节点市场问题处理', en: 'Node market problems' }, '/docs/market-problems'),
    row({ zh: '给主控安装插件', en: 'Install a plugin' }, { zh: '主控管理员、网站用户', en: 'Administrator, site user' }, { zh: '插件安装与使用', en: 'Plugins' }, '/docs/plugins'),
    row({ zh: '安装或运行出错', en: 'Something failed' }, { zh: '主控管理员', en: 'Administrator' }, { zh: '问题处理', en: 'Troubleshooting' }, '/docs/troubleshooting'),
  ],
  footer: {
    zh: '找不到相应菜单时，先确认当前进入的是哪个平台、登录的是管理员还是普通用户（见[先分清入口和账号](/docs/getting-started#entries)）。授权和购买问题联系平台；主控资源问题联系本主控管理员；节点问题先联系直接供货方；插件问题联系主控管理员或插件提供者。插件开发见开发者平台。',
    en: 'If a menu is missing, first check which platform you are in and whether you signed in as an administrator or a regular user (see [Entry points and accounts](/docs/getting-started#entries)). Licence and purchase questions go to the platform; control-plane resources to your administrator; nodes to your direct supplier; plugins to your administrator or the plugin provider. Plugin development is covered on the developer platform.',
  },
  allTitle: { zh: '全部文档', en: 'All documents' },
}
