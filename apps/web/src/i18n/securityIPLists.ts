import i18n from './index'

// IP 名单页：WAF 规则条件“IP 名单”引用的命名名单。
const zhCN = {
  title: 'IP 名单',
  description: '在 WAF 规则里用“IP 名单”条件引用这里的名单。修改名单后，引用它的网站会自动重新发布。',
  platformHint: '平台名单由平台管理员维护，所有用户的规则都可以引用，这里只读。',
  columns: { name: '名称', description: '说明', entries: '条目数', revision: '版本', owner: '归属', updatedAt: '更新时间', actions: '操作' },
  owner: { platform: '平台', own: '本账号' },
  actions: { create: '新建名单', edit: '编辑', delete: '删除', refresh: '刷新', save: '保存', cancel: '取消' },
  form: {
    createTitle: '新建 IP 名单', editTitle: '编辑 IP 名单 {{name}}', name: '名称', description: '说明',
    entries: '地址与网段', entriesHint: '一行一个 IP 或 CIDR，# 后为注释；最多 10000 条。保存时网段按掩码对齐并去重。',
    invalidEntries: '有 {{count}} 条不是合法的 IP 或 CIDR：{{entries}}。改正后再保存。',
    entriesPlaceholder: '192.0.2.10\n198.51.100.0/24\n2001:db8::/32',
  },
  confirmDelete: '删除 IP 名单“{{name}}”？仍被安全策略引用的名单不能删除。',
  saved: '已保存名单“{{name}}”（版本 {{revision}}），引用它的网站会自动重新发布。',
  deleted: '已删除名单“{{name}}”。',
  empty: '还没有 IP 名单',
  errors: {
    failed: '操作失败，请稍后重试。', invalid: '名称、说明或条目不合法（IP/CIDR 格式、最多 10000 条）。',
    nameConflict: '已有同名的名单。', version: '名单已被其他人修改，请刷新后重试。',
    inUse: '仍有安全策略引用这个名单，先从规则里移除再删除。', limit: '名单数量已达上限。',
    notFound: '名单不存在或已删除。', permission: '没有操作权限。',
  },
}

const enUS: typeof zhCN = {
  title: 'IP lists',
  description: 'WAF rules reference these lists with the "IP list" condition. Changing a list republishes the sites that use it.',
  platformHint: 'Platform lists are maintained by platform administrators; every user\'s rules may reference them. Read only here.',
  columns: { name: 'Name', description: 'Description', entries: 'Entries', revision: 'Revision', owner: 'Owner', updatedAt: 'Updated', actions: 'Actions' },
  owner: { platform: 'Platform', own: 'This account' },
  actions: { create: 'New list', edit: 'Edit', delete: 'Delete', refresh: 'Refresh', save: 'Save', cancel: 'Cancel' },
  form: {
    createTitle: 'New IP list', editTitle: 'Edit IP list {{name}}', name: 'Name', description: 'Description',
    entries: 'Addresses and networks', entriesHint: 'One IP or CIDR per line, # starts a comment; at most 10000 entries. Networks are masked and duplicates removed on save.',
    invalidEntries: '{{count}} entries are not a valid IP or CIDR: {{entries}}. Fix them and save again.',
    entriesPlaceholder: '192.0.2.10\n198.51.100.0/24\n2001:db8::/32',
  },
  confirmDelete: 'Delete IP list "{{name}}"? A list a security policy still references cannot be deleted.',
  saved: 'Saved list "{{name}}" (revision {{revision}}); sites that use it are republished.',
  deleted: 'Deleted list "{{name}}".',
  empty: 'No IP lists yet',
  errors: {
    failed: 'The operation failed; try again later.', invalid: 'The name, description or entries are invalid (IP / CIDR, at most 10000).',
    nameConflict: 'A list with this name already exists.', version: 'The list was changed by someone else; refresh and retry.',
    inUse: 'A security policy still references this list; remove it from the rules first.', limit: 'Too many IP lists.',
    notFound: 'The list does not exist or was deleted.', permission: 'You are not allowed to do this.',
  },
}

function pseudo(value: unknown): unknown {
  return typeof value === 'string'
    ? `［${value}］`
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const securityIPListsMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }

for (const [locale, messages] of Object.entries(securityIPListsMessages)) {
  i18n.addResourceBundle(locale, 'securityIPLists', messages, true, true)
}
