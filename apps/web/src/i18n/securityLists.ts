import i18n from './index'

// 列表与对象：IP 名单与字符串集合两个标签页。
const zhCN = {
  title: '列表与对象',
  description: '被 WAF 规则引用的命名集合。改动后，引用它的网站自动重新发布。',
  platformHint: '平台集合由平台管理员维护，所有用户的规则都可以引用，这里只读。',
  tabs: { ip: 'IP 名单', strings: '字符串集合' },
  add: '字符串集合', addIP: 'IP 名单',
  columns: { name: '名称', mode: '匹配方式', case: '大小写', members: '成员数', usedBy: '被引用', updatedAt: '更新时间', actions: '操作' },
  mode: { all: '全部匹配方式', exact: '完全相等', prefix: '前缀', suffix: '后缀', contains: '包含', wildcard: '通配符' },
  modeExample: { exact: '值与某个成员完全相同，例：/admin', prefix: '值以某个成员开头，例：/api/ 命中 /api/v1', suffix: '值以某个成员结尾，例：.php',
    contains: '值里含有某个成员，例：sqlmap', wildcard: '* 任意多个字符，? 一个字节，例：/api/*/users' },
  case: { sensitive: '区分', insensitive: '不区分' },
  platform: '平台',
  usedBy: '{{count}} 条策略',
  usedByNone: '未被引用',
  deleteDisabled: '被 {{count}} 条策略引用，先在规则里去掉对它的引用',
  search: '搜索名称',
  actions: { edit: '编辑', view: '查看', delete: '删除', save: '保存', cancel: '取消', retry: '重试', reload: '重新加载', viewReferences: '查看引用', gotIt: '知道了', openPolicy: '打开策略' },
  confirmDelete: '删除字符串集合“{{name}}”？',
  saved: '已保存字符串集合“{{name}}”（版本 {{revision}}），引用它的网站会自动重新发布。',
  deleted: '已删除字符串集合“{{name}}”。',
  form: {
    createTitle: '添加字符串集合', editTitle: '编辑字符串集合 {{name}}', viewTitle: '查看字符串集合 {{name}}',
    name: '名称', description: '描述', mode: '匹配方式', modeLocked: '创建后不能修改。要换匹配方式，请新建一份集合',
    prefixHint: '前缀按字符比较：成员 /api 也会命中 /apiary，只想匹配目录请写 /api/',
    wildcardHint: '* 匹配任意多个字符，? 匹配一个字节（不是一个汉字）',
    caseSensitive: '区分大小写', caseHint: 'User-Agent、Referer 这类大小写不固定的值建议关闭',
    caseInsensitiveHint: '不区分时只把 A–Z 转成小写，其他字母原样比较',
    members: '成员（每行一个）', counter: '{{n}} 条 / {{max}} · {{size}} / 256 KiB',
    normalizeHint: '保存时会去掉首尾空格、去重并排序。要停用一份白名单，请停用规则，不要清空集合。',
    moreProblems: '还有 {{count}} 处',
  },
  lineReason: {
    too_long: '超过 512 字节', invalid_utf8: '不是合法的 UTF-8 文本', control_character: '含有控制字符',
    wildcard_too_many_stars: '通配符最多 3 个 *', wildcard_only_wildcards: '不能只有 * 和 ?', empty: '是空行',
  },
  setReason: { too_many_entries: '成员数超出上限（通配符最多 2000 条，其他最多 10000 条）', too_large: '成员合计超过 256 KiB', none: '至少要有一个成员' },
  empty: { title: '还没有字符串集合', body: '把多条规则共用的 UA、路径、域名放进一份集合，改一处所有规则生效。' },
  references: { title: '引用「{{name}}」的策略', policy: '策略名称', kind: '类型', rules: '规则数', empty: '没有策略引用它' },
  errors: {
    load: '加载失败', failed: '操作失败，请稍后重试。', inUse: '无法删除：仍有 {{count}} 条策略引用它',
    nameConflict: '已有同名集合', version: '这份集合已被其他人修改', versionDetail: '重新加载会丢弃这里未保存的修改。',
    limit: '每个账号最多 200 份字符串集合', notFound: '集合不存在或已删除。', permission: '没有操作权限。', line: '第 {{line}} 行：{{reason}}',
  },
}

const enUS: typeof zhCN = {
  title: 'Lists and objects',
  description: 'Named sets that WAF rules reference. Sites that use a set are republished automatically when it changes.',
  platformHint: 'Platform sets are maintained by platform administrators; every user\'s rules may reference them. Read only here.',
  tabs: { ip: 'IP lists', strings: 'String sets' },
  add: 'string set', addIP: 'IP list',
  columns: { name: 'Name', mode: 'Match', case: 'Case', members: 'Members', usedBy: 'Used by', updatedAt: 'Updated', actions: 'Actions' },
  mode: { all: 'All match modes', exact: 'Exact', prefix: 'Prefix', suffix: 'Suffix', contains: 'Contains', wildcard: 'Wildcard' },
  modeExample: { exact: 'The value equals a member, e.g. /admin', prefix: 'The value starts with a member, e.g. /api/ matches /api/v1',
    suffix: 'The value ends with a member, e.g. .php', contains: 'The value contains a member, e.g. sqlmap',
    wildcard: '* any characters, ? one byte, e.g. /api/*/users' },
  case: { sensitive: 'Case-sensitive', insensitive: 'Case-insensitive' },
  platform: 'Platform',
  usedBy: '{{count}} policies',
  usedByNone: 'Not used',
  deleteDisabled: 'Used by {{count}} policies. Remove it from those rules first.',
  search: 'Search by name',
  actions: { edit: 'Edit', view: 'View', delete: 'Delete', save: 'Save', cancel: 'Cancel', retry: 'Retry', reload: 'Reload', viewReferences: 'View references', gotIt: 'Got it', openPolicy: 'Open policy' },
  confirmDelete: 'Delete string set "{{name}}"?',
  saved: 'Saved string set "{{name}}" (revision {{revision}}); sites that use it are republished.',
  deleted: 'Deleted string set "{{name}}".',
  form: {
    createTitle: 'Add string set', editTitle: 'Edit string set {{name}}', viewTitle: 'String set {{name}}',
    name: 'Name', description: 'Description', mode: 'Match mode', modeLocked: 'Cannot be changed after creation. Create a new set to use another match mode.',
    prefixHint: 'Prefix matching compares characters: /api also matches /apiary. Write /api/ to match only the directory.',
    wildcardHint: '* matches any characters; ? matches one byte (not one CJK character).',
    caseSensitive: 'Case-sensitive', caseHint: 'Turn off for values with inconsistent case, such as User-Agent and Referer.',
    caseInsensitiveHint: 'Only A–Z are lower-cased; other letters compare as they are.',
    members: 'Members (one per line)', counter: '{{n}} / {{max}} · {{size}} / 256 KiB',
    normalizeHint: 'Leading and trailing spaces are removed, and duplicates are dropped and sorted on save. To turn an allow list off, disable the rule instead of emptying the set.',
    moreProblems: '{{count}} more',
  },
  lineReason: {
    too_long: 'longer than 512 bytes', invalid_utf8: 'not valid UTF-8 text', control_character: 'contains a control character',
    wildcard_too_many_stars: 'at most 3 * in a wildcard', wildcard_only_wildcards: 'cannot be only * and ?', empty: 'empty line',
  },
  setReason: { too_many_entries: 'Too many members (at most 2000 for wildcard sets, 10000 otherwise).', too_large: 'Members exceed 256 KiB together.', none: 'Add at least one member.' },
  empty: { title: 'No string sets yet', body: 'Put the user agents, paths and hosts that several rules share in one set. Edit it once and every rule follows.' },
  references: { title: 'Policies that use "{{name}}"', policy: 'Policy', kind: 'Type', rules: 'Rules', empty: 'No policy uses it.' },
  errors: {
    load: 'Failed to load', failed: 'The operation failed; try again later.', inUse: 'Cannot delete: {{count}} policies still use it.',
    nameConflict: 'A set with this name already exists.', version: 'This set was changed by someone else', versionDetail: 'Reloading discards your unsaved changes here.',
    limit: 'Each account can have at most 200 string sets.', notFound: 'The set does not exist or was deleted.', permission: 'You are not allowed to do this.', line: 'Line {{line}}: {{reason}}',
  },
}

function pseudo(value: unknown): unknown {
  return typeof value === 'string'
    ? `［${value}］`
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const securityListsMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }

for (const [locale, messages] of Object.entries(securityListsMessages)) {
  i18n.addResourceBundle(locale, 'securityLists', messages, true, true)
}
