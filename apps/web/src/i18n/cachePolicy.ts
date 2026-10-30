import i18n from './index'

export type CachePolicyMessageTree = { [key: string]: string | CachePolicyMessageTree }
type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }

const zhCN = {
  title: '缓存规则',
  count: '{{count}} 条',
  quick: { home: '首页缓存', site: '全站缓存', static: '静态资源缓存', video: '视频文件缓存', wordpress: 'Wordpress缓存' },
  // 新增缓存规则 dialog
  dialog: {
    addTitle: '新增缓存规则', editTitle: '编辑缓存规则', basic: '基础规则', scope: '缓存范围', expire: '有效期', expireUnit: '有效期单位',
    strategy: '缓存策略', advanced: '高级设置', ok: '确定', cancel: '取消', more: '更多匹配条件',
    ignoreQuery: '忽略 URL 参数', ignoreQueryDesc: '同一路径不同参数共用缓存。',
    ignoreQueryHelp: '开启后 ?a=1 和 ?a=2 读到同一份缓存；关闭时按「其他设置」里的查询参数方式。',
    forceCache: '强制 CDN 缓存', forceCacheDesc: '忽略源站缓存头，按 CDN 规则缓存。',
    forceCacheHelp: '开启后忽略源站的 Cache-Control/Expires，按这里的有效期缓存；关闭时源站缓存头优先，有效期作兜底。源站标 private/no-store 或带 Set-Cookie 的响应始终不缓存。',
    slice: '分片回源', sliceDesc: '大文件按 1M 分片回源并缓存。',
    ignoreVary: '忽略 Vary', ignoreVaryDesc: '不把源站 Vary 响应头加入缓存 Key。',
    noCache: '不缓存条件', noCacheCount: '{{count}} 条', noCacheDesc: '命中这些条件的请求不会读取或写入缓存。',
    noCacheEmpty: '暂无不缓存条件', noCacheSource: '请选择匹配项', noCachePattern: '请输入匹配值，支持正则表达式',
    noCacheHeader: '请求头名称，如 cookie', addCondition: '添加', removeCondition: '删除条件',
    scopes: { home: '首页', site: '全站', dir: '目录', suffix: '后缀', path: '单个路径' },
    scopeInput: { dir: '目录，如 /static/', suffix: '后缀，用 | 分隔，如 jpg|png|css', path: '路径，如 /index.html' },
    presets: { m10: '10分钟', h1: '1小时', d1: '1天', d7: '7天', d30: '30天' },
    units: { d: '天', h: '时', s: '秒' },
    sources: { uri: '请求URI', path: '请求URI(不带参数)', client_ip: '客户IP地址', scheme: '请求协议', args: '请求参数', host: '域名', header: '自定义' },
  },
  table: {
    scope: '缓存范围', expire: '有效期', options: '缓存策略', actions: '操作', edit: '编辑',
    none: '—', noCacheRule: '不缓存',
    flags: { ignoreQuery: '忽略参数', forceCache: '强制缓存', noForce: '遵循源站缓存头', slice: '分片', ignoreVary: '忽略 Vary', noCache: '不缓存条件 {{count}}' },
  },
  empty: {
    title: '暂无缓存规则', add: '新增第一条规则',
    description: '当前为“{{mode}}”。可以新增规则，或使用快速设置生成常用缓存策略。',
  },
  other: { title: '其他设置', description: '缓存模式、缓存键参数、响应头缓存状态和节点存储。' },
  actions: {
    save: '保存策略', refresh: '刷新', retry: '重试', reload: '重新加载', compare: '对比差异',
    retryAfterReload: '重新加载后重试', history: '修订历史', previous: '上一页', next: '下一页',
    addRule: '添加规则', removeRule: '删除规则', moveUp: '上移', moveDown: '下移',
    showAdvanced: '展开高级设置', hideAdvanced: '收起高级设置', cancel: '取消', quick: '快速设置缓存',
  },
  help: {
    staleIfError: '源站出错、超时或返回 500/502/503/504 时，继续返回已过期但仍在磁盘上的缓存（最多保留 24 小时）。',
    backgroundUpdate: '缓存过期后先返回旧内容，同时由一个请求在后台向源站更新（需先开启源站故障用旧缓存）。',
    objectBytes: '只缓存大小在下限与上限之间的响应（按 Content-Length，0 表示不限）；防止单个超大文件挤掉整个站点的缓存。',
    varyHeaders: '源站按这些请求头返回不同内容时（如按语言、按手机/电脑出不同页面）选上，节点为每种取值各存一份缓存，访客拿到对应版本。不选时同一地址所有访客共用一份。取值种类越多命中率越低，User-Agent 几乎每个浏览器都不同，慎选。Cookie、Authorization 不可选。',
    diskQuota: '本站点在每个节点上最多占用的缓存空间，满了按最久未访问淘汰。启用缓存时必须在 {{min}} 到 {{max}} 之间（不支持不限）。',
    sliceBytes: '大文件（视频、下载）按此大小分片缓存，拖动进度或断点续传只回源缺少的分片。',
    browserTtl: '响应给浏览器的缓存时长，不能超过边缘缓存有效期；0 表示不改源站的浏览器缓存头。',
    browserTtlOff: '沿用源站',
    noCache: '匹配的请求不在边缘缓存，并告诉浏览器不要缓存。',
  },
  slice: { off: '不分片', size: '每片 {{size}}' },
  statusHeader: {
    label: '响应头显示缓存状态（X-CDN-Cache）',
    help: '便于在浏览器或 curl 中确认缓存是否生效；攻击升级到 B 级及以上时自动隐藏',
    saved: '已保存响应头显示缓存状态', saveFailed: '响应头显示缓存状态保存失败',
    errors: {
      version_conflict: '网站配置已被其他操作修改，请刷新页面后重试。', site_locked: '网站已被锁定，不能修改。',
      permission_denied: '当前账号缺少网站管理权限。', request_failed: '保存失败，请稍后重试。',
    },
  },
  flush: {
    title: '清空全部缓存', action: '清空全部缓存',
    description: '在承载该站点的所有节点上清理它的全部缓存（创建一条整站清理任务，进度见“刷新预热”）。修改 WAF、证书等其他设置不会清空缓存。',
    confirm: '确认清空该站点在所有节点上的全部缓存？之后的请求都会回源。',
    done: '已提交整站清理任务，可在“刷新预热”查看进度。',
  },
  states: {
    loading: '缓存策略加载中', empty: '当前站点尚未发布缓存策略。', loadError: '缓存策略加载失败。',
    forbiddenTitle: '无权访问缓存设置', forbiddenDescription: '当前账号缺少站点查看权限。',
    readOnly: '当前账号只有查看权限。', unchanged: '策略未修改', saving: '正在保存策略', saved: '缓存策略已保存',
    conflictTitle: '策略修订已变化', conflictDescription: '服务器策略已更新。请重新加载并对比后再重试。',
  },
  modes: { disabled: '停用缓存', follow_origin: '遵循源站', override: '自定义规则' },
  modeHelp: {
    disabled: '不在边缘存储响应内容。',
    follow_origin: '按源站响应中的缓存指令执行边缘缓存。',
    override: '按下方规则顺序设置边缘缓存有效期。',
  },
  fields: {
    mode: '缓存模式', rules: '缓存规则', order: '顺序', match: '匹配条件', extensions: '文件扩展名',
    pathPrefix: '路径前缀', statusCodes: '状态码', ttlSeconds: '边缘缓存有效期', queryMode: '查询参数',
    queryNames: '查询参数名称', varyHeaders: '按请求头区分缓存', diskQuotaBytes: '磁盘配额（每个节点）',
    staleIfError: '源站故障时使用旧缓存', backgroundUpdate: '后台更新过期缓存', minObjectBytes: '单个对象最小',
    maxObjectBytes: '单个对象最大', sliceBytes: '分片缓存',
    pathRegex: '路径正则', contentTypes: '响应内容类型',
    action: '动作', browserTtlSeconds: '浏览器缓存有效期',
  },
  ruleActions: { cache: '缓存', no_cache: '不缓存' },
  placeholders: { pathRegex: '例如 ^/static/.+\\.(?:css|js)$', contentTypes: '例如 image/*, text/css', varyHeaders: '不区分（所有访客共用一份缓存）；可选常用请求头或直接输入' },
  queryModes: { preserve: '保留全部参数', ignore: '忽略全部参数', include: '仅保留指定参数', exclude: '排除指定参数' },
  matchTypes: { all: '全部请求', extensions: '扩展名', pathPrefix: '路径前缀', statusCodes: '响应状态码' },
  advanced: { title: '高级设置', description: '按请求头区分缓存、节点磁盘配额与可缓存的文件大小。' },
  varyHeaderOptions: {
    'accept-encoding': 'Accept-Encoding（压缩格式）', 'accept-language': 'Accept-Language（语言）', 'user-agent': 'User-Agent（浏览器/设备，命中率会大幅下降）',
    accept: 'Accept（内容类型，如 WebP）', origin: 'Origin（跨域来源）', 'sec-ch-ua-mobile': 'Sec-CH-UA-Mobile（是否手机）',
  },
  history: {
    title: '策略修订历史', empty: '暂无历史修订。', revision: '修订', createdAt: '发布时间',
    createdBy: '发布用户', requestId: '请求 ID', view: '查看', detailError: '历史修订加载失败。',
  },
  comparison: { title: '修订差异', base: '编辑基准', latest: '最新策略', draft: '当前草稿' },
  confirm: {
    overwriteLatest: '确认以当前草稿覆盖最新策略？',
    refreshDiscard: '确认重新加载最新策略并放弃当前草稿？',
  },
  validation: {
    required: '此字段不能为空。', ruleRequired: '自定义规则模式至少需要一条规则。',
    ttlRange: '有效期必须是 1 到 31536000 秒。', quotaRange: '启用缓存时磁盘配额必须在 {{min}} 到 {{max}} 之间。',
    queryNamesRequired: '当前查询参数模式至少需要一个参数名称。', queryNamesForbidden: '当前查询参数模式不能填写参数名称。',
    duplicate: '不能包含重复值。', invalidExtension: '扩展名必须以点开头，并使用小写字母或数字。',
    invalidPath: '路径前缀必须以斜杠开头（如 /api，保存时自动补成 /api/），不能含 //、?、#、% 或反斜杠，也不能有 . 或 .. 路径段。', invalidStatus: '状态码必须在 100 到 599 之间。',
    invalidHeader: '请输入有效且允许参与 Vary 的请求头名称。', overlap: '缓存规则的匹配范围不能重叠。',
    invalidExtensions: '对象大小下限必须小于上限；后台更新需先开启源站故障用旧缓存；停用缓存时不能开启这些选项。',
    invalidPathRegex: '路径正则无效或超过 256 个字符。', invalidContentTypes: '内容类型须为 类型/子类型 或以 * 结尾的前缀，最多 16 个。',
    tooManyConditionalRules: '带路径正则或内容类型的规则最多 {{max}} 条。',
    browserTtlRange: '浏览器缓存有效期必须在 0 到边缘缓存有效期之间。',
    invalidExactPath: '单个路径须以 / 开头，不能含 ?、#、%、空格、// 或 . / .. 路径段。',
    invalidCondition: '不缓存条件须选择匹配项并填写有效的正则（最长 256 字符）；自定义需填写请求头名称。',
    tooManyConditions: '每条规则最多 {{max}} 个不缓存条件。',
  },
  errors: {
    network_error: '无法连接服务，请稍后重试。', invalid_response: '服务响应无效，请刷新确认当前状态。',
    permission_denied: '当前账号缺少缓存策略权限。', revision_conflict: '策略修订已变化，请重新加载后重试。',
    idempotency_conflict: '该幂等键已用于不同请求，请刷新后重新提交。', validation_error: '缓存策略无效，请检查输入。',
    invalid_request: '缓存策略请求无效，请检查输入。', not_found: '未找到该站点或缓存策略。',
    service_unavailable: '缓存策略服务暂不可用，请稍后重试。', request_failed: '缓存策略请求失败，请稍后重试。',
  },
  units: { seconds: '秒', bytes: '字节', mib: 'MiB', gib: 'GiB', tib: 'TiB', kb: 'KB', mb: 'MB', gb: 'GB', tb: 'TB', unitOf: '{{field}}单位' },
} as const

const enUS = {
  title: 'Cache rules',
  count: '{{count}}',
  quick: { home: 'Home page', site: 'Whole site', static: 'Static assets', video: 'Video files', wordpress: 'WordPress' },
  dialog: {
    addTitle: 'Add cache rule', editTitle: 'Edit cache rule', basic: 'Basic rule', scope: 'Cache scope', expire: 'Lifetime', expireUnit: 'Lifetime unit',
    strategy: 'Cache strategy', advanced: 'Advanced settings', ok: 'OK', cancel: 'Cancel', more: 'More match conditions',
    ignoreQuery: 'Ignore URL parameters', ignoreQueryDesc: 'One cached copy for a path whatever its parameters.',
    ignoreQueryHelp: 'On: ?a=1 and ?a=2 read the same copy. Off: the query parameter setting under Other settings applies.',
    forceCache: 'Force CDN caching', forceCacheDesc: 'Ignore origin cache headers and cache by the CDN rule.',
    forceCacheHelp: 'On: the origin Cache-Control/Expires are ignored and this lifetime applies. Off: origin cache headers win, the lifetime is the fallback. Responses marked private/no-store or setting a cookie are never cached.',
    slice: 'Ranged origin fetch', sliceDesc: 'Large files are fetched and cached in 1M slices.',
    ignoreVary: 'Ignore Vary', ignoreVaryDesc: 'The origin Vary header does not split the cache key.',
    noCache: 'No-cache conditions', noCacheCount: '{{count}}', noCacheDesc: 'Requests matching any of these are neither read from nor written to the cache.',
    noCacheEmpty: 'No no-cache conditions', noCacheSource: 'Select a field', noCachePattern: 'Value to match, regular expressions allowed',
    noCacheHeader: 'Request header name, e.g. cookie', addCondition: 'Add', removeCondition: 'Remove condition',
    scopes: { home: 'Home page', site: 'Whole site', dir: 'Directory', suffix: 'Suffix', path: 'Single path' },
    scopeInput: { dir: 'Directory, e.g. /static/', suffix: 'Suffixes separated by |, e.g. jpg|png|css', path: 'Path, e.g. /index.html' },
    presets: { m10: '10 min', h1: '1 hour', d1: '1 day', d7: '7 days', d30: '30 days' },
    units: { d: 'days', h: 'hours', s: 'seconds' },
    sources: { uri: 'Request URI', path: 'Request URI (no query)', client_ip: 'Client IP', scheme: 'Scheme', args: 'Query string', host: 'Host', header: 'Custom header' },
  },
  table: {
    scope: 'Scope', expire: 'Lifetime', options: 'Strategy', actions: 'Actions', edit: 'Edit',
    none: '—', noCacheRule: 'Do not cache',
    flags: { ignoreQuery: 'Ignore query', forceCache: 'Forced', noForce: 'Origin headers first', slice: 'Sliced', ignoreVary: 'Ignore Vary', noCache: 'No-cache conditions {{count}}' },
  },
  empty: {
    title: 'No cache rules', add: 'Add the first rule',
    description: 'Mode: {{mode}}. Add a rule, or use a quick preset for common caching.',
  },
  other: { title: 'Other settings', description: 'Cache mode, cache key parameters, cache status header and node storage.' },
  actions: {
    save: 'Save policy', refresh: 'Refresh', retry: 'Retry', reload: 'Reload', compare: 'Compare changes',
    retryAfterReload: 'Reload and retry', history: 'Revision history', previous: 'Previous', next: 'Next',
    addRule: 'Add rule', removeRule: 'Remove rule', moveUp: 'Move up', moveDown: 'Move down',
    showAdvanced: 'Show advanced settings', hideAdvanced: 'Hide advanced settings',
 cancel: 'Cancel', quick: 'Quick presets',
  },
  help: {
    staleIfError: 'When the origin errors, times out or answers 500/502/503/504, keep serving the expired copy still on disk (kept up to 24 hours).',
    backgroundUpdate: 'After expiry, serve the old copy while one request refreshes it from the origin in the background (needs stale-if-error).',
    objectBytes: 'Only store responses whose size (Content-Length) is within these bounds (0: no bound), so one huge file cannot push out the whole site cache.',
    varyHeaders: 'Pick these when the origin answers differently by them (by language, mobile or desktop pages): nodes keep one copy per value and visitors get theirs. Without any, all visitors share one copy of a URL. More distinct values mean a lower hit rate; User-Agent differs for almost every browser. Cookie and Authorization are not allowed.',
    diskQuota: 'The most cache space this site may use on each node; when full, the least recently used is evicted. With caching on it must be {{min}} to {{max}} (no unlimited).',
    sliceBytes: 'Large files (video, downloads) are cached in slices of this size; seeking or resuming fetches only the missing slices.',
    browserTtl: 'How long browsers may cache the response, at most the edge cache lifetime; 0 keeps the origin browser cache headers.',
    browserTtlOff: 'Keep origin',
    noCache: 'Matching requests are not cached at the edge, and browsers are told not to cache them.',
  },
  slice: { off: 'Off', size: '{{size}} per slice' },
  statusHeader: {
    label: 'Show cache status in response headers (X-CDN-Cache)',
    help: 'Lets you confirm caching in the browser or with curl; hidden automatically while an attack is escalated to level B or above',
    saved: 'Cache status header setting saved', saveFailed: 'Could not save the cache status header setting',
    errors: {
      version_conflict: 'The site was changed by another operation. Refresh the page and try again.', site_locked: 'The site is locked and cannot be changed.',
      permission_denied: 'The current account lacks site management permission.', request_failed: 'Save failed. Try again later.',
    },
  },
  flush: {
    title: 'Flush all cache', action: 'Flush all cache',
    description: 'Purges everything the site cached on every node that carries it (one whole-site purge task, tracked under Purge & prewarm). Changing WAF, certificates or other settings never flushes the cache.',
    confirm: 'Flush all of this site\'s cache on every node? Requests then go to the origin.',
    done: 'Whole-site purge submitted; track it under Purge & prewarm.',
  },
  states: {
    loading: 'Loading cache policy', empty: 'No cache policy has been published for this site.',
    loadError: 'Failed to load the cache policy.', forbiddenTitle: 'Cache settings unavailable',
    forbiddenDescription: 'The current account lacks site read permission.', readOnly: 'The current account has read-only access.',
    unchanged: 'No policy changes', saving: 'Saving policy', saved: 'Cache policy saved',
    conflictTitle: 'Policy revision changed', conflictDescription: 'The server policy changed. Reload and compare before retrying.',
  },
  modes: { disabled: 'Caching disabled', follow_origin: 'Follow origin', override: 'Custom rules' },
  modeHelp: {
    disabled: 'Do not store response content at the edge.',
    follow_origin: 'Apply origin response cache directives at the edge.',
    override: 'Set edge cache lifetime using the ordered rules below.',
  },
  fields: {
    mode: 'Cache mode', rules: 'Cache rules', order: 'Order', match: 'Match conditions', extensions: 'File extensions',
    pathPrefix: 'Path prefix', statusCodes: 'Status codes', ttlSeconds: 'Edge cache lifetime', queryMode: 'Query parameters',
    queryNames: 'Query parameter names', varyHeaders: 'Separate cache by request header', diskQuotaBytes: 'Disk quota (per node)',

    staleIfError: 'Serve stale on origin errors', backgroundUpdate: 'Refresh expired objects in the background',
    minObjectBytes: 'Minimum object size', maxObjectBytes: 'Maximum object size', sliceBytes: 'Slice caching',
    pathRegex: 'Path regex', contentTypes: 'Response content types',
    action: 'Action', browserTtlSeconds: 'Browser cache lifetime',
  },
  ruleActions: { cache: 'Cache', no_cache: 'Do not cache' },
  placeholders: { pathRegex: 'e.g. ^/static/.+\\.(?:css|js)$', contentTypes: 'e.g. image/*, text/css', varyHeaders: 'Not separated (one copy for all visitors); pick a common header or type one' },
  queryModes: { preserve: 'Preserve all parameters', ignore: 'Ignore all parameters', include: 'Preserve selected parameters', exclude: 'Exclude selected parameters' },
  matchTypes: { all: 'All requests', extensions: 'Extensions', pathPrefix: 'Path prefix', statusCodes: 'Response status codes' },
  advanced: { title: 'Advanced settings', description: 'Separate cache by request header, node disk quota and cacheable file sizes.' },
  varyHeaderOptions: {
    'accept-encoding': 'Accept-Encoding (compression)', 'accept-language': 'Accept-Language (language)', 'user-agent': 'User-Agent (browser/device; hit rate drops sharply)',
    accept: 'Accept (content type, e.g. WebP)', origin: 'Origin (cross-origin source)', 'sec-ch-ua-mobile': 'Sec-CH-UA-Mobile (mobile or not)',
  },
  history: {
    title: 'Policy revision history', empty: 'No previous revisions.', revision: 'Revision', createdAt: 'Published at',
    createdBy: 'Published by', requestId: 'Request ID', view: 'View', detailError: 'Failed to load the historical revision.',
  },
  comparison: { title: 'Revision differences', base: 'Editing base', latest: 'Latest policy', draft: 'Current draft' },
  confirm: {
    overwriteLatest: 'Overwrite the latest policy with the current draft?',
    refreshDiscard: 'Reload the latest policy and discard the current draft?',
  },
  validation: {
    required: 'This field is required.', ruleRequired: 'Custom rules mode requires at least one rule.',
    ttlRange: 'Lifetime must be between 1 and 31536000 seconds.', quotaRange: 'Disk quota must be between {{min}} and {{max}} when caching is enabled.',
    queryNamesRequired: 'This query mode requires at least one parameter name.', queryNamesForbidden: 'This query mode does not accept parameter names.',
    duplicate: 'Duplicate values are not allowed.', invalidExtension: 'Extensions must start with a dot and use lowercase letters or digits.',
    invalidPath: 'Path prefixes must start with a slash (such as /api, saved as /api/) and cannot contain //, ?, #, % or a backslash, or a . or .. segment.', invalidStatus: 'Status codes must be between 100 and 599.',
    invalidHeader: 'Enter a valid request header that is allowed in Vary.', overlap: 'Cache rule match ranges cannot overlap.',

    invalidExtensions: 'The minimum object size must be below the maximum; background refresh needs stale-if-error; none of these apply with caching disabled.',
    invalidPathRegex: 'The path regex is invalid or longer than 256 characters.', invalidContentTypes: 'Content types must be type/subtype or a prefix ending in *, at most 16.',
    tooManyConditionalRules: 'At most {{max}} rules may use a path regex or content types.',
    browserTtlRange: 'The browser cache lifetime must be between 0 and the edge cache lifetime.',
    invalidExactPath: 'A single path starts with / and has no ?, #, %, spaces, // or . / .. segments.',
    invalidCondition: 'A no-cache condition needs a field and a valid regular expression (at most 256 characters); a custom one needs a header name.',
    tooManyConditions: 'At most {{max}} no-cache conditions per rule.',
  },
  errors: {
    network_error: 'Unable to connect to the service. Try again later.', invalid_response: 'The service response was invalid. Refresh to confirm the current state.',
    permission_denied: 'The current account lacks cache policy permission.', revision_conflict: 'The policy revision changed. Reload before retrying.',
    idempotency_conflict: 'The idempotency key was used for a different request. Refresh and submit again.', validation_error: 'The cache policy is invalid. Check the input.',
    invalid_request: 'The cache policy request is invalid. Check the input.', not_found: 'The site or cache policy was not found.',
    service_unavailable: 'The cache policy service is unavailable. Try again later.', request_failed: 'The cache policy request failed. Try again later.',
  },
  units: { seconds: 'seconds', bytes: 'bytes', mib: 'MiB', gib: 'GiB', tib: 'TiB', kb: 'KB', mb: 'MB', gb: 'GB', tb: 'TB', unitOf: '{{field}} unit' },
} satisfies MessageShape<typeof zhCN>

function pseudoText(value: string): string {
  const expanded = value
    .split(/({{[^}]+}})/g)
    .map((part) => part.startsWith('{{') && part.endsWith('}}')
      ? part
      : [...part].map((character) => (/\s/u.test(character) ? character : `${character}~`)).join(''))
    .join('')
  return `［${expanded}］`
}

function pseudoTree(tree: CachePolicyMessageTree): CachePolicyMessageTree {
  return Object.fromEntries(Object.entries(tree).map(([key, value]) => [
    key,
    typeof value === 'string' ? pseudoText(value) : pseudoTree(value),
  ]))
}

const pseudoCN = pseudoTree(zhCN)

export const cachePolicyMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  CachePolicyMessageTree
> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

i18n.addResourceBundle('zh-CN', 'cachePolicy', zhCN, true, true)
i18n.addResourceBundle('en-US', 'cachePolicy', enUS, true, true)
i18n.addResourceBundle('qps-ploc', 'cachePolicy', pseudoCN, true, true)
i18n.addResourceBundle('qps-Ploc', 'cachePolicy', pseudoCN, true, true)
