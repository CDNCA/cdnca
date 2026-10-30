import i18n from './index'

// 站点“访问控制”页：主机跳转、HSTS、压缩、
// 单 IP 并发与单请求限速、basic 认证、维护页、强制 HTTPS 状态码与排除域名。
const zhCN = {
  title: '访问控制',
  hint: '这些设置只作用于本站，改动即自动下发到节点。',
  streamingHint: '流式响应（如 SSE 的 text/event-stream）无需在此设置：节点逐块转发源站已刷出的数据；如需节点完全不缓冲某个响应，由源站在该响应上发送 X-Accel-Buffering: no。',
  loading: '正在加载访问控制', loadFailed: '访问控制加载失败', retry: '重试',
  save: '保存', saving: '正在保存', saved: '已保存，正在下发到节点。', readOnly: '你没有修改本站设置的权限。',
  locked: '平台管理员锁定了本站，当前不能修改。',
  enabled: '开启', inactive: '未生效',
  forceHttps: {
    title: '强制 HTTPS', notEnabled: '本站未开启强制 HTTPS（在 HTTPS 页开启）。以下设置在开启后生效。',
    status: '跳转状态码', statusHint: '301/308 浏览器会缓存，302/307 不缓存；307/308 保持请求方法与请求体。',
    exclude: '不强制的域名', excludeHint: '这些域名继续用 HTTP 访问；不能选择全部域名。',
  },
  hostRedirects: {
    title: '主机跳转', hint: '把本站某个域名的所有请求跳到另一个主机（例如裸域跳 www），ACME 证书验证路径不跳。',
    source: '来源域名', target: '目标主机', scheme: '协议', port: '端口（可空）', status: '状态码', preserveUri: '保留路径与参数',
    schemes: { follow: '跟随请求', https: 'HTTPS', http: 'HTTP' }, add: '添加主机跳转', remove: '删除',
  },
  hsts: {
    title: 'HSTS', hint: '让浏览器在有效期内只用 HTTPS 访问本站，只在 HTTPS 响应中发送。', needsHttps: '本站未开启 HTTPS，不能开启 HSTS。',
    maxAge: '有效期（秒）', includeSubdomains: '包含子域名', preload: '加入预加载列表（preload）',
    preloadHint: '预加载需要有效期至少一年（31536000 秒）并包含子域名，加入后很难撤回。',
  },
  compression: {
    title: '压缩', hint: '不设置时使用平台默认（仅压缩 HTML）。', mode: '压缩方式',
    modes: { inherit: '平台默认', on: '本站开启', off: '本站关闭' }, detailOpen: '压缩方式设置', detailDone: '完成',
    types: '压缩类型', typesHint: '每行一个 MIME 类型；text/html 总会压缩。', minLength: '最小长度（字节）',
    encodings: '压缩算法', encodingsHint: '客户端同时支持时优先 Brotli。', encoding: { br: 'Brotli', gzip: 'Gzip' },
    gzipLevel: 'Gzip 压缩级别', brotliLevel: 'Brotli 压缩级别', levelHint: '0 为节点默认（Gzip 用系统设置，Brotli 为 6）；级别越高越省流量、越耗节点 CPU。',
    nodeHint: 'Brotli 和自定义压缩级别需要节点支持（节点运行时编入 Brotli）；有节点不支持时发布会被拒绝并列出这些节点。',
  },
  webp: {
    title: '自动转 WebP', hint: '浏览器支持 WebP 时把 JPEG/PNG 转成 WebP 返回（Vary: Accept）。图片第一次经过节点时仍返回原图并在后台转换，之后返回 WebP；超过 5 MB 或 800 万像素的图片、动图 PNG、源站没有 ETag/Last-Modified 的图片和转换后不更小的图片保持原图。需要节点支持 WebP 转换。',
    quality: 'WebP 质量', qualityHint: '1–100，0 为默认 80。',
  },
  responseRules: {
    title: '响应规则',
    hint: '节点收到源站响应头时按顺序检查（不读响应体）：状态码和响应头条件都满足时执行动作。改写响应头的规则会继续检查后面的规则；替换为错误页或拦截后不再检查。',
    cacheHint: '与缓存的关系：改写响应头的规则对回源响应和缓存命中的响应都执行；记录日志、替换为错误页、拦截只对回源响应执行，被替换或拦截的响应不会写入缓存。节点自己生成的响应（拦截页、错误页）不检查。',
    rule: '响应规则', id: '规则 ID', up: '上移', down: '下移', remove: '删除规则', add: '添加响应规则',
    statuses: '状态码', statusesHint: '逗号分隔，可写区间，例如 404, 500-504；留空为任意状态码。',
    headers: '响应头条件', headersHint: '全部满足才匹配；多个值的头任一值满足即可。正则按 PCRE 匹配。',
    headerName: '响应头名称', op: '条件', headerValue: '值', removeCondition: '删除条件', addCondition: '添加条件',
    ops: { exists: '存在', absent: '不存在', equals: '等于', regex: '匹配正则' },
    action: '动作',
    actions: { headers: '改写响应头', log: '记录日志', error_page: '替换为错误页', block: '拦截' },
    actionHints: {
      headers: '设置、添加或删除响应头，然后继续检查后面的规则。',
      log: '在安全日志里记录一条（类型 response），然后继续检查后面的规则。',
      error_page: '换成本站该状态码的错误页（错误页设置里的源站响应或边缘页），没有则用内置文本页。',
      block: '返回指定状态码和内置拦截文本，并记录安全日志。',
    },
    headerActions: '响应头动作', kind: '操作', actionName: '头名称', actionValue: '头的值', removeAction: '删除动作', addAction: '添加动作',
    kinds: { set: '设置', add: '添加', delete: '删除' },
    reservedHint: '不能改 Content-Length、Transfer-Encoding 等分帧头，以及 Alt-Svc、Strict-Transport-Security、X-CDN-Cache、x-cdnca- 开头的头。',
    status: '返回状态码',
    nodeHint: '响应规则需要节点支持（EDGE_RESPONSE_RULES）；有节点不支持时发布会被拒绝并列出这些节点。',
  },
  limits: {
    title: '连接与限速', hint: '按客户端 IP 限制（HTTP 层）；节点内核级连接限制在 DDoS 防护里设置。',
    connections: '单 IP 并发请求数', connectionsHint: '超过返回 429；0 为不限。HTTP/2 每个并发流计一次。',
    rate: '单请求下载速率（KB/s）', rateHint: '0 为不限。', rateAfter: '前多少 KB 不限速',
  },
  basicAuth: {
    title: '访问认证（Basic）', hint: '访问本站需要输入用户名和密码；密码只保存哈希，不会再显示。',
    realm: '提示名称', users: '用户', username: '用户名', password: '密码', passwordKeep: '留空保持原密码',
    passwordNew: '至少 8 位', add: '添加用户', remove: '删除', exclude: '不需要认证的路径前缀', excludeHint: '每行一个，例如 /health',
  },
  maintenance: {
    title: '维护页', hint: '开启后所有访问直接返回维护页，不再回源；ACME 证书验证与放行网段不受影响。',
    status: '状态码', contentType: '内容类型', body: '页面内容', retryAfter: 'Retry-After（秒，可空）',
    allowed: '放行网段', allowedHint: '每行一个 CIDR，例如 203.0.113.0/24',
  },
  errors: {
    validation_error: '设置不正确：请检查域名、状态码、MIME 类型、网段、用户名和响应规则（规则 ID、状态码区间、头名称、正则）。',
    site_access_https_required: 'HSTS 和强制 HTTPS 的状态码/排除域名需要本站先开启 HTTPS。',
    version_conflict: '本站设置已被修改，请刷新后再保存。',
    idempotency_conflict: '重复提交了不同的内容，请刷新后再试。',
    site_locked: '平台管理员锁定了本站，当前不能修改。',
    unknown: '保存失败（{{code}}）',
  },
}

const enUS: typeof zhCN = {
  title: 'Access control',
  hint: 'These settings apply to this site only and go to the nodes when saved.',
  streamingHint: 'Streaming responses (such as SSE, text/event-stream) need no setting here: nodes pass on each chunk the origin flushes. To have nodes not buffer a response at all, the origin sends X-Accel-Buffering: no on it.',
  loading: 'Loading access control', loadFailed: 'Could not load access control', retry: 'Retry',
  save: 'Save', saving: 'Saving', saved: 'Saved. Deploying to the nodes.', readOnly: 'You cannot change this site.',
  locked: 'A platform administrator locked this site; it cannot be changed now.',
  enabled: 'On', inactive: 'Not in effect',
  forceHttps: {
    title: 'Forced HTTPS', notEnabled: 'Forced HTTPS is off for this site (turn it on in the HTTPS tab). These settings apply once it is on.',
    status: 'Redirect status', statusHint: 'Browsers cache 301/308, not 302/307; 307/308 keep the method and body.',
    exclude: 'Domains not forced', excludeHint: 'These domains stay on plain HTTP; not every domain.',
  },
  hostRedirects: {
    title: 'Host redirects', hint: 'Send every request for one of the site domains to another host (for example the bare domain to www); ACME validation is not redirected.',
    source: 'Source domain', target: 'Target host', scheme: 'Scheme', port: 'Port (optional)', status: 'Status', preserveUri: 'Keep path and query',
    schemes: { follow: 'Same as request', https: 'HTTPS', http: 'HTTP' }, add: 'Add host redirect', remove: 'Remove',
  },
  hsts: {
    title: 'HSTS', hint: 'Browsers use only HTTPS for this site until it expires; sent on HTTPS responses only.', needsHttps: 'HTTPS is off for this site, so HSTS cannot be on.',
    maxAge: 'Max age (seconds)', includeSubdomains: 'Include subdomains', preload: 'Preload list',
    preloadHint: 'Preload needs a max age of at least one year (31536000 s) and subdomains; it is hard to undo.',
  },
  compression: {
    title: 'Compression', hint: 'Without a setting the platform default applies (HTML only).', mode: 'Compression',
    modes: { inherit: 'Platform default', on: 'On for this site', off: 'Off for this site' }, detailOpen: 'Compression settings', detailDone: 'Done',
    types: 'MIME types', typesHint: 'One MIME type per line; text/html is always compressed.', minLength: 'Minimum length (bytes)',
    encodings: 'Encodings', encodingsHint: 'Brotli is preferred when the client accepts both.', encoding: { br: 'Brotli', gzip: 'Gzip' },
    gzipLevel: 'Gzip level', brotliLevel: 'Brotli level', levelHint: '0 is the node default (system gzip setting, Brotli 6); higher saves traffic and costs node CPU.',
    nodeHint: 'Brotli and custom levels need node support (Brotli in the node runtime); a release to nodes without it is refused and names them.',
  },
  webp: {
    title: 'Automatic WebP', hint: 'JPEG/PNG are sent as WebP to browsers that accept it (Vary: Accept). The first request for an image still gets the original while the node converts it; images over 5 MB or 8 megapixels, animated PNG, images without ETag/Last-Modified from the origin and conversions that are not smaller stay the original. Needs node WebP support.',
    quality: 'WebP quality', qualityHint: '1–100, 0 is the default 80.',
  },
  responseRules: {
    title: 'Response rules',
    hint: 'Nodes check these in order when the origin response headers arrive (the body is never read): when the status and every header condition match, the action runs. Header rules go on to the next rule; an error page or block ends the check.',
    cacheHint: 'With the cache: header rules run on origin responses and on cached responses; log, error page and block run on origin responses only, and a replaced or blocked response is not cached. Responses the node generates itself (block pages, error pages) are not checked.',
    rule: 'Response rule', id: 'Rule ID', up: 'Move up', down: 'Move down', remove: 'Remove rule', add: 'Add response rule',
    statuses: 'Status', statusesHint: 'Comma separated, ranges allowed, for example 404, 500-504; empty means any status.',
    headers: 'Header conditions', headersHint: 'All must hold; for a header with several values one value is enough. Regexes are PCRE.',
    headerName: 'Header name', op: 'Condition', headerValue: 'Value', removeCondition: 'Remove condition', addCondition: 'Add condition',
    ops: { exists: 'exists', absent: 'is absent', equals: 'equals', regex: 'matches regex' },
    action: 'Action',
    actions: { headers: 'Rewrite headers', log: 'Log', error_page: 'Error page', block: 'Block' },
    actionHints: {
      headers: 'Set, add or delete response headers, then go on with the next rule.',
      log: 'Write a security log line (type response), then go on with the next rule.',
      error_page: 'Replace with the site error page of that status (origin response or edge page in error pages), else the built-in text page.',
      block: 'Answer with the status and the built-in block text, and write a security log line.',
    },
    headerActions: 'Header actions', kind: 'Operation', actionName: 'Header name', actionValue: 'Header value', removeAction: 'Remove action', addAction: 'Add action',
    kinds: { set: 'set', add: 'add', delete: 'delete' },
    reservedHint: 'Framing headers (Content-Length, Transfer-Encoding, ...), Alt-Svc, Strict-Transport-Security, X-CDN-Cache and headers starting with x-cdnca- cannot be changed.',
    status: 'Response status',
    nodeHint: 'Response rules need node support (EDGE_RESPONSE_RULES); a release to nodes without it is refused and names them.',
  },
  limits: {
    title: 'Connections and rate', hint: 'Per client IP at the HTTP layer; node kernel connection limits are in DDoS protection.',
    connections: 'Concurrent requests per IP', connectionsHint: 'Above it: 429. 0 is unlimited. Each HTTP/2 stream counts.',
    rate: 'Download rate per request (KB/s)', rateHint: '0 is unlimited.', rateAfter: 'Unthrottled first KB',
  },
  basicAuth: {
    title: 'Basic authentication', hint: 'Visitors must enter a username and password; passwords are stored hashed and never shown again.',
    realm: 'Realm', users: 'Users', username: 'Username', password: 'Password', passwordKeep: 'Leave empty to keep',
    passwordNew: 'At least 8 characters', add: 'Add user', remove: 'Remove', exclude: 'Paths without authentication', excludeHint: 'One prefix per line, for example /health',
  },
  maintenance: {
    title: 'Maintenance page', hint: 'Every request gets the maintenance page without reaching the origin; ACME validation and allowed networks are not affected.',
    status: 'Status', contentType: 'Content type', body: 'Page content', retryAfter: 'Retry-After (seconds, optional)',
    allowed: 'Allowed networks', allowedHint: 'One CIDR per line, for example 203.0.113.0/24',
  },
  errors: {
    validation_error: 'Invalid settings: check domains, statuses, MIME types, networks, usernames and response rules (rule IDs, status ranges, header names, regexes).',
    site_access_https_required: 'HSTS and the forced HTTPS status or exclusions need HTTPS on this site.',
    version_conflict: 'The site changed meanwhile; reload and save again.',
    idempotency_conflict: 'A different request was sent with the same key; reload and retry.',
    site_locked: 'A platform administrator locked this site; it cannot be changed now.',
    unknown: 'Could not save ({{code}})',
  },
}

function pseudo(value: unknown): unknown {
  return typeof value === 'string'
    ? `［${value}］`
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const siteAccessMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }

for (const [locale, messages] of Object.entries(siteAccessMessages)) i18n.addResourceBundle(locale, 'siteAccess', messages, true, true)
