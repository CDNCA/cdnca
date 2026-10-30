import i18n from './index'

type TranslationTree = { [key: string]: string | TranslationTree }

const zhCN = {
  title: '添加网站',
  tabs: { label: '创建方式', single: '单个', batch: '批量' },
  targetScope: {
    label: '目标租户作用域',
    placeholder: '输入租户作用域 UUID',
    invalid: '请输入有效的租户作用域 UUID',
  },
  ownerUser: {
    label: '所属用户',
    ariaLabel: '所属用户',
    searchPlaceholder: '输入ID、邮箱、用户名、手机号搜索',
    placeholder: '输入该租户内的用户 UUID',
    invalid: '请选择有效的所属用户',
  },
  packageSelect: { label: '用户套餐', placeholder: '请选择', empty: '该用户暂无可用套餐', unnamed: '套餐名称未提供' },
  groupSelect: { label: '所属分组', placeholder: '网站分组，可不选' },
  lookup: {
    empty: '暂无匹配记录', more: '加载更多', retry: '重新读取', failed: '读取失败，请重试',
    usersDenied: '当前账号没有查询用户权限，请联系管理员授权。',
    packagesDenied: '当前账号没有查询套餐权限，无法选择套餐。',
  },
  domain: {
    label: '网站域名',
    placeholder: '例如 www.example.com',
    invalid: '请输入有效的网站域名',
    help: '多个域名用逗号或换行分隔',
  },
  origin: {
    label: '源站地址',
    placeholder: '每行一个 IP、IP:端口、域名或域名:端口',
    invalid: '请输入有效且不重复的源站地址（最多 32 个）',
    help: '源站可填写 IP、域名，端口可选',
  },
  originScheme: {
    label: '回源协议',
    options: { http: 'HTTP', https: 'HTTPS', follow: '跟随访问协议' },
    defaultPlaceholder: '使用默认设置（未设置为 HTTP）',
    help: '节点到源站使用的协议；跟随时 HTTPS 访问用 HTTPS（443 端口）回源，HTTP 访问用 HTTP 回源',
  },
  originHost: {
    label: '回源 Host',
    placeholder: '可选，例如 origin.example.com',
    invalid: '请输入有效的域名或 IP，可带端口',
    help: '留空时使用访客访问的域名；建站后可在“回源设置”里改为源站地址或其他值',
  },
  advanced: { expand: '高级设置', collapse: '高级设置' },
  batch: {
    dataLabel: '网站数据',
    placeholder: '数据格式为key=value的方式，一行一个网站配置\ndomain=www.abc.com,abc.com|ip=1.1.1.1\ndomain=www.qq.com|ip=1.1.1.1,2.2.2.2',
    help: 'domain是网站域名，ip源站地址，配置项以 | 分隔。',
    invalid: '请按示例填写至少一行有效的网站数据（最多 100 行）',
    ignoreLabel: '忽略错误',
    ignoreHelp: '有网站添加出错时不中断，继续添加下一条',
    partialResult: '批量创建完成：成功 {{saved}} 条，失败 {{failed}} 条',
    resultUnknownHelp: '存在结果待确认的网站，暂时锁定表单。请使用原请求重试，系统会复用每条请求的幂等键，避免重复创建。',
    storageFailed: '无法保存安全重试记录，尚未发送请求。请检查浏览器存储后重试。',
    storageBlocked: '安全重试记录无法读取或更新，已停止创建。请保留当前浏览器数据并联系管理员核实原请求结果。',
  },
  balance: {
    label: '负载均衡',
    defaultPlaceholder: '使用默认设置（未设置为轮询）',
    options: {
      round_robin: '轮询',
      ip_hash: 'IP 哈希',
      url_hash: 'URL 哈希',
      least_conn: '最少连接',
      random: '随机',
    },
  },
  packageID: { label: '套餐 ID', placeholder: '可选，需同时填写套餐名称' },
  packageName: { label: '套餐名称', placeholder: '可选，需同时填写套餐 ID' },
  packageSubscription: { label: '套餐订阅 ID', placeholder: '可选，输入有效 UUID' },
  groupID: { label: '网站分组 ID', placeholder: '可选，需同时填写分组名称' },
  groupName: { label: '网站分组名称', placeholder: '可选，需同时填写分组 ID' },
  httpPorts: { label: 'HTTP 监听端口', placeholder: '留空使用默认设置（未设置为 80）' },
  httpsEnabled: { label: '启用 HTTPS' },
  httpsPorts: { label: 'HTTPS 监听端口', placeholder: '留空使用默认设置（未设置为 443）' },
  cname: { label: 'CNAME', placeholder: '可选，例如 edge.example.com', help: '留空自动分配；填写则使用你自己的 CNAME 主机名（选了套餐时以套餐分配为准）' },
  cnamePackage: { label: 'CNAME 分配', value: '由所选套餐决定：CNAME 域名、主机名与分配模式按套餐生成，建站时不能单独设置；需要修改请到套餐里改' },
  tls: { safeOnly: 'TLS 固定启用 TLSv1.2 和 TLSv1.3，不允许降级。' },
  validation: {
    ports: '监听端口必须为 1-65535 的不重复整数，HTTP 与 HTTPS 不能重叠。',
    references: '套餐或分组信息已失效，请重新选择。',
    cname: 'CNAME 信息无效；显式分配模式必须绑定套餐订阅。',
  },
  defaults: '端口和负载均衡留空时按网站默认设置填写（分组优先于全局），没有设置时 HTTP 监听 80、HTTPS 监听 443、轮询。',
  actions: {
    cancel: '取消',
    create: '创建网站',
    confirm: '确定',
    retrySameRequest: '使用同一请求重试',
    retryFailed: '重试失败项',
  },
  resultUnknown: '创建结果待确认',
  resultUnknownDescription: '仅可使用完全相同的请求内容和幂等键重试；修改字段会开始新请求。',
  viewSite: '查看站点',
  success: '网站 {{domain}} 创建成功。接下来在网站详情检查 DNS 解析、配置证书并查看发布状态，发布完成前公网还不能访问',
  errors: {
    site_domain_conflict: '该网站域名已存在',
    domain_blocked: '该域名不允许添加',
    domain_verified_by_other: '该域名的根域名所有权已被其他账户验证，无法添加',
    domain_ownership_required: '添加该域名前需要先验证根域名所有权',
    validation_error: '网站信息校验失败，请检查后重试',
    fields: {
      domains: '域名格式不正确：请填写合法域名（可用 *. 通配），每行一个',
      cname: 'CNAME 格式不正确，请填写合法域名',
      http_listen_ports: 'HTTP 端口不正确：端口需在 1-65535 之间',
      https_listen_ports: 'HTTPS 端口不正确：开启 HTTPS 时至少填一个 1-65535 的端口，且不能与 HTTP 端口重复',
      force_https: '强制 HTTPS 需要先开启 HTTPS 并配置 HTTPS 端口',
      https_redirect_port: '跳转端口必须是已配置的 HTTPS 端口之一',
      origins: '源站地址不正确：需填写 1-32 个合法的 IP 或域名（可带端口），且不能重复',
    },
    permission_denied: '当前账号没有创建网站权限',
    idempotency_conflict: '幂等请求内容不一致，请修改后重新提交',
    entitlement_denied: '当前授权不允许创建网站',
    entitlement_unavailable: '授权状态暂不可用，请稍后重试',
    entitlement_state_denied: '当前授权状态不允许创建网站',
    entitlement_feature_denied: '当前授权未启用网站创建',
    entitlement_quota_denied: '网站授权额度不足',
    entitlement_quota_exceeded: '网站授权额度已用尽',
    request_failed: '网站创建失败，请稍后重试',
  },
} satisfies TranslationTree

const enUS = {
  title: 'Add site',
  tabs: { label: 'Creation mode', single: 'Single', batch: 'Batch' },
  targetScope: {
    label: 'Target tenant scope',
    placeholder: 'Enter the tenant scope UUID',
    invalid: 'Enter a valid tenant scope UUID',
  },
  ownerUser: {
    label: 'Owner user',
    ariaLabel: 'Owner user',
    searchPlaceholder: 'Search by ID, email, username, or phone',
    placeholder: 'Enter a user UUID in this tenant',
    invalid: 'Select a valid owner user',
  },
  packageSelect: { label: 'User package', placeholder: 'Please select', empty: 'No available packages for this user', unnamed: 'Package name unavailable' },
  groupSelect: { label: 'Site group', placeholder: 'Optional site group' },
  lookup: {
    empty: 'No matching records', more: 'Load more', retry: 'Reload', failed: 'Could not load records. Try again.',
    usersDenied: 'You cannot look up users. Contact an administrator for access.',
    packagesDenied: 'You cannot look up packages, so package selection is unavailable.',
  },
  domain: {
    label: 'Site domain',
    placeholder: 'For example, www.example.com',
    invalid: 'Enter a valid site domain',
    help: 'Separate domains with commas or new lines',
  },
  origin: {
    label: 'Origin address',
    placeholder: 'One IP, IP:port, hostname, or hostname:port per line',
    invalid: 'Enter valid, unique origin addresses (up to 32)',
    help: 'Use an IP address or hostname with an optional port',
  },
  originScheme: {
    label: 'Origin protocol',
    options: { http: 'HTTP', https: 'HTTPS', follow: 'Follow visitor protocol' },
    defaultPlaceholder: 'Use the default setting (HTTP if none)',
    help: 'How nodes connect to the origin; Follow uses HTTPS (port 443) for HTTPS visits and HTTP for HTTP visits',
  },
  originHost: {
    label: 'Origin Host',
    placeholder: 'Optional, for example origin.example.com',
    invalid: 'Enter a valid hostname or IP, with an optional port',
    help: 'Empty sends the visitor\'s Host; change it later under Origin settings',
  },
  advanced: { expand: 'Advanced settings', collapse: 'Advanced settings' },
  batch: {
    dataLabel: 'Site data',
    placeholder: 'Use key=value format, one site per line\ndomain=www.abc.com|ip=1.1.1.1\ndomain=www.qq.com|ip=1.1.1.1,2.2.2.2',
    help: 'domain is the site domain, ip is the origin address, and | separates options.',
    invalid: 'Enter at least one valid site row (up to 100 rows)',
    ignoreLabel: 'Ignore errors',
    ignoreHelp: 'Continue adding the next row when one site fails',
    partialResult: 'Batch creation finished: {{saved}} rows succeeded, {{failed}} failed',
    resultUnknownHelp: 'Some site results are unknown, so editing is locked. Retry the original requests with their original idempotency keys to avoid duplicate creation.',
    storageFailed: 'The safe retry record could not be saved. No request was sent. Check browser storage and retry.',
    storageBlocked: 'The safe retry record could not be read or updated, so creation is blocked. Keep this browser data and ask an administrator to verify the original request outcome.',
  },
  balance: {
    label: 'Load balancing',
    defaultPlaceholder: 'Use the default setting (round robin if none)',
    options: {
      round_robin: 'Round robin',
      ip_hash: 'IP hash',
      url_hash: 'URL hash',
      least_conn: 'Least connections',
      random: 'Random',
    },
  },
  packageID: { label: 'Package ID', placeholder: 'Optional; requires a package name' },
  packageName: { label: 'Package name', placeholder: 'Optional; requires a package ID' },
  packageSubscription: { label: 'Package subscription ID', placeholder: 'Optional UUID' },
  groupID: { label: 'Site group ID', placeholder: 'Optional; requires a group name' },
  groupName: { label: 'Site group name', placeholder: 'Optional; requires a group ID' },
  httpPorts: { label: 'HTTP listen ports', placeholder: 'Leave empty to use the default setting (80 if none)' },
  httpsEnabled: { label: 'Enable HTTPS' },
  httpsPorts: { label: 'HTTPS listen ports', placeholder: 'Leave empty to use the default setting (443 if none)' },
  cname: { label: 'CNAME', placeholder: 'Optional, for example edge.example.com', help: 'Leave empty to allocate automatically; fill it to use your own CNAME hostname (with a package, the package allocation wins)' },
  cnamePackage: { label: 'CNAME allocation', value: 'Decided by the selected package: the CNAME domain, hostname and mode follow the package and cannot be set when creating a site; change them on the package' },
  tls: { safeOnly: 'TLSv1.2 and TLSv1.3 are always enabled; downgrade is blocked.' },
  validation: {
    ports: 'Listen ports must be unique integers from 1 to 65535, and HTTP and HTTPS cannot overlap.',
    references: 'The package or group is no longer valid. Select it again.',
    cname: 'The CNAME details are invalid. An explicit allocation mode requires a package subscription.',
  },
  defaults: 'Empty ports and load balancing follow your website default settings (group before global); without them HTTP listens on 80, HTTPS on 443, with round robin.',
  actions: {
    cancel: 'Cancel',
    create: 'Create site',
    confirm: 'Confirm',
    retrySameRequest: 'Retry the same request',
    retryFailed: 'Retry failed items',
  },
  resultUnknown: 'Site creation outcome unknown',
  resultUnknownDescription: 'Retry only with the exact same request body and idempotency key. Editing a field starts a new request.',
  viewSite: 'View site',
  success: 'Site {{domain}} created. Next, check DNS, set up the certificate and watch the release in the site details; it is not publicly reachable until released',
  errors: {
    site_domain_conflict: 'This site domain already exists',
    domain_blocked: 'This domain is not allowed',
    domain_verified_by_other: 'Another account verified the root domain of this domain',
    domain_ownership_required: 'Verify ownership of the root domain before adding this domain',
    validation_error: 'The site details are invalid. Check the form and try again.',
    fields: {
      domains: 'Invalid domain: enter valid domains (*. wildcards allowed), one per line',
      cname: 'Invalid CNAME: enter a valid domain',
      http_listen_ports: 'Invalid HTTP port: ports must be 1-65535',
      https_listen_ports: 'Invalid HTTPS port: with HTTPS on, enter at least one port 1-65535 that is not also an HTTP port',
      force_https: 'Forced HTTPS needs HTTPS enabled with an HTTPS port',
      https_redirect_port: 'The redirect port must be one of the HTTPS ports',
      origins: 'Invalid origin: enter 1-32 distinct valid IPs or domains (port optional)',
    },
    permission_denied: 'Your account cannot create sites',
    idempotency_conflict: 'The request differs from the original idempotent request. Edit it before submitting again.',
    entitlement_denied: 'The current entitlement does not allow site creation',
    entitlement_unavailable: 'The entitlement state is unavailable. Try again later.',
    entitlement_state_denied: 'The current entitlement state does not allow site creation',
    entitlement_feature_denied: 'Site creation is not enabled by the current entitlement',
    entitlement_quota_denied: 'The entitlement does not grant site quota',
    entitlement_quota_exceeded: 'The site quota has been exhausted',
    request_failed: 'The site could not be created. Try again later.',
  },
} satisfies TranslationTree

function pseudoText(value: string): string {
  const expanded = value
    .split(/({{[^}]+}})/g)
    .map((part) => part.startsWith('{{') && part.endsWith('}}')
      ? part
      : [...part].map((character) => (/\s|\d/.test(character) ? character : `${character}~`)).join(''))
    .join('')
  return `［${expanded}］`
}

function pseudoTree(tree: TranslationTree): TranslationTree {
  return Object.fromEntries(
    Object.entries(tree).map(([key, value]) => [
      key,
      typeof value === 'string' ? pseudoText(value) : pseudoTree(value),
    ]),
  )
}

const pseudoCN = pseudoTree(zhCN)

i18n.addResourceBundle('zh-CN', 'siteCreate', zhCN, true, true)
i18n.addResourceBundle('en-US', 'siteCreate', enUS, true, true)
i18n.addResourceBundle('qps-ploc', 'siteCreate', pseudoCN, true, true)
i18n.addResourceBundle('qps-Ploc', 'siteCreate', pseudoCN, true, true)
