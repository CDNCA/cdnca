import i18n from './index'

// 网站“高级”页“302 调度”卡片（与 DNS 调度组成“DNS + 302 双调度”）。
const zhCN = {
  title: '302 调度',
  hint: '访客到达节点后，按访客的运营商与地区，从本站线路组里选当前在线、负载最低的最合适节点，用 302 把请求跳到该节点（签名短期有效，防止盗链）；选不出可用节点时不跳转、直接服务。节点故障或恢复时秒级切换。',
  warning: '适合下载、视频等大文件。普通网页（HTML、接口、小图片）不建议开启：每个请求多一次跳转，页面会变慢，部分浏览器和客户端也不跟随 POST 跳转。',
  enabled: '开启 302 调度',
  target: '跳转到', targetAddress: '节点 IP（线路组里的节点地址）', targetHostname: '节点直连域名（节点没有直连域名时不参与调度）',
  keepLabel: '跳转保留', keepPath: '保留路径', keepQuery: '保留查询参数',
  ttl: '签名有效期（秒）', ttlHint: '跳转链接在这段时间内有效，过期访问会被拒绝（403）。范围 10–3600 秒。',
  httpsToHttp: 'HTTPS 请求也跳转', httpsToHttpHint: '节点没有自身地址的证书，HTTPS 请求会跳到节点的 HTTP 端口。关闭时 HTTPS 请求不跳转。',
  filters: '只对这些请求跳转', filtersHint: '都留空表示所有 GET/HEAD 请求都跳转；填写后需同时满足。',
  extensions: '文件扩展名', extensionsPlaceholder: 'mp4, zip, iso',
  pathPrefixes: '路径前缀', pathPrefixesPlaceholder: '/download/ /video/',
  minSize: '最小文件大小（MB）', minSizeHint: '0 表示不限。节点第一次服务某个 URL 时记下它的大小，之后同一 URL 达到该大小才跳转。',
  noPlainHTTP: '本站没有 HTTP 端口：302 调度的落地请求走节点的 HTTP 端口，请先在“基本设置”里添加 HTTP 端口。',
  loadFailed: '读取 302 调度设置失败', retry: '重试',
  save: '保存', saving: '正在保存', saved: '已保存，正在下发到节点。',
  ttlInvalid: '填写 10 到 3600 之间的整数',
  sizeInvalid: '填写不小于 0 的数字',
  errors: {
    schedule302_no_plain_http: '本站没有 HTTP 端口，无法开启 302 调度',
    version_conflict: '站点已被修改，请刷新后重试', idempotency_conflict: '请求重复，请刷新后重试',
    site_locked: '站点已被平台管理员锁定', validation_error: '输入不正确（扩展名只能是字母和数字，路径前缀要以 / 开头）',
    unknown: '保存失败（{{code}}）',
  },
}

const enUS: typeof zhCN = {
  title: 'HTTP 302 scheduling',
  hint: 'When a visitor reaches a node, the node picks the best node of this site\'s line group for the visitor\'s carrier and region (online, least loaded) and redirects the request there with 302 (a short-lived signature stops hotlinking); with no suitable node it serves the request itself. Node failures and recoveries switch within seconds.',
  warning: 'Meant for large files such as downloads and video. Not recommended for ordinary web pages (HTML, APIs, small images): every request takes an extra redirect, pages get slower, and some browsers and clients do not follow redirects for POST.',
  enabled: 'Enable 302 scheduling',
  target: 'Redirect to', targetAddress: 'Node IP (the node address in the line group)', targetHostname: 'Node direct hostname (nodes without one are not scheduled)',
  keepLabel: 'Keep in redirect', keepPath: 'Keep the path', keepQuery: 'Keep the query string',
  ttl: 'Signature lifetime (seconds)', ttlHint: 'A redirect works for this long; later use is refused (403). 10–3600 seconds.',
  httpsToHttp: 'Redirect HTTPS requests too', httpsToHttpHint: 'Nodes hold no certificate for their own address, so HTTPS requests land on the node\'s HTTP port. Off: HTTPS requests are not redirected.',
  filters: 'Only redirect these requests', filtersHint: 'All empty: every GET/HEAD request is redirected; otherwise all filled conditions must match.',
  extensions: 'File extensions', extensionsPlaceholder: 'mp4, zip, iso',
  pathPrefixes: 'Path prefixes', pathPrefixesPlaceholder: '/download/ /video/',
  minSize: 'Minimum file size (MB)', minSizeHint: '0 means any size. A node records a URL\'s size the first time it serves it; later requests for that URL are redirected once it is this large.',
  noPlainHTTP: 'This site has no HTTP port: scheduled requests land on the node\'s HTTP port. Add an HTTP port under Basic settings first.',
  loadFailed: 'Could not read the 302 scheduling settings', retry: 'Retry',
  save: 'Save', saving: 'Saving', saved: 'Saved. Deploying to the nodes.',
  ttlInvalid: 'An integer from 10 to 3600',
  sizeInvalid: 'A number not below 0',
  errors: {
    schedule302_no_plain_http: 'This site has no HTTP port; 302 scheduling cannot be enabled',
    version_conflict: 'The site was changed; refresh and try again', idempotency_conflict: 'Duplicate request; refresh and try again',
    site_locked: 'The site is locked by a platform administrator', validation_error: 'Invalid input (extensions are letters and digits, path prefixes start with /)',
    unknown: 'Save failed ({{code}})',
  },
}

type Messages = { [key: string]: string | Messages }

// Pseudo-locale like every other namespace: {{name}} placeholders stay intact.
function pseudoText(value: string): string {
  const expanded = value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{') ? part
    : [...part].map((character) => /\s/u.test(character) ? character : `${character}~`).join('')).join('')
  return `［${expanded}］`
}

function pseudo(value: Messages): Messages {
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [
    key,
    typeof child === 'string' ? pseudoText(child) : pseudo(child),
  ]))
}

const pseudoCN = pseudo(zhCN)

export const siteSchedule302Messages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudoCN, 'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(siteSchedule302Messages)) {
  i18n.addResourceBundle(locale, 'siteSchedule302', messages, true, false)
}
