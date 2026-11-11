import i18n from './index'

// Grouped rule condition fields with a one-line
// help each; JA4 and the IP intelligence fields in the WAF rule editor.
const zhCN = {
  fields: {
    ja4: 'TLS 指纹（JA4）', country: '国家/地区', asn: 'ASN', province: '省份', city: '城市', carrier: '运营商', ip_tag: 'IDC 机房',
    browser: '浏览器', browser_version: '浏览器版本', device: '设备类型', request_time: '请求时间',
  },
  operatorsMap: {
    in: '在列表内', not_in: '不在列表内', in_string_set: '在字符串集合中', not_in_string_set: '不在字符串集合中',
    version_eq: '等于', version_gte: '不低于', version_lt: '低于', in_time_range: '在时间段内', not_in_time_range: '不在时间段内',
  },
  conditionFields: {
    groups: { basic: '基础', client: '客户端与设备', content: '请求头与内容', fingerprint: 'Bot 与指纹', geo: '地理与网络', time: '时间' },
    help: {
      path: '请求路径，不含查询串', method: '请求方法，如 GET、POST', host: '请求的域名', port: '客户端访问的端口',
      http_version: 'HTTP 协议版本：1.0、1.1、2、3', request_uri: '完整 URI，含查询串', uri_length: 'URI 的字节长度',
      client_ip: '客户端 IP 或网段（CIDR）', ip_list: '网站 → IP 名单里维护的一组地址',
      distinct_user_agents: '同一客户端在统计窗口内用过的不同 UA 数', status_404_count: '同一客户端在统计窗口内得到的 404 次数',
      header: '指定名称的请求头的值', user_agent: '浏览器 UA（User-Agent 请求头）', referer: '请求来源（Referer 请求头）',
      cookie: 'Cookie 的值，可指定 Cookie 名', args: '查询参数与表单字段', query: '查询串参数', body: '请求体内容',
      header_names: '所有请求头名称', content_type: '请求的 Content-Type', upload_filename: '上传文件的文件名',
      upload_extension: '上传文件的扩展名', multipart_field_names: 'Multipart 表单的字段名',
      request_length: '整个请求的字节数', body_length: '请求体字节数', header_max_length: '最长那个请求头的长度',
      header_count: '请求头个数', arg_count: '参数个数', multipart_part_count: 'Multipart 分段个数',
      multipart_field_max_length: '最长 Multipart 字段的长度',
      ja4: 'TLS 握手的客户端指纹，可识别脚本、爬虫工具；明文 HTTP 与 HTTP/3 请求没有指纹，不会命中',
      country: '客户端 IP 所属国家/地区（两位代码，如 CN、US）', asn: '客户端 IP 所属 AS 号码',
      province: '客户端 IP 所属省份（六位行政区划代码，如 440000）', city: '客户端 IP 所属城市（六位代码，如 440300）',
      carrier: '客户端 IP 所属运营商', ip_tag: '客户端 IP 是否属于 IDC 机房（服务器）网段',
      browser: '按 User-Agent 识别，可被伪造，适合分流和粗过滤，不能当身份认证',
      browser_version: '不是所选浏览器的请求不命中；识别不出版本号时不命中',
      device: '只看 User-Agent；“爬虫或脚本”指自称爬虫或脚本客户端，放行真实爬虫请用快速屏蔽的爬虫校验',
      request_time: '按节点时间判断，夏令时自动处理',
    },
    browsers: {
      wechat_browser: '微信内置浏览器', qq_browser: 'QQ 浏览器', uc_browser: 'UC 浏览器', baidu_browser: '百度浏览器', sogou_browser: '搜狗浏览器',
      '360_browser': '360 浏览器（识别率有限）', microsoft_edge: '微软 Edge', opera: 'Opera', samsung_browser: '三星浏览器', firefox: 'Firefox',
      google_chrome: '谷歌 Chrome', safari: 'Safari', unknown: '无法识别',
    },
    devices: { mobile: '手机', tablet: '平板', desktop: '桌面', bot: '爬虫或脚本' },
    stringSet: {
      select: '选择字符串集合', option: '{{name}} · {{mode}} · {{count}} 条', create: '新建集合',
      ja4Only: 'JA4 只能引用“完全相等、区分大小写”的集合', unavailable: '集合不存在或不能使用',
      modes: { exact: '完全相等', prefix: '前缀', suffix: '后缀', contains: '包含', wildcard: '通配符' },
    },
    version: { browser: '浏览器', value: '版本号', invalid: '版本号只能是数字和点，如 100 或 119.0.6045' },
    time: {
      zone: '时区', weekly: '每周', ranges: '日期区间', from: '开始', to: '结束', addSlot: '再加一段', remove: '删除这一段',
      days: { mon: '一', tue: '二', wed: '三', thu: '四', fri: '五', sat: '六', sun: '日' },
      dayNames: { mon: '星期一', tue: '星期二', wed: '星期三', thu: '星期四', fri: '星期五', sat: '星期六', sun: '星期日' },
      noDay: '至少选一天', sameTime: '开始和结束不能相同', noRange: '选择开始和结束时间', unknownZone: '无法识别的时区',
      maxWeekly: '最多 7 段', maxRanges: '最多 4 段',
    },
    tryUA: {
      button: '试一下', title: '解析 User-Agent', input: 'User-Agent', parse: '解析',
      result: '浏览器：{{browser}} {{version}} · 设备：{{device}}', failed: '解析失败，请稍后重试。',
    },
    v6Hint: '字符串集合、浏览器、设备类型与请求时间条件需要节点支持 WAF v6；不支持的节点会拒绝发布并列出。',
    placeholder: {
      ja4: '一行一个 JA4，如\nt13d1516h2_8daaf6152771_b186095e22b6',
      country: '一行一个，如\nCN\nUS', asn: '一行一个，如\n4134', province: '一行一个，如\n440000', city: '一行一个，如\n440300',
      carrier: '一行一个：carrier:cn-telecom、carrier:cn-unicom、carrier:cn-mobile、carrier:cn-cernet 等',
      ip_tag: '一行一个：idc:cn（国内机房）、idc:global（境外机房）',
    },
    singleValue: '“等于/不等于”只能填一个值，多个请选“在列表内/不在列表内”',
    ja4Invalid: 'JA4 指纹格式不对：{{values}}。应形如 t13d1516h2_8daaf6152771_b186095e22b6，可从访问日志复制',
    nodeHint: 'JA4 条件需要节点启用 JA4 模块，“不在列表内”还需节点支持 WAF_JA4_NEGATION；地理与网络条件需要节点已同步 IP 情报库。不满足的节点会拒绝发布并提示“节点版本过低”。',
  },
}

type Messages = typeof zhCN

const enUS: Messages = {
  fields: {
    ja4: 'TLS fingerprint (JA4)', country: 'Country/region', asn: 'ASN', province: 'Province', city: 'City', carrier: 'Carrier', ip_tag: 'IDC',
    browser: 'Browser', browser_version: 'Browser version', device: 'Device type', request_time: 'Request time',
  },
  operatorsMap: {
    in: 'In list', not_in: 'Not in list', in_string_set: 'In string set', not_in_string_set: 'Not in string set',
    version_eq: 'Equals', version_gte: 'At least', version_lt: 'Below', in_time_range: 'Within', not_in_time_range: 'Outside',
  },
  conditionFields: {
    groups: { basic: 'Basic', client: 'Client and device', content: 'Headers and content', fingerprint: 'Bot and fingerprint', geo: 'Geo and network', time: 'Time' },
    help: {
      path: 'Request path without the query string', method: 'Request method, such as GET or POST', host: 'Requested host', port: 'Port the client connected to',
      http_version: 'HTTP version: 1.0, 1.1, 2, 3', request_uri: 'Full URI with the query string', uri_length: 'URI length in bytes',
      client_ip: 'Client IP address or network (CIDR)', ip_list: 'A named list maintained under Site → IP lists',
      distinct_user_agents: 'Distinct user agents one client used in the window', status_404_count: '404 responses one client got in the window',
      header: 'Value of the named request header', user_agent: 'Browser user agent (User-Agent header)', referer: 'Request source (Referer header)',
      cookie: 'Cookie value, optionally one named cookie', args: 'Query and form arguments', query: 'Query string arguments', body: 'Request body',
      header_names: 'All request header names', content_type: 'Request Content-Type', upload_filename: 'Uploaded file name',
      upload_extension: 'Uploaded file extension', multipart_field_names: 'Multipart form field names',
      request_length: 'Whole request size in bytes', body_length: 'Request body size in bytes', header_max_length: 'Length of the longest header',
      header_count: 'Number of request headers', arg_count: 'Number of arguments', multipart_part_count: 'Number of multipart parts',
      multipart_field_max_length: 'Length of the longest multipart field',
      ja4: 'TLS ClientHello fingerprint, identifies scripts and crawler tools; plain HTTP and HTTP/3 requests have none and never match',
      country: 'Country/region of the client IP (two letters, such as CN, US)', asn: 'AS number of the client IP',
      province: 'Province of the client IP (six digit code, such as 440000)', city: 'City of the client IP (six digit code, such as 440300)',
      carrier: 'Carrier of the client IP', ip_tag: 'Whether the client IP is in a data center (IDC) network',
      browser: 'Detected from the User-Agent, which clients can fake. Use it for routing and coarse filtering, not authentication.',
      browser_version: 'Requests from other browsers do not match, nor do requests whose version cannot be detected.',
      device: 'Based on the User-Agent only. "Bot or script" means a client that says it is a crawler or script; to allow real crawlers, use the crawler check in quick block.',
      request_time: 'Evaluated on the edge node\'s clock; daylight saving time is handled.',
    },
    browsers: {
      wechat_browser: 'WeChat browser', qq_browser: 'QQ Browser', uc_browser: 'UC Browser', baidu_browser: 'Baidu Browser', sogou_browser: 'Sogou Browser',
      '360_browser': '360 Browser (limited detection)', microsoft_edge: 'Microsoft Edge', opera: 'Opera', samsung_browser: 'Samsung Internet', firefox: 'Firefox',
      google_chrome: 'Google Chrome', safari: 'Safari', unknown: 'Not detected',
    },
    devices: { mobile: 'Mobile', tablet: 'Tablet', desktop: 'Desktop', bot: 'Bot or script' },
    stringSet: {
      select: 'Choose a string set', option: '{{name}} · {{mode}} · {{count}}', create: 'New set',
      ja4Only: 'JA4 can only use exact, case-sensitive sets', unavailable: 'The set does not exist or cannot be used',
      modes: { exact: 'Exact', prefix: 'Prefix', suffix: 'Suffix', contains: 'Contains', wildcard: 'Wildcard' },
    },
    version: { browser: 'Browser', value: 'Version', invalid: 'Use digits and dots only, such as 100 or 119.0.6045' },
    time: {
      zone: 'Time zone', weekly: 'Weekly', ranges: 'Date ranges', from: 'From', to: 'To', addSlot: 'Add a slot', remove: 'Remove this slot',
      days: { mon: 'Mon', tue: 'Tue', wed: 'Wed', thu: 'Thu', fri: 'Fri', sat: 'Sat', sun: 'Sun' },
      dayNames: { mon: 'Monday', tue: 'Tuesday', wed: 'Wednesday', thu: 'Thursday', fri: 'Friday', sat: 'Saturday', sun: 'Sunday' },
      noDay: 'Choose at least one day', sameTime: 'Start and end cannot be the same', noRange: 'Choose a start and an end', unknownZone: 'Unknown time zone',
      maxWeekly: 'At most 7 slots', maxRanges: 'At most 4 ranges',
    },
    tryUA: {
      button: 'Try it', title: 'Parse a User-Agent', input: 'User-Agent', parse: 'Parse',
      result: 'Browser: {{browser}} {{version}} · Device: {{device}}', failed: 'Parsing failed; try again later.',
    },
    v6Hint: 'String set, browser, device type and request time conditions need nodes with WAF v6; other nodes refuse the release and are listed.',
    placeholder: {
      ja4: 'One JA4 per line, such as\nt13d1516h2_8daaf6152771_b186095e22b6',
      country: 'One per line, such as\nCN\nUS', asn: 'One per line, such as\n4134', province: 'One per line, such as\n440000', city: 'One per line, such as\n440300',
      carrier: 'One per line: carrier:cn-telecom, carrier:cn-unicom, carrier:cn-mobile, carrier:cn-cernet ...',
      ip_tag: 'One per line: idc:cn (China data centers), idc:global (elsewhere)',
    },
    singleValue: 'Equals / not equals take one value; choose in list / not in list for several',
    ja4Invalid: 'Not a JA4 fingerprint: {{values}}. Expected the form t13d1516h2_8daaf6152771_b186095e22b6; copy it from the access log',
    nodeHint: 'JA4 conditions need nodes with the JA4 module, "not in list" also WAF_JA4_NEGATION; geo and network conditions need nodes that synced the IP intelligence library. Other nodes refuse the release as "node version too old".',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const conditionFieldMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN) as Messages, 'qps-Ploc': pseudo(zhCN) as Messages,
}

for (const [locale, messages] of Object.entries(conditionFieldMessages)) {
  i18n.addResourceBundle(locale, 'securityPolicies', messages, true, true)
}
