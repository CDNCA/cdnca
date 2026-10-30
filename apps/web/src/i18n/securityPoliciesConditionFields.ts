import i18n from './index'

// Grouped rule condition fields with a one-line
// help each; JA4 and the IP intelligence fields in the WAF rule editor.
const zhCN = {
  fields: {
    ja4: 'TLS 指纹（JA4）', country: '国家/地区', asn: 'ASN', province: '省份', city: '城市', carrier: '运营商', ip_tag: 'IDC 机房',
  },
  operatorsMap: { in: '在列表内', not_in: '不在列表内' },
  conditionFields: {
    groups: { basic: '基础', client: '客户端', content: '请求头与内容', fingerprint: 'Bot 与指纹', geo: '地理与网络' },
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
    },
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
  },
  operatorsMap: { in: 'In list', not_in: 'Not in list' },
  conditionFields: {
    groups: { basic: 'Basic', client: 'Client', content: 'Headers and content', fingerprint: 'Bot and fingerprint', geo: 'Geo and network' },
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
    },
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
