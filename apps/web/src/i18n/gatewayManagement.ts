import i18n from './index'

type TranslationTree = { [key: string]: string | TranslationTree }

const zhCN = {
  title: '网关管理',
  description: '独立网关装在另一台机器上，和主控自带的本机网关一起为节点服务。添加网关得到一次性绑定令牌（1 小时内有效、只能用一次），在网关机上执行安装命令即可接入。',
  local: {
    current: '本主控当前使用主控自带的本机网关，节点都通过它连接主控。',
    nodes: '现有 {{count}} 台节点都连在本机网关上。',
    optional: '独立网关是可选的：装在另一台机器上，用作冗余或分机部署；不装也不影响使用。',
    closed: '本主控还没有开启独立网关接入，所以这里暂时不能添加网关。需要时请在主控机上以 root 执行下面这条命令开启（只需执行一次，会短暂重启主控服务，节点会自动重连）：',
    command: '开启独立网关接入的命令',
    copy: '复制命令',
    copied: '已复制',
    after: '执行完成后刷新本页，就可以添加独立网关了。',
  },
  add: '添加网关',
  refresh: '刷新',
  empty: '还没有独立网关。主控自带的本机网关不在此列表。',
  columns: { name: '名称', host: '网关地址', ports: '注册 / 通道端口', status: '状态', version: '版本', certificates: '证书到期', allowedIPs: '放行 IP', actions: '操作' },
  status: { pending: '待绑定', bound: '已绑定', active: '在线', disabled: '已停用', deleted: '已删除' },
  certificate: { client: '客户端 {{date}}', server: '服务端 {{date}}' },
  actions: { token: '重发令牌', allowedIPs: '放行 IP', disable: '停用', enable: '启用', delete: '删除' },
  confirm: {
    disable: '停用后该网关不再接入新节点，并通知已连节点切换到其他网关；30 分钟后仍未切走的节点会被断开（重连到其他网关）。',
    delete: '删除后吊销该网关全部证书，不能恢复；要重新接入请重新添加。',
    ok: '确定', cancel: '取消',
  },
  form: {
    title: '添加网关', name: '名称', namePlaceholder: '例如 gw-hk-1', nameRequired: '请填写名称（1–64 个字符）',
    host: '网关公网地址', hostPlaceholder: '域名或 IP，节点用它连接网关', hostRequired: '请填写合法的域名或 IP',
    submit: '生成令牌', cancel: '取消',
  },
  command: {
    title: '网关安装命令', description: '在网关机上以 root 执行。令牌只显示这一次，{{expires}} 前有效；过期或丢失请点“重发令牌”。',
    label: '网关安装命令', copy: '复制命令', copied: '已复制', copyFailed: '复制失败，请手动选择命令复制', close: '关闭',
    noInstaller: '本页面没有取到授权端地址，无法生成完整命令；请从授权门户下载 install-control.sh，用下面的令牌执行 --mode gateway。',
    token: '绑定令牌',
    publicCertificate: '网关对节点出示的证书默认由本主控根 CA 签发。网关套 CDN 且 CDN 回源要校验源站证书时，在命令末尾加 --server-cert <公网证书链> --server-key <私钥>（只用于 CDN 回源那一层 TLS）。',
  },
  allowedIPs: {
    title: '放行 IP', label: '放行 IP（每行一个）', save: '保存',
    description: '主控只接受这些地址的网关连接，主机防火墙同步更新。默认是绑定时的来源地址 {{source}}；网关出口与入口地址不同（NAT）时在这里改。',
    invalid: '请每行填写一个 IPv4 或 IPv6 地址（1–16 个，不能是网段）',
  },
  settings: {
    title: '网关下发设置', save: '保存并下发', saved: '已保存，网关 1 分钟内生效',
    changed: '设置已被他人修改，未保存。已重新读取最新设置，请在此基础上重新修改。', loadFailed: '网关下发设置加载失败',
    confirmTitle: '确认保存并下发？', confirmContent: '保存后会下发到所有网关，并经网关下发到所有节点，约 1 分钟内生效。可信回源 IP 段或节点入口写错会影响节点真实 IP 识别和节点接入。', confirmOk: '确认下发', confirmCancel: '取消',
    proxies: '可信 CDN 回源 IP 段', entrypoints: '额外节点入口',
    proxiesHint: '可信 CDN 回源 IP 段（每行 网段=请求头，不写请求头即 X-Forwarded-For）。只预置了 Cloudflare；用其他 CDN 时请添加该 CDN 的回源 IP 段，否则节点真实 IP 会显示为 CDN 地址。',
    entrypointsHint: '额外节点入口（每行 地址:端口 网关证书名 grpc|ws [外层域名]），排在在线网关之后下发给节点。套 CDN 就加一行 CDN 域名:443 ws。',
    invalidProxies: '可信回源段格式不对：每行一个网段，可选 =请求头', invalidEntrypoints: '节点入口格式不对：地址:端口 证书名 grpc|ws [外层域名]（外层域名只用于 ws）',
  },
  errors: {
    forbidden: '没有网关管理权限', load: '网关列表加载失败', permissionDenied: '没有权限执行此操作',
    nameTaken: '名称已被其他网关使用', conflict: '网关当前状态不允许此操作，请刷新后重试', invalid: '输入不合法', failed: '操作失败，请稍后重试',
  },
  done: { disabled: '已停用', enabled: '已启用', deleted: '已删除', allowedIPs: '放行 IP 已保存' },
}

const enUS: typeof zhCN = {
  title: 'Gateways',
  description: 'Standalone Gateways run on separate hosts and serve nodes together with the control plane\'s own local Gateway. Adding one returns a one-time binding token (valid 1 hour, single use); run the install command on the Gateway host.',
  local: {
    current: 'This control plane uses its own local Gateway; nodes connect through it.',
    nodes: 'All {{count}} nodes are connected to the local Gateway.',
    optional: 'Standalone Gateways are optional: run them on other hosts for redundancy or a split deployment. Everything works without them.',
    closed: 'Standalone Gateway access is not turned on yet, so Gateways cannot be added here. When you need it, run this command once as root on the control host (control services restart briefly; nodes reconnect on their own):',
    command: 'Command that turns on standalone Gateway access',
    copy: 'Copy command',
    copied: 'Copied',
    after: 'Refresh this page when it finishes; you can then add standalone Gateways.',
  },
  add: 'Add Gateway',
  refresh: 'Refresh',
  empty: 'No standalone Gateways. The control plane\'s own local Gateway is not listed.',
  columns: { name: 'Name', host: 'Gateway address', ports: 'Enrollment / agent port', status: 'Status', version: 'Version', certificates: 'Certificates expire', allowedIPs: 'Allowed IPs', actions: 'Actions' },
  status: { pending: 'Waiting for binding', bound: 'Bound', active: 'Online', disabled: 'Disabled', deleted: 'Deleted' },
  certificate: { client: 'Client {{date}}', server: 'Server {{date}}' },
  actions: { token: 'New token', allowedIPs: 'Allowed IPs', disable: 'Disable', enable: 'Enable', delete: 'Delete' },
  confirm: {
    disable: 'The Gateway takes no new nodes and asks connected ones to move to another Gateway; nodes still connected after 30 minutes are disconnected and reconnect elsewhere.',
    delete: 'All certificates of this Gateway are revoked. This cannot be undone; add it again to reconnect.',
    ok: 'OK', cancel: 'Cancel',
  },
  form: {
    title: 'Add Gateway', name: 'Name', namePlaceholder: 'e.g. gw-hk-1', nameRequired: 'Enter a name (1-64 characters)',
    host: 'Gateway public address', hostPlaceholder: 'Domain or IP nodes connect to', hostRequired: 'Enter a valid domain or IP',
    submit: 'Create token', cancel: 'Cancel',
  },
  command: {
    title: 'Gateway install command', description: 'Run as root on the Gateway host. The token is shown only once and is valid until {{expires}}; use "New token" if it expired or was lost.',
    label: 'Gateway install command', copy: 'Copy command', copied: 'Copied', copyFailed: 'Copy failed; select the command and copy it manually', close: 'Close',
    noInstaller: 'This console does not know the authorization center address; download install-control.sh from the portal and run --mode gateway with this token.',
    token: 'Binding token',
    publicCertificate: 'The Gateway presents a certificate signed by this control plane\'s root CA. If the Gateway sits behind a CDN that verifies origin certificates, append --server-cert <public chain> --server-key <key> (used only for the CDN-facing TLS).',
  },
  allowedIPs: {
    title: 'Allowed IPs', label: 'Allowed IPs (one per line)', save: 'Save',
    description: 'The control plane accepts this Gateway only from these addresses; the host firewall follows. Default is the binding source address {{source}}; change it when the Gateway egress differs from its address (NAT).',
    invalid: 'Enter one IPv4 or IPv6 address per line (1-16, no ranges)',
  },
  settings: {
    title: 'Published Gateway settings', save: 'Save and publish', saved: 'Saved; Gateways apply it within a minute',
    changed: 'Someone else changed the settings, so nothing was saved. The latest settings were reloaded; make your changes again.', loadFailed: 'Could not load the published Gateway settings',
    confirmTitle: 'Save and publish?', confirmContent: 'This is published to every Gateway and through them to every node within about a minute. Wrong trusted ranges or entry points affect real client IPs and node connections.', confirmOk: 'Publish', confirmCancel: 'Cancel',
    proxies: 'Trusted CDN back-to-origin ranges', entrypoints: 'Extra node entry points',
    proxiesHint: 'Trusted CDN back-to-origin ranges (one cidr=Header per line; no header means X-Forwarded-For). Only Cloudflare is preset; add your CDN\'s ranges or node real IPs show as CDN addresses.',
    entrypointsHint: 'Extra node entry points (one "host:port gateway-cert-name grpc|ws [outer host]" per line), listed to nodes after the online Gateways. Behind a CDN add "cdn-host:443 ... ws".',
    invalidProxies: 'Invalid range: one cidr per line, optional =Header', invalidEntrypoints: 'Invalid entry: host:port cert-name grpc|ws [outer host] (outer host for ws only)',
  },
  errors: {
    forbidden: 'You cannot manage Gateways', load: 'Could not load Gateways', permissionDenied: 'You are not allowed to do this',
    nameTaken: 'Another Gateway uses this name', conflict: 'The Gateway state does not allow this; refresh and retry', invalid: 'Invalid input', failed: 'The operation failed; try again later',
  },
  done: { disabled: 'Disabled', enabled: 'Enabled', deleted: 'Deleted', allowedIPs: 'Allowed IPs saved' },
}

function pseudo(value: string | TranslationTree): string | TranslationTree {
  if (typeof value === 'string') return `［${value.replace(/\S/g, '$&~')}］`
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, pseudo(item)]))
}

for (const [locale, messages] of Object.entries({
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo(zhCN),
  'qps-Ploc': pseudo(zhCN),
})) {
  i18n.addResourceBundle(locale, 'gatewayManagement', messages, true, true)
}

export { enUS, zhCN }
