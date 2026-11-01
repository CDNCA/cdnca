import i18n from '../i18n'

const zhCN = {
  title: 'SSH 连接',
  subtitle: '从主控直接登录节点、通过 SSH 安装单台或批量安装节点。登录密码与私钥只经主控加密传输，不会回显。',
  sectionsLabel: 'SSH 功能',
  noPermission: '当前账号没有 SSH 连接或节点管理权限。',
  loading: '加载中…',
  sections: { terminal: 'SSH 终端', single: '单台安装', batch: '批量安装' },
  fields: {
    port: 'SSH 端口', username: 'SSH 用户', auth: '登录方式', password: 'SSH 密码', privateKey: 'SSH 私钥（OpenSSH 未加密）',
    restrictSSH: '仅允许主控 SSH 连接（装好后其他来源连不上 SSH 端口）',
  },
  values: { password: '密码', privateKey: '私钥', saved: '使用已记住的登录' },
  validation: {
    node: '请选择一个节点', port: '端口为 1-65535', username: '用户名格式不正确', secret: '请填写登录信息',
  },
  actions: {
    connect: '连接', disconnect: '断开', readHostKey: '读取主机指纹', forget: '忘记此登录', retry: '重试', cancel: '取消',
  },
  status: { connecting: '连接中', open: '已连接', closed: '已断开', error: '连接失败' },
  codes: {
    client_closed: '已断开连接', remote_exit: '远端 shell 已退出', idle_timeout: '15 分钟无输入，已自动断开',
    max_duration: '会话已达 2 小时上限，已自动断开', session_revoked: '登录会话已失效或权限已撤销，已断开',
    host_key_mismatch: '节点的主机指纹与确认的不一致，已拒绝连接（可能被中间人劫持）',
    ssh_auth_failed: 'SSH 登录失败（用户名、密码或私钥错误）', ssh_unreachable: '无法连接节点 SSH（检查地址、端口与防火墙）',
    host_key_required: '请先读取并确认主机指纹', terminals_busy: '主控同时打开的终端已达上限，请稍后再试',
    node_address_missing: '该节点没有 IP 地址，无法连接', permission_denied: '只有平台管理员可以使用 SSH 终端',
    unauthorized: '登录已过期，请重新登录', open_required: '连接请求无效', not_found: '节点不存在或没有记住的登录',
    invalid_request: '登录信息格式不正确', unavailable: 'SSH 终端暂不可用',
  },
  terminal: {
    title: '连接节点',
    description: '选择一个已接入的节点，主控代为发起 SSH 连接，浏览器内直接操作。首次连接先读取并核对主机指纹。',
    node: '节点', nodePlaceholder: '搜索节点名称或 IP', noNodes: '没有可连接的节点（需有 IP 地址）',
    fingerprint: '主机指纹',
    confirmKey: '我已在节点上核对一致（ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub）',
    hostKeyHelp: '连接前需读取节点的 SSH 主机指纹并核对，未确认不会发送登录信息。',
    remember: '记住此登录（加密保存在主控，下次免输入）',
    rememberHelp: '记住后同时钉定当前主机指纹，之后指纹变化会拒绝连接。可随时「忘记此登录」。',
    savedHint: '将以 {{username}} 登录端口 {{port}}，使用记住时钉定的主机指纹。',
    idle: '未连接', placeholder: '选择节点并连接后，终端显示在这里。',
    screenLabel: 'SSH 终端',
    limits: '空闲 15 分钟或连接满 2 小时自动断开；每次会话（谁、何时、哪台、时长）记入操作日志，不记录键入内容。',
  },
  single: { title: '单台 SSH 安装' },
  batch: {
    title: '批量 SSH 安装',
    description: '每行一台服务器，按格式填写后先预览，格式错误的行标红、不会提交。每台单独安装、互不影响，装好后出现在「待初始化」。',
    lines: '服务器列表', placeholder: '203.0.113.10 22 root 密码\n203.0.113.11 root 密码',
    format: '格式：IP 端口 用户名 密码（每行一台；省略端口时为 22；# 开头为注释）。密码为用户名之后的全部内容。',
    summary: '共 {{valid}} 台可安装，{{invalid}} 行有错误', ok: '可安装',
    columns: { line: '行', host: '服务器', username: '用户', password: '密码', check: '检查' },
    errors: {
      columns: '列数不对', host: '地址无效', port: '端口无效', username: '用户名无效', duplicate: '与上面的行重复', too_many: '超过 100 台',
    },
    concurrency: '主控每次最多同时安装 4 台，其余排队；每台安装超时 20 分钟。',
    start: '开始安装 {{count}} 台',
    hostKeyHelp: '每台先读取 SSH 主机指纹，核对后确认即开始安装；未确认不会发送登录信息。',
    confirmAll: '确认全部指纹并安装（{{count}} 台）',
    retryPassword: '重试 {{host}}（用户 {{username}}）：请重新输入密码',
  },
  access: {
    title: '仅允许主控 SSH 连接',
    description: '开启后，节点防火墙只放行主控出口地址（及下方白名单）访问 SSH 端口，其他来源一律拒绝；关闭恢复原状。节点应用后 5 分钟内未收到主控确认会自动撤销，避免把自己锁在外面。与节点的 fail2ban 防爆破并存。',
    egress: '主控出口地址：{{cidrs}}',
    egressUnknown: '主控未配置 SSH 出口地址（CDNCA_NODE_SSH_CONTROLLER_CIDRS），不能开启，以免锁死。',
    allow: '额外允许的地址（可选）', allowPlaceholder: '运维跳板机 IP 或网段，一行一个，如 198.51.100.0/24',
    saveAllow: '保存白名单',
    unsupportedTag: '节点版本不支持',
    unsupported: '节点版本不支持「仅允许主控 SSH」（节点未声明 SSH_ACCESS 能力），请先升级节点。',
    failure: '原因：{{code}}',
    states: { pending: '待下发', applied: '已应用、待确认', confirmed: '已生效', reverted: '未确认已自动撤销', failed: '应用失败' },
  },
  errors: { unavailable: 'SSH 功能暂不可用，请稍后重试' },
}

type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }
type Messages = MessageShape<typeof zhCN>

const enUS: Messages = {
  title: 'SSH',
  subtitle: 'Log in to nodes from the controller and install one or many nodes over SSH. Passwords and keys travel encrypted through the controller and are never shown again.',
  sectionsLabel: 'SSH features',
  noPermission: 'This account has neither SSH nor node management permission.',
  loading: 'Loading…',
  sections: { terminal: 'SSH terminal', single: 'Single install', batch: 'Batch install' },
  fields: {
    port: 'SSH port', username: 'SSH user', auth: 'Login', password: 'SSH password', privateKey: 'SSH private key (unencrypted OpenSSH)',
    restrictSSH: 'Only the controller may SSH (other sources cannot reach the SSH port once installed)',
  },
  values: { password: 'Password', privateKey: 'Private key', saved: 'Saved login' },
  validation: {
    node: 'Choose a node', port: 'Port must be 1-65535', username: 'Invalid user name', secret: 'Enter the login',
  },
  actions: {
    connect: 'Connect', disconnect: 'Disconnect', readHostKey: 'Read host key', forget: 'Forget this login', retry: 'Retry', cancel: 'Cancel',
  },
  status: { connecting: 'Connecting', open: 'Connected', closed: 'Disconnected', error: 'Failed' },
  codes: {
    client_closed: 'Disconnected', remote_exit: 'The remote shell exited', idle_timeout: 'Disconnected after 15 minutes without input',
    max_duration: 'Disconnected at the 2 hour session limit', session_revoked: 'Your sign-in expired or the permission was revoked',
    host_key_mismatch: 'The node\'s host key differs from the confirmed one; refused (possible man in the middle)',
    ssh_auth_failed: 'SSH login failed (wrong user, password or key)', ssh_unreachable: 'Cannot reach the node\'s SSH (check the address, port and firewall)',
    host_key_required: 'Read and confirm the host key first', terminals_busy: 'Too many terminals are open on the controller; try again later',
    node_address_missing: 'The node has no IP address', permission_denied: 'Only platform administrators can use the SSH terminal',
    unauthorized: 'Your sign-in expired; sign in again', open_required: 'Invalid connection request', not_found: 'The node or its saved login does not exist',
    invalid_request: 'Invalid login', unavailable: 'The SSH terminal is unavailable',
  },
  terminal: {
    title: 'Connect to a node',
    description: 'Choose a connected node; the controller opens the SSH connection and you work in the browser. The first connection reads the host key for you to compare.',
    node: 'Node', nodePlaceholder: 'Search by node name or IP', noNodes: 'No node to connect to (it needs an IP address)',
    fingerprint: 'Host key',
    confirmKey: 'I compared it on the node (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)',
    hostKeyHelp: 'Read and compare the node\'s SSH host key before connecting; no login is sent before that.',
    remember: 'Remember this login (stored encrypted on the controller)',
    rememberHelp: 'Remembering also pins this host key; a later change is refused. You can forget it at any time.',
    savedHint: 'Logs in as {{username}} on port {{port}} with the host key pinned when it was saved.',
    idle: 'Not connected', placeholder: 'Choose a node and connect; the terminal appears here.',
    screenLabel: 'SSH terminal',
    limits: 'Sessions end after 15 idle minutes or 2 hours. Each session (who, when, which node, how long) is in the operation log; keystrokes are not recorded.',
  },
  single: { title: 'Install one server over SSH' },
  batch: {
    title: 'Batch install over SSH',
    description: 'One server per line. Preview first: lines with format errors are marked red and not sent. Each server is installed separately and then appears under Pending initialization.',
    lines: 'Servers', placeholder: '203.0.113.10 22 root password\n203.0.113.11 root password',
    format: 'Format: IP port user password (one server per line; port 22 when omitted; # starts a comment). The password is everything after the user.',
    summary: '{{valid}} servers to install, {{invalid}} lines with errors', ok: 'Ready',
    columns: { line: 'Line', host: 'Server', username: 'User', password: 'Password', check: 'Check' },
    errors: {
      columns: 'Wrong number of columns', host: 'Invalid address', port: 'Invalid port', username: 'Invalid user', duplicate: 'Duplicate of a line above', too_many: 'More than 100 servers',
    },
    concurrency: 'The controller installs at most 4 servers at once and queues the rest; each install times out after 20 minutes.',
    start: 'Install {{count}} servers',
    hostKeyHelp: 'Each server\'s SSH host key is read first; confirm it to start installing. No login is sent before that.',
    confirmAll: 'Confirm all host keys and install ({{count}})',
    retryPassword: 'Retry {{host}} (user {{username}}): enter the password again',
  },
  access: {
    title: 'Only the controller may SSH',
    description: 'When on, the node\'s firewall only lets the controller\'s egress addresses (and the allowlist below) reach the SSH port and refuses every other source; off restores it. If the controller does not confirm within 5 minutes after the node applies it, the node reverts by itself so you cannot be locked out. Works alongside the node\'s fail2ban.',
    egress: 'Controller egress: {{cidrs}}',
    egressUnknown: 'The controller has no SSH egress address configured (CDNCA_NODE_SSH_CONTROLLER_CIDRS), so it cannot be turned on without a lockout risk.',
    allow: 'Also allow (optional)', allowPlaceholder: 'Jump host IPs or networks, one per line, e.g. 198.51.100.0/24',
    saveAllow: 'Save allowlist',
    unsupportedTag: 'Node version not supported',
    unsupported: 'This node version does not support "only the controller may SSH" (the node does not declare SSH_ACCESS); upgrade the node first.',
    failure: 'Reason: {{code}}',
    states: { pending: 'Pending', applied: 'Applied, awaiting confirmation', confirmed: 'Active', reverted: 'Reverted (not confirmed)', failed: 'Failed' },
  },
  errors: { unavailable: 'SSH is unavailable; try again later' },
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value} · ${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as Messages

export const nodeSSHPanelMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo,
  'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(nodeSSHPanelMessages)) {
  i18n.addResourceBundle(locale, 'nodeSSHPanel', messages, true, true)
}
