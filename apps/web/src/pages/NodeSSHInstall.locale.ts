import i18n from '../i18n'

const zhCN = {
  tab: 'SSH 远程安装',
  commandTab: '复制命令安装',
  description: '填写一台或多台服务器的 IP 与 SSH 登录信息，主控登录后执行与左侧相同的安装命令；节点完成注册后出现在「待初始化」列表。登录密码或私钥加密保存，任务结束即删除，不会回显。',
  fields: {
    hosts: '服务器 IP 或域名', port: 'SSH 端口', username: 'SSH 用户', auth: '登录方式',
    password: 'SSH 密码', privateKey: 'SSH 私钥（OpenSSH 未加密）',
  },
  placeholders: { hosts: '一行一个，或用逗号、空格分隔，最多 100 台' },
  help: {
    hosts: '多台服务器使用相同的端口和登录信息，每台单独安装、互不影响。',
    password: '非 root 用户需有 sudo 权限，密码同时用于 sudo（只经标准输入传给 sudo，不出现在命令行）。',
    privateKey: '粘贴完整私钥（-----BEGIN OPENSSH PRIVATE KEY----- 开头）。非 root 用户需要免密 sudo。',
    refreshedAt: '下表为最近的安装任务（含关闭弹窗前提交的），状态更新于 {{time}}。',
    hostKey: '首次连接只读取服务器的 SSH 主机指纹，请在服务器上执行 ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 核对一致后点击「确认指纹并安装」；未确认前不会发送登录信息。',
  },
  values: { password: '密码', privateKey: '私钥' },
  columns: { host: '服务器', state: '状态', hostKey: '主机指纹', detail: '进度', actions: '操作' },
  states: {
    awaiting_host_key: '待确认指纹', pending: '排队中', running: '安装中', succeeded: '已完成', failed: '失败', cancelled: '已取消',
    installed_pending_initialization: '已安装、待初始化',
    installed_pending_ticket: '已安装、待首票',
    installed_banned: '已安装、已被封禁',
    installed_ticket_expired: '已安装、凭据已过期',
    installed_resume_failed: '已安装、恢复服务失败',
  },
  failures: {
    host_key_mismatch: '主机指纹与确认的不一致，已停止（可能被中间人劫持）',
    ssh_unreachable: '无法连接 SSH（检查 IP、端口与防火墙）',
    ssh_auth_failed: 'SSH 登录失败（用户名、密码或私钥错误）',
    install_failed: '安装脚本执行失败，见进度中的最后一行',
    install_timeout: '安装超时（20 分钟）',
    credential_unavailable: '登录信息无法解密（主控密钥已更换），请重新提交',
    registration_unavailable: '主控未配置节点注册密钥，无法安装',
    installed_pending_initialization: '已安装、待初始化：节点已连上主控，请到「节点列表 → 待初始化」初始化该节点，初始化后自动下发授权签名凭据并开始服务',
    installed_pending_ticket: '已安装、等待授权凭据生效：请在节点上查看 journalctl -u cdnca-edge-agent 中 installation ban 的报错，并确认主控能连上授权端、许可证有效（「授权」页）；若该节点仍在「节点列表 → 待初始化」中，先初始化。凭据生效后节点自动开放',
    installed_banned: '已安装、已被封禁：本主控安装已被授权方停用，节点不对外服务（所有站点 503、四层关闭）。请联系授权方处理，解除后节点自动恢复',
    installed_ticket_expired: '已安装、凭据已过期：节点持有的授权签名凭据已过期，节点不对外服务（所有站点 503、四层关闭）。请确认主控能连上授权端、客户与许可证有效',
    installed_resume_failed: '已安装、恢复服务失败：授权签名凭据已生效，但节点恢复对外服务失败，仍不对外服务（所有站点 503、四层关闭）。Agent 每分钟自动重试；请在节点上查看 journalctl -u cdnca-edge-agent 中 installation ban 的报错',
  },
  actions: { start: '开始', confirm: '确认指纹并安装', cancel: '取消' },
  validation: {
    hosts: '请填写 1 到 100 个服务器地址', port: '端口为 1-65535', username: '用户名格式不正确',
    secret: '请填写登录信息',
  },
  errors: { unavailable: 'SSH 远程安装暂不可用，请稍后重试', ssh_install_in_progress: '该服务器已有进行中的安装任务', refreshFailed: '安装任务状态更新失败：{{reason}}。下表可能不是最新状态，进行中的任务会继续自动重试读取。' },
}

type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }
type Messages = MessageShape<typeof zhCN>

const enUS: Messages = {
  tab: 'SSH remote install',
  commandTab: 'Install with a command',
  description: 'Enter the IPs and SSH login of one or more servers. The controller logs in and runs the same install command as the other tab; each node then registers and appears under Pending initialization. The password or private key is stored encrypted, deleted when the job ends and never shown again.',
  fields: {
    hosts: 'Server IPs or host names', port: 'SSH port', username: 'SSH user', auth: 'Login',
    password: 'SSH password', privateKey: 'SSH private key (unencrypted OpenSSH)',
  },
  placeholders: { hosts: 'One per line, or separated by commas or spaces; up to 100' },
  help: {
    hosts: 'All servers use the same port and login; each one is installed separately.',
    password: 'A non-root user needs sudo; the password is also given to sudo (on its standard input, never on the command line).',
    privateKey: 'Paste the whole key (starting with -----BEGIN OPENSSH PRIVATE KEY-----). A non-root user needs passwordless sudo.',
    refreshedAt: 'Recent install jobs, including ones submitted before the dialog was closed. Status updated at {{time}}.',
    hostKey: 'The first connection only reads the server\'s SSH host key. Compare it with ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub on the server, then choose Confirm and install; no login is sent before that.',
  },
  values: { password: 'Password', privateKey: 'Private key' },
  columns: { host: 'Server', state: 'State', hostKey: 'Host key', detail: 'Progress', actions: 'Actions' },
  states: {
    awaiting_host_key: 'Confirm host key', pending: 'Queued', running: 'Installing', succeeded: 'Done', failed: 'Failed', cancelled: 'Cancelled',
    installed_pending_initialization: 'Installed, pending initialization',
    installed_pending_ticket: 'Installed, awaiting first ticket',
    installed_banned: 'Installed, banned',
    installed_ticket_expired: 'Installed, ticket expired',
    installed_resume_failed: 'Installed, resume failed',
  },
  failures: {
    host_key_mismatch: 'The host key differs from the confirmed one; stopped (possible man in the middle)',
    ssh_unreachable: 'Cannot reach SSH (check the IP, port and firewall)',
    ssh_auth_failed: 'SSH login failed (wrong user, password or key)',
    install_failed: 'The installer failed; see the last progress line',
    install_timeout: 'Installation timed out (20 minutes)',
    credential_unavailable: 'The login cannot be decrypted (controller key changed); submit again',
    registration_unavailable: 'The controller has no node registration key configured',
    installed_pending_initialization: 'Installed, pending initialization: the node is connected to the controller. Initialize it under Nodes → Pending initialization; it then receives its license ticket and starts serving',
    installed_pending_ticket: 'Installed, waiting for the license credential: check installation ban errors in journalctl -u cdnca-edge-agent on the node, and that the controller reaches the license service with a valid license (License page); if the node is still under Pending initialization, initialize it first. The node opens automatically once the credential is active',
    installed_banned: 'Installed, banned: the license side has disabled this controller installation, so the node does not serve (all sites 503, layer 4 closed). Contact the licensor; the node recovers by itself once lifted',
    installed_ticket_expired: 'Installed, ticket expired: the license ticket the node holds has expired, so the node does not serve (all sites 503, layer 4 closed). Check that the controller reaches the license service and the customer and license are valid',
    installed_resume_failed: 'Installed, resume failed: the license ticket is valid but the node could not resume serving, so it still does not serve (all sites 503, layer 4 closed). The Agent retries every minute; check installation ban errors in journalctl -u cdnca-edge-agent on the node',
  },
  actions: { start: 'Start', confirm: 'Confirm and install', cancel: 'Cancel' },
  validation: {
    hosts: 'Enter 1 to 100 server addresses', port: 'Port must be 1-65535', username: 'Invalid user name',
    secret: 'Enter the login',
  },
  errors: { unavailable: 'SSH remote install is unavailable; try again later', ssh_install_in_progress: 'This server already has an install in progress', refreshFailed: 'Could not refresh the install jobs: {{reason}}. The table may be out of date; jobs in progress keep retrying the read.' },
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value} · ${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as Messages

export const nodeSSHInstallMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo,
  'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(nodeSSHInstallMessages)) {
  i18n.addResourceBundle(locale, 'nodeSSHInstall', messages, true, true)
}
