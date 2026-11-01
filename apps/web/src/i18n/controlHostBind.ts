import i18n from './index'

// the "console address / bind a domain" card of
// System settings → System. The page only shows the state and the root
// command; the bind itself runs on the control host (control-api control-host bind).
const zhCN = {
  title: '管理端地址 / 绑定域名',
  intro: '主控先用 IP 安装、之后改用域名访问（或换域名）时，在主控服务器上以 root 执行下面的命令。不重装、已装节点不断、业务不中断；浏览器用域名访问时使用正式证书，之后复制的节点安装命令改用域名。',
  current: '当前状态',
  address: '当前访问地址',
  certificate: '当前证书',
  certificatePublic: '公网受信证书',
  certificatePrivate: '本机私有证书（浏览器提示不安全）',
  gateway: '新节点连接的网关',
  ipNotice: '当前用 IP 访问。Let\'s Encrypt 不为 IP 签发证书，绑定域名后浏览器即可正常显示安全锁。',
  domainLabel: '要绑定的域名',
  domainPlaceholder: 'console.example.com',
  domainInvalid: '请输入域名（不能是 IP 或通配符）',
  commandLabel: '在主控服务器上以 root 执行',
  commandCertLabel: '已有证书时（不需要 80 端口）',
  statusLabel: '查看绑定状态（地址、证书到期、SAN）',
  copy: '复制命令',
  copied: '已复制',
  requirementsTitle: '执行前确认',
  requirements: [
    '域名的 A/AAAA 记录已解析到本主控的公网 IP（暂时关闭 CDN 代理/小黄云）。',
    '申请 Let\'s Encrypt 证书需要公网能访问本机 TCP 80 端口，且 80 端口没有被其他程序占用；否则用 --cert-file/--key-file 提供已有证书。',
    '执行过程会重载网页、重启节点网关和 control-api：已装节点自动重连，业务不受影响。',
    '原 IP 地址继续可用，节点按原地址继续升级；任一步失败自动回滚，改动前的文件备份在 /var/lib/cdnca-control/host-bind-backup-<时间>/。',
    '完成后用新域名重新打开管理端，再复制节点安装命令。',
  ],
  baota: '宝塔环境：公网证书由宝塔站点负责，请在宝塔「网站」中为域名开启 SSL，不使用此命令。',
}

const enUS: typeof zhCN = {
  title: 'Console address / bind a domain',
  intro: 'When the control plane was installed by IP and should now be reached by a domain (or a new domain), run the command below as root on the control host. No reinstall, installed nodes stay connected and traffic is not interrupted; browsers get a trusted certificate on the domain and node install commands copied afterwards use the domain.',
  current: 'Current state',
  address: 'Current address',
  certificate: 'Current certificate',
  certificatePublic: 'Publicly trusted certificate',
  certificatePrivate: 'Private certificate of this host (browsers warn)',
  gateway: 'Gateway for new nodes',
  ipNotice: 'The console is reached by IP. Let\'s Encrypt does not issue IP certificates; bind a domain for a trusted padlock.',
  domainLabel: 'Domain to bind',
  domainPlaceholder: 'console.example.com',
  domainInvalid: 'Enter a domain name (not an IP address or wildcard)',
  commandLabel: 'Run as root on the control host',
  commandCertLabel: 'With an existing certificate (port 80 not needed)',
  statusLabel: 'Show the binding (address, certificate expiry, SAN)',
  copy: 'Copy command',
  copied: 'Copied',
  requirementsTitle: 'Before you run it',
  requirements: [
    'The domain\'s A/AAAA records point at this control plane\'s public IP (turn CDN proxying off for now).',
    'A Let\'s Encrypt certificate needs TCP port 80 on this host reachable from the Internet and free; otherwise pass an existing certificate with --cert-file/--key-file.',
    'The web is reloaded and the node Gateway and control-api are restarted: installed nodes reconnect on their own and traffic is not affected.',
    'The old IP keeps working and nodes keep upgrading from it. Any failure rolls everything back; the previous files are kept in /var/lib/cdnca-control/host-bind-backup-<time>/.',
    'Afterwards reopen the console at the new domain before copying node install commands.',
  ],
  baota: 'BaoTa installation: the public certificate belongs to the BaoTa site. Enable SSL for the domain under BaoTa Websites instead of running this command.',
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.replace(/[A-Za-z一-鿿]/g, '$&~')}］`
  if (Array.isArray(value)) return value.map(pseudo)
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const controlHostBindMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }
for (const [locale, messages] of Object.entries(controlHostBindMessages)) {
  i18n.addResourceBundle(locale, 'controlHostBind', messages, true, true)
}
