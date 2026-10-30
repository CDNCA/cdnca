// 官网对外链接的唯一来源。官网不持有账号：登录/注册一律整页跳到授权端
// 统一登录（apps/license-portal/src/auth/entry.ts:7 UNIFIED_LOGIN_PATH='/'，
// App.tsx:39 /console/register、:42 /console/licenses）。
export const SITE_ORIGIN = 'https://www.cdnca.com'
export const AUTH_ORIGIN = 'https://auth.cdnca.com'

export const LINKS = {
  login: `${AUTH_ORIGIN}/`,
  register: `${AUTH_ORIGIN}/console/register`,
  licenses: `${AUTH_ORIGIN}/console/licenses`,
  // 卖家站登录（apps/seller-portal/src/App.tsx:23 /login），经授权端 /console/seller-login 换短时身份。
  developerLogin: 'https://developer.cdnca.com/login',
  // 主控 root 恢复手册（docs/runbooks/platform-admin-recovery.md，build-auth.sh 随授权端包发布到 downloads/；卡 41）。
  adminRecovery: `${AUTH_ORIGIN}/downloads/platform-admin-recovery.md`,
} as const

// 同一份手册在主控本机的位置（native 发布包成员 docs/platform-admin-recovery.md，install-control.sh NATIVE_ROOT/current）。
export const ADMIN_RECOVERY_LOCAL_PATH = '/data/cdnca-native-root/cdnca/current/docs/platform-admin-recovery.md'

// 市场公开只读接口（market-service 公开监听，www-design.md §5.6）。同源路径：68 门户机 nginx 把
// /public/v1/ 反代到市场机公开监听（scripts/install-site.sh），CSP connect-src 只有 'self'
// （check-dist 核对是同源路径且 install-site.sh 有反代段）。
export const MARKET_PUBLIC_API = '/public/v1'

// 主控域名示例。
export const CONTROL_EXAMPLE_DOMAIN = 'console.cdnca.com'

// 主控安装命令：与授权门户生成规则逐字一致
// （packages/cdnca-ui/src/installerCommand.ts，apps/license-portal/src/tests/lib.test.ts 同一期望值）。
// 实际命令以授权中心页面复制的为准；官网测试会对照该期望值防漂移。
export const CONTROL_INSTALL_COMMAND =
  `(f=$(mktemp) || exit 1; trap 'rc=$?; rm -f "$f"; exit $rc' EXIT; trap 'exit 130' INT; trap 'exit 143' TERM; { curl --proto '=https' --proto-redir '=https' -fsSL -o "$f" 'https://auth.cdnca.com/downloads/install-control.sh'; } || { rc=$?; echo '[cdnca-control] error: 无法下载安装脚本' >&2; exit $rc; }; { [ "$(head -c 2 "$f")" = '#!' ] && [ "$(tail -n 1 "$f")" = 'main "$@"' ]; } || { echo '[cdnca-control] error: 下载的安装脚本为空或不完整' >&2; exit 1; }; bash "$f" --licensing-server 'https://auth.cdnca.com')`
