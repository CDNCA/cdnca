#!/usr/bin/env node
// 生成/刷新 allowlist.json：保留已有条目的人工理由，新条目按下面的规则给出归类理由；
// 规则覆盖不到的条目理由为 "待分诊"（--check 仍通过，但会在报告里列出，须人工补）。
// 用法：node tests/ui-route-coverage/gen-allowlist.mjs [--repo <dir>]
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runAudit } from './lib/audit.mjs'
import { KEYS } from './lib/allowlist.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const args = process.argv.slice(2)
const repo = resolve(args.includes('--repo') ? args[args.indexOf('--repo') + 1] : join(here, '../..'))
const file = join(here, 'allowlist.json')
const previous = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {}
const result = runAudit(repo)

// [表, 正则（匹配稳定键）, 理由, 承接]；从上到下取第一条命中。
const RULES = [
  // ---- 表① 机器/流程内部调用，不需要按钮 ----
  ['table1', /^license-service POST \/operator\/v1\/(sessions|password-reset-requests)$/, '旧运营登录/找回入口：统一登录后浏览器走 /auth/v1/*（unilogin），此路由保留给脚本/兼容，不设按钮', '-'],
  ['table1', /^license-service POST \/portal\/v1\/sessions$/, '旧门户登录入口：统一登录后门户走 /auth/v1/sessions，保留兼容，不设按钮', '-'],
  ['table1', /^license-service GET \/portal\/v1\/identity-proofs\/callback$/, '人脸核身服务商回跳地址（浏览器整页跳转），不是按钮', '-'],
  ['table1', /^control-api POST \/v1\/auth\/login-challenge-verifications$/, '登录二次校验由登录页内嵌流程按服务端 challenge 类型触发；待核实前端是否改走 /v1/auth/login 合并步骤', 'ui-audit 待核'],
  ['table1', /^license-service GET \/operator\/v1\/market\/$/, '代理前缀挂载（market_admin_proxy.go），实际路由按白名单逐条对账', '-'],
  ['table1', /^control-api \* \/v1\/tenant\/package-period-reset\/authority-bindings\/?$/, '套餐周期重置授权绑定：工作负载/运维接口（package_period_reset_authority_runtime.go），无租户页面需求', '-'],
  ['table1', /^control-api \* \/v1\/(admin\/)?analytics\/connections\/(dead-letters|retention)/, '连接日志死信/保留期：运维诊断接口，当前无页面；建议并入「系统任务」页诊断区', '待派'],
  ['table1', /^control-api POST \/v1\/admin\/site-rollouts\/reconciliations$/, '发布对账：运维/定时任务触发', '-'],
  ['table1', /^control-api \* \/v1\/system-settings\/csp-hosts$/, '前端运行时读取 CSP 白名单（index.html/服务端注入），非按钮', '-'],
  ['table1', /^control-api POST \/v1\/admin\/aggregated-edge\/accounts\/rewrap$/, '凭据重新加密：密钥轮换运维接口（install 脚本调用）', '-'],
  // ---- 表① 自动防御：整页仍是 mock ----
  ['table1', /^control-api \S+ \/v1\/(admin\/)?security\/autodefense\//, '自动防御页面（apps/web/src/pages/autodefense）仍用 createMockClient，AD-11 HTTP 客户端未接（ad-13-web.md 第 18 行、ad-wire.md 第 79 行）', '待派 ad-web-http'],
  // ---- 表① 节点市场/插件市场（主控买卖方） ----
  ['table1', /^control-api \S+ \/v1\/admin\/(market|sites\/\{site\}\/market)/, '主控节点/插件市场买卖方页面未覆盖该操作', 'ml-* 系列（ML-29/ML-11b/ML-direct-pay 在跑），合入后复跑'],
  // ---- 表① 运营端市场代理 ----
  ['table1', /^license-service \S+ \/operator\/v1\/market\//, '运营后台市场页面未接该代理路由（详情/动作按钮缺失）', 'ml-29 在跑（运营后台市场页面补充），合入后复跑'],
  // ---- 表① 卖家站 ----
  ['table1', /^market-service \S+ \/seller\/v1\/(onboarding-policy|onboarding-orders)$/, '卖家站开通费（ML-26 后端已完成），卖家站页面未接', 'ml-26 页面归 ML-29/ML-28（ml-26.md 第 24 行）'],
  ['table1', /^market-service \S+ \/seller\/v1\//, '卖家站页面未接该接口', '待派 seller-ui'],
  // ---- 表① 门户 ----
  ['table1', /^license-service \S+ \/portal\/v1\/plugin-licenses/, '门户插件许可/改绑页面未做（market-unify.md S5 未勾）', 'market-unify S5（未完成）'],
  ['table1', /^license-service POST \/portal\/v1\/topups$/, '门户余额充值下单无按钮（余额页只读）', '待派 portal-topup'],
  // ---- 表① 其余：按模块给出落点 ----
  ['table1', /\/v1\/admin\/aggregated-edge\//, '聚合边缘：账号详情/编辑、供给详情无页面入口（列表与新建已有）', '待派 web 聚合边缘（AggregatedEdge*Page 补详情抽屉与编辑）'],
  ['table1', /\/v1\/(admin\/)?analytics\/(quality-diagnostics|site-monitoring)$/, '旧诊断/实时监控挂载：前端已改用 site-quality-diagnostics 与 site-realtime，旧路由无调用方', '待派 control 清理（确认后删路由）'],
  ['table1', /\/v1\/(admin\/)?analytics\/top\/$/, 'TOP 排行子树挂载：前端调用 /analytics/top-*（具体路径），此前缀行无独立调用', '-'],
  ['table1', /\/v1\/admin\/cache-policies\//, '平台管理员按站点查看/改缓存策略：前端只调租户侧 /v1/cache-policies，管理端代管无入口', '待派 web 缓存策略（管理端 scope 切换）'],
  ['table1', /\/v1\/(admin\/)?cname-allocations\/(diagnose|\{allocation_id\})$/, 'CNAME 分配诊断/详情无按钮（CnameAllocationsPage 只用列表与诊断 POST 体）', '待派 web CNAME 页'],
  ['table1', /\/v1\/package-monitor\//, '用户端套餐监控：前端只有管理端 /v1/admin/package-monitor/*，用户看不到自己的套餐告警/执行状态', '待派 web 用户端套餐监控页'],
  ['table1', /\/v1\/admin\/package-addons\/(assignments|bindings|subscriptions)$/, '附加包分配/绑定/订阅明细查询无页面（PackageAddonsPage 只有产品与命令）', '待派 web 附加包页'],
  ['table1', /\/v1\/admin\/account\/orders/, '管理端消费记录写接口无调用：FinanceOrdersPage.tsx:371 管理员与租户都写 /v1/account/orders（带 tenantID），admin 写路由是冗余入口', '待派 control/web 二选一（删冗余路由或前端改用 admin 路由）'],
  ['table1', /\/v1\/admin\/recharge-payments\/orders\/\{order_id\}\/(refunds|voids|reconciliation)$/, '充值订单退款/作废/对账：财务充值页无按钮', '待派 web 财务充值'],
  ['table1', /\/v1\/(admin\/)?recharges\/orders/, '充值订单列表/对账详情：前端未接（只调 recharge-payments）', '待派 web 财务充值'],
  ['table1', /\/v1\/admin\/recharge-payment-approvals\/(export|\{approval_id\})$/, '充值审批导出/详情无按钮', '待派 web 财务充值'],
  ['table1', /\/v1\/admin\/system-operations\/(preview|\{operation_id\}\/reject)$/, '高危操作审批：页面只有"批准"无"驳回"、无提交前预览（highRiskOperations.ts 只有 list/get/create/approve）', '待派 web 高危操作'],
  ['table1', /\/v1\/admin\/users\/\{user_id\}\/api-keys/, '管理员代管用户 API 密钥（列表/签发/吊销）：用户管理页无入口', '待派 web 用户管理'],
  ['table1', /\/v1\/admin\/tenant-scopes$/, '租户目录下拉接口：前端改用 /v1/admin/users 选人；平台子管理员无 identity.users.manage 时可改用它', '待派 web 权限对齐（见表③）'],
  ['table1', /\/v1\/waf-rule-libraries/, 'WAF 规则库订阅：只接了"待发布"列表，规则库列表/订阅/取消/刷新无页面（PA-25 后端已合）', '待派 web 规则库订阅页'],
  ['table1', /\/v1\/security-policies\/(filters|matchers)?\/?\{id\}$|\/v1\/security-policies\/\{id\}$/, '安全策略/匹配器/过滤器单条详情：列表页内联展示，未单独调用；可接受', '-'],
  ['table1', /\/v1\/url-auth-policies\/\{id\}$/, 'URL 鉴权策略单条详情：列表内联，可接受', '-'],
  ['table1', /DELETE \/v1\/sites\/\{id\}$/, '单站删除：前端统一走 /v1/sites/batch-action delete，单条 DELETE 无调用；可接受', '-'],
  ['table1', /\/v1\/site-publications(\/security-activations\/\{candidate_id\})?$/, '租户侧手工发布/安全激活候选详情：前端只走管理端 /v1/admin/site-publications 与列表', '待派 web 发布页（确认租户是否需要）'],
  ['table1', /\/v1\/admin\/nodes\/ssh-installs\/\{id\}$/, 'SSH 安装任务详情：节点列表只轮询创建结果，无详情查看', '待派 web 节点安装'],
  ['table1', /\/v1\/admin\/control-upgrade-rollouts\/\{id\}$/, '主控升级批次详情：升级页只列表', '待派 web 主控升级'],
  ['table1', /\/v1\/(admin\/)?recharge-identity-policy/, '充值实名策略修改：页面只读展示', '待派 web 财务设置'],
  ['table1', /\/v1\/admin\/admin-access-policy$/, '管理端访问策略修改：页面只读（AdminAccessPage 仅 GET）', '待派 web 系统设置'],
  ['table1', /\/v1\/admin\/payment-channels\/\{id\}$/, '支付通道单条详情：列表内联编辑，可接受', '-'],
  ['table1', /\/v1\/admin\/security\/coordination\/metrics$/, '安全协同指标：无页面（可并入 CC 协同页）', '待派 web 监控'],
  ['table1', /promotion-(policies|reservations)/, '促销策略历史/预留详情无页面', '待派 web 促销'],
  ['table1', /challenge-policies\/\{policy_id\}\/publications\/\{rollout_id\}\/promote$/, '挑战策略发布"推进"按钮缺失（只有创建与查看）', '待派 web 挑战策略'],
  ['table1', /\/v1\/openresty-security\/effective$/, 'OpenResty 安全生效配置查看：无页面', '待派 web 安全'],
  ['table1', /\/v1\/admin\/package-commerce\/traffic-purchases\/$/, '管理端流量包购买单详情子树：无调用', '待派 web 套餐'],
  ['table1', /\/v1\/traffic-packages\/purchases$/, '用户端旧流量包购买接口：已由 /v1/package-commerce/traffic-purchases 替代', '待派 control 清理'],
  ['table1', /\/operator\/v1\/customers\/.*\/plugin-installations\/.*\/(confirm|disable|enable|install-applied|uninstall|upgrade)$/, '运营后台客户安装插件授权的启停/卸载/升级：PluginInstallationsRoute 页只读', '待派 operator 插件安装'],
  ['table1', /\/operator\/v1\/customers\/.*\/waf-rule-reports/, '客户安装的 WAF 自定义规则上报：运营后台无查看入口（自定义规则报表页只看 security）', '待派 operator 规则上报'],
  ['table1', /\/operator\/v1\/identity-proof\/providers/, '人脸核身服务商配置（查看/保存）：运营后台无页面', '待派 operator 客户中心'],
  ['table1', /\/operator\/v1\/payment-(channels\/\{id\}|channels\/\{id\}\/crypto-pool|exceptions)/, '收款通道详情/USDT 地址池补充/支付异常处理：运营后台支付通道页未覆盖', '待派 operator 支付'],
  ['table1', /\/operator\/v1\/plugin-market\/rebind-policy$/, '插件许可改绑频率策略：运营后台无设置页（mu-license 后端已合）', '待派 operator 市场设置'],
  ['table1', /\/operator\/v1\/plugin-catalogs\/\{catalog_id\}\/resync-latest$/, '插件目录"重新同步最新"按钮缺失', '待派 operator 插件目录'],
  ['table1', /\/operator\/v1\/rule-packs(\/traces)?$/, '官方规则包发布与泄露追溯：无页面（目前只有离线脚本）', '待派 operator 规则包'],
  ['table1', /\/operator\/v1\/rule-intel\/merges\/\{merge_id\}$/, '规则情报并入单条详情无入口', '待派 operator 规则情报'],
  ['table1', /\/operator\/v1\/signer-revocations\/current$/, '当前生效吊销清单查看：页面只列历史', '待派 operator 签名者吊销'],
  ['table1', /\/analytics\/logs\/access\/exports\/\{export_id\}$/, '访问日志导出单条详情：页面靠列表轮询状态，未单独查询；可接受', '-'],
  ['table1', /./, '后端已实现、四端无调用：缺页面入口或按钮', '待分配'],
  // ---- 表② ----
  ['table2', /security-rule-catalog$/, '旧规则目录接口已被 PA-02 统一制品目录替代（0e55973e4），前端 installationState 成员遗留且无页面引用，属死代码', '待派 operator 清理'],
  ['table2', /seller-portal GET \/seller\/v1\/plugins\/\{\}\/versions$/, '卖家站插件版本列表调用 GET，后端只有 POST（上传）；PluginVersions.tsx 打开即 405', '待派 seller-ui（需后端补 GET 或前端改走 plugin-versions）'],
  ['table2', /user-package\/traffic\/usage/, 'directRouteDefinitions 登记了用户端流量包用量详情，但 App.tsx 无该 <Route>', '待派 web 小修'],
  ['table2', /./, '待分诊', '待分诊'],
  // ---- 表③ ----
  ['table3', /\/v1\/admin\/users/, '页面里的用户选择器调 /v1/admin/users（identity.users.manage），页面可见权限不含它：子管理员打开下拉 403', '待派 web 权限对齐'],
  ['table3', /GET \/v1\/nodes/, '系统配置页节点选择器调 /v1/nodes（nodes.read），可见条件只有 system_configuration.read/error_pages.read', '待派 web 权限对齐'],
  ['table3', /GET \/v1\/streams/, '四层访问日志按 sites.read 显示，但四层列表需要 streams.read', '待派 web 权限对齐'],
  ['table3', /\/operator\/v1\/customers/, '安全规则/主控安装页按本页权限显示，但客户选择器需要 licensing.customers.manage', '待派 operator 权限对齐'],
  ['table3', /permission_never_gated/, '接口权限码在前端从未作为显示条件：只持有该码的子账号/运营者看不到入口，持有其它码者按钮可见但 403', '待派 权限对齐'],
  ['table3', /unknown_permission/, '前端判断的权限码不在后端迁移权限目录中：任何角色都不满足', '待派 权限对齐'],
  ['table3', /./, '待分诊', '待分诊'],
  // ---- 表④ ----
  ['table4', /^web \/account\/(balance|balance-log)$/, '用户端账户余额/流水页无菜单项（userNavigation 账户中心未列，navigation.ts:338-355）', '待派 web 菜单'],
  ['table4', /^web \/account\/message$/, '用户端站内消息页无菜单与顶栏入口', '待派 web 菜单'],
  ['table4', /^web \/sys\/notification$/, '旧通知设置页：已并入 /sys/setting 通知页签（SystemGlobalSettingsPage 页签 notification），旧路由残留', '待派 web 清理'],
  ['table4', /^web \/monitor\/site\/(block-event-log|cc-coordination)$/, '监控页无菜单项（navigation.ts monitor 分组未列）', '待派 web 菜单'],
  ['table4', /^web \/finance\/billing-admin$/, '平台账务管理页无菜单项', '待派 web 菜单'],
  ['table4', /./, '待分诊', '待分诊'],
  // ---- 表⑤ ----
  ['table5', /mock_client web createMockClient/, '自动防御 8 个页签全部是内存假数据（仅节点下发/签名两项接真接口），用户看到的统计、判定、拉黑、误伤报表、平台设置均为假', '待派 ad-web-http（AD-11 后端已在集成头）'],
  ['table5', /not_implemented operator-console/, '运营后台插件市场该操作前端硬编码 501，不发请求；对应代理行已 forwarded（routes.go:130-139），按钮点击必失败', 'ml-29 / 待派 operator 市场'],
  ['table5', /disabled_placeholder operator-console mp\.(lockNamespace|rescan|revokeLicense)/, '运营后台插件市场按钮常驻禁用（"后端未提供"），但代理行已 forwarded（routes.go:135-139），应接真接口', 'ml-29 / 待派 operator 市场'],
  ['table5', /./, '待分诊', '待分诊'],
  // ---- 代理/OpenAPI ----
  ['proxyGaps', /\/v1\/(blacklist|icp\/reports|acme\/)/, '市场成员接口（黑名单订阅/ICP 举报/供给域名 ACME）主控侧未接：member.go 无映射且 marketclient 无调用', '待派 market 主控接线'],
  ['proxyGaps', /relay\/cursor/, '中继游标查询：marketruntime 用 inbox?after= 自管游标，此接口仅调试', '-'],
  ['proxyGaps', /./, '待分诊', '待分诊'],
  ['openapiNotServed', /rule-intel-reports/, 'OpenAPI 登记了主控上报规则情报，代码在 RI-11 分支未合入', 'ri-11（未合入，release-prep.md 阻塞项）'],
  ['openapiNotServed', /./, '待分诊', '待分诊'],
]

const tables = { table1: result.table1, table2: result.table2, table3: result.table3, table4: result.table4, table5: result.table5, proxyGaps: result.proxyGaps, openapiNotServed: result.openapiCheck.notServed }
const out = {}
for (const [name, rows] of Object.entries(tables)) {
  out[name] = {}
  for (const row of rows.slice().sort((a, b) => KEYS[name](a).localeCompare(KEYS[name](b)))) {
    const key = KEYS[name](row)
    const kept = previous[name]?.[key]
    if (kept && kept.reason && kept.reason !== '待分诊' && !/见 ui-audit-report/.test(kept.owner ?? '')) { out[name][key] = kept; continue }
    const rule = RULES.find(([t, re]) => t === name && re.test(key))
    out[name][key] = { reason: rule?.[2] ?? '待分诊', owner: rule?.[3] ?? '待分诊', evidence: row.evidence }
  }
}
writeFileSync(file, JSON.stringify(out, null, 2) + '\n')
const pending = Object.values(out).flatMap((t) => Object.entries(t)).filter(([, v]) => v.reason === '待分诊').length
console.log(`allowlist.json 已写入：${Object.entries(out).map(([k, v]) => `${k}=${Object.keys(v).length}`).join(' ')}；待分诊 ${pending}`)
