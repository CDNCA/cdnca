# ADR 0019：财务系统对接插件（WHMCS / 智简魔方）

- 状态：已拍板（2026-10-27）Q1 a 免费、Q2 a 按剩余天数折算批发差价、Q3 a 终止后停用账号、Q4 a 免密登录跳过二次验证（插件设置可改为要验）；Q5/Q6 资料与测试环境待用户提供。BB-01～05 后端已实现（BB-04/05：bb0405，control 迁移 553 占位）。
- 代码核对基于集成头 `c94c2199d`。路径前缀：主控 `services/control-api/`。
- 用户已定（10-27）：A（代理商在我们平台转售）、B（买授权自建主控）两种都支持，客户可选其一或两种都用；两边都必须做成插件形态。

## 1. 目标

IDC 商在 WHMCS 或智简魔方里上架"CDN 产品"。他们的客户在财务系统下单、续费、停用、升降级时，CDN 侧自动开户、开套餐、停服、续期、改套餐。客户在财务系统里点按钮免密进入 CDN 控制台，财务系统也能显示流量用量。

## 2. 插件形态

| 端 | 形态 | 说明 |
|---|---|---|
| 我们的主控 | 官方插件 `io.cdnca.billing-bridge`，kind `module`，功能码 `module.billing.bridge` | 照"迁移导入"（market 049）在市场上架；`libs/entitlement/module.go` 登记，Revoke = `RevokeKeepExisting`（收回后对接接口返回 `entitlement_feature_denied`，已开的客户和订阅不受影响）；未启用时菜单、接口、密钥页都不出现 |
| WHMCS | provisioning module `modules/servers/cdnca/` | 源码放仓库 `integrations/whmcs/`，打 zip 后由插件页提供下载 |
| 智简魔方 | 老版财务的接口模块（`modules/servers/`），新版业务系统（ZJMF-CBAP）走它自己的插件结构 | 源码放 `integrations/zjmf/`；与 WHMCS 共用一个 PHP 客户端类 |

A、B 是同一个插件的两个入口，只是"密钥属于谁"不同：

- A：代理商在用户后台「财务对接」页生成密钥，密钥代表这个代理商 scope，只能管自己名下的客户。我们平台的管理员需要启用插件，并且该租户是有效代理商（`reseller_profiles.status=active`）。
- B：IDC 在自己主控的管理后台「财务对接」页生成密钥，密钥代表平台 scope，管该主控上的直客。
- 两种都用：一个 IDC 既在我们平台当代理商（A 密钥，调 `我们的域名`），又有自建主控（B 密钥，调自己的域名）。WHMCS 里配两个"服务器"即可，插件代码相同。

## 3. 现状核对（为什么不能直接用现有 API Key）

| 问题 | 位置 |
|---|---|
| 包交易写操作只认 Bearer 会话：`CredentialKind` 必须是 `session`，否则拒 | `internal/packagecommerce/authorization.go:90,113`；`internal/packagecommercehttp/runtime.go:128,171` |
| 用量接口只认 Bearer | `cmd/control-api/main.go:5918-5930` |
| 代登录 grant 要求主会话 `SessionID`，DB 外键指向 `auth_sessions` | `internal/impersonationhttp/handler.go:249-264,464`；迁移 482:85-98 |
| API Key 只能落在 tenant scope：`tenant_id NOT NULL`、外键、写触发器、`targetPrincipal`、认证 JOIN tenants，且禁 `identity.*` | 迁移 `025_api_keys.up.sql:24,40,251`；`internal/apikey/service.go:490,523,1094,1190` |
| 代理商不能升降级/取消客户订阅；升降级限定平台套餐 | `internal/packagecommercehttp/handler.go:759-777`；`internal/packagecommerce/checkout.go:278-298` |
| 平台取消订阅只停站点，不退款、不记账 | `internal/packagesubscription/store.go:339` |
| 代理商停用客户只禁登录、撤会话，不停站点；没有删除客户接口 | `internal/identity/reseller_customers.go:190-199`；`internal/httpapi/server.go:929-932` |

结论：现有 API Key 在 A、B 两种模式下都无法下单。把通用 API Key 改成也能落在 platform scope、也能带 `identity.*`，影响面会覆盖全部 API，不划算。

## 4. 方案：插件自带"对接密钥" + 一组窄门面接口

### 4.1 凭据

- 新表 `billing_bridge_keys`（插件自有，不碰 `api_keys`）：owner_scope_id（平台 scope 或代理商 scope）、名称、`key_id`、secret 摘要（复用 `apikeycredential` 的 pepper keyring）、IP 白名单（必填，至少一条）、状态、过期时间、最后使用时间、revision。
- 请求签名，不传明文 secret：`X-Cdnca-Bridge-Key`、`X-Cdnca-Timestamp`（±300 秒）、`X-Cdnca-Nonce`（5 分钟内防重放），`X-Cdnca-Signature = HMAC-SHA256(secret, method\npath\nquery\ntimestamp\nnonce\nsha256(body))`。即使 WHMCS 数据库泄露 secret，攻击者也必须同时绕过 IP 白名单。
- 鉴权后合成一个 actor：`CredentialKind = "bridge"`，权限是固定集合，不可自选。包交易的 `authorization.go`、用量、身份三处各加一个 `bridge` 分支，只对门面路由开放；其他路由一律不认这种凭据。
- 生成、轮换、吊销需要 step-up（与现有 API Key 管理一致），写审计。

### 4.2 门面接口（`/v1/billing-bridge/*`，A、B 共用）

| 财务系统动作 | 接口 | A（代理商） | B（平台） |
|---|---|---|---|
| TestConnection | `GET /ping` | 返回 owner 类型、插件状态 | 同 |
| ConfigOptions 套餐下拉 | `GET /products` | 代理商自己上架的套餐 | 平台套餐 |
| CreateAccount | `POST /services`（`external_service_id` = 财务系统服务 ID，作为幂等键） | 按 `external_client_id` 找到或新建客户 → 代下单（只扣代理商预付批发价，RS-03 现成） | 找到或新建用户 → `routeAdminOpen` 开通，不扣费 |
| Suspend / Unsuspend | `POST /services/{id}/suspend`、`/unsuspend` | 新增订阅级停用：停站点、保留配置；只停这一个服务，不动客户其他服务 | 同 |
| Terminate | `POST /services/{id}/terminate` | 取消订阅、停站点；客户名下已没有有效服务时，按 §9 Q3 处理账号 | 同 |
| Renew | `POST /services/{id}/renew` | 代理商代续（扣批发价） | 平台续期（不扣费） |
| ChangePackage | `POST /services/{id}/change` | 新增：代理商升降级，差价按 §9 Q2 | 平台升降级（现成） |
| ServiceSingleSignOn | `POST /services/{id}/sso` → 返回一次性登录链接 | 见 4.3 | 同 |
| UsageUpdate | `GET /usage?external_service_ids=...` | 本周期流量、带宽峰值、95 带宽（复用 `packageusage`） | 同 |
| ClientArea | 由 PHP 端调 `/services/{id}` 渲染套餐、到期、用量 | 同 | 同 |

服务映射表 `billing_bridge_services(owner_scope_id, external_system, external_service_id, external_client_id, tenant_scope_id, user_id, subscription_id, status)`，`(owner_scope_id, external_system, external_service_id)` 唯一。财务系统的 cron 重试时按这张表幂等，不会重复开户。

### 4.3 免密登录

客户登录自己的账号，不是代登录，所以不走 impersonation。门面签发一次性票据（60 秒、只能用一次、绑定 user_id 与 owner），浏览器打开 `https://<控制台域名>/sso/bridge?ticket=...`，主控验票后签发普通登录会话（`auth_sessions` 记 `method=billing_bridge`）。A 模式跳到代理商的白标域名（RS-07 主题继承）。客户开了二次验证时是否还要验，见 §9 Q4。

### 4.4 门面接口契约（BB-04/05 定稿；PHP 模块按此实现）

通用：
- 基址 `{控制台域名}/v1/billing-bridge`；所有门面请求签名鉴权（§4.1，BB-02 已实现 `Authenticator.Middleware`），写请求另带 `Idempotency-Key`（`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`，PHP 端用 `{system}:{service_id}:{action}:{财务系统任务/发票 ID 或日期}`）。
- 响应统一 JSON：成功 `{"data":...}`；失败 `{"error":{"code","message","request_id"}}`，HTTP 状态按语义。PHP 端把 `message` 原样返回给财务系统（WHMCS 约定：成功返回字符串 `success`，否则返回错误文本）。
- `external_system` ∈ `whmcs`、`zjmf`、`zjmf_cbap`；`external_service_id`、`external_client_id` 1–64 位可见 ASCII。
- 对接密钥的 owner 决定一切作用域：A（reseller）只能看到、操作该代理商名下的客户与订阅；B（platform）只能操作直客（`tenants.parent_scope_id IS NULL`），不能动代理商名下客户。越界一律 404（不泄露存在性）。
- 每次调用 `RecordCall` 记对接日志（动作、external_service_id、结果、耗时）。

| 方法与路径 | 请求 | 响应 data |
|---|---|---|
| `GET /ping` | — | `{owner_kind, owner_scope_id, module_enabled, server_time}`（BB-02 已有） |
| `GET /products` | — | `[{id, revision, name, periods:[{period, price_minor, wholesale_minor?}], site_limit, node_limit}]`（A：代理商自有已上架套餐；B：平台已上架套餐） |
| `POST /services` | `{external_system, external_service_id, external_client_id, client:{email, username?, display_name?}, product_id, product_revision?, period}` | `Service`；同一 `(owner, external_system, external_service_id)` 重复调用返回同一服务（200，`created:false`），参数不同 409 `bridge_service_conflict` |
| `GET /services/{external_system}/{external_service_id}` | — | `Service` |
| `POST /services/{sys}/{sid}/suspend` | `{reason?}` | `Service` |
| `POST /services/{sys}/{sid}/unsuspend` | — | `Service` |
| `POST /services/{sys}/{sid}/renew` | `{period?}` | `Service` |
| `POST /services/{sys}/{sid}/change` | `{product_id, product_revision?, period?}` | `Service`（按新旧价自动判升/降级；同价按升级处理） |
| `POST /services/{sys}/{sid}/terminate` | — | `Service`（订阅取消、站点停服；客户名下已无其他有效服务时停用账号，Q3） |
| `POST /services/{sys}/{sid}/sso` | `{redirect?}`（站内相对路径，默认 `/`） | `{url, expires_at}`，一次性、60 秒 |
| `GET /usage?external_system=&ids=a,b,c` | ≤100 个 | `[{external_service_id, period_start, period_end, traffic_bytes, peak_bandwidth_bps, bandwidth_95th_bps, finalized_through}]`（当前计费周期） |

`Service` = `{external_system, external_service_id, external_client_id, status: active|suspended|terminated, product:{id, revision, name}, period, starts_at, ends_at, suspended_at, user:{id, username, email}, console_url, created}`。

开户规则：同一 owner 下 `(external_system, external_client_id)` 映射一个 CDN 用户，首次开服务时建户（A：代理商开户；B：平台建直客），用户名默认 `{system}_{client_id}`，冲突加短后缀；随机密码不返回（客户只走 SSO 或自行重置）。客户的第二个服务复用同一用户。

错误码（PHP 端按码给出中文提示）：`bridge_unauthenticated`(401)、`entitlement_feature_denied`(403)、`bridge_service_not_found`(404)、`bridge_product_not_found`(404)、`bridge_service_conflict`(409)、`bridge_service_terminated`(409)、`reseller_prepaid_insufficient`(422)、`reseller_wholesale_unpriced`(422)、`bridge_validation_error`(400)，其余沿用包交易错误码。

鉴权实现约束：门面调用包交易、订阅、身份服务时，用 bridge actor（`CredentialKind="bridge"`）进入各服务的授权层；授权层新增 `bridge` 分支，在同一事务内复核对接密钥仍为 active、未过期、owner 仍有效（代理商仍 active、模块仍启用），并把 actor 映射为 owner scope 的固定权限集（A：`reseller.customers.manage`；B：`package_subscriptions.manage`、`billing.adjustments.manage`、`identity.users.manage`），不得接受其他权限。`bridge` 分支只对门面路由构造的 actor 生效；通过 Bearer / CdncaKey 进来的请求永远构造不出 bridge actor。

SSO：票据存表（`billing_bridge_sso_tickets`：token 摘要、user_id、owner、redirect、expires_at、used_at），`GET /sso/bridge?ticket=` 由控制台前端路由调用 `POST /v1/auth/bridge-sso`（无鉴权，凭票据）换普通会话（`auth_sessions` 记 `method=billing_bridge`），跳过二次验证（Q4 a；插件设置 `sso_require_mfa` 可改为要验，此时返回 `mfa_required` 让前端走现有二次验证流程）。A 模式 `console_url` 用代理商白标域名（若已配置）。

## 5. 新增的订阅能力（插件外也可复用）

1. 订阅级停用/恢复：`package_subscriptions` 加 `suspended_at / suspend_reason`；停用时把该订阅下的站点下发停服（复用 `TaskActionSuspend`），恢复时重新下发。到期计时不暂停（与财务系统一致：停用期间照常计费到期）。
2. 代理商升降级：放开 `checkout.go:278-298` 对代理商自有套餐的限制；actor 走 `authorizeResellerActor`（`reseller.go:156`）；批发价差额结算按 §9 Q2。
3. 代理商取消客户订阅：放宽 `packagesubscription/store.go:451` 的同 scope 限制为"actor 是客户的上级代理商"。

## 6. 页面

- 我们平台管理端：插件市场里出现该插件；「系统 → 财务对接」管 B 密钥、看对接日志、下载 PHP 包。
- 代理商用户端：「代理商 → 财务对接」管 A 密钥、看对接日志、下载 PHP 包。菜单按 `module.billing.bridge` + 代理商身份显示。
- 对接日志：每次门面调用记一行（动作、external_service_id、结果、耗时、来源 IP），保留 90 天。

## 7. 数据与编号

control 迁移 1 个（`billing_bridge_keys`、`billing_bridge_services`、`billing_bridge_nonces`、`billing_bridge_logs`、订阅停用列），market 迁移 1 个（官方上架）。号合入时按头号 +1 分配；本 ADR 写作时 control 本地头 545（总账 546–549 已占），market 头 061。OpenAPI `api/openapi/v1/control.yaml` 新增约 12 个 operation，同步 `tools/contract-doc-check/openapi-index.test.mjs:511-513` 计数与 `docs/api/openapi-index.md`。

## 8. 任务拆分

| ID | 范围 | 依赖 | 验收 |
|---|---|---|---|
| BB-01 上架与门控 | market 上架迁移、`module.go` 登记、门面路由统一过 `module.billing.bridge` | 无 | 未启用：门面全部 403 `entitlement_feature_denied`、菜单不出现；启用后出现 |
| BB-02 对接密钥 | 表、HMAC 验签、nonce、IP 白名单、step-up 生成/轮换/吊销、`bridge` actor | BB-01 | 时间偏差 >300s、重放 nonce、错签名、非白名单 IP、吊销后均 401；用对接密钥调任何非门面路由均被拒 |
| BB-03 订阅停用/恢复、代理商升降级与取消 | §5 三项 | 无 | PG：停用后站点下发停服、恢复后重新下发；代理商升降级三方账本正确；不能操作别家代理商的客户 |
| BB-04 门面接口 | §4.2 全部动作 + 映射表幂等 + 对接日志 | BB-02、BB-03 | 同一 external_service_id 重复 create 只开一次；A 扣代理商批发价、B 不扣费；A 密钥访问非自己客户 404 |
| BB-05 免密登录 | 票据签发、`/sso/bridge` 验票建会话 | BB-02 | 票据第二次用、过期、别家客户均失败；成功后是客户本人会话、有审计 |
| BB-06 页面 | 管理端与代理商端「财务对接」页、日志、PHP 包下载 | BB-02、BB-04 | vitest + 截图 |
| BB-07 WHMCS 模块 | `integrations/whmcs/`：MetaData、ConfigOptions、CreateAccount、Suspend、Unsuspend、Terminate、Renew、ChangePackage、TestConnection、ServiceSingleSignOn、UsageUpdate、ClientArea、AdminServicesTabFields | BB-04 接口定稿 | phpunit（mock 服务端）+ 真实 WHMCS 走一遍全流程 |
| BB-08 智简魔方模块 | `integrations/zjmf/`：老版财务接口模块 + 新版业务系统插件 | BB-04、§9 Q5 资料 | 真实智简魔方走一遍全流程 |
| BB-09 验收 | runbook 与复测脚本：A、B、A+B 三种组合 | 全部 | 见各项 |

可并行：BB-01、BB-02、BB-03 同时开工；BB-04 等 BB-02/03；BB-05、BB-06、BB-07 等 BB-04 接口定稿后并行；BB-08 等资料到位。

## 9. 待用户拍板

| # | 问题 | 选项 | 推荐 |
|---|---|---|---|
| Q1 | 插件收费吗 | a 免费；b 收费（价格另定） | a，用来拉 IDC 客户 |
| Q2 | A 模式升降级时，代理商批发价差额怎么算 | a 按剩余天数折算新旧批发价差（升级补扣、降级退回预付余额）；b 升级补扣、降级不退；c 不折算，下个周期按新价 | a，与客户侧升降级算法一致 |
| Q3 | Terminate 后客户名下没有有效服务了，CDN 账号怎么办 | a 停用账号（禁登录，数据保留）；b 删除账号；c 不动 | a，误删不可逆 |
| Q4 | 免密登录时客户开了二次验证 | a 跳过（财务系统已验过身份，WHMCS 惯例）；b 仍要验 | a，可由 IDC 在插件设置里改成 b |
| Q5 | 智简魔方版本与资料 | 需要提供：要支持哪几个版本（老版财务 v2/v3、新版业务系统），官方模块开发文档或一个现成接口插件 | — |
| Q7 | 代理商升降级订单能否退款/作废（10-27 定） | 不能：服务层返回 409 `reseller_change_irreversible`，迁移 551 守卫 P5515 兜底 | 已定 |
| Q6 | 测试环境 | WHMCS 是商业软件，真实验收需要一个 WHMCS 授权（开发版即可）；智简魔方同样需要可装的环境 | 用户提供 |
