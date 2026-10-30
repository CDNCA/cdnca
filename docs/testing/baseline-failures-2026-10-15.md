# 基线失败分类（2026-10-15，基线 b8348499）

范围：`apps/web`、`apps/operator-console`、`apps/license-portal` 的 vitest；`control-api`、`license-service`、
`agent-gateway`、`edge-agent` 的 `go test`（含 `-tags integration`）与 `go vet`；`scripts`/`tests` 下的静态检查与 `node --test`。

分类口径：

- **真实缺陷**：测试揭示的线上问题（功能不可达、数据加载失败、逻辑错误、硬编码、缺文案），改代码。
- **测试过时**：页面/接口已按设计改动，测试没跟上，改测试。
- **环境偶发**：只在本机（macOS、高负载、共享 PG）出现，CI（Linux）或单独重跑可通过；用加大超时、去掉时序依赖处理，不跳过。

## 一、真实缺陷（已修代码）

| # | 位置 | 影响 | 修复 |
|---|---|---|---|
| D1 | `apps/web` 个人资料页 `AccountUserPage` | 9/19 精简资料页时删掉了改密码表单与 MFA 面板，「登录密码 ******」旁的铅笔是装饰图标：**用户端无法自助修改密码、租户无法设置两步验证** | 铅笔改为按钮展开改密码表单（成功后清会话回登录页）；「登录安全设置 / 立即设置」展开真实 MFA 面板 |
| D2 | 同上 | 手机/邮箱/登录安全的状态徽章全部写死（邮箱永远“已绑定”、手机永远“未绑定”、登录安全永远“未设置”），按钮文案也写死 | 徽章与按钮按资料与 `GET /v1/account/mfa` 推导；MFA 未读到前不显示徽章 |
| D3 | 同上 | 绑定手机/邮箱只判空不跑表单规则，格式校验形同虚设；当前密码进入 `mutate()` 变量被 MutationCache 缓存；密码错误后不清空输入；换身份时改密码 mutation 未清理 | 先 `validateFields`；密码只放 ref；失败清空；清理两个 mutation |
| D4 | 同上 | 「立即认证」永远禁用，租户无法从资料页进入实名认证 | 有 `identity_verification.self.manage` 的租户跳 `/account/verification`（实名状态暂无读取接口，徽章仍为“未认证”，见“剩余问题”） |
| D5 | `services/control-api/internal/dashboard` 租户首页 | 资源计数区要求 `nodes.read`，而迁移 042/079/094 禁止租户系统角色持有该权限：**用户首页「域名」「转发」永远显示占位符** | 资源计数只依赖基础读权限；节点网络区块仍由 `nodes.read` 控制 |
| D6 | `services/control-api/internal/edgestatus` | 证书/密钥（`node_secret_bundle`）下发完成时，节点带 v1 身份能力但没有配置身份，迁移 087 触发器以 P8702 拒绝 healthy 状态；该错误不在永久错误列表，状态被无限重投，**证书下发永远停在 activated** | 只有 configuration 制品记录身份 API 版本（不新增迁移） |
| D7 | `services/control-api/internal/nodeidentity` | 10/14 让待初始化的自注册节点保持会话以续期证书，但续期的 `prepareRenewal`/`finalizeRenewal` 仍只允许 active/draining：**自注册节点 24 小时证书到期后只能删掉重装** | 抽出 `renewalAllowedForNodeState`，放行 pending 的自注册节点；补回归用例 |
| D8 | 同上 | 续期在检查续期窗口之前就申请租约 ID，过早续期也消耗 ID（违背“重放预检不依赖 ID 生成器”的约定） | 租约 ID 延迟到所有只读闸门通过后生成 |
| D9 | `apps/web` i18n | en-US 顶层 `errors` 缺 5 个 `package_*` 键；维护升级缺 10/14 新增的 3 个“升级主控”弹窗键：**英文界面显示原始 key** | 补齐文案 |
| D10 | `apps/web` 套餐管理页 | 一段按语言写死 “No packages/暂无套餐” 的隐藏文本，无论是否有套餐都存在（硬编码 + 读屏误报） | 删除，空态沿用表格 `values.noProducts` |
| D11 | `services/agent-gateway` 节点监控下发 | consumer `MaxWaiting: 1`，fetch 超时后立即重拉会收到 409 “Exceeded MaxWaiting”，被当作致命错误，网关以 “node monitoring artifact delivery failed” **断开整个节点会话**，节点反复重连 | 视为暂时状态，退避 50 ms 后重试 |

## 二、测试过时（改测试）

按模块汇总（每条在对应 commit message 里有逐项说明）：

- **web**：`AccountUserPage(.i18n)`、`AccountMfaPanel`（资料页改为安全卡）、`UserListPage(.i18n)`（`include_platform_admins`、`username=` 精确筛选、编辑弹窗读登录安全）、`ChallengePoliciesPanel`（挑战策略改为「更多」子视图）、`FinanceOrdersPage`（统一订单列表、每页 10 条）、`PackageBasicPage.i18n`、`i18nSafety`（维护升级 key 误报）、`routes`/`routeAuthorization`/`AdminTasksRoute`/`NodeSchedulingRoutes`/`AnalyticsRoutes`/`batchKLNavigation`/`RouteErrorBoundary`、`SiteTLSProtocol`（TLS 移到 HTTPS 标签）、`SiteEditPage.i18n`、`SiteCnameLifecycle`、`NodeListPage.i18n`、`NodeRegionManagement`、`SystemSentLogPanel`。
- **control-api**：`PackageCycle` 组装 SHA；`certificatepublish`（vet：生产组装用 `CertificatePublisherStore`）；`edgepublish`（vet copylocks）；`nodeidentity`/`nodepresence`/`nodecertlifecycle` 迁移往返（见第四节）；`nodepresence`/`edgestatus`/`dashboard` 夹具（`display_id`、真实 Ed25519 签名、`node_config_state` 认领作用域、运行时探测、迁移 170 具名约束、迁移 092 四层转发必须绑定订阅、迁移 090 套餐目录审计、迁移 085 证书资产操作者作用域、租户角色不得持有 `nodes.read`）。
- **静态检查**：`tests/installers-static-test.sh`（19443/19444 改由 `node-install-defaults` 发布）、`scripts/operator-console-container-static.sh`（3 个同源 License API 前缀 + runtime 夹具挂载 `master-downloads.conf`）、`tools/contract-doc-check/openapi-index`（823 个 operation）。

### 删除的用例与理由

| 用例 | 理由 |
|---|---|
| `AccountUserPage`：显示名称编辑、未知结果重试/放弃、`updates profile with revision…`、`retries an unknown contact update…` 等 | 对应的“基本信息表单 / 保存结果待确认”UI 已在 9/19 删除，功能不存在；绑定与改密码的保护性断言已改写到新入口 |
| `AccountUserPage.i18n`：`maps a stable profile error…`、`locks all writes and retries…`、`closes an unknown profile result…`、`refreshes the stale form after a localized revision conflict` | 同上 |
| `FinanceOrdersPage`：`keeps the disabled item visible while the route remains absent` | `/finance/order` 已不受功能开关控制，路由常开 |

## 三、环境偶发

| 用例 | 原因 | 处理 |
|---|---|---|
| `UserListPage` 5 条（显式 20 s 超时） | `userEvent` 逐字输入在负载 20+ 时超过 20 s | `userEvent.setup({ delay: null })`，翻页改为等待元素出现；最慢用例降到约 7 s |
| `edge-agent/internal/challenge` | macOS `TempDir` 在 `/var → /private/var` 软链下，发布根目录禁止软链祖先 | 测试夹具先 `EvalSymlinks`（与仓库其它测试一致） |
| `edge-agent/internal/drainruntime` 全部 | 依赖 Linux `/proc/self/fd` 与 pidfd，macOS 不可运行 | 未改；`golang:1.24.13-bookworm` 容器内 `go test` 通过（CI 为 ubuntu-24.04） |
| `edge-agent/internal/cc` `TestIndependentPublishersCannotRegressCurrentVersion` | macOS 上约 1/3 概率 `open CC policy lock: ENOENT` | 未改；Linux 容器 `-count=20` 全过 |
| `edge-agent/internal/cachetask` 批量清理 | 默认 5 秒扫描时限在高负载下把后半批判为超时 | 该用例扫描时限放宽到 30 秒 |
| operator-console 63 条 | vitest 默认 5 秒超时 | `testTimeout: 30_000`（与 web 一致），两个长流程去掉逐字输入延时 |
| agent-gateway 集成 | 夹具状态流前缀重叠、缺 3 个配套遥测流 | 改夹具 |
| control-api 全量集成在 `-p 2` 下大量 `context deadline exceeded` | 所有包共用一个库时迁移 advisory lock 串行，单次迁移 283 号在高负载下 1–3 分钟 | 每次只跑一个包，按包重跑 |

## 四、迁移 268 / 032 的 down

二者都是**已发布迁移，不改文件内容**（原生升级会校验已有迁移的 up/down 校验和）。选择“只改测试期望”，不新增修复迁移：

- **268**：down 是刻意的单向闸门（P2682，“保留修正后的节点监控 outbox 触发器”），从发布头回滚必然失败，属于设计而非缺陷。需要验证早期迁移往返的测试改为只装载 `1..N` 号迁移（新增 `internal/database/databasetest.MigrateThrough`，沿用 `migrations` 包已有的 version-isolated 做法），不再从发布头逐个回滚。
- **032（license-service）**：down 用 `authorization` 作别名导致语法错误，只影响“从 032 之后回滚到 031 以前”。032 之后已有 27 个后续迁移，生产不会回滚到 031；新增修复迁移也无法改写 032 的 down 文本（down 由各自版本文件执行）。结论见第六节。

管理端没有新增迁移（D6 改在 Go 侧，没有改 087）。

## 五、与其他任务的边界

- `operator-console` 文案与菜单（r134-plainlang）：只改了 `scripts/operator-console-container-static.sh`，未改 operator-console 源码。
- 授权端登录/注册/会话（r134-unilogin）、插件（r134-plugindist）、`controlplaneupgrade` runner（r133-upgradelog）：未改。
- 节点 WAF/CC 与规则编辑器（r135-secwaf）：只改了 `ChallengePoliciesPanel.test.tsx`（入口从标签改为「更多」），未改源码。

## 六、剩余问题（未修，需要后续处理）

| 项 | 现象 | 原因 / 建议 |
|---|---|---|
| R1 套餐订单退款/作废不可达（**已修，r135-refundkyc**） | 9/23 起 `/finance/order` 渲染统一订单列表，按租户查套餐订单并执行退款/作废的 `FinanceOrdersContent` 不再挂载，平台管理员在界面上无法退款/作废套餐订单 | 统一订单列表行内「操作」列给已付款的套餐订单加「退款/作废」，点开按订单 ID 读详情、按真实状态给按钮，二次确认写清后果；作废门槛改为只有未退款过的已生效订单；接口不变 |
| R2 实名认证徽章（**已修，r135-refundkyc**） | 「未认证」仍为固定文案 | 新增只读 `GET /v1/identity-verification/status`（不新增迁移）；资料页按 未认证/审核中/已认证/被驳回 显示，已认证隐藏「立即认证」，读不到状态时不显示徽章 |
| R3 control-api 从发布头回滚经过 268 的用例 | `httpapi` 约 12 个、`identityverification` 8 个（`TestIdentityVerificationMigrationRoundTrip`、3 个 `TestMigration037Down*`、4 个 `TestMigration068*`，r135-refundkyc 在 2ee4e024 上逐个复核）、`securitybinding` 1 个 `*MigrationRollback*/DownUp` 用例 | 268 down 是刻意闸门；需要逐个改为“只装载 1..N 并在 N 上种数据”（`databasetest.MigrateThrough` 已就绪）。`nodeidentity`/`nodepresence`/`nodecertlifecycle` 已按此改完 |
| R4 license-service 集成 | 37 个失败，其中 32 个是 `context deadline exceeded`（夹具 60 s 内装载 59 个迁移，本机负载 20+）；另 5 个待查：`signer_revocation_checkpoints is append-only`、`plugin_installation_transition_receipts.actor_id` 默认值、`signer revocation approval does not match an active proposal`、billing 回调运行时直读、operator 读锁 | 需在低负载机器或 CI 上复跑后再逐个定性 |
| R5 contract-doc-check | `check.mjs` 389 条（257 条错误响应缺 `code/request_id`、59 条幂等键 schema 等） | 文档契约质量债，不在 CI（CI 只跑 openapi-index，已修好）；量大，建议单独任务按外部 openapi 文件分批补 |
| R7 `identityverification` 集成另有 8 个基线失败（2ee4e024 干净构建同样失败，r135-refundkyc 复核） | `Get(other user)`/`Get(cross tenant)`/审计失败后读取期望 `ErrNotFound`，实际 `permission denied`（`TestDatabaseCreationWriteRequestAndPermissionGuards`、`TestPersonalReverificationEnterpriseIsolationAndRedaction`、`TestAuditRollbackTamperProtectionAndFixedClockExpiry`）；并发与 IAM 全局锁用例 `CreateDraft` 返回 unavailable 或超时（`TestConcurrentSingleActiveReviewPerUserAndEnterpriseSubject`、`TestReviewerAuthorizationSerializesRevocationCommitOrder`、`TestReviewerReadSerializesRevocationAndNeverFallsBackToSelfPermission`、`TestStrongIsolationRevocationCommitOrderMatrix`、`TestWriteFirstLockIsIAMGlobalShared`） | 前三个是用例期望与当前 `get` 先做 self.manage 授权的行为不一致；并发类需在低负载机器复跑后再定性 |
| R6 control-api 全量集成未跑完 | 所有包共用迁移 advisory lock，单包从 1 号装载到 283 号在本机需 1–3 分钟，全量串行估计 10 小时以上 | 已跑并修完基线清单涉及的包；全量需在 CI 跑 |

## 七、全量结果对比

| 项 | 基线 | 现在 |
|---|---|---|
| apps/web vitest | 144 失败 / 5449 通过 | **0 失败 / 5604 通过**（2 个原有 `skipIf` 功能开关用例） |
| apps/operator-console vitest | 偶发超时；本机全量 63 失败 / 1569 通过 | 63 个失败用例复跑 **0 失败**（testTimeout 30 s） |
| apps/license-portal vitest | — | 24 / 24 |
| control-api `go test`（单元） | 1 失败（PackageCycle） | **249 包全过** |
| control-api `-tags integration`（已跑的包） | 见基线清单 | nodeidentity、nodepresence、nodecertlifecycle、edgestatus、dashboard、identity 全过；httpapi 回滚类见 R3 |
| license-service `go test`（单元） | — | 35 包全过 |
| license-service `-tags integration` | 35+4 失败 | signerrevocation 全过；其余见 R4 |
| agent-gateway `go test` + integration（NATS 2.11.4 / Redis 7.4） | 集成 12 失败 | **全过** |
| edge-agent `go test` | macOS 上 challenge/drainruntime 失败 | challenge 已修；drainruntime、cc 并发用例仅 macOS 失败，Linux 容器全过 |
| `go vet` / `go vet -tags integration` | certificatepublish、edgepublish 报错 | 四个模块均 0 |
| scripts/tests `node --test` | 9 失败 | **0 失败**（6 个原有环境条件跳过：需 nginx/PG 二进制或 Linux root） |
| 静态检查 | installers 缺 `:19443`；operator-console-container 2 项 | installers、operator-console-container（static+runtime）、web-container、helm、openapi-index 全过 |
