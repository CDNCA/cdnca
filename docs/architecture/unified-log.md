# 统一日志（unified-log）

1.0.35 起，所有改变状态的操作都写审计事件，日志中心按分类展示白话详情，各分类可设置保留天数。本文是设计依据与约定，代码在 `services/control-api/internal/audit`。

## 1. 数据源

| 日志 | 存储 | 写入方 | 说明 |
| --- | --- | --- | --- |
| 操作 / 登录 / 系统事件 | PG `audit_events`（每个 scope 一条哈希链） | `audit.Append` / `audit.AppendTx` | 本文的主体 |
| 访问日志 | ClickHouse（analyticslog 访问表） | 节点上报 | 量大，不进 PG；保留用 CH TTL |
| 攻击 / 拦截日志（WAF、CC、黑名单、四层） | ClickHouse（拦截事件表） | 节点上报 | 同上；字段对照见第 7 节 |
| license-service、market-service 审计 | 各自的 `license_audit_events` / `market_audit_events` | 各服务 | 命名与模板约定同本文；目录各自维护（遗留，见第 9 节） |

PG 审计链保持 FX01 的机制：按 scope 的 `stream_position` + `previous_hash`，过期行先复制到 `audit_event_archive` 并推进 `audit_chain_checkpoints`，再删主表中未被引用的行。

## 2. 统一字段（迁移 361，占位号）

`audit_events` 在原有列之外增加正式列，全部进入版本 2 的事件哈希：

| 列 | 含义 | 来源（`audit.Event` 未填时） |
| --- | --- | --- |
| `category` | 事件目录分类 | 由 action 查目录得出；未登记为 `other` |
| `actor_kind` | `user` / `system` / `plugin` / `node` | `audit.WithActor(ctx)`，否则有 `ActorUserID` 为 `user`，否则 `system` |
| `actor_ref` | 非用户操作者或凭据：`plugin:<id>`、`node:<id>`、`job:<名>`、`api_key:<id>` | `WithActor` |
| `source_ip` | 来源 IP（单个地址，不含端口） | `Payload["ip"]` → `Payload["source_ip"]` → `audit.WithSourceIP(ctx)`（HTTP 中间件统一注入） |
| `reason_code` | 被拒绝 / 失败的原因码 | `Payload["reason_code"]` |
| `changes` | 改前 → 改后：`[{"field","before","after"}]` | `Payload["changes"]`（支持列表、`{字段:{before,after}}`、`{字段:[前,后]}`）|

时间仍是 `occurred_at`，作用域是 `scope_id`（平台 / 租户），对象是 `resource_type` + `resource_id`，结果是 `result`（success / denied / failure）。

脱敏：

- 写入时：键名像密钥的（password、secret、token、api_key、access_key、private_key、cookie、authorization…）在 payload 与 changes 里一律替换为 `[REDACTED]`，不可恢复。
- 展示时：目录里 `Masked` 列出的字段（邮箱、手机号等）以 `a***@x.com`、`138******00` 形式展示；目录里没列出的 payload 键，租户视角不展示。

约束（361 的 CHECK）：分类与 actor_kind 取值固定；`actor_kind='user'` 时必须有 `actor_user_id`；`source_ip` 必须是单个地址；`changes` 必须是数组。

## 3. action 命名与事件目录

新 action 一律用 `<分类>.<对象>.<动作>`，分类取第 4 节的值，例如 `site.cc.update`、`finance.recharge.create`、`plugin.package.install`。

已有 action（约 450 个，如 `firewall.policy.put`、`auth.login`）保持原名：多处数据库触发器和读路径按 action 字符串匹配（例如 034、066、078、094、331 迁移），改名会破坏这些约束；分类由目录给出，不靠前缀。

事件目录是 Go 注册表（`internal/audit/catalog*.go`），每个 action 一条：

```go
e("firewall.policy.put", CategorySecurity,
    "修改网站 {resource} 的防火墙策略{changes}",
    "updated the firewall policy of site {resource}{changes}"),
e("identity.user.update", CategoryAdmin, "修改用户 {resource} 的资料", "updated user {resource}").m("email", "phone"),
```

- 模板只写"做了什么"。渲染时统一加前缀：`<操作人> 于 <时间> 从 <IP> …`，结果非成功时加"，被拒绝 / ，失败（原因：…）"。模板里不得出现 `{actor}`、`{time}`、`{ip}`。
- 可用占位符：`{resource}`（对象名称，查不到时为 ID）、`{resource_type}`、`{resource_id}`、`{reason}`、`{changes}`，以及条目 `.f(...)` / `.m(...)` 声明过的 payload 键。
- `.f(...)`：可展示的 payload 字段；`.m(...)`：展示时打码的字段。

强制埋点（`TestEventCatalogCoversProductionActions`）：测试用 go/parser 扫描 control-api 全部生产代码中的 `audit.Event` 字面量（含 `[]audit.Event{{...}}`）与 `event.Action = ...`，把 Action 表达式解析成可能的字符串集合（字符串常量、包级常量、`+` 拼接、局部赋值、参数回溯到调用处、返回值）。以下任一情况测试失败：

1. 写入的 action 不在目录里；
2. Action 表达式解析不出来（拼接了结构体字段、运行时值），且没有在 `dynamicActionSites["<文件>:<函数>"]` 里列出全部可能取值；
3. `dynamicActionSites` 里的条目已经对不上任何动态写入点（过时）；
4. 目录条目没有任何生产代码写入（死条目）。

另有 `TestEventCatalogIntegrity`（命名、分类、中英文模板、占位符只用允许的字段、不重复）和 `TestCategoriesMatchMigrationCheck`（目录分类与 361 的 CHECK 一致）。

其它任务埋点的做法：

1. 写 `audit.Event`，Action 用常量；能给就给 `Changes`（或 payload `changes`）、`ReasonCode`；HTTP 请求里的 IP 自动带上，后台任务用 `audit.WithActor(ctx, audit.ContextActor{Kind: audit.ActorSystem, Ref: "job:<名>"})`，插件用 `ActorPlugin` + `plugin:<id>`。
2. 在对应分类的 `catalog_*.go` 加一条，模板写白话。
3. 写测试断言关键操作产生了正确的审计事件（action、对象、changes）。

## 4. 分类与默认保留天数

| 分类 | 中文 | 覆盖 | 默认保留（天） |
| --- | --- | --- | --- |
| admin | 管理员操作 | 用户/角色/代登录/黑名单/授权 | 365 |
| user | 用户操作 | 本人资料、二次验证、API 密钥、实名、工单 | 180 |
| auth | 登录与安全 | 登录、退出、会话、凭据被拒 | 90 |
| site | 网站配置 | 网站、回源、缓存、鉴权、四层转发、日志导出 | 180 |
| security | 防御策略 | CC/WAF/防火墙/人机验证/地区访问/快速屏蔽 | 180 |
| rule | 规则 | WAF 规则库订阅、错误页 | 180 |
| finance | 财务 | 余额、充值、订单、收款通道、优惠、四层计费 | 1095 |
| package | 套餐 | 套餐、订阅、流量包、超限执行、用量告警 | 365 |
| plugin | 插件 | 插件安装、下发、Webhook | 180 |
| node | 节点 | 节点、线路分组、二级节点、配置发布 | 90 |
| dns | DNS | DNS 账号、域名、记录、CNAME、域名所有权 | 180 |
| cert | 证书 | 证书、ACME、节点通信证书 | 180 |
| system | 系统 | 系统设置、升级、备份、后台任务、公告、通知、保留清理 | 365 |
| other | 其它 | 未登记的 action（不应出现） | 180 |

0 表示永久保留，上限 3650 天。

## 5. 保留与归档

PG（`audit_events`）：

- 每行按自己分类的保留天数判断是否过期；清理任务（FX01 的 `retentioncleanup`，`cdnca_retention_cleanup` 角色）把 scope 链上连续的过期前缀复制到 `audit_event_archive`、推进检查点，然后删除主表中未被引用的行（外键引用、链头、同对象最新一条、`cache.*` 仍保留，规则见 331）。
- 归档表是链校验的依据，日志中心可勾选"包含已归档"查看。
- 原 FX01 的 `login_records_days` / `operation_records_days` 由按分类设置取代（1.0.35 为初始版本，不做旧设置迁移）。

ClickHouse：访问日志、攻击日志各一个保留天数，清理任务用 ingest 身份 `ALTER TABLE … MODIFY TTL`（沿用 FX01 的 `clickhouse_ttl.go`）。

设置入口：主控"系统设置 → 数据清理与日志保留"，每个分类一行；修改本身写 `system_cleanup_settings.update` 审计（带 changes）。

## 6. 查询与导出

日志中心接口（主控 control-api）：

- 列表：按分类、时间范围、操作人（用户 ID / 用户名）、来源 IP、对象类型 + ID、结果、action 筛选，按 `occurred_at` 倒序分页；平台管理员可跨租户（按 scope 筛选），租户只看自己 scope。
- 每行返回服务端渲染好的 `summary`（白话一句话）与结构化字段：时间、分类、操作人、IP、对象、结果、原因、改动列表、可展示字段、请求 ID。前端只展示，不拼句子。
- 导出 CSV（同样的筛选，单次上限条数），导出操作本身写审计。
- 语言按 `Accept-Language` 选中文 / 英文模板。

## 7. 攻击日志列

| 列 | 来源（CH 拦截事件） |
| --- | --- |
| 时间 | 事件时间 |
| 客户端 IP | client_ip |
| 地区 / 运营商 | IP 库查表（G3-d） |
| 网站（域名） | site_id、host |
| URL | uri |
| 规则 / 过滤器 | rule / filter / waf 规则 ID 与类别 |
| 动作 | action |
| 命中位置 / 内容 | 已有字段时展示，超长截断 |
| 次数 | 聚合计数 |
| 到期 / 解锁 | 封禁到期时间；解锁操作写 `security` 审计 |

## 8. 页面

统一"日志中心"：页签即分类（含"全部""攻击日志""访问日志"），每页签同一套筛选（时间、操作人、IP、对象、结果）与白话列表，点开看改动明细与技术详情（请求 ID、原始 action），右上角导出。攻击日志页签用第 7 节的列，并保留解锁操作。

## 9. 遗留与边界

- license-service、market-service 的审计表结构不同（market 无哈希链），目录与覆盖测试暂只在 control-api；两服务新埋点照本文命名与模板约定，合入后再各自加同样的扫描测试。在此之前，两服务写的 action 也登记在 control-api 目录里并列入 `catalogOnlyActions`（如 license 的 `system.signer_trust.publish`），保证模板统一。
- `site_protocol_audit_events`、`control_signer_*_audit` 等专用审计表不进统一日志。
- 只能运行时确定的 action（`dynamicActionSites`）依赖人工列全取值；新增取值时目录测试无法自动发现，评审时注意。
