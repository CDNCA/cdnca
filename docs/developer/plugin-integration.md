# 插件市场与外部集成契约 v1

<!-- contract-doc:plugin-example file="../../tests/contracts/plugin-manifest-v1.json" schema="../../api/schemas/marketplace/v1/plugin-manifest.schema.json" signature="manifest-ed25519-v1" publisher="../../tests/contracts/plugin-publisher-v1.json" -->
<!-- contract-doc:plugin-example file="../../tests/contracts/domain-event-v1.json" schema="../../api/schemas/marketplace/v1/domain-event.schema.json" -->
<!-- contract-doc:plugin-example file="../../tests/contracts/domain-event-deployment-v1.json" schema="../../api/schemas/marketplace/v1/domain-event.schema.json" -->
<!-- contract-doc:plugin-example file="../../api/schemas/marketplace/v1/extension-catalog.json" schema="../../api/schemas/marketplace/v1/extension-catalog.schema.json" -->
<!-- contract-doc:plugin-signature algorithm="webhook-hmac-sha256-v1" vector="examples/webhook-signature-v1.json" -->

## 1. 目标与范围

插件市场用于接入 DNS、短信、邮件、备案查询、支付、分析导出和自动化系统。v1 第三方插件只有三种形态：运行在开发者自己服务器上的 HTTPS 服务（`external_https`，含 provider）、由核心引擎解释的声明式数据包（`rule_pack`、`theme`）、开发者自己 origin 上的沙箱页面（`ui_page`）；不把第三方二进制、Lua 或前端脚本加载进控制面和边缘请求路径。该约束保证插件故障不会中断已有 CDN 流量，也避免插件取得数据库或节点私钥。

本文件定义实现必须遵守的契约。当前仓库已交付平台授权运营端的受信目录注册表、远程签名快照同步、发布者信任管理、单个清单远程验签、安装授权、安装实例级能力批准与可撤销短时工作负载身份，以及客户主控中的 Webhook 订阅、测试事件控制 API、加密 secret 轮换和持久测试投递运行时。通用领域事件 outbox 已接入（见第 8.1 节），扩展点目录中状态为 `available` 的事件可以订阅；客户 Control 的第三方进程安装执行仍属于独立挂载边界。目录项保持 `reserved` 时不能用于生产安装，也不能把测试事件链路、包内测试或数据库迁移当成插件已在客户控制面执行的证据。

隔离外部进程、签名 manifest 和持久幂等原则见 [`Webhook 审计接收器示例`](examples/webhook-audit-sink.md)。该示例仍演示 legacy v1 接收格式，不是当前生产 v2 测试 Webhook 的验收客户端。

当前 v2 Webhook 的可运行参考接收端见 [`Webhook v2 接收器示例`](examples/webhook-v2-receiver.md)，支持测试事件与 `io.cdnca.site.v1.updated`，并带配套清单。该示例按本文件第 8 节的顺序验证原始正文摘要、HMAC、时间窗、租户/订阅绑定，以 delivery ID 识别重试、以事件 ID 保证业务只执行一次，再将 durable journal `fsync` 后返回 `2xx`；生产部署仍需按示例文档补齐 TLS、共享幂等存储、secret manager、监控和备份。

发布者登记与清单验签的 operator-only HTTP 接入见
[`插件供应链运营接口`](plugin-supply-chain.md)。这些接口属于平台授权运营端，不是
租户插件身份、安装 API 或客户主控运行时。

安装、升级、保护性禁用/卸载与 LKG 回执见
[`插件安装授权与运营工作流`](plugin-installation-authorization.md)；版本矩阵、可执行验证器和
弃用迁移规则见 [`插件兼容与弃用契约`](plugin-compatibility-and-deprecation.md)。

## 2. 受信目录注册表

平台授权运营端通过 `licensing.plugin_catalogs.manage` 独立权限管理目录注册，接口定义见 [`license.yaml`](../../api/openapi/v1/license.yaml)：

- `GET/POST /operator/v1/plugin-catalogs`
- `GET/PUT /operator/v1/plugin-catalogs/{catalog_id}`
- `POST /operator/v1/plugin-catalogs/{catalog_id}/disable`
- `POST /operator/v1/plugin-catalogs/{catalog_id}/sync`
- `GET /operator/v1/plugin-catalogs/{catalog_id}/snapshots`
- `GET /operator/v1/plugin-catalogs/{catalog_id}/snapshots/{snapshot_id}`
- `GET /operator/v1/plugin-catalogs/{catalog_id}/sync-attempts`

`catalog_id` 是平台策略 `plugin_market.trusted_catalog_ids` 使用的稳定引用。创建时同时登记规范化的 HTTPS origin 和 Ed25519 公钥 version 1；服务端保存原始 32 字节公钥及其 SHA-256 fingerprint，API 使用无填充 base64url 返回两者。密钥表只允许追加，数据库阻止更新、删除和截断。

注册操作只进行本地语法和地址类别校验，不解析 DNS、不连接 origin，也不下载目录。它拒绝 HTTP、userinfo、路径、query、fragment、非 443 端口、localhost，以及显式的私网、loopback、link-local、multicast 和 unspecified IP。`active` 只表示该登记可以被新平台策略引用，不代表目录内容已抓取、签名已验证、插件可安装或插件可执行。

本版本只允许修改中英文名称和发布者名称，并以 `expected_revision` 做 compare-and-swap。`catalog_id`、origin 和公钥不能原地修改；后续换钥必须通过单独的、追加 key version 的协议交付。禁用是单向操作：它阻止新的平台策略发布继续信任该 ID，但不篡改已有签名策略，也不中断边缘流量。禁用审计记录所有引用策略修订数量和当前引用作用域数量。

平台策略预检会为不存在或已禁用的 `trusted_catalog_ids` 返回 `trusted_catalog_unavailable`；正式发布在同一事务中锁定并复查目录状态，失败返回 HTTP 409。该锁定防止目录禁用与策略发布并发时绕过信任检查。运营处置见 [`plugin-catalog-registry.md`](../runbooks/plugin-catalog-registry.md)。

## 3. 远程签名快照

显式同步只请求登记 origin 下的固定路径 `/.well-known/cdnca/plugin-catalog-v1.json`。调用者不能提供 URL、路径、请求头、代理或拨号目标。服务端每次同步重新解析登记域名；IPv4 和 IPv6 解析结果必须全部是公网地址，出现 loopback、private、link-local、multicast、unspecified、共享地址或保留测试地址时整体拒绝。连接固定拨到本次已验证地址，TLS SNI 和 HTTP Host 保持登记域名，不跟随重定向，不使用环境代理。总超时为 10 秒，连接、TLS handshake 和响应头各有独立较短超时；响应正文最多 2 MiB，并且唯一接受的 Content-Type 是 `application/vnd.cdnca.plugin-catalog.v1+json`。

响应 JSON 必须没有重复字段、未知字段、尾随值或无效 UTF-8，形状如下：

```json
{
  "envelope": {
    "domain": "cdnca-plugin-catalog-snapshot-signature/v1",
    "catalog_id": "cdnca.official",
    "key_version": 1,
    "sequence": 42,
    "issued_at": 1784707200,
    "expires_at": 1784793600,
    "canonical_payload_sha256": "base64url-sha256"
  },
  "payload": {
    "schema": "cdnca.plugin-catalog.payload/v1",
    "plugins": [
      {
        "plugin_id": "cdnca.cache",
        "version": "1.0.0",
        "manifest_path": "/manifests/cdnca.cache-1.0.0.json",
        "manifest_sha256": "base64url-sha256"
      }
    ]
  },
  "signature": "base64url-ed25519"
}
```

canonical payload bytes 使用 UTF-8、无 BOM、无空白、无尾随换行。字段顺序固定为 `schema,plugins`，插件字段顺序固定为 `plugin_id,version,manifest_path,manifest_sha256`，数组顺序保持不变；字符串只转义 JSON 控制字符、双引号、反斜线、U+2028 和 U+2029，不转义 `<`、`>`、`&`，不额外执行 Unicode normalization。计算 SHA-256 后使用无填充 base64url 写入 envelope。

canonical envelope bytes 使用相同编码规则，字段顺序固定为 `domain,catalog_id,key_version,sequence,issued_at,expires_at,canonical_payload_sha256`。发布者用登记 `key_version` 对应的 Ed25519 私钥直接签名这些 bytes，并将 64 字节签名编码为无填充 base64url。验签同时绑定目录 ID、密钥版本和 payload 摘要；远程正文不能声明或自动引入新信任密钥。

`sequence` 必须为正数并对每个目录单调增加。相同 sequence 和相同 payload 摘要视为内容幂等，复用已有不可变快照；相同 sequence 对应不同内容返回 `catalog_snapshot_conflict`；低于最后可用快照的 sequence 返回 `catalog_snapshot_replay`。`issued_at` 最多允许领先服务端时间 5 分钟，`expires_at` 必须晚于 `issued_at` 且同步时尚未过期，签名窗口最长 7 天。

远程请求在数据库事务外完成。成功时，快照、成功同步记录、审计和 Idempotency-Key 结果在一个事务内提交；并发同步由目录行锁串行判定 sequence。远程失败或签名失败只追加脱敏失败记录，不修改最后可用快照，也不占用成功幂等结果；网络结果未知时必须使用原 Idempotency-Key 精确重试。响应正文、签名、解析地址和密钥不得写入错误响应或日志。处置流程见 [`plugin-catalog-sync.md`](../runbooks/plugin-catalog-sync.md)。

同步只保存和展示签名 payload。它不请求 `manifest_path`、不安装或执行插件，也不向客户主控或边缘请求路径下发代码。

## 4. 发布包

发布包至少包含：

```text
plugin.json
schemas/config.schema.json
README.zh-CN.md
```

上传到市场时不是打一个压缩包，而是 `POST /seller/v1/plugins/{id}/versions` 的 `multipart/form-data`：`manifest`（签名后的 `plugin.json`）、`configuration_schema`（其 SHA-256 等于 `spec.configuration_schema.sha256`）、`rule_pack`/`theme` 版本的 `content`（等于 `spec.entrypoint.sha256`）或 `external_https` 版本的 1–16 个 `package:<platform>`，另有可选 `changelog_md`、`channel`、`auto_publish`；其他字段名直接 400（`services/market-service/internal/httpapi/plugin_seller.go` `parseVersionUpload`）。官网开发者页“按类型开发指南”逐类列出。

`plugin.json` 必须通过 [`plugin-manifest.schema.json`](../../api/schemas/marketplace/v1/plugin-manifest.schema.json)。清单使用稳定的反向域名 ID 和语义化版本；所有用户可见名称和说明必须提供 `zh-CN`，英文是可选补充。配置 JSON Schema 只描述配置形状，密码、API Token 和私钥字段必须带写入敏感标记，并由控制面信封加密，读取接口只能返回“已配置”状态。

v1 清单的 `spec.entrypoint.type` 是 schema `oneOf` 的四种之一：`external_https`（开发者自己的 HTTPS 服务，provider 插件也用这一种）、`rule_pack` 与 `theme`（声明式数据包，文件随版本上传，`sha256` 由发布者签名覆盖，最大 8 MiB，不执行代码）、`ui_page`（开发者自己 origin 上的沙箱页面，见第 8.3 节）。各类型的字段互斥，见 [`plugin-manifest.schema.json`](../../api/schemas/marketplace/v1/plugin-manifest.schema.json) 第 106–181 行。市场按插件 kind 强制入口：`rule_pack` 插件只能上传 `rule_pack` 版本、`theme` 插件只能上传 `theme` 版本、`ui_page` 插件只能上传 `ui_page` 版本，其余 kind 一律 `external_https`（`services/market-service/internal/plugin/version.go` `checkEntrypoint`）。

`external_https` 入口的生产安装必须使用公网或管理员明确批准的私网 HTTPS 地址；实现方必须拒绝明文 HTTP、URL 用户信息、非标准重定向以及解析到 loopback、link-local、metadata 和未授权私网网段的地址。每次连接都要重新校验 DNS 结果，防止 DNS rebinding。

## 5. 清单签名

发布者在平台注册 Ed25519 公钥，平台分配稳定 `key_id`。签名输入按以下步骤生成：

1. 删除顶层 `integrity` 字段。
2. 使用本项目 v1 确定性 JSON 编码对剩余对象做 UTF-8 规范化；对象键按字节序排列，数组顺序保持不变，字符串按 [`插件供应链运营接口`](plugin-supply-chain.md) 的签名章节转义。不要用会改变键顺序、Unicode 或转义形式的通用 JSON 重写器代替该算法。
3. 计算 SHA-256，并写入小写十六进制 `integrity.payload_sha256`。
4. 对 `UTF8("cdnca-plugin-manifest/v1\n") || sha256_bytes` 做 Ed25519 签名。
5. 将 64 字节签名编码为无填充 base64url，写入 `integrity.signature`。

服务端先校验 Schema、包内配置 Schema 摘要和发布者状态，再校验清单签名。被撤销密钥不能签发新版本；已安装版本进入告警和管理员决策流程，不得静默替换或直接影响边缘流量。

## 6. 安装与授权

安装过程必须明确显示中文插件名、发布者、目标租户、申请权限、敏感权限、订阅事件和出口地址。管理员确认后生成安装 ID，并只授予清单 `permissions` 的子集。高风险权限需要再次确认并写入不可篡改审计。

插件服务身份使用可撤销的短时版本化工作负载凭据，并精确绑定 tenant、installation、
plugin、capability、action、revision 与 expiry。不得用用户 JWT、管理员 Cookie、全局 API
key 或长期共享密钥模拟插件身份；撤销或事实过期后的新请求默认拒绝。

卸载先撤销服务身份并停止新投递，再清理非审计配置。历史审计、资金账本和已完成投递记录按各自保留策略保存。升级必须重新校验签名、兼容范围和新增权限；不能因版本升级自动扩大授权。

## 7. API 调用规则

### 7.1 当前接入方式

第三方插件服务当前可用的认证只有下表四种。第 6 节的插件工作负载凭据只由主控内部用于逐次授权 Webhook 投递，没有对第三方公开的签发或刷新入口；OAuth 2.0 / client credentials 尚未发布（见 [`release-status.md`](release-status.md)）。

| 方向 | 认证 | 适用范围 | 失效后怎么办 |
| --- | --- | --- | --- |
| 插件服务 → 客户主控 OpenAPI | 客户在目标租户创建并交给你的 API Key：`Authorization: CdncaKey <key_id>.<secret>` | 只限契约标注 `cdncaApiKey` 的接口，范围以[开放接口目录](https://www.cdnca.com/developers/api)中“API Key 可调”的接口为准；实际权限是 Key 的 scope 与创建者当前权限的交集，另受 IP 允许列表和有效期限制 | 由客户核对 Key 是否已撤销、过期或轮换，再把新 secret 交给你；不能用客户会话代替 |
| 主控页面（`ui_page`）→ 插件后端 | 主控代理附带 `X-Cdnca-Plugin-Context`、`X-Cdnca-Plugin-Signature`、`X-Cdnca-Plugin-Key-Id`（第 8.3 节） | 只用于你的 `api_base_url`；不含用户会话或 token | 验签失败按 key_id 重新取得安装签名公钥 |
| 主控 → provider 服务 | `cdnca.provider/v1` 签名请求，响应用你的响应私钥签名 | provider 协议动作 | 按安装公钥与时间窗、nonce 规则处理 |
| 主控 → Webhook 接收端 | Webhook v2 HMAC（第 8 节），secret 由客户创建或轮换订阅时取得 | 订阅的测试事件与已开放领域事件 | 按 `X-CDNCA-Webhook-Key-Id` 选择当前或仍有效的旧 secret |

只接受登录会话的接口（例如创建 API Key、管理 Webhook 订阅）由客户本人在主控里操作；插件服务不得索取、转存或代用客户会话或 Cookie。

### 7.2 调用规则

- 使用对应 OpenAPI 文件中的版本化路径和 Schema，不能依赖界面私有请求。
- 写请求携带 1 到 128 字符的 `Idempotency-Key`；网络超时后使用相同 key 和相同正文重试。
- 记录响应 `X-Request-ID`，并在支持时透传 W3C `traceparent`。
- `401` 表示所用 API Key 无效、已撤销、过期或已轮换：停止用旧 secret 重试，请客户核对或重新签发 Key（第三方没有可刷新的工作负载凭据）；`403` 表示 Key scope、创建者当前权限或租户范围不足，不能无限重试；`409` 需要读取当前资源或检查幂等冲突；`429` 和 `503` 使用带抖动的指数退避并尊重 `Retry-After`。
- 日志不得记录访问令牌、Webhook Secret、DNS 密钥、证书私钥、完整请求体或未经脱敏的安全事件。

## 8. 事件与 Webhook

公开业务事件正文必须通过 [`domain-event.schema.json`](../../api/schemas/marketplace/v1/domain-event.schema.json)，形状兼容 CloudEvents 1.0 structured content，`data` 按 `type` 严格校验（不允许未声明字段）。事件 `id` 是一次事件对一个订阅的唯一标识；`tenant_id` 是服务端确定的租户；`request_id` 是源事实 ID，同一业务事实投到多个订阅时相同；`sequence` 在同一订阅内严格递增；`data.subject_sequence` 在同一租户、事件类型和 subject 内从 1 递增。接收方以事件 ID 处理业务幂等，不能仅依赖顺序。已开放事件见第 8.1 节，`io.cdnca.webhook.v1.test` 测试事件规则不变。

扩展点以 [`extension-catalog.json`](../../api/schemas/marketplace/v1/extension-catalog.json) 为机器可读目录，并由其 Schema 校验。稳定 `catalog_id` 用于和平台策略的 `trusted_catalog_ids` 对照；目录 ID 被信任仍不能替代发布者签名、插件权限检查和租户管理员安装授权。只有状态为 `available` 的事件和权限才可出现在生产安装；`reserved` 只用于提前协调契约。

当前测试 Webhook 使用 `POST` 和 `Content-Type: application/cloudevents+json`。请求正文是 [`webhook-test-event.schema.json`](../../api/schemas/marketplace/v1/webhook-test-event.schema.json) 定义的规范 CloudEvents bytes；运行时直接摘要、签名并发送数据库保存的规范 bytes，不重新格式化 JSON。事件 ID 是正文的 CloudEvents `id`，delivery ID 是一次投递生命周期的标识，两者不能混用。可选 `traceparent` 只接受规范的 lowercase W3C version `00`、非零 trace/span ID 及 `00` 或 `01` flags；存在时它作为 CloudEvents 扩展保留在同一规范正文中并随投递传播，当前协议不额外发送独立 `traceparent` HTTP header。

投递请求包含：

| Header | 含义 |
| --- | --- |
| `X-CDNCA-Webhook-Event-Id` | CloudEvents 事件 UUID；必须与正文 `id` 相同 |
| `X-CDNCA-Webhook-Delivery-Id` | 本次投递 UUID；同一次投递的所有 attempt 保持不变，显式 replay 使用新值 |
| `X-CDNCA-Webhook-Timestamp` | UTC Unix 秒 |
| `X-CDNCA-Webhook-Content-Sha256` | 原始请求体 SHA-256 的小写十六进制 |
| `X-CDNCA-Webhook-Key-Id` | 用于本次签名的 secret-version UUID；接收方据此选择密钥 |
| `X-CDNCA-Webhook-Signature-Version` | 固定为 `v2` |
| `X-CDNCA-Webhook-Signature` | `v2=<43 字符、无 padding 的 base64url HMAC-SHA256>` |
| `X-CDNCA-Idempotency-Key` | `plugin-webhook-v2-<64 位小写十六进制>`；同一次投递保持不变 |
| `X-CDNCA-Webhook-Attempt` | 从 1 开始的 HTTP 尝试序号；不得作为业务去重键 |

创建或轮换返回的 secret 是 43 字符无 padding base64url；必须严格解码为恰好 32 个 raw bytes，并以 raw bytes 作为 HMAC key，不能直接使用 43 个 ASCII 字节。签名输入使用 UTF-8 和 LF 分隔且没有尾随 LF，准确格式为：

```text
cdnca.webhook.signature/v2
POST
<canonical-escaped-request-path>
<timestamp>
<event-id>
<delivery-id>
<secret-version-id>
<lowercase-hex-sha256-of-raw-body>
```

`canonical-escaped-request-path` 是已通过目标 URL 门禁、长度 1 到 512 的 `EscapedPath()`；签名不包含 scheme、host、query 或 fragment。目标 URL 不允许 query/fragment，拒绝非规范百分号编码、编码 slash/backslash、反斜线和 dot segment，因此接收方必须用实际请求的规范 escaped path 原样重建签名输入，不能 URL decode 后再签。

接收方必须先对收到的原始正文 bytes 计算 SHA-256，并与 content digest 做常量时间比较；随后按 `X-CDNCA-Webhook-Key-Id` 选择当前或仍在验签窗口内的密钥，重建 v2 HMAC 并做常量时间比较；只有两项均通过后才能解析 JSON。timestamp 接受窗口是包含边界的接收端时间正负 300 秒。接收方至少保存 delivery ID 30 天用于 attempt 去重；事件 ID 与 delivery ID 保持独立，显式 replay 会生成新 delivery ID。

权威固定 v2 向量位于 OpenAPI 的 `x-cdnca-signature-example` 和测试事件 Schema 同名扩展中。旧 [`webhook-signature-v1.json`](examples/webhook-signature-v1.json) 仍由契约检查器验证，因为 Go 包保留 `Sign`、`Verify` 和 v1 sender 作为 legacy 库级兼容入口；当前数据库支持的生产运行时只发布 queue v2 和上述 v2 HTTP header，不能向新接收端宣称 v1 是现行协议。

任意 `2xx` 表示接收成功；`408`、`425`、`429` 和 `5xx` 可重试，`429` 尊重 `Retry-After`；其他 `4xx` 进入失败记录但不盲目重试。投递语义是至少一次，控制面采用 PostgreSQL 持久 outbox、JetStream、有限并发、指数退避和死信状态。管理员可查看脱敏的尝试历史并显式重放；响应正文只保留大小受限的脱敏摘要。

### 8.1 已开放的领域事件

| 事件类型 | subject | 安装须获批的权限 | data 字段（另含 `subscription_id`、`subject_sequence`） | 产生时机 |
| --- | --- | --- | --- | --- |
| `io.cdnca.deployment.v1.status_changed` | `deployment/<uuid>` | `events.deployment.read` | `deployment_id`、`rollout_id`、`node_id`、`attempt`、`transition_sequence`、`state` | 节点上报的发布状态被受理（平台级节点制品发布不产生租户事件） |
| `io.cdnca.site.v1.updated` | `site/<uuid>` | `events.site.read` | `site_id`、`change`（`created`/`updated`/`enabled`/`disabled`/`deleted`）、`changed_fields`（`domains`/`origins`/`ports`/`https`/`line_group`/`status`/`settings`） | 站点每个已提交的 revision（含锁定、套餐变更、流量停用、域名认领停用等所有写路径） |
| `io.cdnca.certificate.v1.status_changed` | `certificate_order/<uuid>` | `events.certificate.read` | `order_id`、`status`、`previous_status`（新建订单无）、`revision`、`renewal_of_order_id`（续期订单）、`not_after`（已签发后） | 租户 ACME 证书订单每次状态变化（pending→validating→issuing→issued→…，失败、续期、吊销） |
| `io.cdnca.certificate.v1.expiry_reached` | `certificate_asset/<uuid>` | `events.certificate.read` | `asset_id`、`version_id`、`stage`（`expiring_30d`/`expiring_7d`/`expiring_1d`/`expired`）、`not_after`、`source`（`uploaded`/`acme`）、`renewal_order_id`（ACME 证书） | 租户正在使用的证书版本到期前 30 天、7 天、1 天及过期时各一次；跳过的阶段只发最近的那个 |
| `io.cdnca.node.v1.status_changed` | `node/<uuid>` | `events.node.read` | `node_id`、`kind`（`presence` 在线/离线，`admin` 管理状态）、`status`、`previous_status`、`revision` | 节点心跳上线/判定离线，或管理状态变化；按承载该节点的每个租户各产生一条，不含节点地址 |
| `io.cdnca.usage.v1.threshold_reached` | `package_subscription/<uuid>` | `events.usage.read` | `package_subscription_id`、`source`（`monitor`/`enforcement`）、`metric`、`phase`（`triggered`/`recovered`/`suspended`/`resumed`）、`period_key`、`observed_value`（监控类，非到期指标）、`revision` | 套餐监控阈值告警触发/恢复；或套餐因流量、带宽、连接数、站点数超额被停用/恢复（人工强制不算用量事件） |
| `io.cdnca.security.v1.incident_detected` | `site/<uuid>` | `events.security.read` | `site_id`、`category`（当前只有 `cc_auto_switch`）、`incident_sequence`、`node_id`、`started_at` | 站点 CC 自动切换的每个通知窗口（窗口过期后再次触发记为新序号）；不含客户端地址、请求路径 |

`changed_fields` 只给变更类别，不含配置值；需要当前配置时调 OpenAPI 读取。当前第三方服务调用主控只能用租户创建并交给你的 API Key（`Authorization: CdncaKey <key_id>.<secret>`，仅限 OpenAPI 标注 `cdncaApiKey` 的接口）；插件工作负载身份目前只由主控内部用于逐次授权 Webhook 投递，对第三方公开的工作负载凭据签发端点尚未发布（见 [`release-status.md`](release-status.md)）。

节点多为平台共享：节点事件按“承载该节点的租户”展开，即节点所属租户（市场卖家自有节点）和该节点下发过其配置的每个租户（`node_config_state`），每个租户各自一条事实、各自的 `subject_sequence`。证书事件以 ACME 订单为 subject；证书资产到期没有写库时刻，不产生事件。

每类事件的产生点都是记录该业务事实的那张表（`sites`、`certificate_orders`、`node_presence`/`nodes`、`package_monitor_transition_facts`/`package_cycle_enforcement_transitions`、`cc_auto_switch_notification_windows`、证书到期扫描写入的 `certificate_expiry_facts_371`）上的触发器，与业务写同事务，任何写路径都不会漏发。

产生与投递：

1. 业务写与源事实同事务提交（`domain_event_outbox_368`）。业务回滚则没有事件；事件写入失败则业务回滚。站点事件由 `sites` 上的延迟约束触发器在提交前追加，所有改 `sites.revision` 的路径都会产生事件。
2. 同一 subject 的写入按提交顺序取得 `subject_sequence`（subject 头行加锁）。扇出 worker 只在同一 subject 更早的事实都已扇出后才处理下一条，因此一个订阅收到同一 subject 的事件按 `subject_sequence` 先后入队。
3. 扇出时只选择：订阅为 `active`、订阅了该事件类型、订阅创建早于事实发生时间（不补发订阅前的历史）、绑定的安装为 `enabled` 且已获批该事件权限。每条投递（含重放）写入时数据库再次检查安装状态与权限，撤销权限或停用安装后新事件和重放都会被拒绝。
4. 投递语义是至少一次。网络重试在同一 delivery ID 内递增 `X-CDNCA-Webhook-Attempt`；显式重放复用事件 ID、生成新 delivery ID。接收方用事件 ID 去重业务处理，用 `subject_sequence` 识别同一资源的先后，遇到更小的值应视为过期副本丢弃。

### 8.2 订阅过滤、补发与按时间重放

- 按事件类型：订阅的 `event_types` 只能选目录中 `available` 的事件（含测试事件），每个业务事件都要求绑定的安装已获批对应权限。
- 按站点：创建订阅时可带 `site_ids`（1～100 个本租户站点）。带站点过滤的订阅只收这些站点的站点级事件（`site.updated`、`security.incident_detected`），不再收部署、证书、节点、用量等租户级事件，且至少要选一个站点级事件类型；不带则收全部。过滤属于订阅身份，创建后不可修改，要改就新建订阅再撤销旧订阅。
- 不补发订阅前的历史：只有订阅创建之后发生的事实会扇出给它。
- 补发失败：`POST .../plugin-webhook-subscriptions/{id}/delivery-replays`，正文 `{"from","to","statuses":["dead_lettered"],"limit"}` 重发该时间段内进入死信的投递；不带 `statuses` 时重发已送达与死信两类。时间窗最长 31 天，单次最多 100 条，`remaining=true` 表示还有未处理的，可用同一个 `Idempotency-Key` 再调一次继续。
- 按时间重放与单条重放的保证相同：事件 ID 不变、生成新 delivery ID、写审计、受频率限制；数据库在写每条重放时重新检查安装仍为启用、仍有事件权限、站点过滤仍选中该事件，不满足的记为 `permission_denied` 跳过。批次内每条投递的幂等键由批次 `Idempotency-Key` 派生，重试同一批次不会重复重放（结果为 `already_replayed`）。

## 8.3 带页面的插件（ui_page，C3）

页面由开发者自己的 https 站点提供，主控在固定挂载点用 `<iframe sandbox="allow-scripts allow-forms">` 加载（不给 `allow-same-origin`）。框内 origin 是不透明的 `null`：读不到主控的 Cookie、localStorage、sessionStorage、IndexedDB，也碰不到主控 DOM、不能导航顶层窗口。第三方代码不进主控进程、不由主控提供。

- 清单 `spec.entrypoint`：`{"type":"ui_page","origin":"https://ui.example.com","api_base_url":"https://api.example.com/v1","pages":[...]}`。`pages[]` 每项：`id`、`path`（拼在 origin 后作 iframe src）、`mount`（`menu` 菜单项 / `site_tab` 站点详情“扩展”页签）、`menu_parent`（菜单父级：管理端 monitor/node/site/stream/config/package/finance/system，用户端 monitor/site/stream/user-package/account）、`role`（admin/user）、`title{zh-CN,en-US}`、可选 `required_permission`（不吃 platform.admin 兜底）与 `required_module`。`permissions` 必须含 `platform.ui_pages.provide`。格式与校验代码见 `libs/entitlement/pluginui`（市场审核、授权端、主控共用）。
- origin 与 api_base_url 只能是 https、默认端口、DNS 主机名，并且必须先在 developer.cdnca.com 的“页面来源”页登记验证（接口 `/seller/v1/publisher-origins`：把 `cdnca-plugin-origin=<令牌>` 放在 `https://<host>/.well-known/cdnca-plugin-origin.txt`；市场只连公网地址、不跟随重定向）。同一 origin 同时只能属于一个发布者；主控上两个启用的插件也不能共用一个页面 origin。
- CSP：只有本安装已启用的 ui_page 插件 origin 进主控 `frame-src`；授权停用 / 卸载后下次同步即撤下。
- postMessage 协议 `cdnca.plugin-ui/v1`：页面从 URL 片段 `#cdnca-nonce=<nonce>` 读 nonce，向 `parent` 发 `{protocol,type:"cdnca.hello",nonce}`；宿主只认该 iframe 的窗口和该 nonce，回 `{type:"cdnca.ready"}` 并转交一个 MessagePort，之后所有请求只走这个端口：`{protocol,nonce,id,method,params}`，应答 `{protocol,nonce,id,ok,result|error}`。白名单只有 `context.get`（用户 ID/显示名/角色、租户作用域、站点 ID、语言、明暗主题；不含任何凭据）、`navigate`（`{path}`，站内相对路径，登录/找回密码/API 密钥/个人资料等页拒绝）、`api.request`（`{method,path,query?,body?}`）。其他消息一律回 `message_not_allowed`。
- 受限 API：`api.request` 由宿主转给 `POST /v1/plugin-ui/{plugin_id}/proxy`，主控再转发到 `api_base_url`（只连公网、不跟随重定向、只回 JSON、每用户每插件每分钟 120 次）。主控不转发用户会话或 token，而是附带 `X-Cdnca-Plugin-Context`（base64url JSON，`cdnca.plugin-ui-context/v1`，60 秒有效，含 nonce）、`X-Cdnca-Plugin-Signature`（安装私钥 Ed25519，签 `"cdnca-plugin-ui-proxy/v1\n" + METHOD + "\n" + path?query + "\n" + hex(sha256(body)) + "\n" + context`）与 `X-Cdnca-Plugin-Key-Id`。插件后端用安装公钥验签、检查有效期并记住 nonce（公钥由主控管理员在“插件市场 → 插件详情 → 安装签名公钥”复制给开发者，接口 `GET /v1/plugin-ui/signing-key`，`key_id` 即 `X-Cdnca-Plugin-Key-Id`）；需要改主控数据时由插件后端调 OpenAPI（当前用租户 API Key，见第 8.1 节末）。写操作与被拒调用记审计 `plugin.ui_page.proxy`。
- 安装确认：主控管理员确认安装 / 升级时，弹窗按授权端签过的清单指纹到插件市场核对该版本，列出将添加的菜单、页面 origin 与插件后端；指纹对不上或市场不可达时只提示去平台核实，不展示其他版本的声明。
- 开发者 SDK：`examples/plugin-ui-sdk/`。`cdnca-plugin-ui.mjs`（框内，无依赖：`connect()` 完成 hello/端口握手，返回 `context()` / `navigate(path)` / `request({method,path,query,body})`，错误为带 `code` 的 `PluginUIError`）、`index.html`（示例页）、`verify-backend.mjs`（Node 后端验签：签名、key_id、有效期、nonce 防重放）、`proxy-vector.json`（主控测试 `TestDeveloperSDKProxyVector` 生成的金标向量）。自测：`node --test docs/developer/examples/plugin-ui-sdk/sdk.test.mjs`。

## 9. 兼容与弃用

- 清单 `api_version`、事件类型中的 `vN` 和 OpenAPI 版本分别演进，不能互相推断。
- 同一事件大版本只允许增加可选字段；删除字段、改变含义或收紧已有值域必须升大版本。
- 弃用先把目录状态改为 `deprecated`，提供替代项和至少一个稳定发布周期的迁移窗口。
- 插件声明的 `control_api` 范围不满足当前版本时，安装和升级必须失败，已安装插件保持禁用或最近兼容状态，不得绕过检查。

## 10. 实现验收门槛

插件运行时只有同时通过以下验证后，才能把目录项从 `reserved` 改为 `available`：签名与篡改测试、权限拒绝、租户隔离、凭据撤销、SSRF、Webhook 重放和轮换、持久重试和死信、幂等、限流、审计脱敏、升级新增权限确认，以及中文桌面和移动端安装流程的真实浏览器验收。
