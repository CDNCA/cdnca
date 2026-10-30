# 客户主控本地授权租约

状态：已实现独立部署根 pin、本地签名租约安装、安装身份 proof-of-possession、自动激活/续租、可验证 signer 轮换链、PostgreSQL last-known-good、签名吊销清单在线同步（每分钟一轮）与 LKG、安装锁（HTTP 423）、网站/节点/功能/升级的服务端 guard。各操作的完整准入见下文“准入矩阵”；哪些只有本地回归、哪些还待云端验收见文末“实现状态”。

## 信任边界

`control-api` 只允许进程启动时从独立部署文件加载的 Ed25519 公钥成为根信任。在线 keyset 中的新 key 必须同时通过新 key PoP、当前受信 key 的 canonical rotation authorization 和完整 lineage 验证。PostgreSQL 保存的 last-known-good 只用于离线恢复；每次启动都必须校验原始响应摘要并从部署 pin 重验整条链。数据库内容、HTTPS 成功、API 凭据或 ETag 都不能建立或替换根信任；缺少部署 pin 时所有网站新增和发布 fail closed。

网站请求不调用 `license-service`。授权中心不可用时，只要部署锚仍在且本地租约为 `valid` 或 `grace`，网站创建和发布继续工作（用户 2026-10-21 决定：宽限期内主控正常可用；授权端宕机最长约 租期 + 宽限期 内不影响扩容）。本地 `valid` 只表示最后一份已验证租约仍在有效期内，不表示授权端此刻在线。Edge Agent/OpenResty 不读取租约表；但节点是否继续服务由授权端签发、经主控转交的服务票据决定（见“既有流量”），主控租约 30 天宽限不等于节点也能离线服务 30 天。

平台签名私钥不得进入客户主控、安装文件、日志或数据库。受信公钥本身不要求保密，但完整性等同根信任，必须由部署系统以只读文件提供，不能从租约 bundle、数据库或 API 响应自动学习。

客户主控的安装 Ed25519 私钥是另一条独立信任边界。它只证明当前主控持有平台登记的安装身份，不能签发 entitlement。私钥由客户部署系统生成并注入受限文件，不写 PostgreSQL，不进入命令行、日志或审计。授权中心只保存对应公钥。安装私钥泄漏时必须在授权中心吊销该安装并重新注册身份，不能通过更换本地数据库记录完成恢复。

## 两个独立文件

受信 key 文件由部署系统预置，示例：

```json
{
  "keys": [
    {
      "key_id": "platform-signing-2026-01",
      "public_key": "base64url-without-padding-ed25519-public-key"
    }
  ]
}
```

租约 bundle 不包含 keyset，示例：

```json
{
  "installation_id": "customer-control-01",
  "signed_lease": {
    "algorithm": "Ed25519",
    "key_id": "platform-signing-2026-01",
    "lease": {},
    "signature": "base64url-without-padding-signature"
  }
}
```

bundle 出现 `keys` 会被严格 JSON 解析器作为未知字段拒绝。`revoked_serials` 字段仅为后续协议保留；当前只接受缺失或空数组，任何非空值都会以 `unsigned entitlement revocations are not accepted` 拒绝且不落库。这防止未签名 bundle 注入 key 或 serial，造成授权绕过或持久拒绝服务。

两个解析器都拒绝未知字段、多个 JSON 值、超过 1 MiB 的文件、无效公钥和重复 key ID。安装在单一事务内验证 schema、签名、固定 audience、installation ID 和有效期；旧 serial、同 serial 不同租约、未知 key 和错误签名都不会改变当前安装状态。

## 安装与启动

安装命令分别读取部署锚和 bundle，内容不会进入 shell argv：

```sh
DATABASE_URL='postgres://...' \
  control-api install-entitlement \
    --trusted-keys /etc/cdnca/trusted-keys.json \
    --bundle /run/secrets/cdnca/entitlement-bundle.json
```

成功只输出 `serial`、`status` 和 `key_id`。两个文件只允许主控服务账号读取，不得提交到仓库或附在工单正文中。bundle 按组织的敏感制品策略销毁；受信 key 文件由配置管理持续维护。

运行 API 时使用同一独立锚文件：

```sh
ENTITLEMENT_TRUSTED_KEYS_FILE=/etc/cdnca/trusted-keys.json \
  control-api serve
```

环境变量缺失时服务可以启动，以保留读取、禁用和删除能力，但新增、启用和发布返回 `entitlement_unavailable`。文件存在但格式无效或不可读时启动失败。

根文件只负责首次 bootstrap trust，不需要在正常 signer 轮换时加入新 key。`control-api` 从 `GET /public/v1/signing-keyset` 获取 v2 lineage，以 PostgreSQL LKG 的 ETag 发起条件请求，并严格重建 canonical PoP/authorization 文档。新 key 必须由当前链尾授权，candidate chain 必须完整包含并扩展已接受链；旧 ancestor 重放、旁支、未知根、相同 key ID 不同公钥、篡改签名和非 canonical JSON 全部拒绝且不改变运行信任。

迁移 `016_entitlement_signing_keyset` 原子保存 body、SHA-256、ETag、active key 和 chain depth。启动时先校验摘要，再从根 pin 重验后才更新内存 TrustStore。损坏的 LKG 使同步启动失败关闭；授权中心不可用时则保留已经验证的 LKG。旧 key 的新签名截止由它签出的下一跳 authorization expiry 推导，不能由未签名 HTTP 状态提前缩短；截止前 overlap 内的 lease 可验，旧发布物在 `verify_until=null` 时永久可验。

## 自动激活与续租

自动同步是 `serve` 的可选后台任务。先生成 PKCS#8 Ed25519 安装密钥并限制为服务账号独占读取：

```sh
umask 077
openssl genpkey -algorithm ED25519 \
  -out /run/secrets/cdnca/installation-key.pem
chmod 600 /run/secrets/cdnca/installation-key.pem
```

Operator Console 签发的单次激活 credential 必须写入同样受限的普通文件。不要把 credential 放进环境变量、shell 参数、进程管理器 command 字段或工单正文。交互式启动也可将 `CONTROL_ACTIVATION_CREDENTIAL_FILE` 设为 `-`，由标准输入提供。生产 systemd/Kubernetes 部署优先使用仅挂载给服务账号的 secret 文件；首次激活成功并确认本地 serial 后，由部署系统移除 credential 文件。

```sh
LICENSE_SERVICE_URL='https://license.example.test' \
CONTROL_INSTALLATION_ID='00000000-0000-0000-0000-000000000000' \
CONTROL_INSTALLATION_NAME='Primary control' \
CONTROL_INSTALLATION_PRIVATE_KEY_FILE='/run/secrets/cdnca/installation-key.pem' \
CONTROL_ACTIVATION_CREDENTIAL_FILE='/run/secrets/cdnca/activation-code' \
ENTITLEMENT_TRUSTED_KEYS_FILE='/etc/cdnca/trusted-keys.json' \
control-api serve
```

自动同步只接受 HTTPS URL，且没有生产全局 insecure 开关。测试通过注入独立 HTTP client/transport 使用测试证书。安装私钥和 credential 的最终目标必须是普通文件，且 group/other 权限位为零；不满足时启动或首次激活失败。私钥必须是单个未加密 PKCS#8 Ed25519 PEM block。credential 只在本地还没有 current lease 时读取。

激活 proof 精确绑定 v1 消息中的 request ID、installation ID、名称、公钥和 credential 哈希；续租 proof 绑定 request ID 与 installation ID。网络超时、连接中断、HTTP 429 和 5xx 属于未知/可重试结果。一次同步操作会稳定复用完全相同的 `Idempotency-Key`、proof 和 JSON body；请求 ID 由不可变激活输入摘要或 `installation ID + current serial` 决定，因此进程在未知结果后重启也不会换幂等身份。401/400/409 等确定性拒绝不会盲目重试，需由运维人员处理凭据、身份或幂等冲突。

返回 lease 必须同时通过已验证轮换 TrustStore 的 key 签发窗口、schema、Ed25519 signature、key ID、固定 audience、固定 installation ID 和当前时间验证，并且状态必须是 `valid`，才会调用既有事务安装器原子更新缓存。篡改、错实例、未知 key、窗口外旧 signer、future、grace 或 expired 响应都不改变 current serial。发布制品和升级授权使用同一 TrustStore 的 detached signature/window 校验；授权中心不可用不删除历史验证 key。

运营后台新增授权与门户种子套餐（迁移 900 占位）的默认值为租约 7 天（`lease_ttl_seconds=604800`）、宽限 30 天（`grace_seconds=2592000`，即授权端上限）；授权端上限仍为租约 31 天、宽限 30 天。激活凭据默认有效期（24 小时）不随之调整：它是一次性安装凭据，只在首次激活时使用，与授权端宕机期间的续用无关，拉长只会扩大泄露窗口。

正常 lease 在其有效期剩余三分之一时续租；提前量下限 1 分钟，不设上限。因此授权端宕机时，主控仍能保持 `valid` 的时间至少约为租期的 1/3（宕机恰好发生在续租窗口开始时）：7 天租约约 2.3 天，30 天租约约 10 天；续租窗口内持续重试，任一次成功即重新获得完整租期。已经进入续租窗口、grace 或 expired 的本地 lease 会立即尝试续租。429、5xx 和传输未知结果采用 75%-100% jitter 的指数退避，默认从 1 秒增长到最多 5 分钟；`Retry-After` 同样受最大值限制。可用 `ENTITLEMENT_SYNC_BACKOFF_MIN` 和 `ENTITLEMENT_SYNC_BACKOFF_MAX` 调整。

授权中心不可用只产生带错误类别和下次重试时间的日志告警，不删除或覆盖 current lease，不阻塞 `control-api` HTTP 服务，租约续租失败本身也不触发 Edge 配置停用。本地 guard 在 `valid` 与 `grace` 下都放行新建/发布，只在 `expired`、`revoked`、未安装或验证失败时拒绝；`expired`/`revoked` 还会触发安装锁（见准入矩阵）。服务退出会取消正在等待或请求中的同步任务，并在 HTTP shutdown 时等待其结束。

## 准入矩阵（完整 HTTP 入口）

一个写请求要依次通过两层，任一层拒绝即结束：

1. 安装锁（`internal/httpapi/installation_lock.go:60` `withInstallationLock`，在 `server.go` 中包住全部业务路由）。锁由 `installationban.Evaluate` 按本地状态计算，置位条件只有三种：授权端签名的停用通知（BanNotice）生效且没有更高修订的服务票据、本地租约 `last_status=revoked`、本地租约 `expired` 或已过 `grace_until`。从未安装租约或租约仅“验证失败”不置锁（首次激活要能写）。锁生效时除白名单外的一切写请求（POST/PUT/PATCH/DELETE）返回 `423 installation_locked`，响应体含 `reason`（`installation_banned` / `lease_revoked` / `lease_expired`）、`ban_id`、`reason_text`、`until` 和 `request_id`。白名单：GET/HEAD/OPTIONS、登录/登录验证/刷新会话/退出、本人改密与 MFA（`/v1/account/mfa*`）、`POST /v1/installation-lock/check`（“重新检查”）、`/v1/internal/*`。锁只在配置了 `LICENSE_SERVICE_URL`（即启用授权运行时）时计算；启动时先从数据库恢复锁再开 HTTP，重启不会绕过锁。
2. 领域 guard（`internal/entitlementguard`）：校验部署锚、签名、租约时间状态、已接受的吊销清单、feature 与 quota。拒绝码见“错误与审计”。

因此表中“领域 guard 允许收缩”的情形，只要安装锁已生效，完整 HTTP 仍得到 423。下表按操作结果列出最终结果。

| 操作 | 本地租约 `valid` | `grace` | `expired`（含过 `grace_until`） | 已知吊销（清单列出当前 serial） | 无租约 / 无部署锚 / 验证失败 | 授权端签名停用生效 |
| --- | --- | --- | --- | --- | --- | --- |
| 查看现状（GET） | 允许 | 允许 | 允许 | 允许 | 允许 | 允许 |
| 新建扩容（建网站、启用网站或加域名、新建节点） | 允许，受 feature 与额度约束 | 允许，额度不变 | 423 | 423 | 403 `entitlement_unavailable` | 423 |
| 零增量修改（保持启用的网站编辑/发布、创建禁用网站） | 允许；已超额度也不拒绝（Delta=0） | 允许 | 423 | 423 | 403 `entitlement_unavailable` | 423 |
| 收缩删除（禁用/删除网站、禁用/退役节点） | 允许（不调用 guard） | 允许 | 423 | 423 | 允许（不调用 guard） | 423 |
| 主控升级（升级检查、下发升级计划） | 允许（`ReadValidVersion`，还须吊销清单 LKG 可用且未列出当前 serial） | 拒绝：只认 `valid` | 423；只读的升级状态查询返回授权状态被拒 | 423 | 拒绝（不可用） | 423 |
| 重新检查（锁定横幅“重新检查”= `POST /v1/installation-lock/check`；首页“刷新授权”= `POST /v1/admin/entitlement/refresh`） | 允许 | 允许 | “重新检查”允许并会立即续租，成功即解锁；“刷新授权”不在白名单，423 | 两个入口都不会让已吊销的 serial 复活；“重新检查”只在停用通知已解除时触发续租，换新 serial 后解锁；“刷新授权”423 | 允许 | “重新检查”允许，读取最新状态；停用解除后自动续租解锁 |
| 既有流量（已激活节点） | 待定（见下文） | 待定 | 待定 | 待定 | 待定 | 待定 |

几个容易混淆的点：

- `valid` 是本地最后一份已验证租约的时间状态，不是“授权端在线”。授权端离线、吊销清单超过 15 分钟未刷新时，本地 `valid` 租约照常可读、可扩容（见下文吊销 LKG）。
- `grace` 放行的取舍：客户停付或授权被吊销而吊销清单未送达时，主控在宽限期（默认 30 天）内仍可按最后一份租约的额度扩容，额度上限不变。主控升级不受此影响，仍要求 `valid`。
- 403/409 是领域 guard 的业务拒绝；423 是整台主控只读。两者的处理入口不同：403/409 去授权方调整额度或功能，423 按横幅原因处理后点“重新检查”。
- 后台循环（DNS 同步、ACME、发布、计费等）在锁定期间通过 `installationlock.Skip` 暂停本轮，解锁后自动恢复，不需要重启。

### 既有流量

节点（Edge Agent）是否继续服务不看主控租约，而看授权端签发、经主控转交的服务票据与停用通知（`agents/edge-agent/internal/installationban/runtime.go`）。停服规则以下文“既有流量（停服规则）”一条为准：只有生效中的安全封禁停服，票据过期只冻结（`service_ticket_expired`），不停已有流量。

## 网站操作语义

网站 guard 使用固定 feature `sites.manage` 和 quota `domains.count`。`domains.count` 计的是域名数，不是网站数：所有租户中启用且未删除的网站上、当前处于激活状态的域名总数（`entitlementguard/guard.go` `activeDomainCount`），不按当前租户单独计算。一个网站绑 3 个域名占 3 个额度。

宽限期内管理首页“系统授权”卡片显示告警“本地租约已过期，仍在宽限期，剩余 X 天……”（X 为距 `grace_until` 的天数，向上取整；按租约时间判断，不依赖 `last_status`）。租约时间本身不能说明续租失败的原因（网络/DNS/时钟，或客户、许可状态被拒），告警只陈述事实并提示“刷新授权”查看结果（卡片可展开查看当前序列号、授权状态与最近检查时间；结果待确认时自动回读，回读失败仍显示待确认；主控锁定时该按钮与锁定横幅共用“重新检查”），不断言授权中心不可达。

注意：功能/模块类检查（`CheckFeature`、`CheckModule`、内置节点监控、发布授权）以及 `ReadValidFeatures`、`ReadValidVersion` 还要读签名吊销清单，但用的是最后一份已验证清单（LKG，`entitlementguard/revocation.go` `loadRevocationLKGTx`，用户 2026-10-21 定）：清单超过 `RevocationSetWindow`（15 分钟，`libs/entitlement/revocation.go`）没刷新也照常放行，签名、受众、客户/安装/许可证绑定仍按当前清单同样校验，签名密钥也须仍在验证期内；能用多久由租约宽限期约束。因此授权端不可达超过 15 分钟后，这些检查不会因为清单“过期”而拒绝，租约 `valid`/`grace` 内照常可用。仍会拒绝的情况：本地从未接受过吊销清单（`revocation_state_unavailable`）、清单校验失败或签名密钥已过验证期（`revocation_state_invalid`）、清单列出了当前租约序号（`revoked`）。15 分钟窗口只约束推进清单（`Accept`）与同步器（`Restore`）。站点/节点额度检查（`CheckSiteChange`、`CheckNodeCreate`）不读吊销清单。

创建禁用网站仍要求 `valid` 或 `grace`、`sites.manage` 和存在 `domains.count`，但额度增量为 0；创建即启用的网站增量为其域名数。`disabled -> enabled` 的额度增量为该网站的域名数；保持启用的 Basic PATCH 视为发布，只有新增域名计入增量，否则为 0；`enabled -> disabled` 和 DELETE 不调用 guard。平台管理员不绕过授权检查。

guard 先锁单例安装行，再统计全局启用网站上的激活域名，因此不同租户的并发创建也被串行化到同一额度边界。判断、资源写入、幂等结果和审计处于同一数据库事务。已经成功的幂等请求在租约后来进入 grace/expired 后仍返回原结果，不重复消耗额度。

`POST /v1/sites/batch-action` 的 `enable` 对每个通过 scope、锁状态和 revision 检查的项目执行相同 guard；额度不足可与成功项目一起形成有序的逐项结果。`disable` 和 `delete` 不调用 guard；但 expired/revoked 时安装锁已生效，整个批量请求在进入处理前就得到 423（见准入矩阵）。批量请求按 UUID 加锁、按输入顺序响应，成功写入、失败/成功逐项审计和幂等响应在同一事务提交；数据库或审计故障会回滚整批。该接口只更新控制面期望状态，不能作为边缘配置已激活的证明。

## 节点创建语义

`POST /v1/nodes` 要求固定 feature `nodes.manage` 和 quota `nodes.count`。额度统计 platform scope 中所有 `admin_state != retired` 的节点；`disabled` 仍占额度，只有 `retired` 释放额度。列表、读取、禁用和退役不调用节点创建 guard：本地授权不可用（无租约、无部署锚、验证失败）时仍可读取和收缩；租约 expired/revoked 时安装锁已生效，禁用和退役也得到 423，只能读取。grace 时新建也放行。平台管理员的 RBAC 通配权限不绕过 entitlement。

每次创建必须提供合法 `Idempotency-Key`。服务端对规范化后的名称、描述、区域、IP 和 token 选项计算摘要；同 key 异载荷稳定返回 `409 idempotency_conflict`。相同请求先回放已提交结果，再判断当前授权，因此首次成功后即使租约过期，仍返回原节点且不重复占用额度。

一次性 enrollment token 只在首次成功响应中出现。幂等记录只保存节点结果，不保存 token 原文或 token 元数据；重放响应不返回也不重新生成 token。客户端丢失首次响应时必须调用独立的 enrollment token 签发接口，不能依靠重放恢复原 token。

幂等 claim、租约/额度检查、节点、审计、可选 token 和幂等完成记录处于同一事务。guard 拒绝时删除未完成 claim、保留拒绝审计且不留下节点或 token；数据库或审计失败则整个事务回滚。租约单例行串行化不同 idempotency key 的并发额度判断，最后一个名额只能由一个事务获得。

节点的 `revoked` 语义：领域 guard 拒绝新建；完整 HTTP 入口上安装锁使禁用和退役同样得到 423，只能读取。

既有流量（停服规则，已实现，真实 OpenResty/四层用例待出包前跑）：只有授权端签名、生效中的安全封禁（BanNotice）让节点停止对外服务（HTTP/HTTPS 503、四层拒绝），合法解除即恢复；首票到达前不开放。商业到期/暂停/吊销、授权中心不可达、主控失联都不停已有流量：节点服务票据默认 30 天（`LICENSE_NODE_OFFLINE_TOLERANCE`，1h–744h），过期后节点上报 `service_ticket_expired` 并冻结（拒绝新发布、扩容、升级），拿到新票自动解冻。

## 错误与审计

稳定 API 错误：

- `403 entitlement_unavailable`：无租约、无部署锚或本地验证失败；
- `403 entitlement_state_denied`：租约为 expired 或 revoked（grace 不再拒绝）；
- `403 entitlement_feature_denied`：缺少当前操作要求的 feature，例如 `sites.manage` 或 `nodes.manage`；
- `403 entitlement_quota_denied`：缺少当前操作要求的 quota，例如 `domains.count` 或 `nodes.count`；
- `409 entitlement_quota_exceeded`：当前操作的全局额度已到上限；
- `409 idempotency_conflict`：同一 actor/operation 下重复使用 key，但规范化请求不同；
- `423 installation_locked`：安装锁生效（停用通知、租约吊销或过期），除白名单外的写请求一律拒绝；它在领域 guard 之前返回，不写 `entitlement.guard.reject` 审计。

每次拒绝追加 `entitlement.guard.reject` 审计事件，包含 `lease_serial`、`state`、`feature`、`quota`、`current`、`limit`、`request_id`、操作和原因。审计不包含签名、公钥、完整租约或任何私钥。审计表的既有 append-only 哈希链保护继续适用。

## 验证与恢复

安装后核对命令输出的 serial/status/key ID，再以只读方式检查主控日志和拒绝审计；不要输出 `signed_lease` 或完整 key 文件。用隔离租户验证禁用网站、启用网站、发布和跨租户并发额度。

本地回归：

```sh
cd services/control-api
TEST_DATABASE_URL="$DATABASE_URL" GOWORK=off go test -count=5 ./...
TEST_DATABASE_URL="$DATABASE_URL" GOWORK=off go test -race -count=2 ./...
GOWORK=off go vet ./...
```

若 bundle 被拒，事务不会替换当前 serial 或公钥元数据。数据库公钥被篡改不能改变进程信任；下一份由部署锚正确签名的合法租约会恢复对应公钥元数据。已接受的更高 serial 不允许通过旧 bundle 降级，恢复必须使用由预置信任锚签名的更高 serial 租约。

## 实现状态

“已实现”指代码已在主控中接线且有本地回归（真实 PostgreSQL + 固定时钟）；“待云端验收”指代码已在，但还没有在真实部署、真实断网或真实节点流量上验证过，不能对外当作已验证能力承诺；“尚未实现”指代码中没有。

已实现：

- 部署锚、租约安装、自动激活/续租、signer 轮换链与 keyset LKG；
- 签名吊销清单在线同步（`entitlementRevocationRuntime` 每分钟一轮）与吊销 LKG：清单过期后仍按最后一份已验证清单判断（`entitlementguard/revocation_outage_integration_test.go`）；
- 租约状态边界 valid/grace/expired/revoked 与各入口（`entitlementguard/lease_states_integration_test.go`）；零增量编辑不受超额拒绝（`site_zero_delta_integration_test.go`）；
- 安装锁与 HTTP 423 白名单（`internal/httpapi/installation_lock_test.go`）；锁的计算、停用解除后续租解锁、授权端不可达时保留已存状态（`internal/installationban/runtime_test.go`）；
- 主控升级的租约与吊销检查（`ReadValidVersion`，`TestReadValidVersionHonoursAcceptedRevocationList`）；套餐、模块、内置节点监控等功能检查（`CheckFeature`）；
- 宽限期内管理首页“系统授权”告警；
- 节点服务票据与停用通知的签名校验、Stop/Resume 状态机（`agents/edge-agent/internal/installationban`，受控 Serving 替身）。

待云端验收：

- 真实断开授权端后，主控在 valid/grace 内持续可用、过 grace 后锁定、恢复网络后“重新检查”解锁；
- 授权运营端吊销/停用 → 客户主控锁定 → 解除 → 恢复的端到端链路，以及 signer 轮换；
- 主控升级全链路（升级候选、下载信任、执行）在真实授权下的放行与拒绝；
- 节点服务票据过期、停用通知在真实 OpenResty/四层流量上的停止与恢复；
- 授权用量（13 项，含四层检查点计量的月流量）从主控到授权端的真实上报与对账。

尚未实现：

- 覆盖 installation、吊销 serial 和租约摘要的规范签名 manifest；租约 bundle 的 `revoked_serials` 仍只接受空值；
- 吊销清单的离线（无网络）导入与恢复队列；
- 续租失败、进入 grace、即将 expired 时的独立指标与通知路由（目前只有日志告警和首页卡片）；
- 主控按租约流量额度在本地拦截（目前只上报月流量，不在主控准入中执行）。

待定（产品政策，用户未拍板）：

- 商业到期/暂停/吊销、授权中心不可达、主控失联、显式安全停用四种情形下既有流量的处理（见“既有流量”）。

新增能力必须复用独立部署锚和本地验证边界，不能在请求路径加入对授权中心的同步依赖。
