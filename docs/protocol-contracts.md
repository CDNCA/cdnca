# Agent 协议契约

本文定义 `agent.v1` 和 `controlinternal.v1` 的运行语义。protobuf 是字段与服务的权威契约；状态机仍以 [平台架构](architecture.md#6-配置与灰度状态机) 和 [领域模型](domain-model.md#5-edge-delivery-与配置状态机) 为准。

## 1. 契约范围

| 边界 | 服务 | 传输身份 | 用途 |
| --- | --- | --- | --- |
| Agent -> Gateway | `agent.v1.AgentGatewayService.Enroll` | 仅服务器 TLS + 一次性 enrollment token | 首次注册 CSR |
| Agent <-> Gateway | `RenewCertificate`、`Connect`、`FetchArtifact` | 双向 TLS，URI SAN 绑定 `node_id` | 续证、会话、命令/状态、制品 |
| Gateway -> control-api | `controlinternal.v1.ControlInternalService` | 服务间双向 TLS，身份绑定 Gateway workload | 注册授权/完成、续证、节点授权快照、制品代理 |

Agent 不访问 PostgreSQL、Redis、NATS、ClickHouse 或 control-api 内部接口。Gateway 没有数据库凭据和 CA 私钥；ControlInternal 不对公网或 Agent 网络暴露。

`Enroll` 必须绑定独立监听端口，该监听器只注册 Enroll RPC 并使用服务器 TLS。其余 RPC 绑定另一个强制校验客户端证书的 mTLS 监听器。不能在一个“可选客户端证书”的监听器上仅依赖业务代码补鉴权。

## 2. 字段约定

- `request_id`、`event_id`、`message_id`、`deployment_id`、`node_id`、`rollout_id`、`config_version_id`、`artifact_id` 使用规范 UUID 字符串，服务端新 ID 优先 UUIDv7。
- 时间是合法 UTC `google.protobuf.Timestamp`；持续时间非负。接收方拒绝超出 protobuf 合法范围或明显越过允许时钟偏差的安全敏感时间。
- 摘要字段名带算法，例如 `sha256`，长度必须为 32 字节。CSR 使用 PKCS#10 DER；证书和链使用 PEM bytes。
- `traceparent` 只接受 W3C Trace Context 值。它、`correlation_id` 和 `task_id` 只用于关联，不参与幂等判断。
- protobuf 的 `UNSPECIFIED` 枚举值只为未知字段和旧客户端提供安全零值，不能写入领域状态。
- 所有字符串、重复字段和 bytes 在服务实现中设置明确上限；错误消息只能含安全摘要，不能回显令牌、CSR、证书私钥、制品内容或机器标识原文。

## 3. 注册与证书

### 3.1 首次注册

```text
Agent                    Gateway                    control-api / CA signer
  | Enroll(token, CSR, request_id) |                          |
  |------------------------------->| AuthorizeEnrollment      |
  |                                |-------------------------->|
  |                                | authorization_id, node_id |
  |                                |<--------------------------|
  |                                | CompleteEnrollment        |
  |                                |-------------------------->|
  |                                | certificate chain         |
  | certificate chain             |<--------------------------|
  |<-------------------------------|                          |
```

1. Agent 本机生成 mTLS 私钥/CSR，以及独立的 X25519 制品解密密钥。两个私钥都不进入消息；Enrollment 只提交 CSR 和 32 字节 X25519 公钥。
2. `enrollment_token` 是绑定节点、默认十分钟过期、数据库仅存哈希的一次性秘密。Gateway 只在内存中转发，任何日志、trace、错误或指标标签都不能包含它。
3. Gateway 将 Agent 的原始 `request_id` 和请求内容传给 `AuthorizeEnrollment`。control-api 在事务中消费 token 并创建 `signing_pending` 记录。
4. 同一个 `request_id` 与相同请求摘要重试返回同一 `authorization_id`；相同 ID 配不同摘要返回 `CONFLICT`。token 已被其他请求消费返回 `UNAUTHENTICATED`/`FAILED_PRECONDITION`，不能猜测重试。
5. `CompleteEnrollment` 由 control-api 调用受控签名器并持久化序列号及制品公钥绑定。`authorization_id` 和 CSR 摘要保证崩溃恢复后返回同一证书身份，不签发第二个节点身份。
6. 证书 URI SAN 必须是 `spiffe://cdn-platform/node/{node_id}`。响应同时返回绑定的 `artifact_encryption_key_id`；Connect 时 Agent 必须回报同一 key ID。
7. Agent 原子写入权限 `0600` 的证书和两个私钥后，永久删除 enrollment token，后续只使用 mTLS。

Enrollment 端点的服务器信任根必须通过安装包、操作系统信任库或带外指纹预置，不能信任 Enroll 响应临时下发的新根。

### 3.2 证书续期与撤销

- `RenewCertificate` 只在有效 mTLS 会话接受。Gateway 从已验证证书取得 `node_id`，再与 control-api 的授权快照核对；不信任请求体自报身份。
- Agent 生成新私钥/CSR。相同 `request_id` 和 CSR 重试返回同一证书；不同 CSR 必须使用新 request ID。
- 建议证书有效期 24 小时，在剩余三分之一寿命时续期。新证书落盘成功后才替换当前身份，并短暂保留旧证书用于失败回退。
- 证书续期不轮换制品加密 key。制品 key 丢失或疑似泄露时必须停止新部署并执行显式重新注册/后续 key-rotation 契约，不能把续证 CSR 当成隐式换 key。
- 节点禁用或证书撤销由 PostgreSQL + outbox 广播。Gateway 收到后关闭会话；授权快照过期后必须刷新，不能以 Redis 缓存永久放行。

## 4. Connect 握手与版本协商

1. Agent 建立 mTLS 后发送的第一个 `ConnectRequest` payload 必须是 `AgentHello`，stream sequence 为 1。
2. Gateway 验证 SAN node ID、证书序列、节点管理状态、唯一主会话和授权快照。验证期间不能投递部署命令。
3. Gateway 在双方版本区间中选择最高共同版本。主版本没有交集时发送 `StreamError(UNSUPPORTED_VERSION)` 并关闭；minor 版本只允许向后兼容的字段/oneof 扩展。
4. 成功时 Gateway 的第一个 `ConnectResponse` 是 `GatewayHello`，其中 `session_epoch` 单调增加。Agent 后续 Heartbeat 必须回显该 epoch。
5. 双向 `StreamMetadata.sequence` 在各自方向从 1 严格递增。`GatewayHello.message_id_replay_window` 给出 Gateway 保存的最近入站 ID 数量；窗口内同 `message_id`、同 sequence、同完整 payload 是重传，同 ID 不同内容是协议冲突。ID 被逐出窗口后，其旧 sequence 仍被高水位拒绝，不能靠重放绕过幂等检查。
6. 断线后 Agent 使用抖动退避重连，并在新 `AgentHello` 回报本地当前/前一版本及未完成 deployment。新会话不继承旧 sequence；控制面按 deployment ID/attempt 对账。

单节点会话接管与发送必须有同一个可证明的线性化点。旧会话的 `GatewayHello`、HeartbeatAck 和后续命令要么在线性化接管前完成发送，要么在接管后完全不调用底层 Send；仅在 Send 前检查一次 epoch 不能满足此约束。

`GetNodeAuthorizationResponse.artifact_encryption_key_id` 是 Enrollment 绑定的当前制品解密公钥标识。Gateway 在首个 Hello 和每次授权快照刷新时都与 Agent 自报值比较；缺失或变化必须关闭会话，不能把 Agent 自报值当成授权事实。

Capability 的 `api_version` 表示该特性的最高实现版本。配置生成器只能要求 Agent 已启用且版本不低于要求的 capability。未知 capability 被视为不支持，不能默许下发。

## 5. 心跳

- 默认 15 秒发送一次，Gateway 通过 `GatewayHello` 下发实际间隔和离线阈值。
- 每个 Heartbeat 有稳定 `event_id`、当前 session epoch、递增 heartbeat sequence、当前/前一配置、运行状态、磁盘/缓存摘要和未完成部署。
- 新 Agent 必须在 Heartbeat 的可选 `agent_version` 中回显本会话 `AgentHello.capabilities.agent_version`。Gateway 拒绝空白、非法字符或与 Hello 不一致的值，且不得发布或 ACK 该心跳。为兼容旧 Agent，字段缺失时继续接受并记录为“未上报”；版本格式限制为首字符字母或数字，后续最多 127 个字母、数字、点、下划线、加号、冒号或连字符。
- 生产 Gateway 必须将 Heartbeat 以确定性 protobuf 发布到 JetStream 默认 stream `AGENT_HEARTBEATS`、subject `cdnca.agent.heartbeats.{node_id}`，并把 `heartbeat.event.event_id` 设为 `Nats-Msg-Id`。只有收到目标 stream 的 PubAck 后才能发送 `HeartbeatAck`；重复事件仍 ACK，由 JetStream 按稳定 event ID 去重。
- NATS 超时、断开或目标 stream 不匹配时不得 ACK，Gateway 关闭会话，Agent 重连后以相同 event ID 重投。Heartbeat payload 和敏感字段不得写日志。
- control-api 必须拒绝并 Term 早于当前离线阈值的 durable backlog 心跳；时间恰好等于阈值可接受。过旧消息不得创建或刷新 PostgreSQL 投影、Redis 租约或 online 状态，随后到达的新鲜高版本心跳仍按正常确认流程处理。
- durable 模式的 `HeartbeatAck` 只证明 Gateway 已收到目标 JetStream 的 PubAck，不证明 PostgreSQL 在线投影已经完成。control-api 使用显式 ACK 的 durable pull consumer：先单调推进 PostgreSQL 最新投影，再以 `(session_epoch, heartbeat_sequence)` 单调写入带绝对过期时间的 Redis 在线租约，最后用 node ID、epoch、sequence、event ID、request ID、payload digest 和 projected timestamp 精确匹配最新投影，确认 PostgreSQL `last_seen_at`。需要刷新租约的消息只有完成这些步骤后才 ACK；任一步瞬时失败都 NAK 并允许安全重投，已被更高版本取代的旧消息可直接 ACK。
- PostgreSQL 的最新投影和已确认在线 token 分开保存。首次 Redis 写入失败时节点保持 offline 且不产生 online 审计；已 online 节点遇到 Redis 故障可以保存较新的运行摘要，但不得刷新 confirmed `last_seen_at`。只记录 online/offline 状态转换，不为每次心跳写审计。
- PostgreSQL 同样分开保存最新 `agent_version` 和 Redis 租约写入后确认的 `confirmed_agent_version`。节点查询 API 只返回 confirmed 版本，避免把尚未确认的投影当成当前在线 Agent；旧 Agent 或从未确认过的节点返回“未上报”。
- 离线 worker 只扫描 PostgreSQL confirmed `last_seen_at` 超过阈值的 online 节点，并且只有 Redis 明确返回租约不存在时才在行锁事务中按 confirmed epoch、sequence、event、request、digest 和租约截止时间进行条件转换。离线审计必须使用 confirmed request ID，不能使用 event ID 或尚未确认的最新投影 request ID。Redis 错误不能当作租约不存在；并发 worker 和恢复心跳竞争时，最终必须由新心跳恢复为 online。
- 无 heartbeat sink 的兼容构造模式只证明 Gateway 进程内接收，禁止作为生产在线状态依据。
- Gateway/Redis 故障时 Agent 继续本地守护当前健康版本，不主动回滚、删除配置或停止 OpenResty。
- Heartbeat 不承载访问日志、配置正文、私钥、DNS 凭据或无界诊断输出。

### 5.1 节点在线状态查询

- `GET /v1/nodes` 和 `GET /v1/nodes/{id}` 返回 `presence`，包含有效状态、最后确认心跳、已确认 Agent 版本、session epoch、heartbeat sequence、投影新鲜度和 Redis 租约信号。
- 有效 `online` 必须同时满足：存在 confirmed token、PostgreSQL 状态为 online，且 confirmed `last_seen_at` 晚于当前离线阈值。存在 confirmed token 但不满足上述条件时为 `offline`；没有 confirmed token 时为 `unknown`，且不得返回未确认的最新投影字段。
- `GET /v1/nodes?presence=online|offline|unknown` 在 PostgreSQL 查询中先筛选再应用 UUID cursor 和 limit，保证分页不会漏项或产生空页。
- Redis 可用时 `lease_signal` 为 `present` 或 `absent`。Redis 查询失败时 HTTP 请求仍返回 PostgreSQL 的 confirmed 事实并将信号标为 `unavailable`；不得将 Redis 故障解释为节点离线。

### 5.2 自动网络地址报告 V1

`ReportNodeNetworkInventoryV1` 是独立、可选的 mTLS unary RPC，不改动既有 Enrollment 摘要、Connect 1.0 或 capability 枚举。Agent 的请求不含 `node_id` 或可信 peer；Gateway 从已验证客户端证书与实际 transport 分别取得身份和 peer，仅经服务间 mTLS 转交 ControlInternal。转发头与第三方公网 IP 回显均不构成证明。

Linux Agent 从内核默认路由、规则与网卡地址发现每族唯一全局可路由候选；私有地址、CGNAT、ULA、保留地址、无默认路由、多路径或策略路由歧义不能自动登记。Control 在持有与节点编辑相同的 scope 锁及节点/证书锁后，复核当前叶 serial/hash、current 状态、有效期、撤销、安装身份、平台 scope 和节点 active 状态。等待锁后重新取时钟，不能使用到达时间绕过到期或定时撤销。

候选必须与当次真实 peer **同族且完全相同**，只允许 `NULL → 地址`。另一族不能继承证明；已有非空不同地址不覆盖；同 scope 的 active/draining 节点已有相同地址时拒绝抢占。`request_id` 与确定性完整请求摘要保证重放不重复更新 revision、报告或审计，但重放仍重验当前证书权限。新写请求时间允许过去 5 分钟、未来 1 分钟；旧 exact replay 在仍有权限时返回历史回执。

新 Control 的节点库存读接口增加可选 `network_inventory`：`schema_version: 1`、`ipv4_state`、`ipv6_state`，有报告时另有 `received_at`。无报告两族均为 `not_reported` 且省略时间；有报告两族均非 `not_reported`。状态为 `verified`、`address_conflict`、`peer_mismatch`、`no_default_route`、`no_global_address`、`ambiguous_route` 或 `unavailable`。它表示最近报告及其与当前库存的一致性，不是入站服务可达性探测。管理员更改或清空原 verified 地址后，List/Get 必须降为 `address_conflict`，不能给新值继承旧证明。API 不返回原报告、peer、证书或网卡详情。

Agent 在成功 Connect 后后台发现一次，每次 RPC 最多 5 秒，仅暂时不可用/超时以同一 ID、同一 body 重试，最多 3 次；旧 Gateway/Control 的 `UNIMPLEMENTED` 只记录稳定 `unsupported` 状态。失败不能阻塞 Connect、心跳或本机 OpenResty。迁移与回滚顺序见 [自动地址运行手册](runbooks/node-network-discovery-v1.md)。

## 6. 部署命令与幂等

`DeploymentCommand` 是至少一次投递。Agent journal 的去重键是：

```text
(event.event_id, event.request_id, deployment_id, attempt, action)
```

- 完全相同的重投返回已知状态，不重复切换文件、reload 或清理缓存。
- 控制面进行一次新的执行尝试时递增 `attempt` 并生成新 `event_id`；同一业务请求保留原 `request_id`。
- 更换 action、配置版本、制品摘要或 rollback 目标必须创建新 event，不能复用旧 event ID。
- attempt 小于本地 journal 的已知值返回 `STALE_ATTEMPT`；attempt 相同但 payload 摘要不同返回 `CONFLICT` 并隔离部署。
- `deadline_time` 过期且命令尚未改变运行配置时返回 `FAILED` 与 `DEADLINE_EXCEEDED`。已经进入 `ACTIVATED` 后不得用过期直接跳过回滚。

### 6.1 状态映射

| protobuf | 领域值 | 含义 |
| --- | --- | --- |
| `QUEUED` | `queued` | 控制面已创建，通常不由 Agent 首次上报 |
| `DELIVERED` | `delivered` | Agent journal 已持久记录命令 |
| `STAGED` | `staged` | 全部制品长度、SHA-256 和平台签名通过 |
| `PRECHECKED` | `prechecked` | OpenResty、防火墙、端口、文件和证书 dry-run 通过 |
| `ACTIVATED` | `activated` | release 指针已原子切换并完成 reload |
| `HEALTHY` | `healthy` | 本机及策略健康检查达到门槛 |
| `FAILED` | `failed` | 激活前失败，且 `running_config_unchanged=true` |
| `REVERTING` | `reverting` | 已开始回到明确的前一健康版本 |
| `REVERTED` | `reverted` | 前一版本已恢复并健康 |
| `ROLLBACK_FAILED` | `rollback_failed` | 回滚无法确认，必须人工介入 |

`UNSPECIFIED` 不是领域状态。进入 `ACTIVATED` 后健康失败必须依次上报 `REVERTING`，最后是 `REVERTED` 或 `ROLLBACK_FAILED`；不能直接上报普通 `FAILED`。

每个 `DeploymentStatus` 有独立稳定 event ID、相同 deployment/attempt/config version 和递增 `transition_sequence`。重复/乱序事件可审计但不能让 PostgreSQL 状态回退。

## 7. 制品传输

- `DeploymentCommand.artifacts` 冻结 artifact ID、类型、长度、压缩/加密方式、SHA-256、平台签名算法和 key ID。摘要与签名覆盖最终 wire bytes。
- Agent 以 `FetchArtifactRequest` 拉取。该请求必须携带原命令 event ID、request ID、deployment ID、attempt 和 artifact ID；control-api 验证它们的绑定关系后才读制品。
- 同一 offset 和参数的网络重试复用 request ID。断点续传改变 offset，必须使用新 request ID，并继续关联原命令 event ID。
- chunk offset 必须连续，`chunk_sha256` 校验单块，最后一块满足 `offset + len(data) == total_size_bytes`。Agent 还必须验证完整压缩字节的 SHA-256 和平台签名，然后才解压到新的 release 目录。
- `NODE_SECRET_BUNDLE` 必须用 RFC 9180 HPKE 的 X25519/HKDF-SHA256/AES-256-GCM suite 加密，`recipient_key_id` 必须匹配 Enrollment 绑定。Gateway 只代理密文、不解密、不记录 chunk；普通配置制品不得包含证书私钥或 provider 凭据。
- Agent 先验证 wire bytes 的完整摘要/签名，再解密，然后解压。解压必须限制目标目录、总展开大小、文件数和压缩比，拒绝绝对路径、`..`、设备文件、符号链接逃逸和压缩炸弹。

## 8. 错误与重试

- TLS、身份、权限和 RPC 传输失败使用规范 gRPC status；需要进入 Agent journal、任务或审计的失败使用 `common.v1.ProtocolError`。
- 只有 `retryable=true` 且错误码为 `RATE_LIMITED`、`UNAVAILABLE` 或明确可恢复的 `DEADLINE_EXCEEDED` 时自动退避重试。`retry_after_duration` 是下限，客户端仍应增加抖动。
- `INVALID_ARGUMENT`、`UNAUTHENTICATED`、`PERMISSION_DENIED`、`UNSUPPORTED_VERSION`、`DIGEST_MISMATCH`、`REVOKED` 和同 ID 不同 payload 的 `CONFLICT` 不自动重试。
- `INTERNAL` 默认不可盲重试。先用原 request ID 查询/重放幂等结果；无法判断外部副作用时进入人工处理。
- 服务端对同 request ID 保存请求摘要。相同 ID 不同摘要永远是冲突，不能以后写覆盖先前结果。

## 9. 兼容性规则

- `agent.v1` 和 `controlinternal.v1` 在 v1 内只新增可选字段、枚举值、oneof 分支或 RPC；不修改既有字段类型、tag、语义、默认值或必需行为。
- 未知字段必须保留或忽略，未知枚举按不支持处理。旧 Agent 收到未知命令 oneof 时返回 `UNSUPPORTED_VERSION`，不能当作空命令成功。
- 删除字段或枚举值时必须在 proto 中 `reserved` 原 tag 与名称；永不复用。当前没有历史删除项，因此不预留无意义的大段 tag。
- 核心字段使用低 tag；新功能追加新 tag。不得通过 `map<string, bytes>`、任意 JSON 或未约束 metadata 绕过版本评审。
- 合入后以当前 descriptor 建立 Buf breaking 基线。破坏性变更需要新 major package 和迁移/灰度计划。
- `buf format`、`buf lint`、`buf build` 和相对基线的 `buf breaking` 应进入 CI。代码生成配置在 Go module/import path 固定后单独加入，避免现在写入虚假的导入路径。

## 10. 首批实现与测试建议

1. 先生成 Go server/client skeleton，并实现 request digest、inbox/journal 和合法状态转换表。
2. 契约测试覆盖 token 并发消费、同 request ID 不同 CSR、Complete 崩溃恢复、证书撤销、无共同版本和双主会话接管。
3. 流测试覆盖重复/乱序 Heartbeat、命令重投、旧 attempt、同 event ID 不同 payload 和断线后的状态对账。
4. 制品测试覆盖错 offset、chunk/full digest 错误、签名 key 轮换、断点续传、超限归档和路径逃逸。
5. 隔离 Linux VM 测试 `STAGED -> PRECHECKED -> ACTIVATED -> HEALTHY` 以及激活后探针失败的确定性回滚。

当前仍需在实现前固定：单消息/CSR/制品/chunk 上限、允许时钟偏差、授权快照 TTL、证书有效期、签名 key 轮换重叠窗口、制品加密 key 轮换流程，以及 gRPC status 到 `ErrorCode` 的逐项映射。
