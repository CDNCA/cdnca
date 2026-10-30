# 平台架构

本文把 [ADR-0001](adr/0001-platform-architecture.md) 的决策展开为可执行设计；领域实体、事务和幂等边界见 [领域模型](domain-model.md)。本文描述的是首个生产架构基线，而不是要求第一天部署全部高可用组件。

## 1. 目标与假设

### 1.1 目标

- 管理面故障时，已经激活的站点、证书、缓存、安全规则和四层转发继续工作。
- 每次边缘配置变更都有不可变版本、可观察进度、健康确认和确定性回滚目标。
- 业务事实只有一个权威写入点；缓存、事件和分析副本可以重建或对账。
- 本地、单机生产和 HA 生产使用相同协议与制品，只改变副本数和基础设施实现。
- 初期保持可部署的模块化单体；只有出现可测量瓶颈时才拆分服务或引入新基础设施。

### 1.2 明确假设

- 一个节点是平台管理的一台边缘主机，可加入一个或多个节点组；首期一个节点只属于一个调度层级，避免同一监听端口由多个租户策略争抢。
- 站点、四层转发和安全策略的期望状态由 PostgreSQL 保存，边缘的已激活版本由 Agent 本地磁盘保存并向主控回报。
- 首期配置制品以压缩后的 protobuf/归档存入 PostgreSQL。达到第 9.4 节阈值后再引入 S3 兼容对象存储，避免预先增加组件。
- 控制面时间统一使用 UTC；套餐周期保留计费时区快照，不能随租户后续修改而重算历史。
- “不可篡改审计”在平台权限边界内实现为仅追加、哈希链和异机签名检查点；拥有数据库超级用户和所有备份密钥的攻击者不在单一系统能绝对防护的范围内。

## 2. 组件与边界

```text
Browser
  -> apps/web
  -> services/control-api -> PostgreSQL
                          -> Redis
                          -> PostgreSQL outbox -> NATS JetStream
                          -> external DNS / ACME / payment / notification APIs

NATS JetStream -> services/agent-gateway <mTLS gRPC stream> agents/edge-agent
NATS JetStream -> control-api workers -> PostgreSQL
NATS JetStream -> analytics writer -> ClickHouse

edge-agent -> immutable local releases -> OpenResty/Nginx + nftables/ipset
edge-agent -> telemetry batches -> agent-gateway -> NATS JetStream

Platform operator browser -> apps/operator-console -> services/license-service
                                                     -> separate license PostgreSQL
                                                     -> KMS/HSM signing key
services/control-api -> proof-of-possession renewal -> services/license-service
services/control-api -> cached signed entitlement lease -> server-side feature/quota checks
```

### 2.1 控制面

- `apps/web`：管理员和用户 UI。只通过版本化 OpenAPI 调用 `control-api`，不直接访问数据存储。
- `services/control-api`：Go 模块化单体。拥有业务规则、RBAC、事务、outbox、异步 worker 和外部提供商适配器。
- `services/agent-gateway`：Go gRPC 服务。终止 Agent mTLS、协商协议版本、维护双向流、转发命令、接收状态与遥测。它不决定业务期望状态。
- `control-api` 向 Gateway 提供内部 mTLS protobuf 接口，只用于 enrollment 授权/完成、节点授权快照和按 ID 流式读取不可变制品。Gateway 不获得数据库凭据，也不能通过该接口修改领域期望状态。
- PostgreSQL、Redis、ClickHouse 和 NATS JetStream 的职责见第 4 节。

### 2.2 平台授权上层控制面

- `apps/operator-console` 和 `services/license-service` 由平台方运营，管理客户、主控安装实例、许可证、entitlement、版本渠道、吊销和签名密钥元数据。它们使用独立身份、数据库和审计，不能复用客户主控的管理员会话。
- 主控安装时生成自己的安装密钥，通过 proof-of-possession 激活并定期换取 Ed25519 签名的短期 entitlement lease。主控仅保存平台验证公钥、安装私钥和最近有效租约，不保存平台签名私钥。
- 主控把签名租约解析为统一的服务端 feature/quota snapshot。网站、节点、四层、套餐和升级命令在业务事务提交前检查 snapshot；前端只负责展示，不是授权边界。
- 租约过期前主动续租，授权中心不可用时使用有界宽限并持续告警。到期或吊销后可以拒绝新建、扩容、发布和升级，但不能撤销 Agent 已激活版本，也不能进入边缘请求路径。
- 授权中心不直连客户 PostgreSQL、Redis、NATS、Gateway 或 Agent，不提供平台方绕过客户 RBAC 的万能后台入口。平台支持需要客户显式授权的短时会话和双方审计。

### 2.3 数据面

- `agents/edge-agent`：以 systemd 管理的 Go 静态二进制。保存最近已确认版本，完成制品校验、预检、原子激活、健康检查和回滚。
- `edge/openresty`：固定版本、可重复构建的 OpenResty/Nginx 运行时。Lua 只执行请求路径必须的鉴权、WAF、路由和指标逻辑。
- 主机防火墙、证书私钥、缓存目录和运行配置由 Agent 通过受限权限管理；OpenResty 不拥有控制面凭据。

### 2.4 严格边界

- 控制 API 不通过 SSH 操作节点；所有节点操作都形成任务并经过 Agent 协议。
- Agent 不访问 PostgreSQL、Redis、ClickHouse、NATS 或第三方控制面 API。
- Gateway 不直接修改领域表。Agent 回报先进入 NATS，由领域消费者在 PostgreSQL 事务中更新状态。
- Edge 请求处理不依赖控制 API、Gateway、Redis、NATS 或 PostgreSQL 在线。
- PostgreSQL 恢复前，不生成新期望状态；NATS 或 Gateway 恢复前，不投递新版本；两种故障均不能删除 Agent 的当前激活版本。

## 3. 同步、异步与一致性

### 3.1 同步路径

以下操作在响应前完成单个 PostgreSQL 事务：

- 登录会话、RBAC 检查和管理对象的创建/修改；
- 资金账本、订单、套餐、配额及结算记录的状态变更；
- 配置期望状态修订、发布请求、任务记录、审计记录和对应 outbox 事件。

API 成功表示业务状态已经提交，不表示 DNS、证书或节点变更已经生效。异步操作返回 `202 Accepted`、稳定的 `task_id` 和可查询状态。

### 3.2 事务性异步路径

1. `control-api` 在同一 PostgreSQL 事务写领域状态、审计记录和 outbox 行。
2. outbox publisher 以 `FOR UPDATE SKIP LOCKED` 领取事件并发布到 JetStream；收到服务器持久化确认后标记已发布。
3. 重复发布是正常情况。每个消费者用稳定 `event_id` 和自己的 inbox/去重键实现幂等。
4. 消费者完成目标存储的持久写入后才确认 NATS 消息；失败按退避重试，超过上限进入 dead-letter stream 并产生告警。
5. 对账任务扫描未发布 outbox、超时任务和状态不一致项。任何跨存储流程都不依赖分布式事务。

禁止先提交 PostgreSQL 再“尽力”发布消息，也禁止在一个请求中把 PostgreSQL 与 ClickHouse/Redis 当作原子双写。

### 3.3 配置发布主路径

1. 用户修改站点、源站、证书引用或安全策略，产生新的期望状态修订。
2. 发布命令冻结该修订，生成确定性规范化配置和 `sha256`，创建不可变 `ConfigVersion`、`Rollout` 与 outbox 事件。
3. 控制面验证器检查 schema、引用完整性、端口冲突、能力兼容性和安全约束；通过后版本状态为 `releasable`。
4. Rollout 调度器按节点组和灰度策略创建 `NodeDeployment`，经 NATS 投递版本引用。
5. Gateway 只向当前认证节点会话传递命令。Agent 从 Gateway 分块获取制品并验证长度、哈希、签名和兼容范围。
6. Agent 写入新的本地 release 目录，运行 OpenResty/Nginx、防火墙和证书预检，不改动当前软链接。
7. Agent 原子切换 release 指针并 reload，执行本机和外部健康检查。成功后保留新旧至少两个版本；失败则切回明确的 `previous_version_id`。
8. Agent 的每个状态回报包含 `deployment_id`、单调递增 `attempt`、`config_version_id` 和 `event_id`。控制面幂等推进状态机。
9. 灰度批次达到健康门槛才扩批；失败率或关键探针越界时自动暂停。人工或策略可触发全批回滚。

完整状态机见第 6 节。

### 3.4 遥测与计费路径

- Agent 对访问和安全事件赋稳定 `event_id`，批量发送到 Gateway。Gateway 发布至 NATS，ClickHouse writer 批量落库成功后确认消息。
- ClickHouse 用确定性事件 ID 去重，保存原始事件、TTL 和聚合视图。查询报表允许最终一致。
- 周期结算只读取已经越过摄取 watermark 的封闭时间窗，输出含源区间、算法版本和输入摘要的 `UsageSettlement`。
- 结算结果在单个 PostgreSQL 事务内写结算行、额度/资金账本、审计和 outbox。重跑相同结算键不得重复扣费。
- watermark 后到达的迟到数据生成新的调整结算和补偿账本项，不重写已封账记录。

## 4. 数据存储职责

| 组件 | 权威职责 | 允许的数据 | 禁止的数据/用法 | 故障与恢复语义 |
| --- | --- | --- | --- | --- |
| PostgreSQL | 控制面业务事实、关系与事务 | 租户、身份、RBAC、站点期望状态、节点库存、配置制品与 rollout、任务、DNS/证书元数据、订单、余额与用量账本、审计、outbox/inbox | 原始访问日志、高频安全事件、每次心跳、短期限流计数 | 不可用时拒绝新业务写入；边缘继续当前版本；使用 PITR、校验迁移和领域对账恢复 |
| Redis | 可丢失的加速与协调 | API 缓存、短期会话路由、在线租约、限流桶、短锁和幂等响应缓存 | 资金、配额、配置、任务结果或唯一审计副本；不得要求恢复 Redis 才能恢复业务事实 | 丢失后重建；节点短暂显示 `unknown`，限流进入文档化保守模式，不反写猜测状态 |
| ClickHouse | 高吞吐事件与分析事实 | 访问日志、安全事件、明细 TTL、物化聚合、排行和结算输入快照标识 | 身份/RBAC、余额、订单、配置期望状态；不能直接执行扣费 | 摄取停止不影响边缘；NATS 保留期内重放；超出保留期按缺口告警并禁止封账 |
| NATS JetStream | 持久异步投递与有限重放 | outbox 事件、Agent 命令引用、状态回报、遥测批次、重试和 dead-letter | 最终业务查询、长期账本、唯一任务状态、配置制品大对象 | 暂停新异步动作；发布者保留 outbox；消费者幂等重放；容量按最长可接受停机窗口设计 |

数据所有权规则：

- PostgreSQL 的领域状态只能由拥有该领域的模块写；其他模块通过应用服务或事件交互。
- Redis 项必须有 TTL、可重建来源和丢失时的明确行为。
- ClickHouse 明细由分析摄取器写；业务模块只能读取经版本化口径定义的聚合结果。
- NATS subject 和消息 schema 版本化。消息只携带必要数据或不可变引用，不能成为隐式数据库。

## 5. Agent 身份与会话

### 5.1 一次性注册

1. 管理员先在 PostgreSQL 创建 `Node` 和一次性 `EnrollmentToken`。数据库只保存令牌哈希、节点绑定、用途、创建人、到期时间和使用状态；默认 10 分钟过期。
2. Agent 在本机生成不可导出的私钥和 CSR，通过仅服务器 TLS 的 enrollment RPC 提交令牌、CSR、机器指纹和支持的协议/能力版本。
3. Gateway 调用控制面内部授权接口，原子消费令牌。成功只能发生一次；重试通过 enrollment request ID 返回同一结果，不能签发多个身份。
4. 平台在线中间 CA 签发短期客户端证书，URI SAN 固定为 `spiffe://cdn-platform/node/{node_id}`。生产根 CA 离线保存；中间 CA 密钥置于 KMS/HSM 兼容签名器。开发环境使用隔离的开发 CA。
5. Agent 以原子权限 `0600` 保存私钥和证书，之后所有 RPC 都使用双向 TLS。注册令牌被消费后不可用于日常认证。

### 5.2 续期、撤销与授权

- 客户端证书建议 24 小时有效，在剩余三分之一寿命时通过已认证连接续期；服务端证书按平台 PKI 策略轮换。
- Gateway 校验证书链、URI SAN、有效期、节点禁用状态、证书序列撤销状态和协议兼容性。授权依据是 `node_id`，不信任 Agent 上报的租户或节点组。
- 禁用节点或泄露响应在 PostgreSQL 持久化，outbox 广播撤销事件，所有 Gateway 断开相关会话。短证书有效期限制撤销广播丢失的窗口。
- 一个节点同一时间只允许一个主会话。Redis 保存带 TTL 的 `node_id -> gateway_instance/session_id` 路由租约；冲突连接以更高的服务端 epoch 接管，旧会话被关闭。

### 5.3 心跳

- 心跳默认每 15 秒，含会话 epoch、Agent/协议版本、当前与上一配置版本、OpenResty 状态、磁盘/缓存摘要和正在执行的 deployment。
- Gateway 在 Redis 刷新 45 秒在线租约，并把状态变化或最长每 60 秒一次的持久摘要发布到 NATS。在线状态是派生状态，不写成 PostgreSQL 权威布尔值。
- `0-45s` 为 `online`，租约缺失但最近见过为 `unknown`，超过运维策略阈值才显示 `offline`。Redis 故障期间一律显示 `unknown`，不能据此自动删除节点或回收业务。
- PostgreSQL 仅保存最近持久摘要、能力和状态变化历史；Prometheus 保存运行指标。心跳洪峰必须有按节点和 Gateway 的背压。

## 6. 配置与灰度状态机

### 6.1 配置版本

```text
building -> validating -> releasable -> superseded
                 |              |
                 v              v
              invalid        revoked
```

- `building`：冻结输入并生成规范化制品。
- `validating`：执行静态、引用和兼容性验证。
- `releasable`：内容不可再修改，可用于 rollout。
- `invalid`：验证失败，保存结构化错误；不能投递。
- `superseded`：有更新版本，不影响使用它的节点。
- `revoked`：因安全或操作原因禁止新投递；已激活节点必须由显式回滚/替换 rollout 处理。

### 6.2 Rollout

```text
pending -> canary -> expanding -> completed
   |         |           |
   +---------+-----------+-> paused -> canary/expanding
   |         |           |
   +---------+-----------+-> rolling_back -> rolled_back
   +---------+-----------+-> failed
```

- Rollout 保存目标节点集合快照、批次、并发、最小健康样本、超时、失败阈值和明确的前一版本映射。
- `paused` 不撤销已成功节点；恢复时继续原批次。修改配置必须创建新版本和新 rollout。
- `completed` 需要所有非豁免节点健康确认；不可达节点只能标记豁免并留下审批审计，不能静默当作成功。
- 自动回滚和人工回滚使用同一状态机。`rolled_back` 需要目标节点回到各自前一确认版本；若有节点失败，Rollout 为 `failed` 并产生高优先级告警。

### 6.3 单节点部署

```text
queued -> delivered -> staged -> prechecked -> activated -> healthy
   |          |          |           |            |
   +----------+----------+-----------+------------+-> failed
                                      |
                                      +-> reverting -> reverted
                                                      |
                                                      +-> rollback_failed
```

- `delivered` 仅表示命令到达 Agent，不表示配置生效。
- `staged` 需要制品签名和 SHA-256 通过；`prechecked` 需要配置语法、端口、文件权限、证书和防火墙 dry-run 通过。
- 激活使用同文件系统内的原子 rename/symlink 切换；reload 失败不得销毁旧进程。
- `healthy` 需要本机进程、监听端口、配置版本探针和策略指定的外部探针通过。
- `failed` 只表示激活前失败，或确认运行配置未改变的投递失败。进入 `activated` 后健康失败必须走 `reverting -> reverted|rollback_failed`，不能以普通失败跳过回滚。
- Agent 重启后读取本地 journal，用 `(deployment_id, attempt)` 恢复或重复执行幂等步骤；绝不根据临时目录猜测已激活版本。
- 回滚目标必须是该节点上最近一次 `healthy` 的制品；不存在可用目标时进入 `rollback_failed`，保留当前进程并拒绝破坏性清理。

## 7. 故障边界与降级

| 故障 | 必须保持 | 暂停/降级 | 恢复动作 |
| --- | --- | --- | --- |
| `control-api` 或 PostgreSQL 不可用 | 已激活边缘流量、Agent 本地健康守护 | 新登录/变更/结算/发布暂停 | 恢复数据库，检查迁移与 outbox，再开放写入 |
| Redis 不可用 | PostgreSQL 业务读写、边缘流量 | 在线状态为 `unknown`；缓存旁路；分布式限流使用保守本地限制 | 重建缓存和租约，不把旧 Redis 当事实源 |
| NATS 不可用 | 已提交业务事实和边缘当前版本 | outbox 堆积；新 rollout、遥测和外部任务暂停 | 恢复集群并幂等重放，检查 consumer lag/DLQ |
| ClickHouse 不可用 | 控制面操作和边缘流量 | 日志查询延迟；未覆盖时间窗禁止封账 | 从 NATS 重放，核对 watermark 与事件缺口 |
| Gateway 全部不可用 | Agent 继续运行并本地守护当前版本 | 节点显示失联；不下发新配置 | Agent 抖动退避重连，按 deployment ID 对账 |
| 单个 Agent/OpenResty 异常 | 其他节点与控制面 | 调度摘除故障节点；禁止将未健康版本扩批 | 本地回滚、人工隔离或重装后重新注册 |
| 外部 DNS/ACME/通知 API 异常 | 控制面和现有解析/证书 | 对应任务重试；证书到期进入分级告警 | 使用 provider 幂等键和 reconcile 查询真实外部状态 |
| 授权中心不可用 | 已激活边缘流量、主控本地管理和最近有效租约 | 宽限期内告警并继续；宽限后拒绝新建/扩容/发布/升级 | 校验平台证书与安装身份后续租；对账 lease serial、吊销和额度，不回滚现有边缘配置 |

任何降级模式都不能以“成功”隐藏未执行的外部副作用。UI 和 API 分别展示业务提交状态、任务状态和边缘生效覆盖率。

## 8. 安全与可观测性

- 用户密码使用 Argon2id；访问令牌短期有效；刷新会话以哈希形式保存且可按设备、用户、租户撤销。
- DNS 密钥、证书私钥和第三方凭据使用数据密钥信封加密；主密钥位于 KMS/HSM 兼容提供方。API 默认不回显秘密。
- 服务账户按数据库 schema/操作分权。应用迁移账户与运行账户分离；审计表拒绝 UPDATE/DELETE。
- 每个入口生成或验证 `request_id` 与 W3C trace context。异步事件保存 `trace_id`、`causation_id`、`correlation_id`，任务统一使用 `task_id`，节点操作增加 `deployment_id`。
- 结构化日志包含租户 ID、主体 ID 和对象 ID，但通过字段白名单排除密码、令牌、私钥、请求体和 DNS 密钥。
- Prometheus 至少监控 API 延迟/错误、数据库池、outbox age、NATS consumer lag、Gateway 会话、心跳间隔、rollout 成功率、Agent 回滚、ClickHouse ingest lag 和 settlement watermark。
- 授权链另外监控 lease 剩余寿命、续租错误、宽限实例、吊销传播、未知 key ID、签名失败和 entitlement 拒绝；日志只记录 lease ID/serial/hash，不记录安装私钥或签名原文。
- OpenTelemetry Collector 统一接收 traces/metrics/logs；控制面不可观察性故障不得阻塞业务请求，但必须有本地有界缓冲和丢弃计数。

## 9. 部署拓扑与演进条件

### 9.1 本地开发

- Docker Compose 启动 web、control-api、agent-gateway、PostgreSQL、Redis、ClickHouse、单节点 NATS JetStream、OTel Collector 和 Prometheus。
- 一个开发 Agent 和 OpenResty 可作为 Linux VM/容器 profile 启动；涉及 systemd、nftables、端口和原子切换的验收必须在隔离 Linux VM 中执行，不能用 macOS 容器结果代替。
- 使用独立开发 CA、测试 DNS zone 和固定时钟数据。`make up`/等价命令必须可重复初始化并运行迁移、种子和健康检查。

### 9.2 单机生产

- 单台 Linux 控制面主机运行单节点 Kubernetes（例如 k3s），使用相同 Helm chart；web、control-api 和 Gateway 可多进程，但底层主机和本地存储不是 HA。
- PostgreSQL、Redis、ClickHouse 和单节点 NATS 的持久卷必须使用独立目录并进行异机加密备份。必须定期演练从备份恢复到新主机。
- 入口使用 TLS 负载均衡；Gateway 与公开 API 使用独立端口和证书。边缘节点不能与该控制面主机混部。
- 此拓扑适合可接受控制面恢复时间、但要求边缘持续服务的早期生产。文档必须明确单机故障期间无法变更、查看实时状态或结算。

### 9.3 HA 生产

- 至少三个故障域的 Kubernetes 集群；web/control-api/Gateway/worker 各至少两副本，使用 PodDisruptionBudget、反亲和和滚动升级。
- PostgreSQL 使用三节点或托管 HA、同步故障切换和 PITR；Redis 使用 Sentinel/托管主从，只有经测量需要水平写入时才采用 Cluster。
- NATS JetStream 使用三个节点和复制因子 3；ClickHouse 使用至少两副本、分片按容量测试决定，并使用 ClickHouse Keeper。
- 入口负载均衡支持长时 gRPC 连接、连接排空和跨故障域健康检查。Gateway 无状态会话路由存 Redis，命令事实仍在 NATS/PostgreSQL。
- PKI 中间 CA、信封加密主密钥、备份和审计签名检查点位于独立安全域。恢复演练覆盖整个控制面丢失和单区域丢失。

### 9.4 只在满足条件时演进

| 演进 | 触发条件 | 先验证的证据 |
| --- | --- | --- |
| 配置制品迁移到对象存储 | 单制品压缩后超过 10 MiB，或制品表超过 100 GiB/显著拖慢备份恢复 | 30 天体积分布、数据库备份/恢复时间、下载带宽；新 ADR 和双读迁移演练 |
| 从 control-api 拆领域服务 | 某领域需要独立扩缩/发布，且持续造成 SLO 或团队发布冲突 | profile、队列等待、故障归因和明确数据所有权；禁止共享表 |
| Redis Cluster | 单主写入或内存超过安全容量且纵向扩容/分片键优化无效 | 峰值 QPS、热键、failover 演练和客户端兼容性 |
| ClickHouse 增加分片 | 单分片在目标保留期下 CPU、磁盘或查询 p95 超预算 | 生产形态压测、压缩率、merge backlog 和结算窗口 |
| 独立分析摄取服务 | control-api worker 的资源争用影响 API SLO | CPU/内存 profile、consumer lag、故障隔离收益 |
| 多区域控制面 | 单区域灾难恢复 RTO/RPO 不满足合同 | 明确 RTO/RPO、冲突模型、DNS/PKI 演练；先做冷/暖备，不直接多主写 |

## 10. 下一步契约顺序

1. `proto/agent/v1`：先固定 `Enroll`、`Connect` 双向流、`Heartbeat`、`DeploymentCommand`、`ArtifactChunk`、`DeploymentStatus`、能力与错误码。所有消息带稳定 ID、版本和时间。
2. `proto/control-internal/v1`：固定 enrollment 授权/完成、节点授权快照和不可变制品流；要求服务 mTLS、调用方身份和逐节点授权测试。
3. `api/openapi/v1`：固定认证、节点注册、节点状态、期望配置发布、rollout 查询/暂停/恢复/回滚以及任务查询。
4. PostgreSQL 初始迁移：实现租户/RBAC、节点/注册令牌、配置版本/制品、rollout/node deployment、task、outbox/inbox 和审计最小表。
5. NATS subject：定义 `control.node.command.v1`、`edge.node.status.v1`、`edge.telemetry.access.v1`、`edge.telemetry.security.v1`、DLQ、保留期和最大消息大小。
6. 错误模型：统一可重试/不可重试、乐观锁冲突、幂等重放、兼容性拒绝和人工介入状态，保证 OpenAPI、protobuf 和任务 UI 映射一致。

接口设计必须引用 [领域模型](domain-model.md) 的聚合边界，并通过契约测试证明字段和状态枚举无漂移。
