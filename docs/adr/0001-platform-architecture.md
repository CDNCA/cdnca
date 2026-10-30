# ADR-0001：模块化控制面与独立边缘数据面

- 状态：Accepted
- 日期：2026-07-21
- 决策者：项目架构基线
- 关联文档：[平台架构](../architecture.md)、[领域模型](../domain-model.md)

## 背景

项目需要重建可生产运营的 CDN 平台，既要覆盖多租户管理、网站/DNS/证书、安全、计费和运维，又要保证控制面故障时已有边缘流量继续工作。初期团队和负载尚未证明需要微服务，但节点长连接、边缘特权操作、高吞吐日志与事务型商业数据具有明显不同的故障和扩缩边界。

必须同时解决：

- 控制面业务事务与边缘请求路径解耦；
- 节点身份、配置下发、激活和回滚可验证；
- 管理数据、短期状态、高吞吐分析和持久消息各有唯一职责；
- 从本地到 HA 生产不改变领域语义和接口；
- 避免在需求尚未测量前付出微服务和分布式事务成本。

## 决策

### 1. 应用边界

- `apps/web` 使用 React、TypeScript、Vite、React Router、TanStack Query、Zustand、Ant Design 和 ECharts，调用 OpenAPI-first 的控制 API。
- `services/control-api` 使用 Go 模块化单体，领域包拥有自己的业务规则和表；使用 pgx/sqlc 及可前滚、可回滚迁移。
- `services/agent-gateway` 独立部署为 Go gRPC 服务，因为 mTLS 长连接、连接排空、协议版本和水平扩容与普通 API 不同。Gateway 不拥有业务期望状态；它通过内部 mTLS protobuf 接口向 control-api 完成 enrollment 授权并流式读取不可变制品，不直接访问数据库。
- `agents/edge-agent` 是 systemd 管理的 Go 静态二进制，只通过版本化 protobuf/mTLS 与 Gateway 通信。
- `edge/openresty` 固定并可重复构建。请求路径必要逻辑可用 Lua，编排和控制逻辑保留在 Go 控制面/Agent。

### 2. 控制面与数据面

边缘当前健康版本、前一健康版本和本地 journal 必须在 Agent 主机持久化。控制面、数据库、消息系统或网络中断时，Agent 不删除或替换当前版本，OpenResty 继续服务。所有变更采用不可变配置版本和 `生成 -> 验证 -> 灰度 -> 预检 -> 原子激活 -> 健康确认 -> 必要时回滚` 流程。

控制 API 不通过 SSH 或直接文件写入操作节点。节点不访问控制面数据存储。Gateway 只做认证、会话和协议转发；领域消费者根据 Agent 回报更新 PostgreSQL。

### 3. 数据与消息职责

- PostgreSQL 是控制面业务事实源，保存配置期望、身份/RBAC、节点库存、rollout/task、商业账本、审计以及 outbox/inbox。
- Redis 只保存带 TTL、可重建的缓存、限流、短锁、在线租约和 Gateway 会话路由。
- ClickHouse 保存高吞吐访问/安全事件、聚合和报表/结算输入；它不直接写资金或配额结果。
- NATS JetStream 提供持久投递、重试和有限重放，不作为最终业务查询数据库。

跨组件一致性使用 PostgreSQL transactional outbox、消费者 inbox/稳定事件 ID、状态机和 reconcile。接受至少一次投递，不采用 PostgreSQL/ClickHouse/NATS 间的分布式事务或同步双写。

### 4. 身份与安全

节点使用一次性、短期、绑定 node ID 的 enrollment token 完成 CSR 注册；token 只保存哈希并原子消费。注册后使用短期客户端证书和双向 TLS，证书 URI SAN 绑定 node ID。生产使用离线根 CA、在线中间 CA 与 KMS/HSM 兼容签名器。长期共享节点密钥不被接受。

用户密码使用 Argon2id；刷新会话可撤销；敏感凭据使用信封加密；日志和审计字段白名单不得包含秘密。资金、权限、身份和发布操作写仅追加、哈希链接的审计事件。只读查询不写审计事件：例如公告受众目录搜索与发布前人数（`GET /v1/admin/announcements[/global]/audience-directory`、`.../{id}/audience/count`，C32）与其他 list/get 一样不进审计目录；公告受众的实际选择随公告保存与发布这一写操作进入审计。

### 5. 部署与演进

- 本地使用 Docker Compose 和隔离 Linux Edge VM。
- 单机生产使用单节点 Kubernetes 与 Helm，并明确其非 HA 性质及异机备份要求。
- HA 生产在多个故障域部署无状态服务副本、HA PostgreSQL、Redis failover、三节点 JetStream 和复制 ClickHouse。

不预先拆微服务或引入对象存储。只有 [平台架构第 9.4 节](../architecture.md#94-只在满足条件时演进) 的可测量阈值满足、迁移与回滚方案验证后，才通过新 ADR 演进。

## 关键状态语义

- ConfigVersion：`building|validating|releasable|invalid|superseded|revoked`。
- Rollout：`pending|canary|expanding|paused|completed|rolling_back|rolled_back|failed`。
- NodeDeployment：`queued|delivered|staged|prechecked|activated|healthy|failed|reverting|reverted|rollback_failed`。
- 节点管理状态与在线派生状态分离；Redis 丢失时在线状态为 `unknown`，不猜测为健康或删除节点。

这些枚举是 OpenAPI、protobuf、数据库约束和 UI 的共同基线。修改必须通过后续 ADR 或兼容性评审。

## 被否决的方案

### 从第一天拆成全微服务

否决。身份、网站、节点、证书和计费边界仍在形成，过早拆分会引入共享数据库、跨服务事务、接口版本和运维成本。模块化单体保留代码边界，测量到独立扩缩/发布需求后再拆。

### 控制 API 同步直连 Agent 或 SSH

否决。同步调用会把节点和网络故障带入用户请求，并使重试、审计、灰度与回滚不可控；SSH 也无法提供稳定版本化契约和最小权限身份。

### Redis/NATS 作为配置或任务事实源

否决。两者适合短期协调和投递，不适合作为商业、配置和审计的唯一持久记录。丢失/重放后必须能从 PostgreSQL 恢复任务意图与状态。

### 原始访问日志写 PostgreSQL

否决。高写入量和高基数查询会影响控制面事务与恢复。明细和分析进入 ClickHouse，只有版本化结算结果进入 PostgreSQL。

### 配置覆盖原文件后 reload

否决。部分写入、校验失败或进程崩溃会破坏最后健康状态。必须使用不可变 release、同文件系统原子切换、本地 journal 和明确回滚目标。

### 现在就引入对象存储、工作流引擎或服务网格

否决。尚无制品体积、工作流复杂度或服务数量证明这些组件必要。先用 PostgreSQL 制品、Task 状态机、NATS 和标准 mTLS；达到量化阈值后再评估。

## 结果

### 正面

- 边缘不依赖控制面实时可用，故障范围清晰。
- 事务事实、短期状态、分析数据和消息投递没有含糊双写。
- Agent 长连接可独立扩容，控制 API 仍保持简单部署和本地事务。
- 状态机、稳定 ID 和幂等消费者支持重试、接管、灰度与回滚。
- 本地、单机和 HA 使用同一制品与契约，演进可以由指标驱动。

### 代价

- 用户提交与边缘生效是最终一致，UI/API 必须展示任务与覆盖率，不能只返回一个成功布尔值。
- outbox、inbox、DLQ、reconcile 和状态机增加实现与测试工作。
- 短证书和 PKI 引入证书续期、撤销广播和时钟偏差运维要求。
- ClickHouse/NATS 故障可能造成报表延迟；结算必须受 watermark 和缺口检查保护。
- 单机生产只保证数据面持续服务，不提供控制面 HA，必须诚实披露并演练恢复。

## 必须验证的风险

1. OpenResty、nftables/ipset 和证书在目标 Linux 发行版上的原子预检/切换边界，需要隔离节点故障注入。
2. 配置制品大小、生成时间和分块传输上限尚无真实数据，需要容量基准验证 PostgreSQL 存储假设。
3. Agent 遥测峰值、NATS 保留容量、ClickHouse 分区/TTL 和物化视图必须压测后定值。
4. ACME/DNS provider 的幂等与 reconcile 能力不同，需要逐 provider 契约测试。
5. 用量 watermark、迟到事件、TCP 系数和跨周期调整必须用固定时钟与重复摄取测试。
6. PKI 中间 CA 故障、证书续期风暴、撤销事件丢失和节点时钟漂移需要演练。

## 后续决策

下一步先定义并契约测试 `agent.v1` protobuf、节点/rollout OpenAPI、初始 PostgreSQL 状态约束和 NATS subject。对象存储、服务拆分、多区域写入、ClickHouse 分片及高级工作流引擎必须分别提交带测量证据的新 ADR。
