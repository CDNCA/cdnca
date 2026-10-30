# 核心领域模型

本文定义控制面的领域、聚合、事务和幂等边界。运行组件、数据存储与故障语义见 [平台架构](architecture.md)，选型依据见 [ADR-0001](adr/0001-platform-architecture.md)。

## 1. 通用约定

- 所有持久实体使用 UUIDv7（或数据库可排序 UUID）作为内部 ID；外部显示号单独生成，不能作为关联键。
- 租户数据必须带 `tenant_id`。平台级对象显式使用 platform scope，禁止用空租户表达权限。
- 聚合根带 `revision`，修改使用 `WHERE revision = expected_revision` 的乐观并发控制；冲突返回明确错误，不做静默覆盖。
- 时间保存 UTC 的 `timestamptz`；金额保存币种和最小货币单位整数；流量保存字节整数；比例保存有界定点数。
- 删除默认是受审计的状态转换。资金、用量、审计、配置版本和任务结果只追加或使用补偿记录，不物理覆盖历史。
- 每个命令携带 `request_id`；可重试写操作还必须携带作用域内唯一的 `idempotency_key`。相同 key 和相同输入返回原结果，相同 key 不同输入返回冲突。
- 领域事件在聚合事务内写入 outbox。事件 ID 全局唯一，包含 aggregate ID/revision、causation ID、correlation ID、actor 和 schema version。

## 2. 领域边界

| 领域 | 聚合根 | 负责的事实 | 不负责 |
| --- | --- | --- | --- |
| Identity & Access | `Tenant`、`User`、`Role`、`Session`、`ImpersonationSession`、`ApiCredential` | 多租户身份、RBAC、认证状态、会话撤销、实名认证状态引用 | 余额、节点在线状态、边缘鉴权执行 |
| Customer & Commerce | `Account`、`Order`、`Subscription`、`QuotaCycle` | 余额、充值/退款、套餐订阅、周期、配额和价格快照 | 原始访问日志、实时限流计数 |
| Site Configuration | `Site`、`SiteGroup`、`OriginPool`、`SecurityPolicy`、`CachePolicy`、`L4Application` | 用户期望的 HTTP/L4 配置及引用关系 | 节点上的实际激活状态 |
| Network & Scheduling | `Node`、`NodeGroup`、`RoutePolicy`、`NodeCapability` | 节点库存、层级、线路、IP、权重、容量约束和调度意图 | 高频心跳租约、配置文件内容 |
| Edge Delivery | `ConfigVersion`、`Rollout`、`NodeDeployment` | 不可变制品、目标快照、灰度策略、每节点生效与回滚事实 | 站点编辑草稿、访问日志分析 |
| DNS & Certificate | `DnsProviderAccount`、`DnsZone`、`Certificate`、`CertificateOrder` | DNS 凭据引用、解析期望、ACME 订单、证书生命周期 | 将配置直接写入节点 |
| Task & Integration | `Task`、`ProviderOperation`、`Notification` | 长任务、外部副作用、重试、通知投递 | 领域对象自身的最终业务事实 |
| Observability & Usage | `UsageSettlement`、`UsageLedger`、`AuditStream` | 分析口径版本、封账、迟到调整和控制面审计 | ClickHouse 原始事件、Redis 在线租约 |

模块只能写自己拥有的表。跨领域强一致规则通过同一模块化单体中的应用服务协调一个 PostgreSQL 事务；跨外部系统或高吞吐存储使用 task/outbox 和补偿，不扩大数据库事务。

## 3. 身份、租户与 RBAC

### 3.1 主要实体

- `Tenant`：租户状态、显示信息、默认时区、合规状态。`suspended` 阻止新控制面变更，但是否立即停止边缘服务必须由显式商业策略任务决定。
- `User`：全局登录主体；通过 `TenantMembership` 加入租户。邮箱/手机号的唯一性与登录策略必须在迁移中明确。
- `Role`：租户或平台作用域的权限集合。权限使用稳定动作名，例如 `site.read`、`site.publish`、`billing.refund`、`node.enroll`。
- `Session`：刷新令牌哈希、设备、创建/到期/撤销时间和轮换链。刷新令牌每次使用后轮换，旧令牌重放会撤销整条链。
- `ImpersonationSession`：高权限管理员发起的短时一次性代登录，保存真实 actor、目标用户、原因、审批/工单引用、到期与撤销状态；不能生成普通长期刷新会话。
- `ApiCredential`：公开 key ID、秘密哈希/加密材料、作用域、最后使用时间和撤销状态；秘密只在创建时显示一次。
- `VerificationCase`：个人/企业实名认证状态和外部提供商引用；敏感材料独立加密并有更严格审计。

### 3.2 不变量与事务

- 至少保留一个可管理租户权限的有效主体；删除最后一个 owner 必须被拒绝或在同一事务转移所有权。
- 登录密码验证、失败计数和限流分开：密码事实在 PostgreSQL，短期失败桶在 Redis；Redis 丢失不能绕过账户锁定的持久阈值。
- 修改角色、撤销会话/API key 和更改认证状态时，在同一事务写审计与 outbox，使缓存失效可重放。
- RBAC 在服务端按租户、资源和动作判断；前端隐藏菜单不构成授权。

## 4. 网站、网络与期望配置

### 4.1 Site Configuration 聚合

- `Site`：域名集合、启用状态、监听、TLS 模式、所属组以及对源站/缓存/安全/证书策略的版本化引用；领域状态区分正常、套餐过期、流量超限和管理员锁定，旧 API 的 200/512/513/514 只在兼容层映射。
- `OriginPool`：源站地址、端口、协议、权重、健康检查、失败重试、条件回源和 L2 失败策略；负载算法是 `ip_hash|round_robin|url_hash|least_conn|random` 的受控枚举，不接受自由配置片段。
- `SecurityPolicy`：有序 WAF/CC/ACL 规则。每条规则显式包含匹配条件、动作和 `continue|stop` 控制流。
- `CachePolicy`：有序匹配、TTL、跟随源站、忽略参数、Range、刷新/预热约束。
- `L4Application`：TCP/UDP 监听、后端、Proxy Protocol、连接超时和流量系数。

一次站点编辑事务只能修改一个聚合及其内部子项。共享策略通过 ID 和期望 revision 引用；发布时解析为不可变快照，防止策略随后修改导致旧版本漂移。

关键不变量：

- 同一调度作用域内 `(address_family, listen_ip, port, protocol)` 不能冲突。
- 域名规范化为小写 ASCII/Punycode；通配符层级、证书 SAN 和 DNS 验证必须显式检查。
- 源站不能无意指向当前 CDN 入口形成循环；允许场景必须经过显式 override 和审计。
- 规则顺序是业务语义，使用稳定 position/rank 并在事务内重排。
- 秘密值只保存 `secret_ref`，不能进入普通 API 响应、审计 diff 或日志。

### 4.2 Network & Scheduling 聚合

- `Node`：稳定身份、管理状态、地域、运营商、地址、Agent 兼容范围和注册状态。
- `NodeGroup`：L1/L2 层级、节点成员、备用 IP 顺序、权重、月流量上限、定时禁用和能力要求；L2 健康策略显式保存间隔与失败/恢复阈值，兼容默认值为 10 秒和连续 3 次。
- `RoutePolicy`：域名/线路/区域到节点组的调度意图及健康门槛。
- `NodeCapability`：Agent 回报并由控制面验证的 OpenResty、HTTP/3、IPv6、nftables 等能力快照。

`Node.admin_state` 是 PostgreSQL 事实（`pending|active|draining|disabled|retired`）；`online|unknown|offline` 是基于 Redis 租约和最后观测时间的派生视图，二者不能合并成一个字段。

调度结果必须保存输入 revision 和确定性摘要。节点能力不足、端口冲突或配额越界时，配置验证失败，不能等到 Agent 激活阶段才发现可预检问题。

## 5. Edge Delivery 与配置状态机

### 5.1 ConfigVersion

`ConfigVersion` 是不可变聚合，至少包含：

- `id`、scope/目标类型、输入对象及 revision 清单；
- 规范化 manifest、压缩制品、`sha256`、平台签名、生成器版本；
- Agent 协议和能力兼容范围；
- 状态 `building|validating|releasable|invalid|superseded|revoked`；
- 创建者、原因、验证结果和时间。

只有 `releasable` 可创建 rollout。任何内容变化都创建新 ID；`superseded`/`revoked` 不删除制品。生成必须确定性：相同输入 revision、生成器版本和平台能力产生相同摘要。

### 5.2 Rollout

`Rollout` 冻结以下事实：目标节点 ID 集合、每个节点的前一健康版本、批次计划、并发、超时、失败阈值、最小健康样本、外部探针和审批者。

状态使用 [平台架构第 6 节](architecture.md#6-配置与灰度状态机) 的：

`pending|canary|expanding|paused|completed|rolling_back|rolled_back|failed`

规则：

- 同一节点和配置作用域同一时间最多一个活动 deployment；通过 PostgreSQL 唯一约束或事务锁保证。
- 扩批只由持有 rollout lease 的调度器决定；lease 可丢失，但批次和节点状态在 PostgreSQL，可由新 worker 接管。
- 暂停、恢复和回滚命令使用 `(rollout_id, requested_transition, expected_revision)` 幂等执行。
- 目标集合创建后不随节点组变化；新增节点由新的 reconcile rollout 处理。

### 5.3 NodeDeployment

每个 `(rollout_id, node_id)` 有一个逻辑 deployment，可有递增 `attempt`。状态为：

`queued|delivered|staged|prechecked|activated|healthy|failed|reverting|reverted|rollback_failed`

Agent 回报只有满足以下条件才推进状态：证书身份的 node ID 匹配、deployment/config/attempt 匹配、事件 ID 未处理、状态转换合法。重复或乱序事件保留接收审计但不回退最终状态。

`failed` 只用于激活前失败，或 Agent 已证明运行配置未改变的投递失败。进入 `activated` 后健康失败必须推进到 `reverting`，最终为 `reverted` 或 `rollback_failed`，不能跳过回滚语义。

Agent 本地 journal 和控制面状态可能短暂不一致。连接恢复后由以下规则对账：

- Agent 的已激活摘要与控制面已确认版本一致：补齐遗漏状态。
- Agent 已激活预期版本但控制面未确认：重新执行健康检查后回报，不重复切换。
- Agent 仍在前一健康版本：控制面根据 rollout 状态重发或保持暂停。
- Agent 在未知版本：自动隔离该节点，禁止继续扩批，要求拉取 manifest 和人工/策略决策；不能覆盖证据。

## 6. Agent 注册和在线状态

- `EnrollmentToken` 属于 Node 身份子域，保存 token hash、node ID、purpose、expiry、consumed_at 和 request ID。消费 token 与记录证书序列在单个 PostgreSQL 事务完成。
- `NodeCertificate` 保存证书序列、not_before/not_after、CSR 摘要、状态和替代证书关系，不保存 Agent 私钥。
- `NodeSession` 是 Gateway/Redis 的短期路由对象，不是业务聚合；Redis 丢失后由 Agent 重连重建。
- `NodeObservation` 是经 NATS 限频落入 PostgreSQL 的最后摘要/状态变化，用于审计和运维，不决定实时在线。

注册、mTLS、续期和心跳协议详见 [平台架构第 5 节](architecture.md#5-agent-身份与会话)。

## 7. DNS 与证书

- `DnsProviderAccount` 保存 provider、租户、加密 secret reference、能力和验证状态；凭据轮换产生新 secret version。provider 使用受控标识并至少覆盖阿里云、Cloudflare、华为云、DNSPod CN、DNS.com 和 dns.la/dnsdun，别名与线路/权重能力单独声明。
- `DnsZone` 保存权威 zone、provider account 和外部 zone ID。
- `DnsRecordIntent` 保存期望记录；`ProviderOperation` 保存一次外部 create/update/delete 的幂等请求与观测结果。
- `Certificate` 保存 SAN、有效期、issuer、状态、证书链和加密私钥引用；私钥不得进入通用 ConfigVersion，分发制品需对目标节点单独封装。
- `CertificateOrder` 状态建议为 `pending|authorizing|validating|issuing|issued|retry_wait|failed|revoked`，记录 ACME account、challenge 和下一次重试时间。

外部 DNS 和 ACME 不参与数据库事务。事务先保存期望状态与 `ProviderOperation`，worker 用稳定 provider idempotency key 调用外部系统，然后读取外部真实状态并提交结果。未知超时不得直接重试 create；先 reconcile，避免重复记录或错误删除。

证书续期在到期前按可配置窗口创建新 order。只有新证书签发、匹配 SAN、私钥验证和灰度部署健康后才替换引用；失败保留旧证书并按剩余寿命分级告警。

## 8. 商业、用量与账本

### 8.1 Account 与账本

- `Account` 每个租户/币种唯一，缓存余额仅为账本聚合结果。
- `LedgerTransaction` 表示一次业务动作，包含不可重复的业务键、类型、actor、原因和外部引用。
- `LedgerEntry` 使用复式记账；同一 transaction 内借贷平衡，已过账 entry 不更新/删除，只能追加反向或调整 transaction。
- 充值、支付回调、退款和人工调账均要求 provider/reference 范围内的唯一幂等键，并在同一事务更新订单状态、记账、审计和 outbox。

### 8.2 Subscription 与 QuotaCycle

- `Subscription` 保存套餐和价格快照，后续改价不重算历史订单。
- `QuotaCycle` 冻结起止 UTC、显示时区、包含量、结转规则、TCP 系数和告警阈值。
- 周期切换使用数据库唯一约束和固定时钟测试，确保并发 worker 只创建一个新周期。
- 实时配额判断可读 Redis/ClickHouse 的近实时估计，但强制停服/扣费必须使用已持久化结算和明确安全余量；降级策略需按套餐声明。

### 8.3 UsageSettlement

结算键建议为：

`(tenant_id, subscription_id, quota_cycle_id, metric, window_start, window_end, algorithm_version, revision)`

一条结算保存 ClickHouse 查询版本、watermark、输入行数/摘要、原始量、系数、计费量和状态。首次封账与资金/配额 entry 在单个 PostgreSQL 事务提交。迟到事件或口径修复增加 `revision` 并引用被调整结算，生成差额 entry；不能修改原结算。

## 9. Task、外部副作用与通知

`Task` 是用户可见长任务记录，状态为：

`pending|running|retry_wait|succeeded|failed|cancel_requested|cancelled|needs_attention`

- Task 保存类型、作用域、输入摘要、进度、当前 attempt、最大 attempts、下一次执行时间、错误分类和结果引用。敏感输入只保存 secret reference；刷新、预热、黑名单解锁、日志下载、DNS/证书、部署和运维任务共享统一查询模型，但执行器仍按领域隔离。
- 创建 Task 与触发它的领域变更/outbox 在一个事务；worker 开始和完成各自使用短事务。
- 只有文档化为幂等或可 reconcile 的步骤才能自动重试。不可判定的外部副作用进入 `needs_attention`，不能冒充失败后安全重试。
- 取消是请求，不保证已经发生的外部副作用可撤销；结果必须说明取消点和补偿状态。
- `Notification` 由领域事件创建，按租户订阅、模板版本和渠道生成投递。短信和邮件开关独立；`(event_id, recipient, channel, template_version)` 唯一。

缓存刷新/预热也使用 Task：每个资源和节点子任务有确定性键、速率限制和失败重试；整体成功必须达到策略定义的目标覆盖率，未执行节点单列。

## 10. 审计模型

`AuditStream` 按租户/平台作用域保存只追加事件：actor、授权主体、动作、资源、request/trace/task ID、前后字段白名单摘要、结果、来源 IP、时间、`previous_hash` 和 `event_hash`。

- 应用运行角色只能 INSERT/SELECT，数据库策略拒绝 UPDATE/DELETE；更正以新事件引用原事件。
- 秘密、密码、令牌、证书私钥、完整请求体和 DNS key 永不进入审计 diff。
- 每个 stream 定期生成签名检查点并写入异机备份/独立安全域。校验任务持续检查链断裂并告警。
- 资金、权限、节点身份、配置发布/回滚、provider 凭据和人工豁免必须写审计；审计写失败时对应高风险事务失败关闭。

## 11. PostgreSQL 事务矩阵

| 命令 | 同一事务必须包含 | 事务外步骤 | 幂等/并发保护 |
| --- | --- | --- | --- |
| 创建/修改站点 | Site 聚合、revision、审计、outbox | 无；发布是独立命令 | tenant + client key；expected revision |
| 发布配置 | 冻结输入清单、ConfigVersion building、Task、审计、outbox | 生成/验证可由 worker 完成 | 输入 revisions + generator version digest |
| 创建 rollout | Rollout、目标快照、NodeDeployment、审计、outbox | NATS 投递、Agent 执行 | config/scope 活动 rollout 唯一；request key |
| 推进 deployment | inbox、合法状态变更、Rollout 聚合、outbox | 后续批次命令 | event ID、attempt、状态 CAS |
| 注册 Agent | 消费 EnrollmentToken、NodeCertificate、Node 状态、审计、outbox | CA 签名需使用受控的 prepare/finalize 协议 | enrollment request ID；token 单次约束 |
| 充值/支付回调 | Order、LedgerTransaction/Entry、Account projection、审计、outbox | 通知 | provider event/reference 唯一 |
| 用量封账 | UsageSettlement、额度/账本 entry、审计、outbox | 通知、后续停服策略任务 | settlement 复合键；周期行锁 |
| DNS/ACME 请求 | 期望状态、ProviderOperation/Task、审计、outbox | provider API + reconcile | operation key + provider external ID |
| 撤销节点/凭据 | 持久状态、证书/凭据撤销、审计、outbox | Gateway 断连、缓存失效 | expected revision；重复撤销返回原结果 |

CA 签名不能与 PostgreSQL 形成分布式事务。推荐流程是事务内原子消费 token 并创建 `signing_pending` 证书记录，事务外以 request ID 签名，再以证书序列唯一约束 finalize。崩溃恢复时查询签名器或重用同一 request ID，禁止重新消费 token 产生第二身份。

## 12. NATS 事件与消费者幂等

- 命令/事件 envelope：`event_id`、`schema_version`、`type`、`occurred_at`、`tenant_id/scope`、`actor_id`、`trace_id`、`causation_id`、`correlation_id`、payload。
- 领域消费者在 PostgreSQL 使用 `(consumer_name, event_id)` inbox 唯一键；业务写和 inbox 写同事务。
- ClickHouse 事件使用由 Agent 生成且跨重试稳定的 event ID，并按 event ID 去重；NATS ack 发生在批次持久化成功之后。
- Gateway 命令传递可重复。Agent journal 以 `(deployment_id, attempt, command_kind)` 去重并返回已知结果。
- 消费者不能依赖全局消息顺序；同聚合用 revision 拒绝旧事件。必须顺序执行的 node deployment 使用节点/作用域键分区和数据库状态机共同保证。
- DLQ 不是完成状态。进入 DLQ 时同步更新对应 Task 为 `needs_attention` 或产生可追踪告警；修复后以原 event ID 或显式 replay ID 重放。

## 13. 首批契约与测试边界

下一轮应按以下顺序固定契约：

1. `agent.v1` protobuf：身份、能力、双向流 envelope、心跳、制品分块、部署命令/状态和可重试错误。
2. `control-internal.v1` protobuf：enrollment 授权/完成、节点授权快照和不可变制品流，确保 Gateway 无需数据库权限。
3. OpenAPI：登录/刷新/撤销、租户与 RBAC、节点 enrollment、节点详情、配置发布、rollout 控制和 task 查询。
4. SQL 迁移：先覆盖 Tenant/User/Role、Node/EnrollmentToken/Certificate、ConfigVersion/Rollout/NodeDeployment、Task、Outbox/Inbox/Audit。
5. 契约测试：非法状态转换、重复/乱序 Agent 回报、token 并发消费、相同幂等键不同 payload、rollout worker 接管和 outbox 重放。
6. 固定时钟集成测试：证书续期窗口、套餐跨周期、迟到用量调整和会话/证书过期。

任何新增领域或状态都必须先更新本文和 [平台架构](architecture.md) 的对应状态机，再更新 OpenAPI/protobuf/迁移，避免契约漂移。
