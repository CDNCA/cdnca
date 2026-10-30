# 技术选型

选型以百万域名、千级节点、多租户事务、长连接和高吞吐分析为约束，同时优先复用当前仓库已验证的契约与运行手册。

## Backend

| 方案 | 优点 | 代价 | 结论 |
| --- | --- | --- | --- |
| Go | 部署为静态二进制；并发、gRPC、运维工具和团队经验匹配；启动快 | 泛型/错误建模需要规范；复杂领域需自建约束 | 选择：control-api、agent-gateway、edge-agent |
| Rust | 内存安全和性能强；适合极限数据面 | 开发周期、生态和招聘成本更高；业务迭代慢 | 保留在性能证明充分的独立组件评估 |
| Java | 生态成熟、事务和观测丰富 | 运行时资源、镜像和长连接运维更重 | 不作为首选；已有 Java 生态接入时通过 API 集成 |

Go 模块化单体先承载控制面，Gateway 和 Agent 独立进程以隔离 mTLS/长连接/特权边界。

## Frontend

React 19 + TypeScript + Vite + React Router + TanStack Query + Zustand + Ant Design + ECharts 已与仓库现有实现对齐，组件生态和测试路径完整。Vue 3 的模板体验优秀，但会引入第二套状态/组件约定并偏离现有实现。因此选择 React；通过 i18next、路由元数据和设计令牌保持中文首发及国际化。

## Database

选择 PostgreSQL。它提供事务、行级安全、JSONB、成熟的复制/PITR、约束和扩展，适合租户、RBAC、配置版本、账本和审计事实。MySQL 也成熟且运维广泛，但在本项目需要的 RLS、复杂约束和统一生态上收益较小。Redis 只作可丢失缓存/协调，不能替代 PostgreSQL。

## Analytics

选择 ClickHouse 保存访问日志、安全事件、聚合和结算输入。列式存储、压缩、TTL、物化视图和高吞吐聚合更适合百万域名的时间序列与排行。Elasticsearch 适合全文检索和日志探索，但索引/副本成本与映射运维更高；需要全文能力时可通过独立投影评估，不把它作为控制面事实源。

## Message Queue

选择 NATS JetStream。它提供轻量部署、低延迟、持久 stream、consumer、PubAck 和请求/事件统一模型，适配 outbox、Agent 命令、心跳和遥测。Kafka 在超大吞吐和生态上更强，但分区运维和资源成本更高；RabbitMQ 的路由与传统队列优秀，但长期重放和多团队事件契约不如 JetStream 简洁。若压测证明跨地域吞吐或生态接入成为瓶颈，再用 ADR 评估 Kafka，不改变领域事件 envelope。

## 基础设施与契约

本地 Docker Compose，生产 Kubernetes + Helm；OpenAPI、protobuf 和事件 schema 版本化，生成客户端和契约测试纳入 CI。OpenTelemetry、Prometheus、结构化日志和 SBOM 是所有服务的共同基础，而非某一语言的附加特性。

## AI 运维兼容性

事件 envelope、ClickHouse 原始事件、Prometheus 指标、审计原因码和配置版本都保留来源、时间、租户和算法版本，使异常检测、调度优化和安全策略生成可以离线训练、在线建议、人工确认、审计和回滚。AI 不能绕过 RBAC、发布状态机或边缘安全边界。

## 选型决策表

| 层 | 最终选择 | 主要理由 | 触发重新评估的证据 |
| --- | --- | --- | --- |
| 控制面/Agent | Go | 静态制品、低启动成本、并发和 gRPC 生态统一 | P99、内存或安全隔离长期不达标 |
| Web | React + TypeScript | 已有应用、Ant Design、Query、i18next 和浏览器测试可复用 | 页面团队或性能数据证明第二套前端更划算 |
| 事务库 | PostgreSQL | 事务、RLS、JSONB、约束、PITR 和生态完整 | 租户规模、写入锁竞争或运维成本出现明确瓶颈 |
| 分析库 | ClickHouse | 时间序列、聚合、压缩、TTL 和高吞吐写入 | 全文检索成为主要查询或 ClickHouse 查询成本超目标 |
| 消息 | NATS JetStream | 低延迟、持久 stream、PubAck、请求和事件统一 | 跨地域吞吐或生态接入经压测证明需要 Kafka |

选择不等于永久绑定。重新评估必须提供可复现的负载、故障注入或总成本对照，至少比较吞吐、P99、资源成本、运维复杂度、数据恢复和失败模式；在证据不足时保持当前方案。

## 不采用方案的边界

Rust 可用于经过基准证明的极端性能或强隔离组件，但不能为了语言偏好拆散控制面。Java 可通过 API/Webhook 接入既有企业系统，但不引入第二套核心控制面运行时。MySQL 可用于外部客户现有数据迁移的读取源，不能替代主控制面的租户和审计事实。Elasticsearch 可作为独立搜索投影，不能作为账单、权限或配置事实源。Kafka/RabbitMQ 只有在容量和运维证据满足 ADR 门槛后才能引入。
