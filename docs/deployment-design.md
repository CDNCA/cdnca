# 部署方案设计

## 1. 拓扑

```text
Ingress/LB -> apps/web, apps/operator-console
           -> control-api replicas -> PostgreSQL HA / Redis / NATS JetStream
                                  -> ClickHouse writer/query
                                  -> license-service (独立信任域)
NATS -> agent-gateway replicas == mTLS gRPC == edge-agent -> OpenResty/nftables
```

控制面和边缘数据面独立发布。边缘节点保存当前/上一健康版本和 journal；控制面、数据库、Gateway 或消息系统中断不能删除已激活版本。

## 2. Docker Compose 开发环境

Compose 提供 web、operator-console、control-api、agent-gateway、PostgreSQL、Redis、ClickHouse、NATS JetStream、OTel Collector 和 Prometheus。所有端口默认只绑定 loopback；开发密钥由 `.env`/临时 Secret 注入，不提交真实凭据。迁移显式执行，健康检查通过后再启动依赖服务。

使用独立 Linux VM 或容器模拟 edge-agent，挂载临时 release、证书和防火墙 mock。Compose 只用于开发和契约测试，不代表 HA 能力；测试数据、NATS stream 和 Redis key 必须带任务前缀并在结束时清理。

## 3. Kubernetes 生产环境

以 Helm 管理 namespace、NetworkPolicy、ServiceAccount、ConfigMap、Secret 引用、PodDisruptionBudget、HPA、拓扑分布和迁移 Job。control-api、operator-console、license-service、agent-gateway 均为无状态 Deployment；Gateway 按连接数和 CPU 扩容，优雅排空后再终止。

入口使用受管 TLS、WAF/限流和审计。control-api readiness 只在数据库迁移兼容、Redis/NATS 必需依赖和内部 gRPC 健康满足时为 Ready；liveness 不应因短暂外部 provider 故障重启进程。发布采用分批 rollout、镜像摘要锁定和自动回滚。

## 4. 数据库、Redis、消息与分析

PostgreSQL 生产使用 HA operator、同步副本/PITR、异机备份、加密磁盘和独立迁移账户。Redis 使用哨兵或托管 failover，只保存可重建 TTL 状态；丢失后在线状态进入 `unknown`。NATS JetStream 至少三节点、跨故障域、副本数与最长离线窗口匹配，预创建 stream/consumer，监控 lag 和 DLQ。ClickHouse 使用副本、分区、TTL 和备份；摄取缺口禁止封账。

## 5. CDN 节点部署

节点安装器验证签名、版本、OS/架构、依赖和回滚包，生成本地密钥并通过 enrollment 注册。systemd 以最小权限运行 edge-agent；Agent 管理 OpenResty、证书、缓存、nftables/ipset 和不可变 release。配置发布流程固定为生成、校验、分发、预检、原子激活、健康确认、失败回滚。节点不暴露数据库、Redis、NATS 凭据。

节点升级按节点组灰度，先 canary 再扩批；控制面或 Gateway 不可用时保留现行流量。节点组、容量、区域和版本兼容性写入发布策略，失败节点自动摘除并保留现场日志/版本供审计。

## 6. 备份、恢复与灾难演练

PostgreSQL 做 PITR、逻辑导出和定期恢复演练；ClickHouse、NATS、配置制品、签名公钥和审计检查点分别备份。恢复顺序为基础设施、数据库/迁移、消息流、控制 API、Gateway、节点对账；不把 Redis 恢复当作业务事实恢复。RPO/RTO、备份加密、保留期和恢复责任写入运行手册。

## 7. 观测与发布门禁

所有服务输出结构化日志、指标和 trace；门禁检查镜像 digest、SBOM、漏洞策略、迁移兼容、契约测试、健康探针和回滚包。发布记录 source commit、制品哈希、数据库迁移、current/previous、服务重启次数、关键入口检查和回滚状态。无法取得完整证据时发布状态为未知，不宣称成功。

## 8. 环境分层

| 环境 | 用途 | 数据 | 发布方式 | 允许的证据 |
| --- | --- | --- | --- | --- |
| Local | 开发和契约测试 | 临时、无客户数据 | Compose、任务专属 project | 单机功能和契约，不代表 HA |
| Test cluster | 四机联调、节点故障注入 | 可清理测试数据 | 精确 release、分阶段部署 | 跨主机连接、mTLS、心跳、发布回滚 |
| Production | 客户业务 | 受管控真实数据 | 镜像摘要、灰度、发布锁 | 生产入口、SLO、备份恢复和回滚 |

环境变量、证书、数据库口令、Operator 会话和测试账号都必须由环境外部的 Secret Manager 或受限文件注入。部署日志只能记录变量名、版本和摘要，不能记录变量值。Local/Test 的凭据不能复用到 Production。

## 9. 扩容与容量基线

百万域名场景下，控制 API 采用无状态副本；数据库按租户/时间/索引设计并通过读副本承担查询；分析事件批量进入 ClickHouse；Gateway 按活跃 Agent 会话、发送队列长度和 NATS lag 扩容。每个组件必须设连接池、队列、请求体、并发、磁盘和内存上限。

容量验收至少覆盖：千级节点心跳洪峰、百万域名索引查询、配置发布高峰、NATS 重放、ClickHouse 延迟、数据库故障切换和一半 Gateway 副本退出。指标应记录吞吐、P50/P95/P99、队列延迟、错误率、资源消耗和恢复时间，达到目标前不得宣称生产级容量。

## 10. 发布与回滚操作

发布负责人先锁定 source commit 和 release manifest，验证树、文件哈希、架构、SBOM 和签名；再读取目标主机 current/previous、systemd ExecStart、磁盘和健康状态。Web、Control API、Gateway、迁移和 Agent 包有依赖时必须作为一个候选一起验证。

切换使用同文件系统原子指针，保留失败 release 和日志。readiness、关键 API、节点心跳或业务对账失败时立即切换 previous；回滚后再次验证版本、数据库兼容、边缘流量和告警恢复。只有 source、制品、current/previous 和运行状态全部一致，发布记录才是完成。
