# ClickHouse 可观测数据存储运行手册

## 范围与当前边界

本切片提供访问事件、安全事件、小时统计视图，以及 `control-api/internal/analytics`
中的批量写入、`summary`、`trend`、`top` 查询和 JetStream durable pull 摄取内核。
摄取 runtime 已接入 `control-api` main，但默认关闭；Edge spool、Gateway 到 NATS 的
发布桥、汇总/排行 API 和 access/security raw-event API 已有真实接线。当前 wire 仍缺
authoritative source：signed manifest、EdgeConfig 和 OpenResty 没有生成 `task_id`、JA4、
独立 origin timing 及四类受控 capture。downstream publication、Gateway、control、002 raw
列和查询已经接收这些字段，但 source audit 仍有 19 项 RED；异步导出也未实现，因此不能
关闭 `OBS-11` 或声称完整可观测闭环。精确 handoff 见
`docs/runbooks/analytics-wire-red-handoff.md`。

高基数访问和安全明细只进入 ClickHouse。PostgreSQL 不保存这些明细，也不把
ClickHouse 查询结果直接当作资金、套餐或配额事实。结算仍需独立的 watermark、
输入摘要和 PostgreSQL 事务化账本。

## 表与口径

迁移位于 `infra/clickhouse/migrations`。执行迁移前必须显式选择目标数据库；SQL
本身不切换数据库。原生安装和升级经 `configure-clickhouse.py` 按序执行并记入
`schema_migrations` 账本（见 `native-install-runtime-contract.md`）；compose、Helm 和外部 ClickHouse
用同规则的迁移 Job，见 `clickhouse-migrate-deploy.md`；已发布迁移只能
追加、不能修改，新迁移必须可安全重跑。

| 对象 | 用途 | 分区与排序 | 保留期 |
| --- | --- | --- | --- |
| `access_events` | HTTP 访问明细 | UTC 月分区；`(tenant_id, event_id)` | 30 天 |
| `security_events` | WAF、CC、ACL 等安全明细 | UTC 月分区；`(tenant_id, event_id)` | 90 天 |
| `access_hourly_v1` | 请求、上下行流量、平均带宽、状态码 | 从去重后的访问明细按 UTC 小时聚合 | 跟随明细 |
| `security_hourly_v1` | 安全事件、动作和流量 | 从去重后的安全明细按 UTC 小时聚合 | 跟随明细 |

口径版本固定为 `metric_version=1`，表约束拒绝其他版本。v1 定义：

- `request_count` 是去重后的访问事件数。
- `total_bytes = request_bytes + response_bytes`。
- 带宽只使用下行 `response_bytes`；趋势为 `response_bytes * 8 / 3600`，汇总为
  `response_bytes * 8 / 查询秒数`，单位 bit/s。
- `status_2xx` 至 `status_5xx` 按 HTTP 状态码百位计数。
- 字节列使用 `UInt64`，JSONEachRow 的负数输入会被拒绝。
- 查询窗口为左闭右开，必须按整点对齐，最长 31 天。所有小时均为 UTC，展示层
  再按 locale 和用户时区转换。

当前小时视图是从 `ReplacingMergeTree FINAL` 读取的普通视图。这样可以在跨批重放
时保持正确结果，代价是查询仍会扫描明细。不要改成直接累加的物化视图，否则同一
事件以不同批次重放时会重复计量。只有容量测试证明事件级去重和物化聚合能同时成立
后，才可通过新迁移替换。

## JetStream 摄取契约 v1

发布 subject 只能是 `cdnca.analytics.ingest.v1.<node_uuid>`。`<node_uuid>` 必须是
非零 UUID，且必须与 envelope 和每个事件的 `node_id` 一致。发布者必须同时设置
`Nats-Msg-Id`，其值必须与 envelope 的 `message_id` 完全一致；前缀、schema 和事件
类型均不可由部署配置改写。`Nats-Msg-Id` 与五个 `Cdnca-*` authority header 都必须
只出现一次；缺失、重复、空白、非法格式或与 payload 不一致时，消息不得写入 raw 表。

访问事件示例：

```json
{
  "schema_version": 1,
  "type": "access.v1",
  "message_id": "node-batch-000001",
  "produced_at": "2026-07-22T10:00:05Z",
  "tenant_id": "10000000-0000-4000-8000-000000000001",
  "node_id": "30000000-0000-4000-8000-000000000001",
  "events": [{
    "metric_version": 1,
    "event_id": "request-000001",
    "occurred_at": "2026-07-22T10:00:00Z",
    "tenant_id": "10000000-0000-4000-8000-000000000001",
    "site_id": "20000000-0000-4000-8000-000000000001",
    "node_id": "30000000-0000-4000-8000-000000000001",
    "host": "example.test",
    "path": "/asset.js",
    "client_ip": "2001:db8::1",
    "method": "GET",
    "protocol": "HTTP/2",
    "cache_status": "HIT",
    "status_code": 200,
    "request_bytes": 320,
    "response_bytes": 4096,
    "duration_us": 1200
  }]
}
```

安全事件使用相同外层字段，`type` 为 `security.v1`，事件体把访问协议字段替换为
`event_type`、`action`、`severity` 和可选 `rule_id`；仍必须包含作用域、host、path、
client IP、status 和非负字节数。v1 还严格定义可选 task/JA4/timing 和四类 capture；
Gateway 递归拒绝 unknown/duplicate key、越界内容和未脱敏敏感名，不能静默放宽 decoder。

解码器拒绝未知字段、任意嵌套层级的重复 JSON key、trailing JSON、非 UTC 时间、
无效/跨租户/跨节点声明和批内重复 `(tenant_id,event_id)`。硬边界如下：

| 边界 | v1 值 |
| --- | --- |
| 单条 NATS payload | 1 MiB |
| 每个 envelope 事件数 | 1 至 1000 |
| `message_id`、`event_id` | 1 至 128 bytes；仅字母、数字、`.`、`_`、`:`、`-` |
| host / path / IP | host 253 bytes；path 4096 bytes；IP 必须可解析 |
| 其他字符串 | 各字段上限为 8 至 128 bytes，禁止首尾空白 |
| 时间偏差 | `produced_at` 和事件不得晚于当前 UTC 5 分钟；事件不得晚于生产时间 5 分钟 |
| 迟到上限 | access 30 天、security 90 天；以当前 UTC 计算，TTL 外事件直接隔离 |

## Stream、consumer 与隔离流

默认契约如下。生产必须把副本数设为 3 并在三个故障域验证；代码默认 1 只服务本地
单节点环境。

| 对象 | 默认配置 | 目的 |
| --- | --- | --- |
| `ANALYTICS_INGEST_V1` | WorkQueue、file storage、无基于年龄的自动删除、10 GiB、1000 万消息、1 MiB/消息、10m duplicate window | 有界保存未确认 telemetry；达到消息数或字节上限后以 `DiscardNew` 拒绝新消息，producer 必须保留并重试 |
| `control_api_analytics_ingest_v1` | durable pull、explicit ack、`AckWait=2m`、broker `MaxDeliver=-1` | 重启后从同一 durable 恢复；writer 故障不得被 broker 投递次数上限丢弃 |
| consumer pull 边界 | `FetchBatch=32`、`MaxAckPending=256`、`MaxWaiting=16`、fetch 2s | 单循环 fetch 形成自然 backpressure，不无界启动 goroutine |
| 单次操作 | ClickHouse/NATS operation 10s；NAK 1s 起、指数退避、最大 2m | 每次外部操作和退避都有限 |
| `ANALYTICS_ISOLATION_V1` | Limits、file storage、30d、1 GiB、固定 subject | 保存无 payload 的严格解码 poison 审计记录 |

启动时 `EnsureIngestJetStream` 只创建缺失对象；已存在 stream/consumer 的全部有效配置
都必须精确匹配，包括 source、transform、republish、per-subject 限额、payload、delivery、
ack 和 backoff 字段。只忽略 description、metadata、template 和 consumer 的服务端 name；
其他漂移一律 fail closed，不静默改写生产流。
扩容前按峰值重新计算 stream 的 `MaxBytes`、`MaxMsgs`，并为容量逼近、publish reject、
producer backlog 和最老未确认消息年龄建立告警。默认 `MaxAge=0`，因此不存在隐含的
72 小时淘汰或 RPO 承诺；若未来引入非零 MaxAge，必须重新冻结契约并验证数据丢失告警。

Connections telemetry 使用独立且同样 fail-closed 的 JetStream 拓扑。`control-api` 在绑定
subscriber 前创建缺失对象，或逐字段验证已有对象；不会静默更新漂移配置：

| 对象 | 固定合同 |
| --- | --- |
| `CONNECTIONS_INGEST_V1` | WorkQueue、`cdnca.connections.v1.*.*`、file storage、`DiscardNew`、2 GiB、100 万消息、64 KiB/消息、每 subject 1 条、10m duplicate window |
| `control_api_connections` | durable pull、explicit ack、`AckWait=30s`、`MaxDeliver=8`、`BackOff=[30s,1m,2m,5m,10m,15m,30m,1h]`、`MaxAckPending=256`、`MaxWaiting=16` |
| `CONNECTIONS_DEAD_V1` | Limits、`cdnca.connections.dead.v1`、file storage、`DiscardNew`、30d、1 GiB、100 万消息、8 KiB/消息、24h duplicate window |

投递次数和 stream/consumer sequence 只能来自 JetStream metadata，进程配置、header 和
payload 均不得覆盖。永久 poison 或达到 `MaxDeliver=8` 的消息必须先发布脱敏且有界的
DLQ evidence，验证真实 DLQ PubAck 后才可对原消息执行 `Term`；DLQ publish/PubAck
不确定时不得 ACK 或 Term。启动阶段无法创建对象、读取配置或发现任意 drift 时直接
fail closed，错误不得包含 NATS URL、credentials、payload、header 或底层错误文本。

## control-api 摄取运行时

`control-api` 已正式接入 `BuildIngestRuntime`，但默认
`ANALYTICS_INGEST_ENABLED=false`。关闭时不读取其他摄取变量、不连接 NATS 或
ClickHouse，也不创建 stream/consumer。启用后，进程监听 HTTP 前必须依次完成 NATS
连接、ClickHouse ingest schema/权限确认、JetStream 契约核验和 durable consumer 绑定；
任一步失败均 fail closed。schema gate 精确比较两张事件表的列顺序、类型和
`default_kind`，并分别执行不写业务行的空 `JSONEachRow INSERT`，确保运行身份确实拥有
写权限；仅有 `SELECT 1` 权限不能通过启动检查。

连接与监督配置如下。凭据只允许由运行时 Secret 注入；URL 禁止 userinfo、query、
fragment 和多 server 列表。跨主机 NATS 必须使用 `tls://`，`nats://` 只允许 loopback；
跨主机 ClickHouse 必须使用 HTTPS，HTTP 只允许 loopback。

| 环境变量 | 默认值 | 约束 |
| --- | --- | --- |
| `ANALYTICS_INGEST_ENABLED` | `false` | 只有 `true` 时构造并运行摄取 runtime |
| `ANALYTICS_INGEST_NATS_URL` | 无 | 单一安全 URL；禁止 credentials/path/query/fragment |
| `ANALYTICS_INGEST_NATS_USER` / `ANALYTICS_INGEST_NATS_PASSWORD` | 空 | 必须同时为空或同时有效；禁止控制字符，密码不写日志 |
| `ANALYTICS_INGEST_CLICKHOUSE_URL` | 无 | HTTPS 或 loopback HTTP；只能使用根 path |
| `ANALYTICS_INGEST_CLICKHOUSE_DATABASE` | 无 | ClickHouse identifier，最长 64 bytes |
| `ANALYTICS_INGEST_CLICKHOUSE_USER` / `ANALYTICS_INGEST_CLICKHOUSE_PASSWORD` | 无 | 必填 Secret；禁止控制字符，密码最长 4096 bytes |
| `ANALYTICS_INGEST_CONNECT_TIMEOUT` | `3s` | `100ms` 至 `30s`；同时约束启动确认 |
| `ANALYTICS_INGEST_WRITE_TIMEOUT` | `2s` | `100ms` 至 operation timeout |
| `ANALYTICS_INGEST_SUPERVISOR_BACKOFF_MIN` / `MAX` | `1s` / `1m` | 最小不低于 `100ms`，最大不超过 `5m` |

JetStream 配置入口均使用 `ANALYTICS_INGEST_` 前缀：`STREAM`、`DURABLE`、
`ISOLATION_STREAM`、`ACK_WAIT`、`FETCH_TIMEOUT`、`OPERATION_TIMEOUT`、
`NAK_BASE_DELAY`、`NAK_MAX_DELAY`、`MAX_DELIVER`、`MAX_ACK_PENDING`、`MAX_WAITING`、
`FETCH_BATCH`、`STREAM_MAX_AGE`、`STREAM_MAX_BYTES`、`STREAM_MAX_MESSAGES`、
`ISOLATION_MAX_AGE`、`ISOLATION_MAX_BYTES`、`DUPLICATE_WINDOW` 和 `REPLICAS`。
未设置时采用上表“默认契约”；只有进程接线的 operation timeout 默认为 `3s`，以确保
单次取消 settlement 小于当前 `10s` 主进程停机预算。生产三副本必须显式设置
`ANALYTICS_INGEST_REPLICAS=3`。

`ANALYTICS_INGEST_MAX_DELIVER` 不配置 broker 投递上限；broker 固定为 `-1`。该值只在
严格解码 poison 已确认、但 isolation sink 连续失败时充当应用侧终止边界，防止一条
无法保存隔离证据的坏消息永久阻塞 WorkQueue。writer 失败不使用这个边界。

运行中 NATS 或 ClickHouse 故障只把 ingest 标记为 `degraded`，记录稳定错误类别、
累计 `restart_count` 和下一次退避，不退出 `control-api`，也不改变 `/health/ready`；
未确认消息继续保留在原 durable backlog。`GET /health/detail` 只返回
`enabled/state/restart_count`，不返回 URL、原始依赖错误、tenant/site/event 或 payload。
恢复后 supervisor 继续使用同一 runtime 和 durable；退避在 `MIN` 与 `MAX` 之间指数
增长，worker 不会静默永久退出或忙循环。

停机顺序固定为：取消主 context 停止 fetch/取消 ClickHouse 写入，等待已领取批次完成
ACK/NAK/Term settlement，再关闭 consumer、drain/关闭 NATS，最后关闭 ClickHouse HTTP
idle connections。`CloseContext` 复用主 shutdown context 的剩余时间，并取其与 runtime
上限中的较短者，不得在主停机预算后再追加一轮完整 timeout。consumer settlement 仍以
ClickHouse 成功响应和 `AckSync` 成功为唯一已确认条件；取消、timeout 或不确定响应不得
假 ACK。

## 写入与幂等

Agent 必须生成跨重试稳定的 `event_id`，并且重试时保持 `tenant_id`、`occurred_at`
和事件内容不变。Gateway 后续发布时也必须保持 `message_id`、`Nats-Msg-Id` 和原始
payload 字节稳定。consumer 把同类型 envelope 合并到最多 1000 个事件的 JSONEachRow
写入，只有 ClickHouse 成功返回后才能确认对应 JetStream 消息。

幂等有两层：

1. consumer 对排序后的 `(message_id,SHA-256(payload))` 生成确定性
   `insert_deduplication_token`；相同 fetch 组合不受投递顺序影响。
2. 原始表按 `(tenant_id, event_id)` 使用 `ReplacingMergeTree`；小时视图使用 `FINAL`，
   防止同一事件跨批重放后重复统计。

同一 `message_id` 在同一 fetch 中绑定不同摘要会被隔离。跨重启或不同 fetch 组成会
产生不同 block token，因此可能留下重复物理行；查询必须保留 `FINAL`，逻辑统计才只
计一次。`non_replicated_deduplication_window=10000` 只服务本地单节点开发。生产复制
表必须由单独迁移配置 Keeper、复制路径和足以覆盖 NATS 重放窗口的 block 去重设置，
不能把本地窗口当作永久唯一约束。

每批默认最多 1000 个事件、8 MiB JSON；包内还拒绝批内重复事件 ID、非 UTC 时间、
空作用域 ID、非 v1 口径和越界字符串。凭据只放在进程环境或受管 secret 中，禁止放进
URL、日志、错误、trace 或批次内容。

## ACK、重试与 poison 处置

| 情况 | 处置 | 队列结果 |
| --- | --- | --- |
| ClickHouse 明确成功 | 对批内每条消息执行 `AckSync` | 只有服务器确认 ACK 后才移出 WorkQueue |
| 任意 ClickHouse HTTP、timeout、transport、响应超限或不确定错误 | `NakWithDelay`，按投递次数做有上限的指数退避 | 保持原消息；包括 400/401/403/404/413，修复 schema、权限或路由后原消息仍可恢复 |
| 严格解码失败 | isolation audit 成功后 `Term` | 已确认无法通过当前 v1 decoder 的 poison 不阻塞后续消息 |
| isolation sink 暂时失败 | 未到应用侧 `MaxDeliver` 时 NAK | 优先保住隔离证据并重试 |
| isolation sink 到应用侧边界仍失败 | 记录无 payload 错误并 `Term` | 队列不永久阻塞，但隔离审计有缺口，必须告警 |
| runtime context 取消 | 在有界 settlement context 内 NAK 已领取且未写成功的消息 | 重启后由同一 durable 重投；资源关闭不得超出主 shutdown 总预算 |

隔离记录只包含 reason、合法 message ID、subject、payload SHA-256/大小、投递次数、
stream sequence 和隔离时间，不保存原 payload。日志也只允许稳定错误类别和计数，
不能记录 ClickHouse/NATS 原始错误、URL userinfo、请求体或事件字段。

consumer 重启必须绑定原 stream/durable，不能创建新的 durable 跳过积压。正常停机先
取消 worker、等待已领取批次完成 ACK/NAK/Term，再关闭 subscription 和 NATS 连接。
如果 `NumAckPending` 长时间接近 `MaxAckPending`，先查 ClickHouse 写入 p95 和 NAK 次数，
不要盲目增加 fetch 并发；批量上限与 `MaxAckPending` 是内存和故障放大的硬边界。

## 容量估算与扩容阈值

分别对访问和安全事件估算，不用本 smoke 的高重复合成数据压缩率外推生产：

```text
daily_rows = peak_events_per_second * 86400
retained_bytes = daily_rows * retention_days * measured_compressed_bytes_per_row
required_disk = retained_bytes * replica_count * 1.30
```

`measured_compressed_bytes_per_row` 必须来自脱敏后的真实字段分布，包含高基数 path、
event ID、IP 和 trace ID。30% 余量覆盖 merge、mutation、备份暂存和流量波动。按峰值
同时记录批写 p95、parts 数、merge backlog、磁盘吞吐、查询 p95/p99 和 `FINAL`
扫描行数。

满足任一条件即停止只加机器并重新评估分片/预聚合设计：

- 任一副本磁盘持续超过 70%，或预计在一个采购周期内超过 70%。
- 后台 merge 持续 15 分钟追不上写入，inactive parts 或 mutation backlog 连续增长。
- 31 天租户查询 p95 超过 3 秒，或固定首页窗口查询 p95 超过 1 秒。
- 单分片峰值写入 p95 超过 2 秒，导致 JetStream consumer lag 连续增长。

本地回归命令：

```sh
./infra/clickhouse/analytics-smoke.sh
```

默认写入 100000 条确定性容量事件，验证 up/down/up、批次和事件级幂等、小时对账、
负数字节拒绝、TTL merge、容量查询、压缩占用与 task 数据库清理。可用
`ANALYTICS_SMOKE_ROWS` 和 `ANALYTICS_SMOKE_MAX_SECONDS` 提高规模或收紧门槛。

摄取生命周期回归命令：

```sh
./infra/clickhouse/analytics-ingest-smoke.sh
```

它创建 task-owned ClickHouse database、ingest stream、durable consumer 和 isolation
stream，注入一次“ClickHouse 已提交但代理返回 503”的不确定结果，关闭并重建 runtime，
验证重投最终只计一次、poison 隔离、8 条积压按 4 条 fetch 上限排空，最后删除所有
task-owned 资源。脚本只消费现有本地开发环境注入的凭据，不输出凭据。

正式进程接线 smoke：

```sh
./infra/clickhouse/analytics-ingest-runtime-smoke.sh
```

该脚本调用 `cmd/control-api` 的正式 `openAnalyticsIngestRuntime`，并通过 `config.Load`
验证生产同名配置。它使用唯一 task-owned database/stream/durable/isolation stream，覆盖
启动期 ClickHouse 不可用 fail closed、access/security 摄取、提交后 503 的重启重投与
幂等、poison 隔离、ClickHouse 不可用期间 backlog 保留及恢复、写入中的优雅取消，并对
最终 summary 和 URL/IP/域名/地区/运营商五类排行逐项对账。结束时只删除本次 task-owned
资源，不删除共享 database、stream 或 consumer。

## TTL 与迟到数据

TTL 以事件的 UTC `occurred_at` 计算，不以摄取时间续命。ClickHouse 在 part merge 时
执行删除，因此过期行不会保证在 TTL 时刻立即消失。监控最老 active part、TTL mutation
和磁盘回收速度；不要用高频 `OPTIMIZE FINAL` 代替正常 merge。

迟到事件在解码时若已经超过明细 TTL 会被隔离；恰好位于边界的事件仍可能在写入后
立即进入 ClickHouse TTL 删除范围。consumer 仍需推进独立的 ingest watermark，并
记录最早/最晚事件时间、最后成功消息摘要和 NATS sequence。封账窗口必须早于已确认
watermark；晚于封账的有效事件走追加调整，不能改写历史账本。

## 查询超时、响应上限与熔断

包内 ClickHouse client 默认查询超时 5 秒、写入超时 10 秒、解码上限 4 MiB；外部
analytics-log HTTP handler 默认和硬上限均为 1 MiB，允许配置得更小。调用方取消会直接
取消 ClickHouse HTTP 请求。排行最多 100 条，数据库、租户、站点、节点、时间和 limit 都
使用 ClickHouse 参数，不拼入 SQL。任何超时、5xx、429、超限或坏 JSON 都返回错误，
上层不得把它转换为“0 流量”。

HTTP API 接入时由 analytics 调用层持有熔断器，不在无状态存储客户端内隐藏全局状态。
初始策略为：连续 5 次可重试失败后打开 30 秒，半开只允许 1 个探测；成功关闭，失败
重新打开。4xx 参数错误不计入熔断。熔断只影响新分析查询/写入尝试，不影响边缘请求；
写入由 JetStream 留存并退避重试，查询返回带 request ID 的“数据暂不可用”。多副本
control-api 必须导出每实例 breaker 状态和总失败率，避免单实例状态掩盖集群故障。

## 数据延迟与告警

必须同时发布以下指标，不能只看 ClickHouse 可连通性：

副本指标 `cdnca_clickhouse_replica_alert_status` 的值为 `0=healthy`、`1=firing`、
`2=source unavailable`、`3=replication capability unsupported`。值 `3` 表示 ClickHouse
可访问但当前数据库使用普通 `MergeTree`、没有 `system.replicas` 行；它不伪造副本健康，
也不应在本地单节点开发环境触发存储故障告警。生产复制部署仍必须提供 `system.replicas`
证据并对 `1`/`2` 建立告警。

- `analytics_ingest_lag_seconds`：当前时间减最后持久化事件的摄取时间。
- `analytics_event_lag_seconds`：最后持久化事件的摄取时间减事件时间，区分迟到数据。
- `analytics_consumer_lag_messages` 和最老未确认消息年龄。
- 每批行数、字节、耗时、重试次数、拒绝原因和最后成功 batch ID 的不可逆摘要。
- 查询耗时、扫描行/字节、超时、超限、熔断状态和按 scope 类型区分的错误率。

建议 ingest lag 超过 60 秒告警，超过 5 分钟把 UI/结算标记为 stale；stream 容量、
publish reject、producer backlog 和最老未确认消息年龄必须同步告警。poison isolation
写入达到应用侧边界仍失败、stream `DiscardNew` 拒绝和 sequence 缺口均为 paging 告警。
阈值最终必须按 JetStream 容量和业务 SLO 校准。延迟状态必须随 summary/trend/top API 返回，不能让旧数据
看起来像当前零流量。

## 备份与恢复

生产使用 ClickHouse `BACKUP` 到启用版本、服务端加密和不可变保留的对象存储；访问
凭据由 ClickHouse named collection 或 secret 注入，不写在 SQL、脚本或备份日志中。
至少备份两张原始表、DDL、Keeper 元数据和备份清单。小时视图可由原始事件重建，仍需
把对应 DDL 版本记录在清单中。

每月至少在隔离集群执行一次恢复演练：恢复到新数据库，校验行数、`uniq(event_id)`、
时间范围、分区数、小时总量/状态码和抽样事件摘要，再运行固定查询。恢复完成前，相关
时间窗保持“数据不完整”，禁止封账。NATS 的重放范围与 ClickHouse 备份点分别记录；
若两者之间存在不可恢复缺口，创建明确的数据缺口事件和人工处理记录。

## 故障处理

1. 先确认 ClickHouse health、磁盘、parts、merge/mutation 和查询队列，再看 consumer lag。
2. 写入 429/5xx/超时保持原 `message_id`、`Nats-Msg-Id` 和 payload 重试；consumer
   依据实际合批组成重新计算确定性 token，不能让同一 message ID 绑定不同内容。
3. 查询故障返回不可用，不返回缓存外的猜测值。确认 tenant/site/node 参数仍在请求中。
4. 恢复后从最早未确认 JetStream sequence 重放，按 raw `FINAL`、小时视图、consumer
   pending/ack floor 和 isolation sequence 对账。
5. producer 重试边界耗尽或发现 NATS sequence 缺口时停止受影响窗口的结算，登记缺口范围；不得手工补写虚构事件。

## 本轮未解决边界

- Edge/Gateway/NATS 与 NATS/control-api/ClickHouse/API 两个真实分段已分别通过 smoke，
  但尚未用同一消息身份贯穿证明。`installation_id` 已由 authoritative NATS header 覆盖
  payload，002 raw 也有 task/capture/JA4/timing 列；EdgeConfig/OpenResty source 仍缺九类
  字段，且空 capture presence 会被折叠，因此完整单链仍是 RED。
- Prometheus/OpenTelemetry 指标、跨 Gateway/NATS/ClickHouse trace 关联和告警规则尚未接线，
  因此 `OBS-10` 仍是 partial。
- 生产三副本 JetStream、Keeper/复制 ClickHouse、跨机断网、stream 满载淘汰、备份恢复和
  更大真实字段分布容量测试尚未完成，因此 `OBS-11` 仍是 partial。
- raw access/block HTTP API、中文 UI 及 URL/IP/域名/地区/运营商排行已实现并有 focused
  证据；JA4/timing/capture downstream 契约存在但 source 未闭合，异步下载、watermark 和事务化结算账本仍未实现，
  `OBS-01` 仍不能关闭。
