# 边缘缓存刷新与预热执行内核

状态：已实现并验证节点本地执行内核；**CACHE-03 尚未闭环**。

## 当前范围

本切片包含 `agents/edge-agent/internal/cachetask` 的 schema v2 执行器、共享 OpenResty
renderer 接线，以及 `edge/openresty/cache` 和 `scripts/edge-cache-task-smoke.sh` 的隔离运行时验收入口。
支持：

- 精确 URL 刷新，query 按原始字节精确隔离；
- 目录前缀刷新，按路径 segment 隔离；
- 当前租户、站点和配置修订的整站刷新；
- 通过专用 loopback listener 执行 URL 预热；
- 节点本地 journal、幂等、取消、崩溃恢复、重试、退避、限流和逐项结果。

本切片没有接入 control task/outbox、NATS、protobuf、Agent Gateway、daemon command
consumer、多节点 fan-out 或控制面聚合状态。共享 OpenResty renderer 已接入 v2 缓存键，
但不能把控制面 `queued` 当作已投递，不能把本内核称为 CACHE-03 闭环，
也不能用旧 smoke/compile fixture 代替正式接线。

## Task 与可信站点上下文

执行器只接受 `schema_version=2`。调用方必须提供稳定的 task ID、operation ID、
tenant/site scope、不可变配置 version/revision、delivery attempt、deadline 和资源预算：

```json
{
  "schema_version": 2,
  "task_id": "cache-task-01",
  "operation_id": "cache-operation-01",
  "tenant_id": "tenant-01",
  "site_id": "site-01",
  "scope": "url",
  "config_version_id": "config-1042",
  "config_revision": 42,
  "delivery_attempt": 1,
  "deadline": "2026-07-23T04:00:00Z",
  "budget": {
    "max_attempts": 3,
    "max_concurrency": 2,
    "max_purge_entries": 0,
    "max_scan_entries": 0,
    "max_scan_bytes": 0,
    "max_scan_duration": 0,
    "max_total_bytes": 1073741824,
    "max_resource_bytes": 67108864,
    "requests_per_second": 10,
    "burst": 2,
    "initial_retry_backoff": 100000000,
    "maximum_retry_backoff": 2000000000
  },
  "action": "prewarm",
  "targets": ["https://www.example.com/assets/app.js?v=42"]
}
```

Go `time.Duration` 的 JSON 值以纳秒表示。action/scope 组合只能是：

| action | scope | targets |
| --- | --- | --- |
| `purge_exact` | `url` | 1 至 16 个 URL |
| `purge_prefix` | `directory` | 1 至 16 个不带 query 的 URL |
| `purge_site` | `site` | 必须为空，执行器生成一个站点结果项 |
| `prewarm` | `url` | 1 至 16 个 URL |

每个原始 target 最多 16 KiB，单 task 所有原始 target 的字节数合计最多 64 KiB；归一化、
query 脱敏后的持久化 target 同样限制为单项 16 KiB、合计 64 KiB。控制面必须把更大的用户 batch 分片为多个
独立 task/operation，不能把 1000 项当作单个边缘 task 的可用上限。

`SiteResolver` 必须从已发布、已激活的不可变配置解析精确的 tenant、site、version 和
revision。task 不能提供本地路径、cache 目录、dial 地址、源站地址、Host、凭据或任意
header。resolver 返回的 domain、scheme、public listener、专用 prewarm listener 和
cache namespace 都会再次校验；缺失、禁用、旧修订或不一致上下文在 I/O 前拒绝。

URL 必须是目标站点的绝对 HTTP/HTTPS URL，并精确匹配已发布 scheme、规范 host 和
有效 public port。拒绝 userinfo、fragment、本地路径、IP host、控制字符、空白、
反斜杠、路径回退、重复斜杠、编码 slash/backslash、重复目标和超长目标。目录刷新
`/images` 只匹配 `/images` 和 `/images/...`，不匹配 `/images-old`。

## 缓存键与磁盘边界

v2 namespace 为以下字节串的 SHA-256 小写十六进制：

```text
v2\0<tenant-id>\0<site-id>\0<config-version-id>
```

legacy `preserve + no vary` 的 OpenResty cache key 必须逐字节等于：

```text
v2|<tenant-id>|<site-id>|<config-version-id>|<host>|<public-port>|<uri>?<raw-query>
```

启用 query 投影或 vary 后，advanced key 必须逐字节等于：

```text
v2|<tenant-id>|<site-id>|<config-version-id>|<host>|<public-port>|<uri>?~q=<query-sha256>&~v=<vary-sha256>
```

启用 Range enhancement 时，public listener 不使用普通 `cdnca_cache_*` zone。Range
identity 为以下字节串 SHA-256 的前 8 字节（16 字符小写十六进制）：

```text
<tenant-id>\0<site-id>\0<domain>\0<public-port>
```

public Range cache path、zone 和 key 必须逐字节等于：

```text
<state-root>/shared/range/<range-identity>
range_cache_<range-identity>
v=<config-version-id>|policy=<range-policy-version>|tenant=<tenant-id>|site=<site-id>|slice=$slice_range|scheme=$scheme|host=$host|port=$server_port|request=$request_uri
```

Range 的内部 prewarm location 不使用 `range_cache_*`，而是继续使用该站点的普通
`<state-root>/shared/cache/<64-char-namespace>`、`cdnca_cache_*` quota zone 和 legacy
`CacheKeyPrefix + $uri$is_args$args`。因此 public Range slice identity 与 cache-task prewarm
identity 有意不同；不得把两者合并或用其中一个证明另一个。

`query-sha256` 和 `vary-sha256` 都是对有序 length frame 串的 SHA-256 小写十六进制。每个 frame
逐字节为 `<tag>:<UTF-8-byte-length>:<value>;`，长度是 `value` 的字节数，不是 rune 数。

- query 以 `schema=cdnca-cache-query-v1` 和 `mode` frame 开始。`preserve`:保留原始 `raw`，
  并区分 `state=absent|empty|present`；`include`/`exclude`:按原始顺序加入 `pair`，
  仅对 name 做一次 percent decode 以决定去留，pair 本身保留原始字节；
  `ignore`:固定 `state=ignored`，不受 query 是否存在或内容影响。
- vary 以 `schema=cdnca-cache-vary-v1` 开始，按已规范化排序的 header 名逐个加入
  `name` + `state=absent|empty|value`，只有 `value` 状态再加入原始 header `value` frame。

缓存文件位于：

```text
<state-root>/shared/cache/<64-char-namespace>/<nginx levels=1:2 MD5 layout>
```

执行器不把 URL 拼成文件路径，也不使用 glob。它只遍历已验证 namespace，限量读取
OpenResty 原生 `KEY:` metadata，并同时验证 tenant、site、version、host、
port、URI、MD5 文件名和 `levels=1:2` 布局。删除前以目录 descriptor 重新打开每一级
父目录，拒绝 symlink、hardlink、非普通文件、inode/device/size 变化，然后使用
`unlinkat` 并 fsync 父目录。异常布局整体 fail closed，不继续猜测删除。

`<state-root>/shared/cache` 必须是真实目录且精确为 `0700`。生产节点可让该目录归
OpenResty worker 所有，Agent 以 root 管理；父路径必须允许 worker 遍历。journal 与
cache 内容分离：

```text
<state-root>/state/cache-tasks/       0700
  registry.json                       0600
  tasks/<sha256(task-id)>.json        0600
  locks/                              0700
  tmp/                                0700
  tombstones/<2-hex>-<segment>.bin    0600
```

状态先写同文件系统临时文件，chmod `0600`、fsync、rename，再 fsync 父目录。启动只清理
符合固定名称的普通临时文件；异常文件或 symlink 阻断启动并保留现场。

每个 task 的 `site_binding.cache_policy_sha256` 是完整、已规范化并已填充 listener 的
`site_binding` JSON（计算时仅把 `cache_policy_sha256` 自身置为空串）的 SHA-256 小写十六进制。
摘要覆盖 active release SHA、Nginx SHA、64 字符 namespace、policy schema/query/vary/rules，
以及每个 listener 的 domain、scheme、public/prewarm port、prewarm path 和 cache-enabled 状态；
必须在 listener 数组填充完成后计算。task metadata 另行固定真实 tenant/site/config version 和
严格 revision，重启同时验证 metadata、完整 binding、namespace 派生式和摘要，任一漂移均
返回 `ErrJournalCorrupt`，不得只重算 policy 子集摘要后继续。

registry 达到容量时才执行 compaction：先为过期 task ID 和 operation ID 分别写入固定
SHA-256 tombstone，再原子缩减 registry，最后删除 task JSON 并 fsync tasks 目录。崩溃在
registry 切换前仍以 registry 为准并允许保留期内重放；切换后遗留的 task JSON 在启动时
按 registry 清理。被 tombstone 的任一 ID 返回 `ErrTaskExpired`，不会静默当作新任务执行；
tombstone 或 registry 无法保证容量时返回 `ErrTaskCapacity`。
启动、admission、Lookup 和 compaction 在读取 tombstone 正文前先用固定目录项和已打开文件的
`device/inode/size/mtime` 复核连续 segment、单 shard/全局 records 上限；替换、扩展、截断或
超限文件均 fail closed 为 `ErrJournalCorrupt`。

## 幂等、恢复与取消

registry 同时把 task ID 和 operation ID 绑定到规范 payload SHA-256。相同双 ID 和
payload 的 at-least-once 重投返回或恢复原任务；任一 ID 绑定不同 payload 都返回
`ErrConflict`。旧 delivery attempt 只重放当前记录；更新 attempt 只能推进仍在运行的
记录，终态永不重新执行。

公开结果契约同为 schema v2。journal 为 `running` 时 Result 必须返回 `StateRunning`，逐项
只可能是 `pending`、`working` 或已落盘终态；`Progress.Completed/Failed` 只累计已持久化
的终态项，`Affected/Bytes` 只报告已 checkpoint 的事实，`CompletedAt` 保持空。调用方不得
把 `running` 当作 failed/succeeded，也不得用旧 delivery attempt 推进 execution attempt。

每项在网络请求或 unlink 前写入 `working`。purge 在第一次 unlink 前额外持久化
`destructive_started`；每个实际删除还会先写入 inode/device/size delete intent。只有 unlink
和 parent-directory fsync 都确认后才累计 durable `Affected` 并清除 intent。若 unlink 已发生但
fsync 未确认，intent 保持未决；启动、Lookup、GC/compaction、重试或取消 settlement 都必须再次验证 descriptor 并 fsync，
不能把 ENOENT 直接当作成功。重启或取消 settlement 会先收敛遗留 intent；
若文件身份变化导致结果未知则失败，不假定成功。重启时：

- 已成功、跳过或失败的项保留终态；
- `pending` 继续执行；
- 有 durable delete intent 且目标 inode 已不存在时累计一次已执行删除；无 intent 的未知
  purge 结果重新扫描，已不存在的目标不虚报数量；
- 未知的 prewarm 请求按已预留的最大资源字节计入总预算，再决定是否可重试；
- journal 写失败返回错误，不返回伪成功；下一次同 payload 重投从最后一个 durable
  状态恢复。

同 namespace 的任务使用进程内锁和 OS 文件锁串行；一个 prewarm task 内的 URL 可按
预算并行；不同 namespace 可并行但仍受全局并发和速率限制。取消先验证完整 task/
operation/tenant/site 引用，再 signal 活动 context，并在 5 秒默认 settlement 上限内等待
task lock；只有所有不可中断 unlink/fsync 和计数 checkpoint 收敛后才写入/返回 cancelled。
settlement 超时返回错误，不宣称已取消。未发生 I/O 的 pending/site-lock waiter 合法返回
`Attempts=0`；终态取消可重复查询、重放和重启读取。

结果只包含稳定 code、计数、时间和脱敏 target。带 query 的 target 固定显示
`?query=redacted` 并保留 SHA-256 digest 用于关联。journal、Result 和 error 不保存
query secret、Authorization、Cookie、源站凭据或响应正文。调用方也不得把原始 task、
URL、OpenResty error log 或响应正文拼入日志。

## 预热网络边界

prewarm 不解析或连接公网 DNS。它只连接 `Config.LoopbackAddress:<published-prewarm-port>`，
默认 `127.0.0.1`，使用 HTTP GET、已发布 domain 作为 Host，并只增加
`X-CDNCA-Internal-Cache-Task: v2`。public listener 和 prewarm listener 必须不同；
prewarm port 只能绑定 loopback，不能被外部流量访问。

专用 listener 必须绕开浏览器 challenge/WAF 交互。legacy/advanced policy 的 public 与
prewarm route 复用同一普通 v2 namespace/quota zone 和相同 key 投影；Range enhancement
例外：public 使用上述 `range_cache_*` slice identity，prewarm 使用普通 namespace/quota
cache。响应必须同时满足：

- 状态码在 allowlist，默认只有 `200`；
- 只有一个 `X-CDNCA-Config-Version`，且等于精确 version；
- 只有一个 `X-CDNCA-Cache-Namespace`，且等于精确 namespace；
- 只有一个 `X-CDN-Cache`，且值为 `MISS` 或 `HIT`。

重定向一律不跟随，包括指向 loopback、RFC1918、link-local 或其他域的 Location。
Authorization、Cookie、Range、Upgrade 和调用方自定义 header 不会转发。每请求 timeout、
response header 上限、每资源字节、任务总字节、task/site/global 速率和并发同时生效。
首个 `HIT` 返回 `ALREADY_CACHED` 且记为 skipped。首个 `MISS` 只代表本次响应未命中，
不代表已写入缓存；执行器会在相同速率、并发、timeout、取消和 response/task 字节预算下
再发一个严格 loopback GET，只有第二次返回 `HIT` 才报告 `PREWARMED`。第二次仍为 MISS、
超时、重定向、状态码不允许或上下文未知时失败，不假成功。两个响应正文都只流式计入
字节预算，不写入 journal 或日志。

## 默认容量与调优

`DefaultConfig()` 的硬上限/默认值：

| 参数 | 默认值 |
| --- | ---: |
| 全局 prewarm 并发 | 8 |
| 全局请求速率 / burst | 50 请求/秒 / 8 |
| 每 namespace 请求速率 / burst | 10 请求/秒 / 2 |
| 单请求 timeout | 10 秒 |
| 单资源最大响应 | 64 MiB |
| 单任务最大响应总量 | 1 GiB |
| 单 task target 数 | 16 |
| 单 target / target 合计 | 16 KiB / 64 KiB |
| 单项最大尝试 | 5 |
| 单任务 prewarm 并发上限 | 8 |
| 单次 purge 对象上限 | 100000 |
| purge scan entry 上限 | 1000000 |
| purge scan metadata 字节上限 | 256 MiB |
| purge scan 时间上限 | 30 秒 |
| site/revision limiter 数 | 1024 |
| retained completed task low watermark | 4096 |
| registry task 硬上限 | 8192 |
| tombstone task 硬上限 | 1000000 |
| cancel settlement | 5 秒 |
| deadline 最大 horizon | 24 小时 |
| 状态文件上限 | 16 MiB |
| 单 cache metadata 读取上限 | 64 KiB |

每个 task 仍必须显式给预算。prewarm 的资源上限不得超过节点上限，总量不得小于单资源
上限；purge 必须是单并发且字节/速率预算为零，并显式提供不超过节点上限的 scan
entries/bytes/duration。legacy `preserve + no vary` 的精确 URL purge 仍由确定性 MD5 layout
O(1) 直接定位；启用 query include/exclude 或 vary 的高级策略时，同一有效 query identity
可能对应多个 header 变体，必须在该 namespace 内按固定 batch 有界扫描，匹配有效 query
identity，并在首个删除前完成包含全部变体的计划。任何 scan/layout/purge budget 失败都必须
发生在首个删除前，不能只删除一个变体后返回成功。prefix/site purge 同样用固定 64-entry
`ReadDir` batch 流式扫描并先在 `MaxPurgeEntries` 内形成有界计划。初始 backoff 为 1ms
至 1min，最大
backoff 不小于初始值且不超过 10min；指数退避在上限截断后应用注入 jitter。提高并发、
burst 或字节预算前，应按单节点源站带宽、cache 磁盘写放大和 open file 上限压测；不能
通过这些参数让任务占用边缘请求 worker 的同步控制路径。

`MaxTombstoneTasks` 的单位明确是“过期 task 数”，不是 task+operation record 数，也不是
磁盘 shard 数；每个过期 task 固定写两条 32-byte digest（task ID 和 operation ID），因此
默认最多 1000000 tasks / 2000000 records，约 61.04 MiB。启动/lookup/admission 只先用
文件名和 `stat` 证明连续 segment、单 shard 8 MiB/32-byte 对齐、全局 records 不超过
`2*MaxTombstoneTasks`，以及每个 prefix 的 segment 数和最大编号不超过
`ceil(2*MaxTombstoneTasks*32/8MiB)`；证明失败在读取 shard body 前返回 `ErrJournalCorrupt`。
默认 derived 上限为每个 prefix 8 个 segment。tombstone 不静默过期；达到上限后新 task
返回 `ErrTaskCapacity`，需由运维保留现场并升级/迁移 journal 格式，不能删除 tombstone
后重新执行旧 ID。

prewarm 的 record checkpoint 不持有跨整个 task 的全局锁；`state.lock` 只覆盖单次 atomic
write。默认 16 items、每项 5 attempts、无 GC 的 retry-exhausted 路径硬上限为：

```text
task create + registry create + terminal summary + 2 * items * attempts
= 3 + 2 * 16 * 5
= 163 atomic state writes
<= 326 file/directory fsync calls
```

状态文件单次硬上限 16 MiB，因此累计编码字节的形式上界为 2,734,686,208 bytes；容量回归
另将该默认路径的累计 marshal 总量冻结为不超过 2 MiB（本轮实测约 1.02 MiB）。若节点
显式把 `Config.MaxAttempts` 提高到支持的
20，等式上界为 643 writes / 1286 fsync。测试还要求大 prewarm 停在 HTTP I/O 时，另一
namespace 能在前者结束前完成；任务执行不进入边缘请求同步路径。

上述 163 不含新 task 恰好触发的 registry compaction。compaction 只在 registry 达到
8192 tasks 时运行；一次最多保留最新 4096 个 completed task，并按本批实际涉及的 bucket
重写 tombstone tail/overflow segment、再写一次 registry。每个 tombstone shard 写、registry
切换、task 删除和目录 fsync 之间都检查 context；顺序固定为 tombstone -> registry -> task
删除。若在 registry 切换后取消或崩溃，启动或下一次 admission 会按新 registry 清理 orphan
task JSON；切换前取消则旧 registry 保持完整可读。极端分布下单批最多 512 个 tombstone
segment writes 加 1 个 registry write；这是 admission 的独立上界，不会把整个 prewarm
网络执行期置于 `state.lock` 内。

## 故障处置

- `CACHE_LAYOUT_UNSAFE` / `CACHE_METADATA_INVALID`：停止该 namespace 刷新，保留 cache
  现场，检查 owner/mode、symlink/hardlink、renderer key 和 revision；不要手工批量删除。
- `CACHE_ENTRY_CHANGED` / `CACHE_DELETE_FAILED`：按任务 backoff 重试；耗尽后检查磁盘、
  inode 竞争和挂载状态。
- `SITE_CONTEXT_STALE`：停止重试，核对 active publication、listener 响应 version 和
  namespace，禁止降级到旧 revision。
- `PREWARM_REDIRECT_REJECTED`：修复源站 URL/重定向策略；不要开放跟随私网跳转。
- `PREWARM_TIMEOUT` / `PREWARM_UPSTREAM_FAILED` / `PREWARM_STATUS_REJECTED`：按预算重试，
  通过稳定 code 排障，不记录 response body。
- `RETRY_EXHAUSTED`：读取 `cause_code`，由控制面决定新 operation；不要修改旧 journal。
- `ErrJournalCorrupt`：停止 admission/lookup/cancel，保留 registry、task 和 tombstone 现场；
  不得放宽上限、读取超界 shard body、删除 tombstone 或重放未知旧任务。
- `ErrJournalWrite`：结果未知且不得记成功；恢复磁盘后原 task/operation/payload 重投。

刷新和预热都只运行在 Agent 异步任务路径，不进入 OpenResty public request 的同步处理。
执行器故障、控制面离线或任务积压不能停止已经激活的边缘请求。

## 共享 renderer 与最小接线契约

共享 OpenResty renderer 已接入 v2 namespace、cache key 和专用 loopback prewarm listener。
配置发布方必须继续原子提供：

1. tenant ID、site ID、config version ID、严格递增 config revision；
2. 与 `CacheNamespaceID` 逐字节一致的 64 字符 namespace；
3. legacy/advanced public 和 loopback prewarm 使用同一普通 v2 key/zone；Range public 使用
   `range_cache_*` slice identity，而 Range prewarm 保持普通 namespace/quota cache；
4. prewarm listener 返回精确 version、namespace 和 cache state headers，拒绝外部访问；
5. cache root owner/mode 与 Agent 权限契约；
6. resolver 只能从当前已验证 publication 解析精确 revision，不接受 task 提供路径；
7. schema v2 protobuf 的 task、cancel、lookup 和逐项 Result 映射，保留 operation/task
   双幂等、delivery attempt、deadline、预算和 stable code；
8. daemon 在独立有界 worker pool 调用执行器，经 Agent Gateway 回报，不阻塞配置流或
   OpenResty 请求；control task/outbox 负责多节点投递和聚合，不能把本地 success 直接
   当作全局 success。

尚未闭环的接线点涉及 proto、gateway、daemon 和 control-api，本切片没有修改。

## 验证

```sh
cd agents/edge-agent
GOWORK=off go test -count=1 ./internal/cachetask
GOWORK=off go test -race -count=1 ./internal/cachetask
GOWORK=off go vet ./...

cd ../..
sh -n scripts/edge-cache-task-smoke.sh
shellcheck scripts/edge-cache-task-smoke.sh
./scripts/edge-cache-task-smoke.sh
```

默认任务 gate 不是 macOS skip 的替代品：它在 Linux 容器中实际运行真实 `/proc` + pidfd
collector、命令 leader 先退出但 worker 存活的清理、descendant pidfd 首次 close 失败后的重试，
任一用例失败都会由 `docker exec` 原样返回非零状态。随后同一 gate 使用固定 OpenResty
1.27.1.2 验证。真实 OpenResty runtime 证明：**PASS**。
首次 `MISS`、再次 `HIT`；精确 purge 后重新 `MISS,HIT`；prewarm 内部完成
`MISS -> HIT` 二次 loopback receipt，随后第一个 public 请求为 `HIT`；旧 revision
和另一站点保持 `HIT`；恶意 cache metadata 使 purge fail closed，且不误删其他 namespace。

同一 gate 还使用生产 `edgeconfig.Build` 输出验证 `include`/`exclude`/`ignore` 的 query
投影、vary header 隔离和 projected-key freshness 共享状态。freshness access 在内部
redirect 后的 named location 执行，bypass route 不创建 cache lock。脚本在创建前拒绝
容器名或镜像 tag 碰撞。记录的容器/镜像 ID 仍是首选清理目标；ID 丢失或已消失时，脚本
才检查该任务的稳定容器名和镜像 tag，并且只有精确 task owner label 完全匹配时才删除。
稳定名或 tag 指向 foreign、replacement 或 owner 无法证明的资源时必须拒绝删除并以非零
状态退出。任务 tmp 可重复清理，完成后 listener、PID 及 `PPID=1` 任务残留均为 0。
